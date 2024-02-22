package mreality

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/internal/util/mux"
	"github.com/go-gost/x/registry"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

func init() {
	registry.DialerRegistry().Register("mreality", NewDialer)
	registry.DialerRegistry().Register("mtlr", NewDialer)
}

type mrealityDialer struct {
	sessions     map[string]*muxSession
	sessionMutex sync.Mutex
	logger       logger.Logger
	md           metadata
	options      dialer.Options
}

// Copy from xray
//
//go:linkname aesgcmPreferred github.com/refraction-networking/utls.aesgcmPreferred
func aesgcmPreferred(ciphers []uint16) bool

type uVerifier struct {
	*utls.UConn
	ServerName string
	AuthKey    []byte
	Verified   bool
}

func (c *uVerifier) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	p, _ := reflect.TypeOf(c.Conn).Elem().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Pointer(uintptr(unsafe.Pointer(c.Conn)) + p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.AuthKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.Verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &mrealityDialer{
		sessions: make(map[string]*muxSession),
		logger:   options.Logger,
		options:  options,
	}
}

func (d *mrealityDialer) Init(md md.Metadata) (err error) {
	if err = d.parseMetadata(md); err != nil {
		return
	}

	return nil
}

// Multiplex implements dialer.Multiplexer interface.
func (d *mrealityDialer) Multiplex() bool {
	return true
}

func (d *mrealityDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (conn net.Conn, err error) {
	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()

	session, ok := d.sessions[addr]
	if session != nil && session.IsClosed() {
		delete(d.sessions, addr) // session is dead
		ok = false
	}
	if !ok {
		var options dialer.DialOptions
		for _, opt := range opts {
			opt(&options)
		}

		conn, err = options.NetDialer.Dial(ctx, "tcp", addr)
		if err != nil {
			return
		}

		session = &muxSession{conn: conn}
		d.sessions[addr] = session
	}

	return session.conn, err
}

// Handshake implements dialer.Handshaker
func (d *mrealityDialer) Handshake(ctx context.Context, conn net.Conn, options ...dialer.HandshakeOption) (net.Conn, error) {
	opts := &dialer.HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()

	if d.md.handshakeTimeout > 0 {
		conn.SetDeadline(time.Now().Add(d.md.handshakeTimeout))
		defer conn.SetDeadline(time.Time{})
	}

	session, ok := d.sessions[opts.Addr]
	if session != nil && session.conn != conn {
		conn.Close()
		return nil, errors.New("mreality: unrecognized connection")
	}

	if !ok || session.session == nil {
		s, err := d.initSession(ctx, conn)
		if err != nil {
			d.logger.Error(err)
			conn.Close()
			delete(d.sessions, opts.Addr)
			return nil, err
		}
		session = s
		d.sessions[opts.Addr] = session
	}
	cc, err := session.GetConn()
	if err != nil {
		session.Close()
		delete(d.sessions, opts.Addr)
		return nil, err
	}

	return cc, nil
}

func (d *mrealityDialer) initSession(ctx context.Context, conn net.Conn) (*muxSession, error) {

	localAddr := conn.LocalAddr().String()
	uVerifier := &uVerifier{
		ServerName: d.options.REALITYClientConfig.ServerName,
	}

	utlsConfig := &utls.Config{
		PreferSkipResumptionOnNilExtension: true,
		VerifyPeerCertificate:              uVerifier.VerifyPeerCertificate,
		ServerName:                         d.options.REALITYClientConfig.ServerName,
		InsecureSkipVerify:                 true,
		SessionTicketsDisabled:             true,
		KeyLogWriter:                       nil, // &keyLogWriter{},
		NextProtos:                         []string{"h2"},
	}

	// Randomize the fingerprint
	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	randomized := utls.HelloRandomized
	randomized.Seed, _ = utls.NewPRNGSeed()
	randomized.Weights = &weights
	fingerprint := &randomized //TODO: More fingerprint

	// Handshake
	UConn := utls.UClient(conn, utlsConfig, *fingerprint)
	uVerifier.UConn = UConn
	{
		uVerifier.BuildHandshakeState()
		if len(utlsConfig.NextProtos) > 0 {
			for _, extension := range uVerifier.Extensions {
				if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
					alpnExtension.AlpnProtocols = utlsConfig.NextProtos
					break
				}
			}
		}
		hello := uVerifier.HandshakeState.Hello
		hello.SessionId = make([]byte, 32)
		copy(hello.Raw[39:], hello.SessionId) // the fixed location of `Session ID`
		// hello.SessionId[0] = core.Version_x
		// hello.SessionId[1] = core.Version_y
		// hello.SessionId[2] = core.Version_z
		// hello.SessionId[3] = 0 // reserved
		var nowTime time.Time
		if utlsConfig.Time != nil {
			nowTime = utlsConfig.Time()
		} else {
			nowTime = time.Now()
		}
		// Test: disable session ticket
		hello.SessionTicket = make([]byte, 32)
		binary.BigEndian.PutUint64(hello.SessionId, uint64(nowTime.Unix()))

		hello.SessionId[0] = 1
		hello.SessionId[1] = 8
		hello.SessionId[2] = 7
		hello.SessionId[3] = 0 // reserved
		binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
		copy(hello.SessionId[8:], d.options.REALITYClientConfig.ShortId)
		if d.options.REALITYClientConfig.Show {
			d.logger.Debug(fmt.Sprintf("REALITY localAddr: %v\thello.SessionId[:16]: %v\n", localAddr, hello.SessionId[:16]))
		}
		publicKey, err := ecdh.X25519().NewPublicKey(d.options.REALITYClientConfig.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("ecdh.X25519().NewPublicKey: %v", err)
		}
		uVerifier.AuthKey, _ = uVerifier.HandshakeState.State13.EcdheKey.ECDH(publicKey)
		if uVerifier.AuthKey == nil {
			return nil, fmt.Errorf("REALITY: SharedKey == nil")
		}
		if _, err := hkdf.New(sha256.New, uVerifier.AuthKey, hello.Random[:20], []byte("REALITY")).Read(uVerifier.AuthKey); err != nil {
			return nil, err
		}
		var aead cipher.AEAD
		if aesgcmPreferred(hello.CipherSuites) {
			block, _ := aes.NewCipher(uVerifier.AuthKey)
			aead, _ = cipher.NewGCM(block)
		} else {
			aead, _ = chacha20poly1305.New(uVerifier.AuthKey)
		}
		if d.options.REALITYClientConfig.Show {
			d.logger.Debug(fmt.Sprintf("REALITY localAddr: %v\tuConn.AuthKey[:16]: %v\tAEAD: %T\n", localAddr, uVerifier.AuthKey[:16], aead))
		}
		aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
		copy(hello.Raw[39:], hello.SessionId)
		if d.options.REALITYClientConfig.Show {
			d.logger.Debug(fmt.Sprintf("REALITY hello.sessionId: %v\n", hello.SessionId))
			d.logger.Debug(fmt.Sprintf("REALITY uConn.AuthKey: %v\n", uVerifier.AuthKey))
		}
	}

	if err := uVerifier.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	if d.options.REALITYClientConfig.Show {
		d.logger.Debug(fmt.Sprintf("REALITY localAddr: %v\tuConn.Verified: %v\n", localAddr, uVerifier.Verified))
	}

	if !uVerifier.Verified {
		go realityConnFallback(uVerifier, d.options.REALITYClientConfig.ServerName, *fingerprint)
		return nil, fmt.Errorf("REALITY: uConn.Verified == false")
	}

	conn = uVerifier

	/*
		tlsConn := tls.Client(conn, d.options.TLSConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		conn = tlsConn
	*/

	// stream multiplex
	session, err := mux.ClientSession(conn, d.md.muxCfg)
	if err != nil {
		return nil, err
	}
	return &muxSession{conn: conn, session: session}, nil
}

func realityConnFallback(uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()

	client := &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
				return uConn, nil
			},
		},
	}
	request, _ := http.NewRequest("GET", "https://"+serverName, nil)
	request.Header.Set("User-Agent", fingerprint.Client)
	request.AddCookie(&http.Cookie{Name: "sid", Value: randStr(32)})
	response, err := client.Do(request)
	if err != nil {
		return
	}

	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
}

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var src = rand.NewSource(time.Now().UnixNano())

const (
	// 6 bits to represent a letter index
	letterIdBits = 6
	// All 1-bits as many as letterIdBits
	letterIdMask = 1<<letterIdBits - 1
	letterIdMax  = 63 / letterIdBits
)

func randStr(n int) string {
	b := make([]byte, n)
	// A rand.Int63() generates 63 random bits, enough for letterIdMax letters!
	for i, cache, remain := n-1, src.Int63(), letterIdMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdMax
		}
		if idx := int(cache & letterIdMask); idx < len(letters) {
			b[i] = letters[idx]
			i--
		}
		cache >>= letterIdBits
		remain--
	}
	return *(*string)(unsafe.Pointer(&b))
}
