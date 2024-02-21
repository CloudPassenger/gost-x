package reality

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/x/config"
	"github.com/xtls/reality"
)

// LoadServerConfig loads the certificate from cert & key files and client CA file.
func LoadServerConfig(config *config.REALITYConfig) (*reality.Config, error) {
	if config.Dest == "" && config.PrivateKey == "" && len(config.ServerNames) == 0 && len(config.ShortIds) == 0 {
		// Disabled
		return nil, nil
	}
	if config.Dest == "" {
		return nil, fmt.Errorf("REALITY destination is empty")
	}
	if config.PrivateKey == "" {
		return nil, fmt.Errorf("REALITY private key is empty")
	}
	if config.Xver > 2 {
		return nil, fmt.Errorf("REALITY xver is invalid")
	}
	if len(config.ServerNames) == 0 {
		return nil, fmt.Errorf("REALITY server names is empty")
	}
	if len(config.ShortIds) == 0 {
		return nil, fmt.Errorf("REALITY short ids is empty")
	}

	var privateKey []byte
	var err error
	if privateKey, err = base64.RawURLEncoding.DecodeString(config.PrivateKey); err != nil || len(privateKey) != 32 {
		return nil, fmt.Errorf("REALITY private key is invalid")
	}

	shortIds := make(map[[8]byte]bool, len(config.ShortIds))
	for _, s := range config.ShortIds {
		var shortId [8]byte
		if _, err = hex.Decode(shortId[:], []byte(s)); err != nil {
			return nil, fmt.Errorf("REALITY short id is invalid: %s", s)
		}
		shortIds[shortId] = true
	}
	serverNames := make(map[string]bool, len(config.ServerNames))
	for _, s := range config.ServerNames {
		serverNames[s] = true
	}

	var connType string
	switch config.Dest[0] {
	case '@', '/':
		connType = "unix"
		if config.Dest[0] == '@' && len(config.Dest) > 1 && config.Dest[1] == '@' && (runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "android") {
			fullAddr := make([]byte, len(syscall.RawSockaddrUnix{}.Path))
			copy(fullAddr, config.Dest[1:])
			config.Dest = string(fullAddr)
		}
	default:
		connType = "tcp"
	}

	var dialer net.Dialer

	cfg := &reality.Config{
		DialContext: dialer.DialContext,

		Show:        config.Show,
		Dest:        config.Dest,
		Type:        connType,
		Xver:        byte(config.Xver),
		PrivateKey:  privateKey,
		ServerNames: serverNames,
		ShortIds:    shortIds,
		MaxTimeDiff: time.Duration(config.MaxTimeDiff) * time.Millisecond,

		SessionTicketsDisabled: true,

		NextProtos:   nil, // should be nil
		KeyLogWriter: nil, //TODO: Implement key log writer for debugging

	}

	/*
		if config.MinClientVersion != "" {
			cfg.MinClientVer = make([]byte, 3)
			var u uint64
			for i, s := range strings.Split(config.MinClientVersion, ".") {
				if i == 3 {
					return nil, fmt.Errorf("REALITY minClientVer is invalid: %s", config.MinClientVersion)
				}
				if u, err = strconv.ParseUint(s, 10, 8); err != nil {
					return nil, fmt.Errorf("REALITY minClientVer %s should be less than 256", config.MinClientVersion)
				} else {
					cfg.MinClientVer[i] = byte(u)
				}
			}
		}

		if config.MaxClientVersion != "" {
			cfg.MaxClientVer = make([]byte, 3)
			var u uint64
			for i, s := range strings.Split(config.MaxClientVersion, ".") {
				if i == 3 {
					return nil, fmt.Errorf("REALITY maxClientVer is invalid: %s", config.MaxClientVersion)
				}
				if u, err = strconv.ParseUint(s, 10, 8); err != nil {
					return nil, fmt.Errorf("REALITY maxClientVer %s should be less than 256", config.MaxClientVersion)
				} else {
					cfg.MaxClientVer[i] = byte(u)
				}
			}
		}
	*/

	return cfg, nil
}

// LoadClientConfig loads the certificate from cert & key files and CA file.
func LoadClientConfig(config *config.REALITYConfig) (*dialer.RealityClientConfig, error) {

	if config.ServerName == "" && config.PublicKey == "" && config.ShortId == "" {
		// Disabled
		return nil, nil
	}

	if len(config.ServerNames) != 0 {
		return nil, fmt.Errorf("REALITY server names is not supported in client mode")
	}
	if config.PublicKey == "" {
		return nil, fmt.Errorf("REALITY public key is empty")
	}

	var publicKey []byte
	var err error
	if publicKey, err = base64.RawURLEncoding.DecodeString(config.PublicKey); err != nil || len(publicKey) != 32 {
		return nil, fmt.Errorf("REALITY public key is invalid")
	}

	if len(config.ShortIds) != 0 {
		return nil, fmt.Errorf("REALITY short ids is not supported in client mode")
	}
	shortId := make([]byte, 8)
	if _, err = hex.Decode(shortId, []byte(config.ShortId)); err != nil {
		return nil, fmt.Errorf("REALITY short id is invalid: %s", config.ShortId)
	}

	cfg := &dialer.RealityClientConfig{
		Show:       config.Show,
		ServerName: config.ServerName,
		PublicKey:  publicKey,
		ShortId:    shortId,
	}

	return cfg, nil
}
