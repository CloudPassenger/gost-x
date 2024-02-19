package quic

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

const (
	defaultBacklog = 128
)

type metadata struct {
	// keepAlive        bool
	keepAlivePeriod         time.Duration
	handshakeTimeout        time.Duration
	maxIdleTimeout          time.Duration
	maxStreams              int
	recvMbps                int
	initStreamReceiveWindow int
	maxStreamReceiveWindow  int
	initConnReceiveWindow   int
	maxConnReceiveWindow    int
	DisablePathMTUDiscovery bool

	cipherKey []byte
	backlog   int
}

func (l *quicListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keepAlive        = "keepAlive"
		keepAlivePeriod  = "ttl"
		handshakeTimeout = "handshakeTimeout"
		maxIdleTimeout   = "maxIdleTimeout"
		maxStreams       = "maxStreams"
		// Hysteria Congestion
		recvMbps = "recvMbps"
		// QUIC Additional Options
		initStreamReceiveWindow = "initStreamReceiveWindow"
		maxStreamReceiveWindow  = "maxStreamReceiveWindow"
		initConnReceiveWindow   = "initConnReceiveWindow"
		maxConnReceiveWindow    = "maxConnReceiveWindow"
		DisablePathMTUDiscovery = "disablePathMTUDiscovery"

		backlog   = "backlog"
		cipherKey = "cipherKey"
	)

	l.md.backlog = mdutil.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	if key := mdutil.GetString(md, cipherKey); key != "" {
		l.md.cipherKey = []byte(key)
	}

	if mdutil.GetBool(md, keepAlive) {
		l.md.keepAlivePeriod = mdutil.GetDuration(md, keepAlivePeriod)
		if l.md.keepAlivePeriod <= 0 {
			l.md.keepAlivePeriod = 10 * time.Second
		}
	}
	l.md.handshakeTimeout = mdutil.GetDuration(md, handshakeTimeout)
	l.md.maxIdleTimeout = mdutil.GetDuration(md, maxIdleTimeout)
	l.md.maxStreams = mdutil.GetInt(md, maxStreams)
	l.md.recvMbps = mdutil.GetInt(md, recvMbps)
	l.md.initStreamReceiveWindow = mdutil.GetInt(md, initStreamReceiveWindow)
	l.md.maxStreamReceiveWindow = mdutil.GetInt(md, maxStreamReceiveWindow)
	l.md.initConnReceiveWindow = mdutil.GetInt(md, initConnReceiveWindow)
	l.md.maxConnReceiveWindow = mdutil.GetInt(md, maxConnReceiveWindow)
	l.md.DisablePathMTUDiscovery = mdutil.GetBool(md, DisablePathMTUDiscovery)

	// Set default value
	if l.md.maxStreams <= 0 {
		l.md.maxStreams = 1024
	}
	if l.md.initStreamReceiveWindow <= 0 {
		l.md.initStreamReceiveWindow = 8388608
	}
	if l.md.maxStreamReceiveWindow <= 0 {
		l.md.maxStreamReceiveWindow = 8388608
	}
	if l.md.initConnReceiveWindow <= 0 {
		l.md.initConnReceiveWindow = 20971520
	}
	if l.md.maxConnReceiveWindow <= 0 {
		l.md.maxConnReceiveWindow = 20971520
	}

	return
}
