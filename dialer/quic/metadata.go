package quic

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

type metadata struct {
	keepAlivePeriod         time.Duration
	maxIdleTimeout          time.Duration
	handshakeTimeout        time.Duration
	maxStreams              int
	sendMbps                int
	initStreamReceiveWindow int
	maxStreamReceiveWindow  int
	initConnReceiveWindow   int
	maxConnReceiveWindow    int
	DisablePathMTUDiscovery bool

	cipherKey []byte
}

func (d *quicDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keepAlive        = "keepAlive"
		keepAlivePeriod  = "ttl"
		handshakeTimeout = "handshakeTimeout"
		maxIdleTimeout   = "maxIdleTimeout"
		maxStreams       = "maxStreams"
		// Hysteria Congestion
		sendMbps = "sendMbps"
		// QUIC Additional Options
		initStreamReceiveWindow = "initStreamReceiveWindow"
		maxStreamReceiveWindow  = "maxStreamReceiveWindow"
		initConnReceiveWindow   = "initConnReceiveWindow"
		maxConnReceiveWindow    = "maxConnReceiveWindow"
		DisablePathMTUDiscovery = "disablePathMTUDiscovery"

		cipherKey = "cipherKey"
	)

	if key := mdutil.GetString(md, cipherKey); key != "" {
		d.md.cipherKey = []byte(key)
	}

	if md == nil || !md.IsExists(keepAlive) || mdutil.GetBool(md, keepAlive) {
		d.md.keepAlivePeriod = mdutil.GetDuration(md, keepAlivePeriod)
		if d.md.keepAlivePeriod <= 0 {
			d.md.keepAlivePeriod = 10 * time.Second
		}
	}
	d.md.handshakeTimeout = mdutil.GetDuration(md, handshakeTimeout)
	d.md.maxIdleTimeout = mdutil.GetDuration(md, maxIdleTimeout)
	d.md.maxStreams = mdutil.GetInt(md, maxStreams)
	d.md.sendMbps = mdutil.GetInt(md, sendMbps)
	d.md.initStreamReceiveWindow = mdutil.GetInt(md, initStreamReceiveWindow)
	d.md.maxStreamReceiveWindow = mdutil.GetInt(md, maxStreamReceiveWindow)
	d.md.initConnReceiveWindow = mdutil.GetInt(md, initConnReceiveWindow)
	d.md.maxConnReceiveWindow = mdutil.GetInt(md, maxConnReceiveWindow)
	d.md.DisablePathMTUDiscovery = mdutil.GetBool(md, DisablePathMTUDiscovery)

	// Set default value
	if d.md.maxStreams <= 0 {
		d.md.maxStreams = 1024
	}
	if d.md.initStreamReceiveWindow <= 0 {
		d.md.initStreamReceiveWindow = 8388608
	}
	if d.md.maxStreamReceiveWindow <= 0 {
		d.md.maxStreamReceiveWindow = 8388608
	}
	if d.md.initConnReceiveWindow <= 0 {
		d.md.initConnReceiveWindow = 20971520
	}
	if d.md.maxConnReceiveWindow <= 0 {
		d.md.maxConnReceiveWindow = 20971520
	}

	return
}
