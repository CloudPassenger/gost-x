package reality

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

type metadata struct {
	mptcp       bool
	show        bool
	dest        string
	xver        int
	serverNames []string
	privateKey  string
	shortIds    []string
	maxTimeDiff time.Duration
}

func (l *realityListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		show        = "show"
		dest        = "dest"
		xver        = "xver"
		serverNames = "serverNames"
		privateKey  = "privateKey"
		shortIds    = "shortIds"
		maxTimeDiff = "maxTimeDiff"
	)

	l.md.mptcp = mdutil.GetBool(md, "mptcp")
	l.md.show = mdutil.GetBool(md, show)
	l.md.dest = mdutil.GetString(md, dest)
	l.md.xver = mdutil.GetInt(md, xver)
	l.md.serverNames = mdutil.GetStrings(md, serverNames)
	l.md.privateKey = mdutil.GetString(md, privateKey)
	l.md.shortIds = mdutil.GetStrings(md, shortIds)
	l.md.maxTimeDiff = mdutil.GetDuration(md, maxTimeDiff)
	return
}
