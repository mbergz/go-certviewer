package tui

import (
	"crypto/x509"

	"github.com/rivo/tview"
)

type View interface {
	update(cert *x509.Certificate)
	primitive() tview.Primitive
}
