package tui

import (
	"crypto/x509"

	"github.com/rivo/tview"
)

type SignatureView struct {
	signatureTable *tview.Table
}

func newSignatureView() *SignatureView {
	signatureTable := tview.NewTable()
	signatureTable.SetBorder(true).SetTitle("Signature")

	return &SignatureView{signatureTable}
}

func (v *SignatureView) primitive() tview.Primitive {
	return v.signatureTable
}

func (v *SignatureView) update(cert *x509.Certificate) {
	v.signatureTable.Clear()
	row := 0

	appendToTableTitleWidth(v.signatureTable, []string{cert.SignatureAlgorithm.String()}, "Algorithm", 15, &row)
	appendToTableTitleWidth(v.signatureTable, []string{formatToHex(cert.Signature)}, "Value", 15, &row)
}
