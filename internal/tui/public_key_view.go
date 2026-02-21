package tui

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strconv"

	"github.com/rivo/tview"
)

type PublicKeyView struct {
	publicKeyTable *tview.Table
}

func newPublicKeyView() *PublicKeyView {
	publicKeyTable := tview.NewTable()
	publicKeyTable.SetBorder(true).SetTitle("Public key")

	return &PublicKeyView{publicKeyTable}
}

func (v *PublicKeyView) primitive() tview.Primitive {
	return v.publicKeyTable
}

func (v *PublicKeyView) update(cert *x509.Certificate) {
	v.publicKeyTable.Clear()
	row := 0

	appendToTableTitleWidth(v.publicKeyTable, []string{cert.PublicKeyAlgorithm.String()}, "Algorithm", 15, &row)

	switch pubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize := pubKey.N.BitLen()
		appendToTableTitleWidth(v.publicKeyTable, []string{fmt.Sprintf("%s bits", strconv.Itoa(keySize))}, "Key size", 15, &row)

		appendToTableTitleWidth(v.publicKeyTable, []string{formatToHex(pubKey.N.Bytes())}, "Modulus", 15, &row)
		appendToTableTitleWidth(v.publicKeyTable, []string{formatHexStr(fmt.Sprintf("%x", pubKey.E))}, "Exponent", 15, &row)
	case *ecdsa.PublicKey:
		keySize := pubKey.Curve.Params().BitSize
		appendToTableTitleWidth(v.publicKeyTable, []string{fmt.Sprintf("%s bits", strconv.Itoa(keySize))}, "Key size", 15, &row)

		pubKeyValue := "04 " + formatToHex(pubKey.X.Bytes()) + formatToHex(pubKey.Y.Bytes()) // Add 04 for uncompressed point identifier
		appendToTableTitleWidth(v.publicKeyTable, []string{pubKeyValue}, "Value", 15, &row)
		appendToTableTitleWidth(v.publicKeyTable, []string{pubKey.Curve.Params().Name}, "Curve", 15, &row)
	case ed25519.PublicKey:
		// Ed25519 is fixed at 256
		keySize := 256
		appendToTableTitleWidth(v.publicKeyTable, []string{fmt.Sprintf("%s bits", strconv.Itoa(keySize))}, "Key size", 15, &row)
		appendToTableTitleWidth(v.publicKeyTable, []string{formatToHex(pubKey)}, "Value", 15, &row)
	}
}
