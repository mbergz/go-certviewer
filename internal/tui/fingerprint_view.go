package tui

import (
	"crypto/x509"

	"github.com/rivo/tview"
)

type FingerprintView struct {
	fingerprintTable *tview.Table
}

func newFingerprintView() *FingerprintView {
	fingerprintTable := tview.NewTable()
	fingerprintTable.SetBorder(true).SetTitle("Fingerprint")

	return &FingerprintView{fingerprintTable}
}

func (v *FingerprintView) primitive() tview.Primitive {
	return v.fingerprintTable
}

func (v *FingerprintView) update(cert *x509.Certificate) {
	v.fingerprintTable.Clear()
	hashByteSlice := certFingerprintBytes(cert)
	row := 0
	appendToTable(v.fingerprintTable, []string{formatToHex(hashByteSlice)}, "SHA256 Fingerprint", &row)
}
