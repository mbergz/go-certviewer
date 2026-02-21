package tui

import (
	"crypto/x509"

	"github.com/rivo/tview"
)

type IssuerView struct {
	issuerTable *tview.Table
}

func newIssuerView() *IssuerView {
	issuerTable := tview.NewTable()
	issuerTable.SetBorder(true).SetTitle("Issuer").SetBorderPadding(1, 1, 0, 0)

	return &IssuerView{issuerTable}
}

func (v *IssuerView) primitive() tview.Primitive {
	return v.issuerTable
}

func (v *IssuerView) update(cert *x509.Certificate) {
	v.issuerTable.Clear()
	row := 0
	appendToTable(v.issuerTable, []string{colorizeCommonName(cert, true)}, "Common name (CN)", &row)
	appendToTable(v.issuerTable, cert.Issuer.Country, "Country (C)", &row)
	appendToTable(v.issuerTable, cert.Issuer.Organization, "Organization (O)", &row)
	appendToTable(v.issuerTable, cert.Issuer.OrganizationalUnit, "Organization Unit (OU)", &row)
	appendToTable(v.issuerTable, cert.Issuer.Locality, "Locality (L)", &row)
	appendToTable(v.issuerTable, cert.Issuer.Province, "State or province name (S)", &row)
}
