package tui

import (
	"crypto/x509"

	"github.com/rivo/tview"
)

type SubjectView struct {
	subjectTable *tview.Table
}

func newSubjectView() *SubjectView {
	subjectTable := tview.NewTable()
	subjectTable.SetBorder(true).SetTitle("Subject").SetBorderPadding(1, 1, 0, 0)

	return &SubjectView{subjectTable}
}

func (v *SubjectView) primitive() tview.Primitive {
	return v.subjectTable
}

func (v *SubjectView) update(cert *x509.Certificate) {
	v.subjectTable.Clear()
	row := 0
	appendToTable(v.subjectTable, []string{colorizeCommonName(cert, false)}, "Common name (CN)", &row)
	appendToTable(v.subjectTable, cert.Subject.Country, "Country (C)", &row)
	appendToTable(v.subjectTable, cert.Subject.Organization, "Organization (O)", &row)
	appendToTable(v.subjectTable, cert.Subject.OrganizationalUnit, "Organization Unit (OU)", &row)
	appendToTable(v.subjectTable, cert.Subject.Locality, "Locality (L)", &row)
	appendToTable(v.subjectTable, cert.Subject.Province, "State or province name (S)", &row)
}
