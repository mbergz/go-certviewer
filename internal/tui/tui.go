package tui

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/rivo/tview"
)

var (
	app             *tview.Application
	subjectTable    *tview.Table
	validityTable   *tview.Table
	validtyTextView *tview.TextView
)

func Launch(certs []*x509.Certificate) {
	app = tview.NewApplication()

	subjectTable = tview.NewTable()
	subjectTable.SetBorder(true).SetTitle("Subject").SetBorderPadding(1, 1, 0, 0)

	validityTable = tview.NewTable()
	validtyFlex := tview.NewFlex().SetDirection(tview.FlexRow)
	validtyFlex.SetBorder(true).SetTitle("Validity")

	validtyTextView = tview.NewTextView().SetTextAlign(tview.AlignCenter).SetDynamicColors(true)
	validtyFlex.AddItem(validityTable, 0, 2, false).AddItem(validtyTextView, 0, 1, false)

	certChainList := createCertChainList(certs)

	mainFlex := tview.NewFlex().
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(subjectTable, 0, 2, false).
			AddItem(validtyFlex, 0, 1, false).
			AddItem(tview.NewBox().SetBorder(true).SetTitle("Signature"), 10, 1, false), 0, 2, false).
		AddItem(certChainList, 30, 1, true)

	if err := app.SetRoot(mainFlex, true).SetFocus(mainFlex).Run(); err != nil {
		panic(err)
	}
}

func populateSubjectArea(cert *x509.Certificate) {
	row := 0
	appendToTable(subjectTable, []string{cert.Subject.CommonName}, "Common name (CN)", &row)
	appendToTable(subjectTable, cert.Subject.Country, "Country (C)", &row)
	appendToTable(subjectTable, cert.Subject.Organization, "Organization (O)", &row)
	appendToTable(subjectTable, cert.Subject.OrganizationalUnit, "Organization Unit (OU)", &row)
	appendToTable(subjectTable, cert.Subject.Locality, "Locality (L)", &row)
	appendToTable(subjectTable, cert.Subject.Province, "State or province name (S)", &row)
}

func populateValidityArea(cert *x509.Certificate) {
	row := 0
	appendToTable(validityTable, []string{cert.NotBefore.String()}, "Valid From", &row)
	appendToTable(validityTable, []string{cert.NotAfter.String()}, "Valid To", &row)
	validtyTextView.Clear()

	now := time.Now()
	if now.After(cert.NotAfter) {
		fmt.Fprintf(validtyTextView, "Certificate has [red]expired[white]")
	} else {
		expiresIn := cert.NotAfter.Sub(now)
		expiresInDays := int(expiresIn.Hours() / 24)

		if expiresInDays > 30 {
			fmt.Fprintf(validtyTextView, "Certificate will expire in [green]%d[white] days", expiresInDays)
		} else if expiresInDays < 3 {
			fmt.Fprintf(validtyTextView, "Certificate will expire in [red]%d[white] days", expiresInDays)
		} else if expiresInDays < 10 {
			fmt.Fprintf(validtyTextView, "Certificate will expire in [orange]%d[white] days", expiresInDays)
		} else { // 10 - 30 days
			fmt.Fprintf(validtyTextView, "Certificate will expire in [yellow]%d[white] days", expiresInDays)
		}
	}
}

func onSelectedCert(cert *x509.Certificate) func() {
	return func() {
		subjectTable.Clear()
		populateSubjectArea(cert)
		populateValidityArea(cert)
	}
}

func appendToTable(table *tview.Table, value []string, displayName string, rowCount *int) {
	if len(value) > 0 {
		table.SetCell(*rowCount, 0, tview.NewTableCell(fmt.Sprintf("%-30s", displayName)))
		table.SetCell(*rowCount, 1, tview.NewTableCell(strings.Join(value, ",")))
		*rowCount++
	}
}

func createCertChainList(certs []*x509.Certificate) *tview.List {
	certChainList := tview.NewList()
	certChainList.SetBorder(true).SetTitle("Certificate chain")

	for i, cert := range certs {
		text := fmt.Sprintf("%d: CN=%s", i+1, cert.Subject.CommonName)
		certChainList.AddItem(text, "", 0, onSelectedCert(cert))
	}
	onSelectedCert(certs[0])()
	return certChainList
}
