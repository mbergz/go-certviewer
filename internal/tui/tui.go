package tui

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var (
	app             *tview.Application
	mainFlex        *tview.Flex
	subjectTable    *tview.Table
	issuerTable     *tview.Table
	extensionsTable *tview.Table
	validityTable   *tview.Table
	validtyTextView *tview.TextView
	mouseEnabled    bool = true
)

func Launch(certs []*x509.Certificate) {
	app = tview.NewApplication()
	app.EnableMouse(mouseEnabled)

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'm' {
			mouseEnabled = !mouseEnabled
			app.EnableMouse(mouseEnabled)
		}
		return event
	})

	subjectTable = tview.NewTable()
	subjectTable.SetBorder(true).SetTitle("Subject").SetBorderPadding(1, 1, 0, 0)

	issuerTable = tview.NewTable()
	issuerTable.SetBorder(true).SetTitle("Issuer").SetBorderPadding(1, 1, 0, 0)

	extensionsTable = tview.NewTable()
	extensionsTable.SetBorder(true).SetTitle("X.509 v3 extensions").SetBorderPadding(1, 1, 0, 0)

	validityTable = tview.NewTable()
	validtyFlex := tview.NewFlex().SetDirection(tview.FlexRow)
	validtyFlex.SetBorder(true).SetTitle("Validity")

	validtyTextView = tview.NewTextView().SetTextAlign(tview.AlignCenter).SetDynamicColors(true)
	validtyFlex.AddItem(validityTable, 0, 2, false).AddItem(validtyTextView, 0, 1, false)

	certChainList := createCertChainList(certs)

	mainFlex = tview.NewFlex().
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(tview.NewFlex().SetDirection(tview.FlexColumn).
				AddItem(subjectTable, 0, 4, false).
				AddItem(issuerTable, 0, 3, false), 0, 2, false).
			AddItem(validtyFlex, 0, 1, false).
			AddItem(extensionsTable, 0, 2, false).
			AddItem(tview.NewBox().SetBorder(true).SetTitle("Signature"), 0, 2, false), 0, 2, false).
		AddItem(certChainList, 30, 1, true)

	if err := app.SetRoot(mainFlex, true).SetFocus(mainFlex).Run(); err != nil {
		panic(err)
	}
}

func populateSubjectArea(cert *x509.Certificate) {
	subjectTable.Clear()
	row := 0
	appendToTable(subjectTable, []string{cert.Subject.CommonName}, "Common name (CN)", &row)
	appendToTable(subjectTable, cert.Subject.Country, "Country (C)", &row)
	appendToTable(subjectTable, cert.Subject.Organization, "Organization (O)", &row)
	appendToTable(subjectTable, cert.Subject.OrganizationalUnit, "Organization Unit (OU)", &row)
	appendToTable(subjectTable, cert.Subject.Locality, "Locality (L)", &row)
	appendToTable(subjectTable, cert.Subject.Province, "State or province name (S)", &row)
}

func populateIssuerArea(cert *x509.Certificate) {
	issuerTable.Clear()
	row := 0
	appendToTable(issuerTable, []string{cert.Issuer.CommonName}, "Common name (CN)", &row)
	appendToTable(issuerTable, cert.Issuer.Country, "Country (C)", &row)
	appendToTable(issuerTable, cert.Issuer.Organization, "Organization (O)", &row)
	appendToTable(issuerTable, cert.Issuer.OrganizationalUnit, "Organization Unit (OU)", &row)
	appendToTable(issuerTable, cert.Issuer.Locality, "Locality (L)", &row)
	appendToTable(issuerTable, cert.Issuer.Province, "State or province name (S)", &row)
}

func populateExtensionsArea(cert *x509.Certificate) {
	extensionsTable.Clear()
	row := 0
	// Fix own area for SAN
	appendToTable(extensionsTable, cert.DNSNames, "SAN - DNS names", &row)
	if len(cert.IPAddresses) > 0 {
		ipAsString := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ipAsString[i] = ip.String()
		}
		appendToTable(extensionsTable, ipAsString, "SAN - IP addresses", &row)
	}
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
		populateSubjectArea(cert)
		populateValidityArea(cert)
		populateIssuerArea(cert)
		populateExtensionsArea(cert)
	}
}

func appendToTable(table *tview.Table, value []string, displayName string, rowCount *int) {
	if len(value) > 0 {
		table.SetCell(*rowCount, 0, tview.NewTableCell(fmt.Sprintf("%-25s", displayName)).SetSelectable(true).SetTransparency(true))
		table.SetCell(*rowCount, 1, tview.NewTableCell(strings.Join(value, ",")).SetSelectable(true).SetClickedFunc(func() bool {
			displayText := strings.Join(value, ",")

			darkGray := tcell.NewRGBColor(40, 40, 40)
			fullTextView := tview.NewTextView()
			fullTextView.SetText(displayText)
			fullTextView.SetBackgroundColor(darkGray)

			okBtn := tview.NewButton("OK").SetSelectedFunc(func() {
				app.SetRoot(mainFlex, true)
			})
			okBtn.SetBackgroundColor(darkGray) // Doesn't work

			okBtnFlex := tview.NewFlex().SetDirection(tview.FlexColumn).
				AddItem(tview.NewBox().SetBackgroundColor(darkGray), 0, 1, false).
				AddItem(okBtn, 8, 1, false).
				AddItem(tview.NewBox().SetBackgroundColor(darkGray), 0, 1, false)

			fullTextViewWrapper := tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(fullTextView, 0, 3, false).
				AddItem(okBtnFlex, 1, 1, false)
			fullTextViewWrapper.SetBorder(true)
			fullTextViewWrapper.SetBackgroundColor(darkGray)

			vertFlexSize := 1
			if len(strings.Join(value, ",")) > 200 {
				vertFlexSize = 2
			}
			vertFlex := tview.NewFlex().SetDirection(tview.FlexRow).
				AddItem(nil, 0, 2, false).
				AddItem(fullTextViewWrapper, 0, vertFlexSize, false).
				AddItem(nil, 0, 2, false)

			modalFlex := tview.NewFlex().
				AddItem(nil, 0, 1, false).
				AddItem(vertFlex, 0, 2, true).
				AddItem(nil, 0, 1, false)

			modalFlex.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
				if event.Key() == tcell.KeyESC {
					app.SetRoot(mainFlex, true)
				}
				return event
			})

			pages := tview.NewPages().
				AddPage("mainFlex", mainFlex, false, true).
				AddPage("modal", modalFlex, true, true)
			app.SetRoot(pages, true)
			return true
		}))
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
