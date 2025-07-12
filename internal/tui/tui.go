package tui

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"go-certviewer/internal/model"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var (
	app             *tview.Application
	mainFlex        *tview.Flex
	subjectTable    *tview.Table
	issuerTable     *tview.Table
	extensionsTable *tview.Table
	publicKeyTable  *tview.Table
	signatureTable  *tview.Table
	validityTable   *tview.Table
	validtyTextView *tview.TextView
	mouseEnabled    bool = true
)

func Launch(certCollection model.CertificateCollection) {
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

	publicKeyTable = tview.NewTable()
	publicKeyTable.SetBorder(true).SetTitle("Public key")

	signatureTable = tview.NewTable()
	signatureTable.SetBorder(true).SetTitle("Signature")

	validityTable = tview.NewTable()
	validityTable.SetBorderPadding(1, 1, 0, 0)
	validtyFlex := tview.NewFlex().SetDirection(tview.FlexRow)
	validtyFlex.SetBorder(true).SetTitle("Validity")

	validtyTextView = tview.NewTextView().SetTextAlign(tview.AlignCenter).SetDynamicColors(true)
	validtyFlex.AddItem(validityTable, 0, 2, false).AddItem(validtyTextView, 0, 1, false)

	certInfoArea := createCertInfoArea(certCollection)

	mainFlex = tview.NewFlex().
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(tview.NewFlex().SetDirection(tview.FlexColumn).
				AddItem(subjectTable, 0, 4, false).
				AddItem(issuerTable, 0, 3, false), 0, 2, false).
			AddItem(validtyFlex, 0, 2, false).
			AddItem(extensionsTable, 0, 3, false).
			AddItem(publicKeyTable, 0, 1, false).
			AddItem(signatureTable, 0, 1, false), 0, 4, false).
		AddItem(certInfoArea, 0, 1, true)

	if err := app.SetRoot(mainFlex, true).SetFocus(mainFlex).Run(); err != nil {
		panic(err)
	}
}

func createCertInfoArea(certCollection model.CertificateCollection) tview.Primitive {
	certChainList := createCertChainList(certCollection)
	var allCerts *tview.List
	if len(certCollection.All) > 0 {
		allCerts = createAllCertsList(certCollection)
	}

	if allCerts != nil {
		return tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(certChainList, 0, 1, true).
			AddItem(allCerts, 0, 1, false)
	}
	return certChainList
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

	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 || len(cert.EmailAddresses) > 0 || len(cert.URIs) > 0 {
		appendToTableKeyOnly(extensionsTable, "Subject Alternative Name (SAN)", &row)
	}

	appendToTable(extensionsTable, cert.DNSNames, "    DNS names", &row)
	if len(cert.IPAddresses) > 0 {
		ipAsString := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ipAsString[i] = ip.String()
		}
		appendToTable(extensionsTable, ipAsString, "    IP addresses", &row)
	}
	appendToTable(extensionsTable, cert.EmailAddresses, "    Email addresses", &row)
	if len(cert.URIs) > 0 {
		urisAsString := make([]string, len(cert.URIs))
		for i, ip := range cert.URIs {
			urisAsString[i] = ip.String()
		}
		appendToTable(extensionsTable, urisAsString, "    URI's", &row)
	}

	if len(cert.OCSPServer) > 0 || len(cert.IssuingCertificateURL) > 0 {
		appendToTableKeyOnly(extensionsTable, "Authority Information Access (AIA)", &row)
	}
	appendToTable(extensionsTable, cert.OCSPServer, "    OCSP", &row)
	appendToTable(extensionsTable, cert.IssuingCertificateURL, "    Issuer URL", &row)

	appendToTable(extensionsTable, []string{formatToHex(cert.SubjectKeyId)}, "Subject Key Identifier (SKI)", &row)
	appendToTable(extensionsTable, []string{formatToHex(cert.AuthorityKeyId)}, "Authority Key Identifier (AKI)", &row)
}

func populatePublicKeyArea(cert *x509.Certificate) {
	publicKeyTable.Clear()
	row := 0

	appendToTable(publicKeyTable, []string{cert.PublicKeyAlgorithm.String()}, "Algorithm", &row)

	switch pubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize := pubKey.N.BitLen()
		appendToTable(publicKeyTable, []string{fmt.Sprintf("%s bits", strconv.Itoa(keySize))}, "Key size", &row)

		appendToTable(publicKeyTable, []string{formatToHex(pubKey.N.Bytes())}, "Modulus", &row)
		appendToTable(publicKeyTable, []string{formatHexStr(fmt.Sprintf("%x", pubKey.E))}, "Exponent", &row)
	case *ecdsa.PublicKey:
		keySize := pubKey.Curve.Params().BitSize
		appendToTable(publicKeyTable, []string{fmt.Sprintf("%s bits", strconv.Itoa(keySize))}, "Key size", &row)

		pubKeyValue := "04 " + formatToHex(pubKey.X.Bytes()) + formatToHex(pubKey.Y.Bytes()) // Add 04 for uncompressed point identifier
		appendToTable(publicKeyTable, []string{pubKeyValue}, "Value", &row)
		appendToTable(publicKeyTable, []string{pubKey.Curve.Params().Name}, "Curve", &row)
	case ed25519.PublicKey:
		// Ed25519 is fixed at 256
		keySize := 256
		appendToTable(publicKeyTable, []string{fmt.Sprintf("%s bits", strconv.Itoa(keySize))}, "Key size", &row)
		appendToTable(publicKeyTable, []string{formatToHex(pubKey)}, "Value", &row)
	}
}

func populateSignatureArea(cert *x509.Certificate) {
	signatureTable.Clear()
	row := 0

	appendToTable(signatureTable, []string{cert.SignatureAlgorithm.String()}, "Algorithm", &row)
	appendToTable(signatureTable, []string{formatToHex(cert.Signature)}, "Value", &row)
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
		populatePublicKeyArea(cert)
		populateSignatureArea(cert)
	}
}

func appendToTableKeyOnly(table *tview.Table, displayName string, rowCount *int) {
	table.SetCell(*rowCount, 0, tview.NewTableCell(fmt.Sprintf("%-25s", displayName)).SetSelectable(true).SetTransparency(true))
	*rowCount++
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

			fullTextView.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
				if action == tview.MouseRightClick {
					content := fullTextView.GetText(true)
					clipboard.WriteAll(content)
				}
				return action, event
			})

			okBtn := tview.NewButton("OK").SetSelectedFunc(func() {
				app.SetRoot(mainFlex, true)
			})

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

func createCertChainList(certCollection model.CertificateCollection) *tview.List {
	certChainList := tview.NewList()
	title := "Certificate chain"
	if len(certCollection.Chains) > 1 {
		title += "s"
	}
	certChainList.SetBorder(true).SetTitle(title)

	for i, chain := range certCollection.Chains {
		for _, cert := range chain {
			text := fmt.Sprintf("%d: CN=%s", cert.Index, cert.Cert.Subject.CommonName)
			certChainList.AddItem(text, "", 0, onSelectedCert(cert.Cert))
		}
		if i != len(certCollection.Chains)-1 {
			certChainList.AddItem("-----Next chain------", "", 0, nil)
		}
	}

	onSelectedCert(certCollection.Chains[0][0].Cert)()
	return certChainList
}

func createAllCertsList(certCollection model.CertificateCollection) *tview.List {
	allCertsList := tview.NewList().SetSelectedFocusOnly(true)
	allCertsList.SetBorder(true).SetTitle("All certificates")

	for _, cert := range certCollection.All {
		text := fmt.Sprintf("%d: CN=%s", cert.Index, cert.Cert.Subject.CommonName)
		allCertsList.AddItem(text, "", 0, onSelectedCert(cert.Cert))
	}

	return allCertsList
}

func formatToHex(input []byte) string {
	return formatHexStr(hex.EncodeToString(input))
}

func formatHexStr(hexInput string) string {
	var builder strings.Builder

	if len(hexInput)%2 == 1 {
		hexInput = "0" + hexInput
	}

	for i, r := range strings.ToUpper(hexInput) {
		builder.WriteRune(r)
		if i%2 == 1 {
			builder.WriteRune(' ')
		}
	}
	return builder.String()
}
