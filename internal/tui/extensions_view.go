package tui

import (
	"crypto/x509"
	"encoding/asn1"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/mbergz/go-certviewer/internal/certutil"
	"github.com/rivo/tview"
)

var keyUsageTypes = []string{
	"digitalSignature",
	"contentCommitment",
	"keyEncipherment",
	"dataEncipherment",
	"keyAgreement",
	"keyCertSign",
	"cRLSign",
	"encipherOnly",
	"decipherOnly",
}

type ExtensionsView struct {
	extTable *tview.Table
}

func newExtensionsView() *ExtensionsView {
	extTable := tview.NewTable()
	extTable.SetBorder(true).SetTitle("X.509 v3 extensions")

	return &ExtensionsView{extTable}
}

func (v *ExtensionsView) primitive() tview.Primitive {
	return v.extTable
}

func (v *ExtensionsView) update(cert *x509.Certificate) {
	v.extTable.Clear()
	row := 0

	v.appendSubjectAlternativeNames(cert, &row)

	if len(cert.OCSPServer) > 0 || len(cert.IssuingCertificateURL) > 0 {
		v.appendToTableExtensionKeyOnly("Authority Information Access (AIA):", cert, certutil.OidExtensionAuthorityInfoAccess, &row)
	}
	appendToTable(v.extTable, cert.OCSPServer, "    OCSP", &row)
	appendToTable(v.extTable, cert.IssuingCertificateURL, "    Issuer URL", &row)

	appendToTable(v.extTable, []string{formatToHex(cert.SubjectKeyId)}, "Subject Key Identifier (SKI)", &row)
	appendToTable(v.extTable, []string{formatToHex(cert.AuthorityKeyId)}, "Authority Key Identifier (AKI)", &row)

	if cert.BasicConstraintsValid {
		v.appendToTableExtensionKeyOnly("Basic constraints:", cert, certutil.OidExtensionBasicConstraints, &row)
	}
	appendToTable(v.extTable, []string{strconv.FormatBool(cert.IsCA)}, "    Is CA", &row)
	if cert.MaxPathLen != -1 {
		appendToTable(v.extTable, []string{strconv.Itoa(cert.MaxPathLen)}, "    Max path length", &row)
	}

	if cert.KeyUsage > 0 {
		v.appendToTableExtension([]string{parseKeyUsage(cert)}, "Key usage", cert, certutil.OidExtensionKeyUsage, &row)
	}
	if len(cert.ExtKeyUsage) > 0 {
		v.appendToTableExtension([]string{parseExtKeyUsage(cert)}, "Extended Key usage", cert, certutil.OidExtensionKeyUsage, &row)
	}

	v.appendToTableExtension(cert.CRLDistributionPoints, "CRL Distribution points", cert, certutil.OidExtensionKeyUsage, &row)

	// Adjust height and width -2 because of border
	v.extTable.SetDrawFunc(func(screen tcell.Screen, x, y, width, height int) (int, int, int, int) {
		rowOffset, _ := v.extTable.GetOffset()
		totalRows := v.extTable.GetRowCount()

		if rowOffset+height-2 < totalRows {
			lastRowY := y + height - 2

			// Clear the line
			for cx := x + 1; cx < x+width-1; cx++ {
				screen.SetContent(cx, lastRowY, ' ', nil, tcell.StyleDefault)
			}
			tview.Print(screen, "[ ... ▼ Scroll for more ]", x, lastRowY, width, tview.AlignCenter, tcell.ColorLightYellow)

			return x + 1, y + 1, width - 2, height - 3
		}

		return x + 1, y + 1, width - 2, height - 2
	})

}

func parseKeyUsage(cert *x509.Certificate) string {
	keyUsageBitmap := cert.KeyUsage
	res := make([]string, 0)
	// Check all possible flags in bitmap for keyUsage
	for i := 0; i < len(keyUsageTypes); i++ {
		testBit := 1 << i
		if int(keyUsageBitmap)&testBit > 0 {
			res = append(res, keyUsageTypes[i])
		}
	}
	return strings.Join(res, ", ")
}

func parseExtKeyUsage(cert *x509.Certificate) string {
	res := make([]string, 0)
	for _, eku := range cert.ExtKeyUsage {
		res = append(res, eku.String())
	}
	return strings.Join(res, ", ")
}

func (v *ExtensionsView) appendSubjectAlternativeNames(cert *x509.Certificate, row *int) {
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 || len(cert.EmailAddresses) > 0 || len(cert.URIs) > 0 {
		v.appendToTableExtensionKeyOnly("Subject Alternative Name (SAN):", cert, certutil.OidExtensionSubjectAltName, row)
	}

	appendToTable(v.extTable, cert.DNSNames, "    DNS names", row)
	if len(cert.IPAddresses) > 0 {
		ipAsString := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ipAsString[i] = ip.String()
		}
		appendToTable(v.extTable, ipAsString, "    IP addresses", row)
	}
	appendToTable(v.extTable, cert.EmailAddresses, "    Email addresses", row)
	if len(cert.URIs) > 0 {
		urisAsString := make([]string, len(cert.URIs))
		for i, ip := range cert.URIs {
			urisAsString[i] = ip.String()
		}
		appendToTable(v.extTable, urisAsString, "    URI's", row)
	}
}

func (v *ExtensionsView) appendToTableExtensionKeyOnly(displayName string, cert *x509.Certificate, oid asn1.ObjectIdentifier, rowCount *int) {
	name := displayName
	if certutil.IsExtensionMarkedCritical(cert, oid) {
		name += " [#808080::i]critical"
	}
	appendToTableKeyOnly(v.extTable, name, rowCount)
}

func (v *ExtensionsView) appendToTableExtension(value []string, displayName string, cert *x509.Certificate, oid asn1.ObjectIdentifier, rowCount *int) {
	name := displayName
	if certutil.IsExtensionMarkedCritical(cert, oid) {
		name += " [#808080::i]critical"
	}
	appendToTable(v.extTable, value, name, rowCount)
}
