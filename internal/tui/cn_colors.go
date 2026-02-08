package tui

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"go-certviewer/internal/model"
	"math/rand"
)

type CNColors struct {
	subject string
	issuer  string
}

var certColorMap map[string]CNColors

func populateCertColorMap(certCollection model.CertificateCollection) {
	certColorMap = make(map[string]CNColors)

	// Loop backwards from root down to leaf cert
	for _, chain := range certCollection.Chains {
		for i := len(chain) - 1; i >= 0; i-- {
			cert := chain[i]

			currentCertKey := certKey(cert.Cert)
			subjectColor := randomLightHex()
			issuerColor := ""

			if i != len(chain)-1 {
				issuerCert := chain[i+1]
				issuerCertKey := certKey(issuerCert.Cert)
				issuerColor = certColorMap[issuerCertKey].subject
			}

			certColorMap[currentCertKey] = CNColors{subjectColor, issuerColor}
		}
	}
}

func randomLightHex() string {
	r := 100 + rand.Intn(101)
	g := 100 + rand.Intn(101)
	b := 100 + rand.Intn(101)

	return fmt.Sprintf("#%02x%02x%02x", r, g, b)
}

func certKey(cert *x509.Certificate) string {
	return hex.EncodeToString(certFingerprintBytes(cert))
}

func certFingerprintBytes(cert *x509.Certificate) []byte {
	h := sha256.New()
	h.Write(cert.Raw)
	return h.Sum(nil)
}

func colorizeCommonName(cert *x509.Certificate, isIssuer bool) string {
	key := certKey(cert)

	var cn string
	var color string
	if isIssuer {
		color = certColorMap[key].issuer
		cn = cert.Issuer.CommonName
		// Check if root
		if color == "" && cert.Subject.CommonName == cert.Issuer.CommonName {
			color = certColorMap[key].subject
		}
	} else {
		color = certColorMap[key].subject
		cn = cert.Subject.CommonName
	}

	if color == "" {
		return cn
	}
	return fmt.Sprintf("[%s]%s", color, cn)
}
