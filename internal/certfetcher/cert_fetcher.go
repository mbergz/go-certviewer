package certfetcher

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"go-certviewer/internal/model"
	"log"
	"strings"
)

func Get(url string) (model.CertificateCollection, error) {
	formattedUrl := formatUrl(url)

	var certChain []model.CertificateEntry

	verifyFn := func(rawCerts [][]byte, verfiedChains [][]*x509.Certificate) error {
		for i, cert := range rawCerts {
			x509Cert, err := x509.ParseCertificate(cert)
			if err != nil {
				return errors.New("Could not parse certificate from server: " + err.Error())
			}
			certChain = append(certChain, model.CertificateEntry{Index: i + 1, Cert: x509Cert})
		}
		return nil
	}

	conn, err := tls.Dial("tcp", formattedUrl, &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifyFn,
	})
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	for _, ch := range certChain {
		log.Printf("CertChain: idx:%d, subjectDN:%s\n", ch.Index, ch.Cert.Subject.String())
	}

	return model.CertificateCollection{Chains: [][]model.CertificateEntry{certChain}}, nil
}

func formatUrl(url string) string {
	if !strings.HasSuffix(url, ":443") {
		return url + ":443"
	}
	return url
}
