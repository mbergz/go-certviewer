package certfetcher

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
)

func Get(url string) ([]*x509.Certificate, error) {
	formattedUrl := formatUrl(url)

	var certs []*x509.Certificate

	verifyFn := func(rawCerts [][]byte, verfiedChains [][]*x509.Certificate) error {
		for _, cert := range rawCerts {
			x509Cert, err := x509.ParseCertificate(cert)
			if err != nil {
				return errors.New("Could not parse certificate from server: " + err.Error())
			}
			certs = append(certs, x509Cert)
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

	return certs, nil
}

func formatUrl(url string) string {
	if !strings.HasSuffix(url, ":443") {
		return url + ":443"
	}
	return url
}
