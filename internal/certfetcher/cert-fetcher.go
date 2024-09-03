package certfetcher

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

func Get(url string) ([]*x509.Certificate, error) {
	validate(url)

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

	conn, err := tls.Dial("tcp", url, &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifyFn,
	})
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	return certs, nil
}

func validate(url string) {
	//panic("unimplemented")
}
