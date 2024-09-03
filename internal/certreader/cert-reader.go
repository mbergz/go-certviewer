package certreader

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func Get(inputFile string) ([]*x509.Certificate, error) {
	fmt.Println(inputFile)

	file, err := os.ReadFile(inputFile)
	if err != nil {
		panic(err)
	}

	block, rest := pem.Decode(file)
	if block != nil {
		certs := []*x509.Certificate{}
		fmt.Println("Cert is pem!")
		cert := parsePemCert(block)
		certs = append(certs, cert)
		if rest != nil {
			chain := appendCertificateToChain(rest)
			certs = append(certs, chain...)
		}
		return certs, nil
	} else {
		cert, err := x509.ParseCertificate(rest)
		if err != nil {
			panic(err)
		}
		fmt.Println("Cert is DER. Returning one certificate")
		return []*x509.Certificate{cert}, nil
	}
}

func appendCertificateToChain(data []byte) []*x509.Certificate {
	var res []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		cert := parsePemCert(block)
		res = append(res, cert)
		if rest == nil {
			break
		}
		data = rest
	}
	return res
}

func parsePemCert(block *pem.Block) *x509.Certificate {
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	return cert
}
