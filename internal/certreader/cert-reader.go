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
		fmt.Println("Cert is pem!")
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic(err)
		}
		// Todo get entire chain if more certs inside pem
		return []*x509.Certificate{cert}, nil
	} else {
		cert, err := x509.ParseCertificate(rest)
		if err != nil {
			panic(err)
		}
		fmt.Println("Cert is DER. Returning one certificate")
		return []*x509.Certificate{cert}, nil
	}
}
