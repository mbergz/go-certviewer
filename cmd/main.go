package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"

	"go-certviewer/internal/certfetcher"
	"go-certviewer/internal/certreader"
)

func main() {
	urlFlag := flag.String("url", "", "Url of website to fetch certificate from")
	inputFileFlag := flag.String("i", "", "Input certificate file in .pem or .crt format")
	flag.Parse()

	certs, err := getCertificates(*urlFlag, *inputFileFlag)
	if err != nil {
		panic(err)
	}
	for i, cert := range certs {
		fmt.Printf("[%d]: subj='%s' dns=%s. Valid from='%s' to='%s'\n", i, cert.Subject, cert.DNSNames, cert.NotBefore, cert.NotAfter)
	}
}

func getCertificates(urlFlag string, inputFileFlag string) ([]*x509.Certificate, error) {
	if len(urlFlag) > 0 {
		fmt.Println("Fetching certificate from url ", urlFlag)
		certs, err := certfetcher.Get(urlFlag)
		if err != nil {
			return nil, err
		}
		return certs, nil
	}
	if len(inputFileFlag) > 0 {
		fmt.Println("reading from file")
		certs, err := certreader.Get(inputFileFlag)
		if err != nil {
			return nil, err
		}
		return certs, nil
	}
	return nil, errors.New("either url or fileinput must be specified")
}
