package main

import (
	"errors"
	"flag"
	"log"

	"go-certviewer/internal/certfetcher"
	"go-certviewer/internal/certreader"
	"go-certviewer/internal/model"
	"go-certviewer/internal/tui"
)

func main() {
	urlFlag := flag.String("url", "", "Url of website to fetch certificate from")
	inputFileFlag := flag.String("i", "", "Input certificate file in .pem or .crt format")
	flag.Parse()

	certCollection, err := getCertificates(*urlFlag, *inputFileFlag)
	if err != nil {
		log.Fatal(err)
	}

	tui.Launch(certCollection)
}

func getCertificates(urlFlag string, inputFileFlag string) (model.CertificateCollection, error) {
	if len(urlFlag) > 0 {
		log.Println("Fetching certificate from url ", urlFlag)
		certs, err := certfetcher.Get(urlFlag)
		if err != nil {
			return model.CertificateCollection{}, err
		}
		return certs, nil
	}
	if len(inputFileFlag) > 0 {
		log.Println("Reading from file")
		certCollection, err := certreader.Get(inputFileFlag)
		if err != nil {
			return model.CertificateCollection{}, err
		}
		return certCollection, nil
	}
	return model.CertificateCollection{}, errors.New("Either url or fileinput must be specified")
}
