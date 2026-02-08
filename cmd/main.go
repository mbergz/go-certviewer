package main

import (
	"errors"
	"flag"
	"io"
	"log"
	"os"

	"go-certviewer/internal/certfetcher"
	"go-certviewer/internal/certreader"
	"go-certviewer/internal/model"
	"go-certviewer/internal/tui"
)

func main() {
	// Setup log to also append to file
	f, err := os.OpenFile("app.log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	log.SetOutput(io.MultiWriter(f, os.Stderr))

	urlFlag := flag.String("url", "", "Url of website to fetch certificate from")
	inputFileFlag := flag.String("i", "", "Input certificate file in .pem or .crt format")
	inputDirFlag := flag.String("d", "", "Input directory with certificates in .pem or .crt format")
	flag.Parse()

	flagSet := 0
	if *urlFlag != "" {
		flagSet++
	}
	if *inputFileFlag != "" {
		flagSet++
	}
	if *inputDirFlag != "" {
		flagSet++
	}

	if flagSet != 1 {
		log.Fatalf("Either url,i or d flag must be set. Use -h for help")
	}

	certCollection, err := getCertificates(*urlFlag, *inputFileFlag, *inputDirFlag)
	if err != nil {
		log.Fatal(err)
	}
	tui.Launch(certCollection)
}

func getCertificates(urlFlag string, inputFileFlag string, inputDirFlag string) (model.CertificateCollection, error) {
	switch {
	case len(urlFlag) > 0:
		log.Println("Fetching certificate from url", urlFlag)
		return certfetcher.Get(urlFlag)
	case len(inputFileFlag) > 0:
		log.Println("Reading from file")
		return certreader.GetFromFile(inputFileFlag)
	case len(inputDirFlag) > 0:
		log.Println("Reading from directory")
		return certreader.GetFromDirectory(inputDirFlag)
	}

	return model.CertificateCollection{}, errors.New("should not happen")
}
