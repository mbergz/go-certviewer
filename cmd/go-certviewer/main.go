package main

import (
	"errors"
	"flag"
	"io"
	"log"
	"os"

	"github.com/mbergz/go-certviewer/internal/certfetcher"
	"github.com/mbergz/go-certviewer/internal/certreader"
	"github.com/mbergz/go-certviewer/internal/model"
	"github.com/mbergz/go-certviewer/internal/tui"
)

type Flags struct {
	url       *string
	insecure  *bool
	inputFile *string
	inputDir  *string
}

func main() {
	// Setup log to also append to file
	f, err := os.OpenFile("app.log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	log.SetOutput(io.MultiWriter(f, os.Stderr))

	flags := &Flags{
		url:       flag.String("url", "", "Url of website to fetch certificate from"),
		insecure:  flag.Bool("k", false, "Skip TLS certificate verification (allow self-signed or unknown CAs). Only used together with '-url' flag"),
		inputFile: flag.String("i", "", "Input certificate file in .pem or .crt format"),
		inputDir:  flag.String("d", "", "Input directory with certificates in .pem or .crt format"),
	}
	flag.Parse()

	validateFlags(flags)

	certCollection, err := getCertificates(flags)
	if err != nil {
		log.Fatal(err)
	}

	tui.Launch(certCollection)
}

func validateFlags(flags *Flags) {
	flagSet := 0
	if *flags.url != "" {
		flagSet++
	}
	if *flags.inputFile != "" {
		flagSet++
	}
	if *flags.inputDir != "" {
		flagSet++
	}
	if flagSet != 1 {
		log.Fatalf("Either url,i or d flag must be set. Use -h for help")
	}

	if *flags.insecure && *flags.url == "" {
		log.Fatalf("Insecure flag cannot be set without url flag")
	}
}

func getCertificates(flags *Flags) (model.CertificateCollection, error) {
	switch {
	case len(*flags.url) > 0:
		log.Printf("Fetching certificate from url: %s with insecure: %t", *flags.url, *flags.insecure)
		return certfetcher.Get(*flags.url, *flags.insecure)
	case len(*flags.inputFile) > 0:
		log.Println("Reading from file")
		return certreader.GetFromFile(*flags.inputFile)
	case len(*flags.inputDir) > 0:
		log.Println("Reading from directory")
		return certreader.GetFromDirectory(*flags.inputDir)
	}

	return model.CertificateCollection{}, errors.New("should not happen")
}
