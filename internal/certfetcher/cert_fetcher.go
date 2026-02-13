package certfetcher

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"

	"github.com/mbergz/go-certviewer/internal/model"
)

func Get(urlInput string, insecureFlag bool) (model.CertificateCollection, error) {
	parsedUrl, err := parseUrlInput(urlInput)
	if err != nil {
		return model.CertificateCollection{}, err
	}
	log.Println("Parsed URL:", parsedUrl)

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

	if insecureFlag {
		log.Println("Insecure flag is set. Skipping certificate validation")
	}

	conn, err := tls.Dial("tcp", parsedUrl.Host, &tls.Config{
		InsecureSkipVerify:    insecureFlag,
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

func parseUrlInput(urlInput string) (*url.URL, error) {
	if !strings.HasPrefix(strings.ToLower(urlInput), "https://") {
		urlInput = "https://" + urlInput
	}
	u, err := url.ParseRequestURI(urlInput)
	if err != nil {
		return nil, fmt.Errorf("invalid input URL: %v", err)
	}
	host := u.Host
	if host == "" {
		return nil, fmt.Errorf("invalid input URL: empty host")
	}
	_, _, err = net.SplitHostPort(host)
	if err != nil {
		log.Println("Port missing, defaulting to 443")
		host = net.JoinHostPort(host, "443")
	}
	u.Host = host
	return u, nil
}
