package certfetcher

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/mbergz/go-certviewer/internal/model"
)

func Get(urlInput string, insecureFlag bool, cacert string) (model.CertificateCollection, error) {
	parsedUrl, err := parseUrlInput(urlInput)
	if err != nil {
		return model.CertificateCollection{}, err
	}

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

	rootCAs, err := createRootCAs(cacert)
	if err != nil {
		return model.CertificateCollection{}, err
	}

	conn, err := tls.Dial("tcp", parsedUrl.Host, &tls.Config{
		InsecureSkipVerify:    insecureFlag,
		VerifyPeerCertificate: verifyFn,
		RootCAs:               rootCAs,
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

func createRootCAs(cacertFlag string) (*x509.CertPool, error) {
	if cacertFlag == "" {
		return nil, nil // use system CAs (rootCA = nil)
	}

	cacertPemContent, err := readCacertFile(cacertFlag)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cacertPemContent) {
		return nil, fmt.Errorf("failed to parse CA certificate file: %s", cacertFlag)
	}
	log.Printf("Successfully read custom CA cert file: %s", cacertFlag)
	return pool, nil
}

func readCacertFile(cacertPath string) ([]byte, error) {
	file, err := os.ReadFile(cacertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", cacertPath, err)
	}
	return file, nil
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
	log.Println("Parsed URL:", u)
	return u, nil
}
