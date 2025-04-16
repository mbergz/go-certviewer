package certreader

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"go-certviewer/internal/model"
	"os"
)

func Get(inputFile string) (model.CertificateCollection, error) {
	fmt.Println(inputFile)

	file, err := os.ReadFile(inputFile)
	if err != nil {
		return model.CertificateCollection{}, err
	}

	block, rest := pem.Decode(file)
	if block != nil {
		return parsePemCertificates(block, rest), nil
	} else {
		return parseDerCertificate(rest), nil
	}
}

func parsePemCertificates(block *pem.Block, rest []byte) model.CertificateCollection {
	certs := []model.CertificateEntry{}
	cert := parseCertificate(block.Bytes)
	certs = append(certs, model.CertificateEntry{Index: 1, Cert: cert})
	if rest != nil {
		chain := appendCertificateToChain(rest)
		certs = append(certs, chain...)
	}
	chains := getCertificateChains(certs)
	certSet := model.CertificateCollection{All: certs, Chains: chains}
	return certSet
}

func getCertificateChains(allCerts []model.CertificateEntry) [][]model.CertificateEntry {
	var result [][]model.CertificateEntry

	subjectMap := make(map[string]model.CertificateEntry)
	issuerMap := make(map[string]bool)

	for _, cert := range allCerts {
		_, exists := subjectMap[cert.Cert.Subject.String()]
		if exists {
			panic("Duplicate SubjectDN found for " + cert.Cert.Subject.String())
		}

		subjectMap[cert.Cert.Subject.String()] = cert
		issuerMap[cert.Cert.Issuer.String()] = true
	}

	for _, cert := range allCerts {
		subjectDN := cert.Cert.Subject.String()
		issuerDn := cert.Cert.Issuer.String()
		if _, exists := issuerMap[subjectDN]; exists || subjectDN == issuerDn {
			// This cert is used as issuer for some cert,i.e. not a leaf cert
			continue
		}

		chain := []model.CertificateEntry{{Index: cert.Index, Cert: cert.Cert}}
		fmt.Printf("Found leaf cert: SubjectDN:%s, IssuerDN:%s\n", subjectDN, issuerDn)

		for {
			parentCert, ok := subjectMap[issuerDn]
			if !ok {
				break
			}
			chain = append(chain, model.CertificateEntry{Index: parentCert.Index, Cert: parentCert.Cert})
			issuerDn = parentCert.Cert.Issuer.String()
			if parentCert.Cert.Subject.String() == parentCert.Cert.Issuer.String() {
				break
			}
		}

		fmt.Printf("Built chain for leaf cert SubjectDN:%s, length of chain=%d\n", subjectDN, len(chain))
		for _, cc := range chain {
			fmt.Printf("Chain SubjectDN:%s has idx:%d\n", cc.Cert.Subject.String(), cc.Index)
		}
		result = append(result, chain)

	}

	fmt.Println()

	return result
}

func parseDerCertificate(rest []byte) model.CertificateCollection {
	cert := parseCertificate(rest)
	certEntry := model.CertificateEntry{Index: 1, Cert: cert}
	certSet := model.CertificateCollection{All: []model.CertificateEntry{certEntry}}
	return certSet
}

func appendCertificateToChain(data []byte) []model.CertificateEntry {
	var res []model.CertificateEntry
	idx := 2
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		cert := parseCertificate(block.Bytes)
		res = append(res, model.CertificateEntry{Index: idx, Cert: cert})
		if rest == nil {
			break
		}
		data = rest
		idx++
	}
	return res
}

func parseCertificate(der []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert
}
