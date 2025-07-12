package certreader

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"go-certviewer/internal/model"
	"log"
	"os"
)

// Reads certificates from a single given file.
// If the file is in PEM format, it returns all certificates found inside along with any certificate chains.
// If the file is in binary DER format, it returns a single certificate.
func GetFromFile(inputFile string) (model.CertificateCollection, error) {
	file, err := os.ReadFile(inputFile)
	if err != nil {
		return model.CertificateCollection{}, fmt.Errorf("failed to read file %s: %w", inputFile, err)
	}

	block, rest := pem.Decode(file)
	if block != nil {
		certSet, err := parsePemCertificates(block, rest)
		if err != nil {
			return model.CertificateCollection{},
				fmt.Errorf("failed to parse pem certificates from %s: %w", inputFile, err)
		}
		return certSet, nil
	}

	certs, err := parseDerCertificate(rest)
	if err != nil {
		return model.CertificateCollection{},
			fmt.Errorf("failed to parse der certificate from %s. Verify input file format: %w", inputFile, err)
	}
	return certs, nil
}

func parsePemCertificates(block *pem.Block, rest []byte) (model.CertificateCollection, error) {
	certs := []model.CertificateEntry{}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return model.CertificateCollection{}, fmt.Errorf("could not parse pem block: %w", err)
	}

	index := 1
	certs = append(certs, model.CertificateEntry{Index: index, Cert: cert})
	if rest != nil {
		foundCerts := findPemCertificates(rest, &index)
		certs = append(certs, foundCerts...)
	}

	chains := findCertificateChains(certs)
	certSet := model.CertificateCollection{All: certs, Chains: chains}
	return certSet, nil
}

func findCertificateChains(allCerts []model.CertificateEntry) [][]model.CertificateEntry {
	topChainMap := make(map[int][]model.CertificateEntry)
	subjectMap := make(map[string][]model.CertificateEntry)

	for _, cert := range allCerts {
		subjectDN := cert.Cert.Subject.String()

		if subjects, exists := subjectMap[subjectDN]; exists {
			log.Println("Duplicate SubjectDN found for " + subjectDN)
			subjects = append(subjects, cert)
			subjectMap[subjectDN] = subjects
		} else {
			subjectMap[subjectDN] = []model.CertificateEntry{cert}
		}
	}

	for _, cert := range allCerts {
		subjectDN := cert.Cert.Subject.String()
		issuerDn := cert.Cert.Issuer.String()
		aki := cert.Cert.AuthorityKeyId

		chain := []model.CertificateEntry{{Index: cert.Index, Cert: cert.Cert}}
		for {
			parentCerts, ok := subjectMap[issuerDn]
			if !ok || subjectDN == issuerDn {
				break
			}

			var parentCert *model.CertificateEntry
			// If there is only one parent without AKI, assume correct
			if len(parentCerts) == 1 && len(aki) == 0 {
				parentCert = &parentCerts[0]
			} else {
				for _, pc := range parentCerts {
					ski := pc.Cert.SubjectKeyId
					if len(ski) == 0 { // Skip if parent does not have SKI
						continue
					}
					if bytes.Equal(aki, ski) {
						log.Println("Found matching issuer certificate by AKI/SKI")
						parentCert = &pc
						break
					}
				}
			}
			if parentCert == nil {
				log.Println("No matching parent cert found with AKI/SKI, picking first one")
				parentCert = &parentCerts[0]
			}

			chain = append(chain, model.CertificateEntry{Index: parentCert.Index, Cert: parentCert.Cert})
			issuerDn = parentCert.Cert.Issuer.String()
			if parentCert.Cert.Subject.String() == parentCert.Cert.Issuer.String() { // Root
				break
			}
		}

		log.Printf("Built chain for cert SubjectDN:%s, length of chain=%d\n", subjectDN, len(chain))
		for _, cc := range chain {
			log.Printf("Chain SubjectDN:%s has idx:%d\n", cc.Cert.Subject.String(), cc.Index)
		}

		// Update map with longest found chain for a top cert/root (last elem in chain)
		topCert := chain[len(chain)-1]
		existing, found := topChainMap[topCert.Index]
		if !found || len(chain) > len(existing) {
			topChainMap[topCert.Index] = chain
		}
	}

	var result [][]model.CertificateEntry
	for _, chain := range topChainMap {
		result = append(result, chain)
	}
	return result
}

func parseDerCertificate(rest []byte) (model.CertificateCollection, error) {
	cert, err := x509.ParseCertificate(rest)
	if err != nil {
		return model.CertificateCollection{}, fmt.Errorf("could not parse der certificate: %w", err)
	}
	certEntry := model.CertificateEntry{Index: 1, Cert: cert}
	certSet := model.CertificateCollection{All: []model.CertificateEntry{certEntry}, Chains: [][]model.CertificateEntry{{certEntry}}}
	return certSet, nil
}

func findPemCertificates(data []byte, idx *int) []model.CertificateEntry {
	var res []model.CertificateEntry
	*idx += 1
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Panicf("Could not parse certificate in pem file: %v", err)
		}
		res = append(res, model.CertificateEntry{Index: *idx, Cert: cert})
		if rest == nil {
			break
		}
		data = rest
		*idx += 1
	}
	return res
}
