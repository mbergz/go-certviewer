package model

import "crypto/x509"

type CertificateCollection struct {
	All    []CertificateEntry
	Chains [][]CertificateEntry
}

type CertificateEntry struct {
	Index    int
	Cert     *x509.Certificate
	FileName string
}
