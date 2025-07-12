package certreader

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	cert1SubjectCN = "Cert-test-1"

	chain1RootSubjectCN          = "Test-CA-root-cert"
	chain1Intermediate1SubjectCN = "Test-CA-intermediate1-cert"
	chain1Leaf1SubjectCN         = "Test-Leaf1-cert"
)

func TestGetFromFileCrt(t *testing.T) {
	path := filepath.Join("testdata", "cert1.crt")
	certCollection, err := GetFromFile(path)
	if err != nil {
		t.Errorf("Error: %v", err)
	}

	assert.Len(t, certCollection.All, 1)
	assert.Len(t, certCollection.Chains, 1)
	cert := certCollection.All[0]
	assert.Equal(t, cert.Cert.Subject.CommonName, cert1SubjectCN)
	assert.Equal(t, cert.Cert.Issuer.CommonName, cert1SubjectCN)
}

func TestGetFromFilePem(t *testing.T) {
	path := filepath.Join("testdata", "cert1.pem")
	certCollection, err := GetFromFile(path)
	if err != nil {
		t.Errorf("Error: %v", err)
	}

	assert.Len(t, certCollection.All, 1)
	assert.Len(t, certCollection.Chains, 1)
	cert := certCollection.All[0]
	assert.Equal(t, cert.Cert.Subject.CommonName, cert1SubjectCN)
	assert.Equal(t, cert.Cert.Issuer.CommonName, cert1SubjectCN)
}

func TestGetFromFileBuildChain(t *testing.T) {
	path := filepath.Join("testdata", "chain1.pem")
	certCollection, err := GetFromFile(path)
	if err != nil {
		t.Errorf("Error: %v", err)
	}

	assert.Len(t, certCollection.All, 3)
	assert.Len(t, certCollection.Chains, 1)

	cert1 := certCollection.All[0]
	assert.Equal(t, cert1.Cert.Subject.CommonName, chain1Leaf1SubjectCN)
	assert.Equal(t, cert1.Cert.Issuer.CommonName, chain1Intermediate1SubjectCN)

	cert2 := certCollection.All[1]
	assert.Equal(t, cert2.Cert.Subject.CommonName, chain1Intermediate1SubjectCN)
	assert.Equal(t, cert2.Cert.Issuer.CommonName, chain1RootSubjectCN)

	cert3 := certCollection.All[2]
	assert.Equal(t, cert3.Cert.Subject.CommonName, chain1RootSubjectCN)
	assert.Equal(t, cert3.Cert.Issuer.CommonName, chain1RootSubjectCN)
}
