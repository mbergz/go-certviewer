package certutil

import (
	"crypto/x509"
	"encoding/asn1"
)

var (
	OidExtensionSubjectKeyId          = asn1.ObjectIdentifier{2, 5, 29, 14}
	OidExtensionKeyUsage              = asn1.ObjectIdentifier{2, 5, 29, 15}
	OidExtensionExtendedKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	OidExtensionAuthorityKeyId        = asn1.ObjectIdentifier{2, 5, 29, 35}
	OidExtensionBasicConstraints      = asn1.ObjectIdentifier{2, 5, 29, 19}
	OidExtensionSubjectAltName        = asn1.ObjectIdentifier{2, 5, 29, 17}
	OidExtensionCertificatePolicies   = asn1.ObjectIdentifier{2, 5, 29, 32}
	OidExtensionNameConstraints       = asn1.ObjectIdentifier{2, 5, 29, 30}
	OidExtensionCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}
	OidExtensionAuthorityInfoAccess   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	OidExtensionCRLNumber             = asn1.ObjectIdentifier{2, 5, 29, 20}
	OidExtensionReasonCode            = asn1.ObjectIdentifier{2, 5, 29, 21}
)

func IsExtensionMarkedCritical(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return ext.Critical
		}
	}
	return false
}
