package signer

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// OIDs for CAdES
var (
	oidContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSignedData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSHA256               = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSAWithSHA256      = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
)

func oidLess(a, b asn1.ObjectIdentifier) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type essCertIDv2 struct {
	HashAlgorithm pkix.AlgorithmIdentifier `asn1:"optional"`
	CertHash      []byte
	IssuerSerial  issuerAndSerial `asn1:"optional"`
}

type signingCertificateV2 struct {
	Certs []essCertIDv2
}

func marshalAttributes(attrs []attribute) ([]byte, error) {
	// Marshal as SEQUENCE first
	seq, err := asn1.Marshal(attrs)
	if err != nil {
		return nil, err
	}
	// Change tag from SEQUENCE (0x30) to SET (0x31)
	seq[0] = 0x31
	return seq, nil
}

func encodeLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}

	var lenBytes []byte
	for length > 0 {
		lenBytes = append([]byte{byte(length & 0xFF)}, lenBytes...)
		length >>= 8
	}

	return append([]byte{0x80 | byte(len(lenBytes))}, lenBytes...)
}
