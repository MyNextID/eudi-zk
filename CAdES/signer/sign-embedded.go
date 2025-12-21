package signer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sort"
	"time"
)

func SignWithCAdES(data []byte, privateKey *ecdsa.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	// Hash the content with SHA-256
	contentHash := sha256.Sum256(data)

	// Create signing certificate v2 attribute (mandatory for CAdES-BES)
	certHash := sha256.Sum256(cert.Raw)

	essCertID := essCertIDv2{
		HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		CertHash:      certHash[:],
		IssuerSerial: issuerAndSerial{
			Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
			SerialNumber: cert.SerialNumber,
		},
	}

	signingCertV2 := signingCertificateV2{
		Certs: []essCertIDv2{essCertID},
	}

	signingCertV2Bytes, err := asn1.Marshal(signingCertV2)
	if err != nil {
		return nil, fmt.Errorf("marshal signing cert v2: %w", err)
	}

	// Wrap in SET for attribute value
	signingCertV2Set := append([]byte{0x31}, encodeLength(len(signingCertV2Bytes))...)
	signingCertV2Set = append(signingCertV2Set, signingCertV2Bytes...)

	// Create signing time (mandatory)
	signingTime := time.Now().UTC()
	signingTimeBytes, err := asn1.Marshal(signingTime)
	if err != nil {
		return nil, fmt.Errorf("marshal signing time: %w", err)
	}

	// Wrap in SET
	signingTimeSet := append([]byte{0x31}, encodeLength(len(signingTimeBytes))...)
	signingTimeSet = append(signingTimeSet, signingTimeBytes...)

	// Create message digest attribute (mandatory)
	messageDigestBytes, err := asn1.Marshal(contentHash[:])
	if err != nil {
		return nil, fmt.Errorf("marshal message digest: %w", err)
	}

	// Wrap in SET
	messageDigestSet := append([]byte{0x31}, encodeLength(len(messageDigestBytes))...)
	messageDigestSet = append(messageDigestSet, messageDigestBytes...)

	// Create content type attribute (mandatory)
	contentTypeBytes, err := asn1.Marshal(oidData)
	if err != nil {
		return nil, fmt.Errorf("marshal content type: %w", err)
	}

	// Wrap in SET
	contentTypeSet := append([]byte{0x31}, encodeLength(len(contentTypeBytes))...)
	contentTypeSet = append(contentTypeSet, contentTypeBytes...)

	// Build signed attributes - MUST be in ascending order by OID
	attrs := []attribute{
		{Type: oidContentType, Values: asn1.RawValue{FullBytes: contentTypeSet}},
		{Type: oidSigningTime, Values: asn1.RawValue{FullBytes: signingTimeSet}},
		{Type: oidMessageDigest, Values: asn1.RawValue{FullBytes: messageDigestSet}},
		{Type: oidSigningCertificateV2, Values: asn1.RawValue{FullBytes: signingCertV2Set}},
	}

	// Sort attributes by OID (ETSI requirement)
	sort.Slice(attrs, func(i, j int) bool {
		return oidLess(attrs[i].Type, attrs[j].Type)
	})

	// Marshal attributes as SET OF
	signedAttrsSet, err := marshalAttributes(attrs)
	if err != nil {
		return nil, fmt.Errorf("marshal signed attrs: %w", err)
	}

	// Hash the signed attributes for signature
	attrsHash := sha256.Sum256(signedAttrsSet)

	// Sign with ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, attrsHash[:])
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign: %w", err)
	}

	// Encode ECDSA signature as DER SEQUENCE
	ecdsaSig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return nil, fmt.Errorf("marshal ecdsa sig: %w", err)
	}

	// Build SignerInfo manually to ensure correct structure
	var signerInfoBytes []byte

	// Version INTEGER
	versionBytes, _ := asn1.Marshal(1)
	signerInfoBytes = append(signerInfoBytes, versionBytes...)

	// IssuerAndSerialNumber
	sidBytes, err := asn1.Marshal(issuerAndSerial{
		Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
		SerialNumber: cert.SerialNumber,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal sid: %w", err)
	}
	signerInfoBytes = append(signerInfoBytes, sidBytes...)

	// DigestAlgorithm
	digestAlgBytes, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidSHA256})
	if err != nil {
		return nil, fmt.Errorf("marshal digest alg: %w", err)
	}
	signerInfoBytes = append(signerInfoBytes, digestAlgBytes...)

	// SignedAttrs [0] IMPLICIT
	// Change the SET tag (0x31) to context-specific [0] (0xA0)
	signedAttrsImplicit := make([]byte, len(signedAttrsSet))
	copy(signedAttrsImplicit, signedAttrsSet)
	signedAttrsImplicit[0] = 0xA0 // [0] IMPLICIT
	signerInfoBytes = append(signerInfoBytes, signedAttrsImplicit...)

	// SignatureAlgorithm
	sigAlgBytes, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256})
	if err != nil {
		return nil, fmt.Errorf("marshal sig alg: %w", err)
	}
	signerInfoBytes = append(signerInfoBytes, sigAlgBytes...)

	// Signature OCTET STRING
	sigBytes, err := asn1.Marshal(ecdsaSig)
	if err != nil {
		return nil, fmt.Errorf("marshal signature: %w", err)
	}
	signerInfoBytes = append(signerInfoBytes, sigBytes...)

	// Wrap SignerInfo in SEQUENCE
	signerInfoSeq := append([]byte{0x30}, encodeLength(len(signerInfoBytes))...)
	signerInfoSeq = append(signerInfoSeq, signerInfoBytes...)

	// Wrap SignerInfo in SET OF
	signerInfosSet := append([]byte{0x31}, encodeLength(len(signerInfoSeq))...)
	signerInfosSet = append(signerInfosSet, signerInfoSeq...)

	// Build DigestAlgorithms SET
	digestAlgs := []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}}
	digestAlgsBytes, err := asn1.Marshal(digestAlgs)
	if err != nil {
		return nil, fmt.Errorf("marshal digest algs: %w", err)
	}
	digestAlgsBytes[0] = 0x31 // Change to SET

	// Build Certificates [0] IMPLICIT
	certsImplicit := append([]byte{0xA0}, encodeLength(len(cert.Raw))...)
	certsImplicit = append(certsImplicit, cert.Raw...)

	// Build EncapContentInfo
	// For CAdES-BES, eContent must be an OCTET STRING inside [0] EXPLICIT
	contentOctetString, err := asn1.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal content: %w", err)
	}

	// Build eContent [0] EXPLICIT containing OCTET STRING
	eContentExplicit := append([]byte{0xA0}, encodeLength(len(contentOctetString))...)
	eContentExplicit = append(eContentExplicit, contentOctetString...)

	// Build EncapContentInfo SEQUENCE
	contentTypeOIDBytes, _ := asn1.Marshal(oidData)
	encapContentInfo := append([]byte{0x30}, encodeLength(len(contentTypeOIDBytes)+len(eContentExplicit))...)
	encapContentInfo = append(encapContentInfo, contentTypeOIDBytes...)
	encapContentInfo = append(encapContentInfo, eContentExplicit...)

	// Build SignedData SEQUENCE
	var signedDataBytes []byte

	// Version
	signedDataBytes = append(signedDataBytes, versionBytes...)

	// DigestAlgorithms
	signedDataBytes = append(signedDataBytes, digestAlgsBytes...)

	// EncapContentInfo
	signedDataBytes = append(signedDataBytes, encapContentInfo...)

	// Certificates [0]
	signedDataBytes = append(signedDataBytes, certsImplicit...)

	// SignerInfos
	signedDataBytes = append(signedDataBytes, signerInfosSet...)

	// Wrap in SEQUENCE
	signedDataSeq := append([]byte{0x30}, encodeLength(len(signedDataBytes))...)
	signedDataSeq = append(signedDataSeq, signedDataBytes...)

	// Build ContentInfo
	signedDataOIDBytes, _ := asn1.Marshal(oidSignedData)

	// Wrap SignedData in [0] EXPLICIT
	signedDataExplicit := append([]byte{0xA0}, encodeLength(len(signedDataSeq))...)
	signedDataExplicit = append(signedDataExplicit, signedDataSeq...)

	// Build final ContentInfo SEQUENCE
	contentInfo := append([]byte{0x30}, encodeLength(len(signedDataOIDBytes)+len(signedDataExplicit))...)
	contentInfo = append(contentInfo, signedDataOIDBytes...)
	contentInfo = append(contentInfo, signedDataExplicit...)

	return contentInfo, nil
}
