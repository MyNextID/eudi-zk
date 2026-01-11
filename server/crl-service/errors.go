package crlservice

import "errors"

// Defines common errors
var (
	ErrCertificateNotFound = errors.New("certificate not found")
	ErrCRLNotFound         = errors.New("CRL not found")
	ErrSerialNotInRange    = errors.New("serial number not found in any mini CRL range")
)
