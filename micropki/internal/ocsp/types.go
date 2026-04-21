package ocsp

import (
	"crypto/x509"
	"math/big"
	"time"
)

type CertStatus int

const (
	StatusGood    CertStatus = 0
	StatusRevoked CertStatus = 1
	StatusUnknown CertStatus = 2
)

func (s CertStatus) String() string {
	switch s {
	case StatusGood:
		return "good"
	case StatusRevoked:
		return "revoked"
	case StatusUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

type OCSPRequest struct {
	Version       int
	CertIDs       []CertID
	Nonce         []byte
	HasNonce      bool
}

type CertID struct {
	HashAlgorithm   x509.SignatureAlgorithm
	IssuerNameHash  []byte
	IssuerKeyHash   []byte
	SerialNumber    *big.Int
}

type OCSPResponse struct {
	Status        int
	CertStatus    CertStatus
	RevocationTime time.Time
	RevocationReason int
	Nonce         []byte
	ProducedAt    time.Time
	ThisUpdate    time.Time
	NextUpdate    time.Time
}

type IssuerInfo struct {
	Certificate   *x509.Certificate
	SubjectHash   []byte
	KeyHash       []byte
	SubjectString string
}
