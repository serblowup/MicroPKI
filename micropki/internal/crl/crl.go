package crl

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type RevokedCertInfo struct {
	SerialNumber   *big.Int
	RevocationTime time.Time
	ReasonCode     int
}

func GenerateCRL(
	caCert *x509.Certificate,
	caKey crypto.Signer,
	revokedCerts []RevokedCertInfo,
	crlNumber int64,
	nextUpdateDays int,
) ([]byte, error) {
	now := time.Now().UTC()
	nextUpdate := now.AddDate(0, 0, nextUpdateDays)

	revokedList := make([]pkix.RevokedCertificate, 0, len(revokedCerts))
	for _, rc := range revokedCerts {
		revokedCert := pkix.RevokedCertificate{
			SerialNumber:   rc.SerialNumber,
			RevocationTime: rc.RevocationTime,
		}
		
		if rc.ReasonCode != 0 {
			reasonCodeEnum := asn1.Enumerated(rc.ReasonCode)
			reasonCodeBytes, err := asn1.Marshal(reasonCodeEnum)
			if err != nil {
				return nil, fmt.Errorf("ошибка маршалинга ReasonCode: %w", err)
			}
			
			reasonExt := pkix.Extension{
				Id:       []int{2, 5, 29, 21},
				Critical: false,
				Value:    reasonCodeBytes,
			}
			revokedCert.Extensions = []pkix.Extension{reasonExt}
		}
		
		revokedList = append(revokedList, revokedCert)
	}

	aki := caCert.SubjectKeyId
	if len(aki) == 0 {
		aki = caCert.AuthorityKeyId
	}

	crlTemplate := &x509.RevocationList{
		Number:              big.NewInt(crlNumber),
		ThisUpdate:          now,
		NextUpdate:          nextUpdate,
		RevokedCertificates: revokedList,
		Issuer:              caCert.Subject,
		AuthorityKeyId:      aki,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания CRL: %w", err)
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})

	return crlPEM, nil
}
