package ocsp

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"MicroPKI/internal/certs"
)

type OCSPResponderCert struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	CertPEM     []byte
}

func LoadOCSPResponderCert(certPath, keyPath string) (*OCSPResponderCert, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения сертификата OCSP-ответчика: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать сертификат OCSP-ответчика")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга сертификата OCSP-ответчика: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения ключа OCSP-ответчика: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("не удалось декодировать ключ OCSP-ответчика")
	}

	var privateKey crypto.PrivateKey
	if keyBlock.Type == "RSA PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	} else if keyBlock.Type == "EC PRIVATE KEY" {
		privateKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	} else {
		privateKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	}

	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга ключа: %w", err)
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("ключ не поддерживает подписание")
	}

	if err := validateOCSPResponderCert(cert); err != nil {
		return nil, err
	}

	return &OCSPResponderCert{
		Certificate: cert,
		PrivateKey:  signer,
		CertPEM:     certPEM,
	}, nil
}

func validateOCSPResponderCert(cert *x509.Certificate) error {
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("сертификат OCSP-ответчика должен иметь KeyUsage digitalSignature")
	}

	hasOCSPSigning := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			hasOCSPSigning = true
			break
		}
	}
	if !hasOCSPSigning {
		return fmt.Errorf("сертификат OCSP-ответчика должен иметь ExtendedKeyUsage OCSPSigning")
	}

	if cert.IsCA {
		return fmt.Errorf("сертификат OCSP-ответчика не должен быть CA")
	}

	return nil
}

func GenerateOCSPResponderTemplate(
	subjectDN string,
	pubKey crypto.PublicKey,
	validityDays int,
	sanEntries []string,
) (*x509.Certificate, error) {
	return certs.GenerateOCSPResponderTemplate(subjectDN, pubKey, validityDays, sanEntries)
}
