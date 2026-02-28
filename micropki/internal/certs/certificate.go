package certs

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"MicroPKI/internal/cryptoutil"
)

func GenerateSerialNumber() (*big.Int, error) {
	serialNumber := make([]byte, 20)
	_, err := rand.Read(serialNumber)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации серийного номера: %w", err)
	}
	return new(big.Int).SetBytes(serialNumber), nil
}

func CalculateSKI(pubKey crypto.PublicKey) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка маршалинга публичного ключа: %w", err)
	}
	hash := cryptoutil.HashSHA1(pubBytes)
	return hash[:], nil
}

func ParseDN(dn string) (*pkix.Name, error) {
	name := &pkix.Name{}

	if dn == "" {
		return nil, fmt.Errorf("DN не может быть пустым")
	}

	if strings.HasPrefix(dn, "/") {
		parts := strings.Split(dn, "/")
		for _, part := range parts {
			if part == "" {
				continue
			}
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "CN":
				name.CommonName = kv[1]
			case "O":
				name.Organization = []string{kv[1]}
			case "OU":
				name.OrganizationalUnit = []string{kv[1]}
			case "C":
				name.Country = []string{kv[1]}
			case "ST":
				name.Province = []string{kv[1]}
			case "L":
				name.Locality = []string{kv[1]}
			}
		}
		return name, nil
	}

	if strings.Contains(dn, ",") {
		parts := strings.Split(dn, ",")
		for _, part := range parts {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "CN":
				name.CommonName = kv[1]
			case "O":
				name.Organization = []string{kv[1]}
			case "OU":
				name.OrganizationalUnit = []string{kv[1]}
			case "C":
				name.Country = []string{kv[1]}
			case "ST":
				name.Province = []string{kv[1]}
			case "L":
				name.Locality = []string{kv[1]}
			}
		}
		return name, nil
	}

	name.CommonName = dn
	return name, nil
}

func GenerateRootCATemplate(subjectDN string, pubKey crypto.PublicKey, validityDays int) (*x509.Certificate, error) {
	name, err := ParseDN(subjectDN)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга subject: %w", err)
	}

	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации серийного номера: %w", err)
	}

	ski, err := CalculateSKI(pubKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка вычисления subject key identifier: %w", err)
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(0, 0, validityDays)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      *name,
		Issuer:       *name,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,

		BasicConstraintsValid: true,
		IsCA:                  true,

		SubjectKeyId:   ski,
		AuthorityKeyId: ski,
	}

	return template, nil
}

func CreateCertificatePEM(template *x509.Certificate, pubKey crypto.PublicKey, signer crypto.Signer) ([]byte, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, signer)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания сертификата: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM, nil
}

func GetAKIFromCert(cert *x509.Certificate) []byte {
	return cert.SubjectKeyId
}