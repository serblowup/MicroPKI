package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"
	"os"

	"MicroPKI/internal/certs"
	"MicroPKI/internal/san"
)

type CSRConfig struct {
	Subject string
	KeyType string
	KeySize int
	SANs    []string
	OutKey  string
	OutCSR  string
}

type GeneratedCSR struct {
	PrivateKey crypto.PrivateKey
	PublicKey  crypto.PublicKey
	CSRPEM     []byte
	KeyPEM     []byte
}

// GenerateCSR генерирует приватный ключ и CSR
func GenerateCSR(cfg *CSRConfig) (*GeneratedCSR, error) {
	// Генерация ключа
	privKey, pubKey, err := generateKeyPair(cfg.KeyType, cfg.KeySize)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации ключа: %w", err)
	}

	// Парсинг subject
	name, err := certs.ParseDN(cfg.Subject)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга subject: %w", err)
	}

	// Парсинг SAN
	sanEntries, err := san.ParseSANs(cfg.SANs)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга SAN: %w", err)
	}

	// Создание шаблона CSR
	template := &x509.CertificateRequest{
		Subject: *name,
	}

	// Добавление SAN в CSR
	if len(sanEntries) > 0 {
		ext, err := createSANExtension(sanEntries)
		if err != nil {
			return nil, fmt.Errorf("ошибка создания SAN расширения: %w", err)
		}
		template.ExtraExtensions = []pkix.Extension{ext}
	}

	// Создание CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания CSR: %w", err)
	}

	// Кодирование в PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	// Кодирование ключа в PEM
	keyPEM, err := encodePrivateKeyToPEM(privKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка кодирования ключа: %w", err)
	}

	return &GeneratedCSR{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		CSRPEM:     csrPEM,
		KeyPEM:     keyPEM,
	}, nil
}

// SaveCSR сохраняет CSR и ключ в файлы
func SaveCSR(csr *GeneratedCSR, keyPath, csrPath string) error {
	// Сохраняем ключ с правами 0600
	if err := os.WriteFile(keyPath, csr.KeyPEM, 0600); err != nil {
		return fmt.Errorf("ошибка сохранения ключа: %w", err)
	}

	// Сохраняем CSR с правами 0644
	if err := os.WriteFile(csrPath, csr.CSRPEM, 0644); err != nil {
		os.Remove(keyPath)
		return fmt.Errorf("ошибка сохранения CSR: %w", err)
	}

	return nil
}

func generateKeyPair(keyType string, keySize int) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch keyType {
	case "rsa":
		if keySize != 2048 && keySize != 4096 {
			return nil, nil, fmt.Errorf("RSA ключ должен быть 2048 или 4096 бит")
		}
		key, err := rsa.GenerateKey(rand.Reader, keySize)
		return key, &key.PublicKey, err
	case "ecc":
		var curve elliptic.Curve
		switch keySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		default:
			return nil, nil, fmt.Errorf("ECC ключ должен быть 256 или 384 бита")
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		return key, &key.PublicKey, err
	default:
		return nil, nil, fmt.Errorf("неподдерживаемый тип ключа: %s", keyType)
	}
}

func encodePrivateKeyToPEM(privKey crypto.PrivateKey) ([]byte, error) {
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}), nil
	case *ecdsa.PrivateKey:
		bytes, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: bytes,
		}), nil
	default:
		return nil, fmt.Errorf("неподдерживаемый тип ключа")
	}
}

func createSANExtension(sanEntries []san.SANEntry) (pkix.Extension, error) {
	var rawValues []asn1.RawValue

	for _, entry := range sanEntries {
		switch entry.Type {
		case "dns":
			rawValues = append(rawValues, asn1.RawValue{
				Tag:   2,
				Bytes: []byte(entry.Value),
			})
		case "ip":
			ip := net.ParseIP(entry.Value)
			if ip == nil {
				continue
			}
			rawValues = append(rawValues, asn1.RawValue{
				Tag:   7,
				Bytes: ip,
			})
		case "email":
			rawValues = append(rawValues, asn1.RawValue{
				Tag:   1,
				Bytes: []byte(entry.Value),
			})
		case "uri":
			rawValues = append(rawValues, asn1.RawValue{
				Tag:   6,
				Bytes: []byte(entry.Value),
			})
		}
	}

	value, err := asn1.Marshal(rawValues)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       []int{2, 5, 29, 17},
		Critical: false,
		Value:    value,
	}, nil
}