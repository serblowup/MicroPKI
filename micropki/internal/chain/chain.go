package chain

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

func LoadCertificate(path string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения файла сертификата: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("неверный тип блока: %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга сертификата: %w", err)
	}

	return cert, nil
}

func VerifyChain(leafPath, intermediatePath, rootPath string) error {
	leaf, err := LoadCertificate(leafPath)
	if err != nil {
		return fmt.Errorf("ошибка загрузки конечного сертификата: %w", err)
	}

	intermediate, err := LoadCertificate(intermediatePath)
	if err != nil {
		return fmt.Errorf("ошибка загрузки промежуточного сертификата: %w", err)
	}

	root, err := LoadCertificate(rootPath)
	if err != nil {
		return fmt.Errorf("ошибка загрузки корневого сертификата: %w", err)
	}

	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return fmt.Errorf("конечный сертификат вне срока действия")
	}
	if now.Before(intermediate.NotBefore) || now.After(intermediate.NotAfter) {
		return fmt.Errorf("промежуточный сертификат вне срока действия")
	}
	if now.Before(root.NotBefore) || now.After(root.NotAfter) {
		return fmt.Errorf("корневой сертификат вне срока действия")
	}

	if err := leaf.CheckSignatureFrom(intermediate); err != nil {
		return fmt.Errorf("ошибка проверки подписи конечного сертификата: %w", err)
	}

	if err := intermediate.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("ошибка проверки подписи промежуточного сертификата: %w", err)
	}

	if !root.IsCA {
		return fmt.Errorf("корневой сертификат не является CA")
	}
	if !intermediate.IsCA {
		return fmt.Errorf("промежуточный сертификат не является CA")
	}
	if leaf.IsCA {
		return fmt.Errorf("конечный сертификат не должен быть CA")
	}

	if (root.KeyUsage & x509.KeyUsageCertSign) == 0 {
		return fmt.Errorf("корневой сертификат не имеет KeyUsage CertSign")
	}
	if (intermediate.KeyUsage & x509.KeyUsageCertSign) == 0 {
		return fmt.Errorf("промежуточный сертификат не имеет KeyUsage CertSign")
	}

	return nil
}

func VerifyWithOpenSSLCompatibility(leafPath, intermediatePath, rootPath string) error {
	roots := x509.NewCertPool()
	root, err := LoadCertificate(rootPath)
	if err != nil {
		return err
	}
	roots.AddCert(root)

	intermediates := x509.NewCertPool()
	intermediate, err := LoadCertificate(intermediatePath)
	if err != nil {
		return err
	}
	intermediates.AddCert(intermediate)

	leaf, err := LoadCertificate(leafPath)
	if err != nil {
		return err
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("ошибка верификации цепочки: %w", err)
	}

	return nil
}