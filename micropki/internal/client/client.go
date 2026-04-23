package client

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// Client представляет клиент PKI
type Client struct {
	caURL  string
	apiKey string
}

// NewClient создает нового клиента
func NewClient(caURL, apiKey string) *Client {
	return &Client{
		caURL:  caURL,
		apiKey: apiKey,
	}
}

// LoadCertificate загружает сертификат из PEM файла
func LoadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения файла: %w", err)
	}
	
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM")
	}
	
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("неверный тип PEM: %s", block.Type)
	}
	
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга сертификата: %w", err)
	}
	
	return cert, nil
}

// LoadCSR загружает CSR из PEM файла
func LoadCSR(path string) (*x509.CertificateRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения файла: %w", err)
	}
	
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM")
	}
	
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("неверный тип PEM: %s", block.Type)
	}
	
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга CSR: %w", err)
	}
	
	return csr, nil
}

// LoadPrivateKey загружает приватный ключ из PEM файла
func LoadPrivateKey(path string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения файла: %w", err)
	}
	
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM")
	}
	
	// Пробуем разные форматы ключей
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	
	return nil, fmt.Errorf("неподдерживаемый формат ключа: %s", block.Type)
}

// SaveCertificate сохраняет сертификат в PEM файл
func SaveCertificate(path string, cert *x509.Certificate) error {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	
	if err := os.WriteFile(path, pemData, 0644); err != nil {
		return fmt.Errorf("ошибка сохранения сертификата: %w", err)
	}
	
	return nil
}

// SaveCertificatePEM сохраняет PEM данные сертификата в файл
func SaveCertificatePEM(path string, pemData []byte) error {
	if err := os.WriteFile(path, pemData, 0644); err != nil {
		return fmt.Errorf("ошибка сохранения сертификата: %w", err)
	}
	
	return nil
}

// GetCertInfo возвращает базовую информацию о сертификате
func GetCertInfo(cert *x509.Certificate) map[string]interface{} {
	info := map[string]interface{}{
		"subject":      cert.Subject.String(),
		"issuer":       cert.Issuer.String(),
		"serial":       fmt.Sprintf("%x", cert.SerialNumber),
		"not_before":   cert.NotBefore.Format("2006-01-02 15:04:05"),
		"not_after":    cert.NotAfter.Format("2006-01-02 15:04:05"),
		"is_ca":        cert.IsCA,
		"key_usage":    cert.KeyUsage,
		"ext_key_usage": cert.ExtKeyUsage,
		"dns_names":    cert.DNSNames,
		"ip_addresses": cert.IPAddresses,
		"email_addresses": cert.EmailAddresses,
		"uris":         cert.URIs,
	}
	
	// Вычисляем оставшиеся дни
	remaining := cert.NotAfter.Sub(time.Now()).Hours() / 24
	info["days_remaining"] = int(remaining)
	
	return info
}

// ValidateCertificateExpiry проверяет срок действия сертификата
func ValidateCertificateExpiry(cert *x509.Certificate) error {
	now := time.Now().UTC()
	
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("сертификат еще не действителен (начнет действовать: %s)", cert.NotBefore.Format(time.RFC3339))
	}
	
	if now.After(cert.NotAfter) {
		return fmt.Errorf("срок действия сертификата истек: %s", cert.NotAfter.Format(time.RFC3339))
	}
	
	return nil
}

// IsCertificateExpired возвращает true, если сертификат истек
func IsCertificateExpired(cert *x509.Certificate) bool {
	return time.Now().UTC().After(cert.NotAfter)
}

// IsCertificateValidNow возвращает true, если сертификат действителен сейчас
func IsCertificateValidNow(cert *x509.Certificate) bool {
	now := time.Now().UTC()
	return now.After(cert.NotBefore) && now.Before(cert.NotAfter)
}

// LoadCertificatesFromFile загружает все сертификаты из PEM файла
func LoadCertificatesFromFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения файла: %w", err)
	}
	
	var certs []*x509.Certificate
	var block *pem.Block
	
	for {
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			certs = append(certs, cert)
		}
	}
	
	if len(certs) == 0 {
		return nil, fmt.Errorf("не найдено ни одного сертификата в файле")
	}
	
	return certs, nil
}