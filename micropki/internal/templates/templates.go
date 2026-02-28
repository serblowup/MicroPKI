package templates

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"time"

	"MicroPKI/internal/certs"
	"MicroPKI/internal/san"
)

type TemplateType string

const (
	ServerTemplate     TemplateType = "server"
	ClientTemplate     TemplateType = "client"
	CodeSigningTemplate TemplateType = "code_signing"
)

type CertTemplate struct {
	Type             TemplateType
	BasicConstraints bool
	IsCA             bool
	KeyUsage         x509.KeyUsage
	ExtKeyUsage      []x509.ExtKeyUsage
	RequiredSANTypes []string
	AllowedSANTypes  []string
}

func GetTemplate(templateType TemplateType) (*CertTemplate, error) {
	switch templateType {
	case ServerTemplate:
		return &CertTemplate{
			Type:             ServerTemplate,
			BasicConstraints: true,
			IsCA:             false,
			KeyUsage:         x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			RequiredSANTypes: []string{"dns", "ip"},
			AllowedSANTypes:  []string{"dns", "ip"},
		}, nil
	case ClientTemplate:
		return &CertTemplate{
			Type:             ClientTemplate,
			BasicConstraints: true,
			IsCA:             false,
			KeyUsage:         x509.KeyUsageDigitalSignature,
			ExtKeyUsage:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			RequiredSANTypes: []string{},
			AllowedSANTypes:  []string{"dns", "ip", "email"},
		}, nil
	case CodeSigningTemplate:
		return &CertTemplate{
			Type:             CodeSigningTemplate,
			BasicConstraints: true,
			IsCA:             false,
			KeyUsage:         x509.KeyUsageDigitalSignature,
			ExtKeyUsage:      []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			RequiredSANTypes: []string{},
			AllowedSANTypes:  []string{"dns", "uri"},
		}, nil
	default:
		return nil, fmt.Errorf("неизвестный тип шаблона: %s", templateType)
	}
}

func ValidateSANsForTemplate(template *CertTemplate, sanEntries []san.SANEntry) error {
	if len(sanEntries) == 0 && len(template.RequiredSANTypes) > 0 {
		return fmt.Errorf("шаблон %s требует как минимум один SAN типа %v", template.Type, template.RequiredSANTypes)
	}

	hasRequired := false
	for _, entry := range sanEntries {
		allowed := false
		for _, allowedType := range template.AllowedSANTypes {
			if entry.Type == allowedType {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("тип SAN '%s' не разрешен для шаблона %s", entry.Type, template.Type)
		}

		for _, requiredType := range template.RequiredSANTypes {
			if entry.Type == requiredType {
				hasRequired = true
			}
		}
	}

	if len(template.RequiredSANTypes) > 0 && !hasRequired {
		return fmt.Errorf("шаблон %s требует один из типов SAN: %v", template.Type, template.RequiredSANTypes)
	}

	return nil
}

func BuildCertificateTemplate(
	templateType TemplateType,
	subjectDN string,
	pubKey crypto.PublicKey,
	sanEntries []san.SANEntry,
	validityDays int,
	isCA bool,
	pathlen int,
) (*x509.Certificate, error) {
	tmpl, err := GetTemplate(templateType)
	if err != nil {
		return nil, err
	}

	if err := ValidateSANsForTemplate(tmpl, sanEntries); err != nil {
		return nil, err
	}

	name, err := certs.ParseDN(subjectDN)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга subject: %w", err)
	}

	serialNumber, err := certs.GenerateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации серийного номера: %w", err)
	}

	ski, err := certs.CalculateSKI(pubKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка вычисления SKI: %w", err)
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(0, 0, validityDays)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      *name,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:    tmpl.KeyUsage,
		ExtKeyUsage: tmpl.ExtKeyUsage,

		SubjectKeyId: ski,

		BasicConstraintsValid: tmpl.BasicConstraints,
		IsCA:                  isCA,
	}

	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.MaxPathLen = pathlen
		template.MaxPathLenZero = pathlen == 0
	}

	for _, entry := range sanEntries {
		switch entry.Type {
		case "dns":
			template.DNSNames = append(template.DNSNames, entry.Value)
		case "ip":
			ip := net.ParseIP(entry.Value)
			if ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			}
		case "email":
			template.EmailAddresses = append(template.EmailAddresses, entry.Value)
		case "uri":
			if u, err := url.Parse(entry.Value); err == nil {
				template.URIs = append(template.URIs, u)
			}
		}
	}

	return template, nil
}