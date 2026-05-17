package policy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"MicroPKI/internal/san"
	"MicroPKI/internal/templates"
)

// CertType определяет тип сертификата
type CertType string

const (
	RootCA         CertType = "root_ca"
	IntermediateCA CertType = "intermediate_ca"
	EndEntity      CertType = "end_entity"
)

// PolicyEngine содержит правила политик безопасности
type PolicyEngine struct {
	// Размеры ключей
	MinRSARootCA         int
	MinRSAIntermediateCA int
	MinRSAEndEntity      int
	MinECCRootCA         int
	MinECCIntermediateCA int
	MinECCEndEntity      int

	// Сроки действия (в днях)
	MaxValidityRootCA         int
	MaxValidityIntermediateCA int
	MaxValidityEndEntity      int

	// SAN политики
	RejectWildcards         bool
	AllowedWildcardTemplates []templates.TemplateType

	// Path Length
	MaxPathLenIntermediate int
}

// PolicyConfig представляет структуру конфигурационного файла
type PolicyConfig struct {
	Policy PolicySettings `json:"policy"`
}

// PolicySettings содержит настройки политик из конфига
type PolicySettings struct {
	KeySizes  KeySizeSettings  `json:"key_sizes"`
	Validity  ValiditySettings `json:"validity"`
	SAN       SANSettings      `json:"san"`
	PathLength PathLenSettings  `json:"path_length"`
}

// KeySizeSettings содержит настройки размеров ключей
type KeySizeSettings struct {
	RSARoot         int `json:"rsa_root"`
	RSAIntermediate int `json:"rsa_intermediate"`
	RSAEndEntity    int `json:"rsa_end_entity"`
	ECCRoot         int `json:"ecc_root"`
	ECCIntermediate int `json:"ecc_intermediate"`
	ECCEndEntity    int `json:"ecc_end_entity"`
}

// ValiditySettings содержит настройки сроков действия
type ValiditySettings struct {
	RootDays         int `json:"root_days"`
	IntermediateDays int `json:"intermediate_days"`
	EndEntityDays    int `json:"end_entity_days"`
}

// SANSettings содержит настройки SAN политик
type SANSettings struct {
	RejectWildcards         bool     `json:"reject_wildcards"`
	AllowedWildcardTemplates []string `json:"allowed_wildcard_templates"`
}

// PathLenSettings содержит настройки ограничения длины пути
type PathLenSettings struct {
	MaxIntermediate int `json:"max_intermediate"`
}

// DefaultPolicy создает PolicyEngine с настройками по умолчанию
func DefaultPolicy() *PolicyEngine {
	return &PolicyEngine{
		MinRSARootCA:         4096,
		MinRSAIntermediateCA: 3072,
		MinRSAEndEntity:      2048,
		MinECCRootCA:         384,
		MinECCIntermediateCA: 384,
		MinECCEndEntity:      256,

		MaxValidityRootCA:         3650,
		MaxValidityIntermediateCA: 1825,
		MaxValidityEndEntity:      365,

		RejectWildcards: true,
		AllowedWildcardTemplates: []templates.TemplateType{},

		MaxPathLenIntermediate: 0,
	}
}

// LoadPolicyFromFile загружает политики из конфигурационного файла
func LoadPolicyFromFile(configPath string) (*PolicyEngine, error) {
	pe := DefaultPolicy()

	if configPath == "" {
		return pe, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения конфигурационного файла: %w", err)
	}

	var config PolicyConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("ошибка парсинга конфигурации: %w", err)
	}

	// Применяем настройки размеров ключей
	if config.Policy.KeySizes.RSARoot > 0 {
		pe.MinRSARootCA = config.Policy.KeySizes.RSARoot
	}
	if config.Policy.KeySizes.RSAIntermediate > 0 {
		pe.MinRSAIntermediateCA = config.Policy.KeySizes.RSAIntermediate
	}
	if config.Policy.KeySizes.RSAEndEntity > 0 {
		pe.MinRSAEndEntity = config.Policy.KeySizes.RSAEndEntity
	}
	if config.Policy.KeySizes.ECCRoot > 0 {
		pe.MinECCRootCA = config.Policy.KeySizes.ECCRoot
	}
	if config.Policy.KeySizes.ECCIntermediate > 0 {
		pe.MinECCIntermediateCA = config.Policy.KeySizes.ECCIntermediate
	}
	if config.Policy.KeySizes.ECCEndEntity > 0 {
		pe.MinECCEndEntity = config.Policy.KeySizes.ECCEndEntity
	}

	// Применяем настройки сроков действия
	if config.Policy.Validity.RootDays > 0 {
		pe.MaxValidityRootCA = config.Policy.Validity.RootDays
	}
	if config.Policy.Validity.IntermediateDays > 0 {
		pe.MaxValidityIntermediateCA = config.Policy.Validity.IntermediateDays
	}
	if config.Policy.Validity.EndEntityDays > 0 {
		pe.MaxValidityEndEntity = config.Policy.Validity.EndEntityDays
	}

	// Применяем настройки SAN
	pe.RejectWildcards = config.Policy.SAN.RejectWildcards
	if len(config.Policy.SAN.AllowedWildcardTemplates) > 0 {
		pe.AllowedWildcardTemplates = make([]templates.TemplateType, 0, len(config.Policy.SAN.AllowedWildcardTemplates))
		for _, t := range config.Policy.SAN.AllowedWildcardTemplates {
			pe.AllowedWildcardTemplates = append(pe.AllowedWildcardTemplates, templates.TemplateType(t))
		}
	}

	// Применяем настройки длины пути
	if config.Policy.PathLength.MaxIntermediate >= 0 {
		pe.MaxPathLenIntermediate = config.Policy.PathLength.MaxIntermediate
	}

	return pe, nil
}

// ValidateKeySize проверяет размер ключа
func (pe *PolicyEngine) ValidateKeySize(keyType string, keySize int, certType CertType) error {
	switch certType {
	case RootCA:
		if keyType == "rsa" {
			if keySize < pe.MinRSARootCA {
				return fmt.Errorf("размер RSA ключа для корневого CA должен быть не менее %d бит, получено: %d",
					pe.MinRSARootCA, keySize)
			}
		} else if keyType == "ecc" {
			if keySize < pe.MinECCRootCA {
				return fmt.Errorf("размер ECC ключа для корневого CA должен быть не менее P-%d, получено: P-%d",
					pe.MinECCRootCA, keySize)
			}
			if keySize == 256 {
				return fmt.Errorf("ECC P-256 не разрешен для корневого CA, требуется минимум P-%d", pe.MinECCRootCA)
			}
		}
	case IntermediateCA:
		if keyType == "rsa" {
			if keySize < pe.MinRSAIntermediateCA {
				return fmt.Errorf("размер RSA ключа для промежуточного CA должен быть не менее %d бит, получено: %d",
					pe.MinRSAIntermediateCA, keySize)
			}
			if keySize < 2048 {
				return fmt.Errorf("размер RSA ключа для CA должен быть не менее 2048 бит, получено: %d", keySize)
			}
		} else if keyType == "ecc" {
			if keySize < pe.MinECCIntermediateCA {
				return fmt.Errorf("размер ECC ключа для промежуточного CA должен быть не менее P-%d, получено: P-%d",
					pe.MinECCIntermediateCA, keySize)
			}
			if keySize == 256 {
				return fmt.Errorf("ECC P-256 не разрешен для промежуточного CA, требуется минимум P-%d", pe.MinECCIntermediateCA)
			}
		}
	case EndEntity:
		if keyType == "rsa" {
			if keySize < pe.MinRSAEndEntity {
				return fmt.Errorf("размер RSA ключа для конечного сертификата должен быть не менее %d бит, получено: %d",
					pe.MinRSAEndEntity, keySize)
			}
		} else if keyType == "ecc" {
			if keySize < pe.MinECCEndEntity {
				return fmt.Errorf("размер ECC ключа для конечного сертификата должен быть не менее P-%d, получено: P-%d",
					pe.MinECCEndEntity, keySize)
			}
		}
	}
	return nil
}

// ValidateValidityPeriod проверяет срок действия
func (pe *PolicyEngine) ValidateValidityPeriod(certType CertType, days int) error {
	switch certType {
	case RootCA:
		if days > pe.MaxValidityRootCA {
			return fmt.Errorf("срок действия корневого CA не может превышать %d дней, запрошено: %d",
				pe.MaxValidityRootCA, days)
		}
	case IntermediateCA:
		if days > pe.MaxValidityIntermediateCA {
			return fmt.Errorf("срок действия промежуточного CA не может превышать %d дней, запрошено: %d",
				pe.MaxValidityIntermediateCA, days)
		}
	case EndEntity:
		if days > pe.MaxValidityEndEntity {
			return fmt.Errorf("срок действия конечного сертификата не может превышать %d дней, запрошено: %d",
				pe.MaxValidityEndEntity, days)
		}
	}

	if days <= 0 {
		return fmt.Errorf("срок действия должен быть положительным числом")
	}

	return nil
}

// ValidateSANs проверяет SAN записи
func (pe *PolicyEngine) ValidateSANs(templateType templates.TemplateType, sanEntries []san.SANEntry) error {
	// Проверяем wildcard
	if pe.RejectWildcards {
		for _, entry := range sanEntries {
			if IsWildcard(entry) {
				// Проверяем, разрешен ли wildcard для этого шаблона
				allowed := false
				for _, t := range pe.AllowedWildcardTemplates {
					if t == templateType {
						allowed = true
						break
					}
				}
				if !allowed {
					return fmt.Errorf("wildcard сертификаты запрещены (SAN: %s:%s). Используйте конкретные имена",
						entry.Type, entry.Value)
				}
			}
		}
	}

	// Проверяем типы SAN для шаблона
	tmpl, err := templates.GetTemplate(templateType)
	if err != nil {
		return err
	}

	if err := templates.ValidateSANsForTemplate(tmpl, sanEntries); err != nil {
		return err
	}

	return nil
}

// ValidateAlgorithm проверяет алгоритм подписи
func (pe *PolicyEngine) ValidateAlgorithm(keyType string, sigAlgo x509.SignatureAlgorithm) error {
	switch keyType {
	case "rsa":
		switch sigAlgo {
		case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
			return nil
		case x509.SHA1WithRSA:
			return fmt.Errorf("SHA-1 не разрешен для RSA ключей, используйте SHA-256 или сильнее")
		default:
			return fmt.Errorf("неподдерживаемый алгоритм подписи для RSA: %s", sigAlgo.String())
		}
	case "ecc":
		switch sigAlgo {
		case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
			return nil
		default:
			return fmt.Errorf("неподдерживаемый алгоритм подписи для ECC: %s", sigAlgo.String())
		}
	default:
		return fmt.Errorf("неизвестный тип ключа: %s", keyType)
	}
}

// ValidatePathLength проверяет ограничение длины пути
func (pe *PolicyEngine) ValidatePathLength(certType CertType, pathLen int, allowOverride bool) error {
	if certType == IntermediateCA {
		if pathLen > pe.MaxPathLenIntermediate && !allowOverride {
			return fmt.Errorf("ограничение длины пути для промежуточного CA не может быть больше %d, получено: %d",
				pe.MaxPathLenIntermediate, pathLen)
		}
	}
	return nil
}

// ValidatePublicKey проверяет публичный ключ на соответствие политикам
func (pe *PolicyEngine) ValidatePublicKey(pubKey crypto.PublicKey, certType CertType) error {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		keySize := key.N.BitLen()
		return pe.ValidateKeySize("rsa", keySize, certType)
	case *ecdsa.PublicKey:
		keySize := key.Curve.Params().BitSize
		return pe.ValidateKeySize("ecc", keySize, certType)
	default:
		return fmt.Errorf("неподдерживаемый тип ключа")
	}
}

// ValidateCSR проверяет CSR на соответствие политикам
func (pe *PolicyEngine) ValidateCSR(csr *x509.CertificateRequest, templateType templates.TemplateType) error {
	// Проверяем размер ключа
	if err := pe.ValidatePublicKey(csr.PublicKey, EndEntity); err != nil {
		return err
	}

	// Проверяем алгоритм подписи CSR
	if err := pe.ValidateSignatureAlgorithm(csr.SignatureAlgorithm); err != nil {
		return err
	}

	// Извлекаем SAN из CSR
	var sanEntries []san.SANEntry
	for _, ext := range csr.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 17}) {
			entries, err := parseSANFromExtension(ext.Value)
			if err != nil {
				return fmt.Errorf("ошибка парсинга SAN: %w", err)
			}
			sanEntries = entries
			break
		}
	}

	// Проверяем SAN
	if err := pe.ValidateSANs(templateType, sanEntries); err != nil {
		return err
	}

	return nil
}

// ValidateSignatureAlgorithm проверяет алгоритм подписи
func (pe *PolicyEngine) ValidateSignatureAlgorithm(algo x509.SignatureAlgorithm) error {
	switch algo {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return nil
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		return fmt.Errorf("SHA-1 не разрешен, используйте SHA-256 или сильнее")
	default:
		return fmt.Errorf("алгоритм подписи не поддерживается: %s", algo.String())
	}
}

// IsWildcard проверяет, является ли SAN запись wildcard
func IsWildcard(entry san.SANEntry) bool {
	if entry.Type == "dns" && strings.HasPrefix(entry.Value, "*.") {
		return true
	}
	return false
}

// parseSANFromExtension парсит SAN расширение
func parseSANFromExtension(value []byte) ([]san.SANEntry, error) {
	return parseRawSANExtension(value)
}

// parseRawSANExtension парсит сырые SAN данные
func parseRawSANExtension(value []byte) ([]san.SANEntry, error) {
	var rawValues []struct {
		Tag   int
		Bytes []byte
	}

	if _, err := asn1.Unmarshal(value, &rawValues); err != nil {
		return nil, err
	}

	var entries []san.SANEntry
	for _, rv := range rawValues {
		switch rv.Tag {
		case 2: // dNSName
			entries = append(entries, san.SANEntry{Type: "dns", Value: string(rv.Bytes)})
		case 7: // iPAddress
			ip := net.IP(rv.Bytes)
			entries = append(entries, san.SANEntry{Type: "ip", Value: ip.String()})
		case 1: // rfc822Name
			entries = append(entries, san.SANEntry{Type: "email", Value: string(rv.Bytes)})
		case 6: // uniformResourceIdentifier
			entries = append(entries, san.SANEntry{Type: "uri", Value: string(rv.Bytes)})
		}
	}

	return entries, nil
}