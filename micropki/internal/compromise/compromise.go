package compromise

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"MicroPKI/internal/database"
	"MicroPKI/internal/logger"
	"MicroPKI/internal/revocation"
)

// CompromiseResult содержит результат симуляции компрометации
type CompromiseResult struct {
	SerialHex      string `json:"serial_hex"`
	Subject        string `json:"subject"`
	PublicKeyHash  string `json:"public_key_hash"`
	Revoked        bool   `json:"revoked"`
	Reason         string `json:"reason"`
	CRLUpdated     bool   `json:"crl_updated"`
}

// SimulateKeyCompromise симулирует компрометацию приватного ключа
func SimulateKeyCompromise(db *database.Database, certPath string, reason string, force bool) (*CompromiseResult, error) {
	// Загружаем сертификат
	cert, err := loadCertificate(certPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка загрузки сертификата: %w", err)
	}

	serialHex := hex.EncodeToString(cert.SerialNumber.Bytes())

	logger.Info("симуляция компрометации ключа: serial=%s, subject=%s", serialHex, cert.Subject.String())

	// Проверяем существование сертификата в БД
	record, err := db.GetCertificateBySerial(serialHex)
	if err != nil {
		return nil, fmt.Errorf("ошибка поиска сертификата: %w", err)
	}
	if record == nil {
		return nil, fmt.Errorf("сертификат с серийным номером %s не найден в БД", serialHex)
	}

	// Вычисляем хеш публичного ключа
	pubKeyHash, err := computePublicKeyHash(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка вычисления хеша ключа: %w", err)
	}

	logger.Info("хеш публичного ключа: %s", pubKeyHash)

	// Определяем причину
	reasonCode, err := revocation.ReasonCodeToInt(reason)
	if err != nil {
		reasonCode = 1 // keyCompromise по умолчанию
		reason = "keyCompromise"
	}

	// Отзываем сертификат
	if err := revocation.RevokeCertificate(db, serialHex, reasonCode, force); err != nil {
		return nil, fmt.Errorf("ошибка отзыва сертификата: %w", err)
	}

	// Сохраняем информацию о компрометации
	if err := db.InsertCompromisedKey(pubKeyHash, serialHex, reason); err != nil {
		logger.Warn("ошибка сохранения информации о компрометации: %v", err)
	}

	// Логируем в аудит
	logger.LogAuditEvent("key_compromise_simulated", "success",
		fmt.Sprintf("Private key compromised for certificate %s (subject: %s)", serialHex, cert.Subject.String()),
		map[string]interface{}{
			"serial":          serialHex,
			"subject":         cert.Subject.String(),
			"public_key_hash": pubKeyHash,
			"reason":          reason,
			"timestamp":       time.Now().UTC().Format(time.RFC3339),
		})

	result := &CompromiseResult{
		SerialHex:     serialHex,
		Subject:       cert.Subject.String(),
		PublicKeyHash: pubKeyHash,
		Revoked:       true,
		Reason:        reason,
	}

	logger.Info("компрометация ключа успешно симулирована: serial=%s", serialHex)
	return result, nil
}

// IsKeyCompromised проверяет, скомпрометирован ли публичный ключ
func IsKeyCompromised(db *database.Database, pubKey crypto.PublicKey) (bool, error) {
	pubKeyHash, err := computePublicKeyHash(pubKey)
	if err != nil {
		return false, fmt.Errorf("ошибка вычисления хеша ключа: %w", err)
	}

	return db.IsKeyCompromised(pubKeyHash)
}

// computePublicKeyHash вычисляет SHA-256 хеш публичного ключа в DER кодировке
func computePublicKeyHash(pubKey crypto.PublicKey) (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("ошибка маршалинга публичного ключа: %w", err)
	}

	hash := sha256.Sum256(pubKeyBytes)
	return hex.EncodeToString(hash[:]), nil
}

// ComputePublicKeyHash вычисляет хеш публичного ключа из сертификата
func ComputePublicKeyHash(cert *x509.Certificate) (string, error) {
	return computePublicKeyHash(cert.PublicKey)
}

// ComputePublicKeyHashFromCSR вычисляет хеш публичного ключа из CSR
func ComputePublicKeyHashFromCSR(csr *x509.CertificateRequest) (string, error) {
	return computePublicKeyHash(csr.PublicKey)
}

// loadCertificate загружает сертификат из PEM файла
func loadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения файла: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга сертификата: %w", err)
	}

	return cert, nil
}

// GetKeyType возвращает тип ключа
func GetKeyType(pubKey crypto.PublicKey) string {
	switch pubKey.(type) {
	case *rsa.PublicKey:
		return "rsa"
	case *ecdsa.PublicKey:
		return "ecc"
	default:
		return "unknown"
	}
}