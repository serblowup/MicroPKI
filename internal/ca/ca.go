package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"MicroPKI/internal/certs"
	"MicroPKI/internal/cryptoutil"
	"MicroPKI/internal/logger"
)

type RootCA struct {
	Subject        string
	KeyType        string
	KeySize        int
	PassphraseFile string
	OutDir         string
	ValidityDays   int
	Force          bool

	privateKey  crypto.PrivateKey
	certificate *x509.Certificate
	certPEM     []byte
}

func NewRootCA(subject, keyType string, keySize int, passphraseFile, outDir string, validityDays int, force bool) (*RootCA, error) {
	if subject == "" {
		return nil, fmt.Errorf("subject не может быть пустым")
	}
	if keyType != "rsa" && keyType != "ecc" {
		return nil, fmt.Errorf("key-type должен быть 'rsa' или 'ecc', получено: %s", keyType)
	}
	if keyType == "rsa" && keySize != 4096 {
		return nil, fmt.Errorf("Для RSA размер ключа должен быть 4096 бит, получено: %d", keySize)
	}
	if keyType == "ecc" && keySize != 384 {
		return nil, fmt.Errorf("Для ECC размер ключа должен быть 384 бита (P-384), получено: %d", keySize)
	}
	if validityDays <= 0 {
		return nil, fmt.Errorf("validity-days должен быть положительным числом, получено: %d", validityDays)
	}

	return &RootCA{
		Subject:        subject,
		KeyType:        keyType,
		KeySize:        keySize,
		PassphraseFile: passphraseFile,
		OutDir:         outDir,
		ValidityDays:   validityDays,
		Force:          force,
	}, nil
}

func (ca *RootCA) Initialize() error {
	logger.Info("Начало инициализации корневого УЦ")
	logger.Info("Параметры: Subject=%s, KeyType=%s, KeySize=%d, OutDir=%s, ValidityDays=%d",
		ca.Subject, ca.KeyType, ca.KeySize, ca.OutDir, ca.ValidityDays)

	if _, err := os.Stat(ca.PassphraseFile); os.IsNotExist(err) {
		return fmt.Errorf("Файл с парольной фразой не существует: %s", ca.PassphraseFile)
	}

	if err := ca.createDirectories(); err != nil {
		logger.Error("Ошибка создания директорий: %v", err)
		return err
	}

	logger.Info("Чтение парольной фразы из файла: %s", ca.PassphraseFile)
	passphrase, err := os.ReadFile(ca.PassphraseFile)
	if err != nil {
		logger.Error("Ошибка чтения файла с паролем: %v", err)
		return fmt.Errorf("Ошибка чтения файла с паролем: %w", err)
	}

	defer func() {
		for i := range passphrase {
			passphrase[i] = 0
		}
	}()

	if len(passphrase) > 0 && passphrase[len(passphrase)-1] == '\n' {
		passphrase = passphrase[:len(passphrase)-1]
	}
	logger.Info("Парольная фраза успешно прочитана (длина: %d байт)", len(passphrase))

	logger.Info("Генерация %s ключа длиной %d бит...", ca.KeyType, ca.KeySize)
	if err := ca.generateKeys(passphrase); err != nil {
		logger.Error("Ошибка генерации ключей: %v", err)
		return err
	}
	logger.Info("Ключи успешно сгенерированы")

	logger.Info("Создание самоподписанного сертификата...")
	if err := ca.generateCertificate(); err != nil {
		logger.Error("Ошибка создания сертификата: %v", err)
		return err
	}
	logger.Info("Сертификат успешно создан")

	if err := ca.saveCertificate(); err != nil {
		logger.Error("Ошибка сохранения сертификата: %v", err)
		return err
	}
	logger.Info("Сертификат сохранен")

	logger.Info("Проверка соответствия ключа и сертификата...")
	if err := ca.verifyKeyPair(); err != nil {
		logger.Error("Ошибка проверки ключей: %v", err)
		return err
	}
	logger.Info("Ключ и сертификат соответствуют друг другу")

	logger.Info("Создание файла политики...")
	if err := ca.createPolicyFile(); err != nil {
		logger.Error("Ошибка создания policy.txt: %v", err)
		return err
	}
	logger.Info("Файл политики создан")

	if runtime.GOOS == "windows" {
		logger.Warn("На Windows права доступа к файлам (0600/0700) не применяются в полной мере")
	}

	logger.Info("Инициализация корневого УЦ завершена успешно")
	return nil
}

func (ca *RootCA) createDirectories() error {
	dirs := []string{
		filepath.Join(ca.OutDir, "private"),
		filepath.Join(ca.OutDir, "certs"),
	}

	for _, dir := range dirs {
		perm := os.FileMode(0755)
		if dir == filepath.Join(ca.OutDir, "private") {
			perm = 0700
		}
		if err := os.MkdirAll(dir, perm); err != nil {
			return fmt.Errorf("ошибка создания директории %s: %w", dir, err)
		}
		logger.Info("Создана директория: %s (права: %o)", dir, perm)
	}
	return nil
}

func (ca *RootCA) generateKeys(passphrase []byte) error {
	keyPath := filepath.Join(ca.OutDir, "private", "ca.key.pem")

	switch ca.KeyType {
	case "rsa":
		key, err := cryptoutil.GenerateRSAKey(ca.KeySize)
		if err != nil {
			return err
		}
		ca.privateKey = key
		if err := cryptoutil.SaveEncryptedRSAPEM(keyPath, key, passphrase); err != nil {
			return err
		}
	case "ecc":
		key, err := cryptoutil.GenerateECCP384Key()
		if err != nil {
			return err
		}
		ca.privateKey = key
		if err := cryptoutil.SaveEncryptedECCPEM(keyPath, key, passphrase); err != nil {
			return err
		}
	default:
		return fmt.Errorf("Неподдерживаемый тип ключа: %s", ca.KeyType)
	}

	logger.Info("Ключ сохранен: %s", keyPath)
	return nil
}

func (ca *RootCA) generateCertificate() error {
	publicKey := ca.privateKey.(crypto.Signer).Public()

	template, err := certs.GenerateRootCATemplate(ca.Subject, publicKey, ca.ValidityDays)
	if err != nil {
		return fmt.Errorf("Ошибка создания шаблона сертификата: %w", err)
	}

	certPEM, err := certs.CreateCertificatePEM(template, publicKey, ca.privateKey.(crypto.Signer))
	if err != nil {
		return err
	}
	ca.certPEM = certPEM

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("Не удалось декодировать созданный PEM-сертификат")
	}
	ca.certificate, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("Ошибка парсинга созданного сертификата: %w", err)
	}

	logger.Info("Сертификат создан. Серийный номер: %x", ca.certificate.SerialNumber)
	return nil
}

func (ca *RootCA) saveCertificate() error {
	certPath := filepath.Join(ca.OutDir, "certs", "ca.cert.pem")
	if err := os.WriteFile(certPath, ca.certPEM, 0644); err != nil {
		return fmt.Errorf("ошибка сохранения сертификата: %w", err)
	}
	logger.Info("Сертификат сохранен: %s", certPath)
	return nil
}

func (ca *RootCA) createPolicyFile() error {
	policyPath := filepath.Join(ca.OutDir, "policy.txt")
	content := fmt.Sprintf(`[CERTIFICATE POLICY DOCUMENT]
CA Name: %s
Certificate Serial Number: %x
Validity Period: 
  Not Before: %s
  Not After:  %s
Key Algorithm: %s-%d
Purpose: Root CA for MicroPKI demonstration
Policy Version: 1.0
Creation Date: %s
Generated by: MicroPKI
`,
		ca.Subject,
		ca.certificate.SerialNumber,
		ca.certificate.NotBefore.Format(time.RFC3339),
		ca.certificate.NotAfter.Format(time.RFC3339),
		ca.KeyType,
		ca.KeySize,
		time.Now().Format(time.RFC3339),
	)

	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("Ошибка сохранения policy.txt: %w", err)
	}
	logger.Info("Policy файл создан: %s", policyPath)
	return nil
}

func (ca *RootCA) verifyKeyPair() error {
	pubKeyFromCert := ca.certificate.PublicKey
	pubKeyFromPrivate := ca.privateKey.(crypto.Signer).Public()

	switch key := ca.privateKey.(type) {
	case *rsa.PrivateKey:
		testData := []byte("test signature for key verification")
		hash := cryptoutil.HashSHA256(testData)
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		if err != nil {
			return fmt.Errorf("Ошибка создания тестовой подписи: %w", err)
		}
		err = rsa.VerifyPKCS1v15(pubKeyFromCert.(*rsa.PublicKey), crypto.SHA256, hash[:], signature)
		if err != nil {
			return fmt.Errorf("Ошибка проверки подписи: ключ не соответствует сертификату")
		}
	case *ecdsa.PrivateKey:
		if pubKeyFromCert == nil || pubKeyFromPrivate == nil {
			return fmt.Errorf("Публичный ключ не может быть nil")
		}
	}

	return nil
}
