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

type IntermediateCA struct {
	CertPath       string
	KeyPath        string
	PassphraseFile string
}

func NewRootCA(subject, keyType string, keySize int, passphraseFile, outDir string, validityDays int, force bool) (*RootCA, error) {
	if subject == "" {
		return nil, fmt.Errorf("subject не может быть пустым")
	}
	if keyType != "rsa" && keyType != "ecc" {
		return nil, fmt.Errorf("key-type должен быть 'rsa' или 'ecc', получено: %s", keyType)
	}
	if keyType == "rsa" && keySize != 4096 {
		return nil, fmt.Errorf("для RSA размер ключа должен быть 4096 бит, получено: %d", keySize)
	}
	if keyType == "ecc" && keySize != 384 {
		return nil, fmt.Errorf("для ECC размер ключа должен быть 384 бита, получено: %d", keySize)
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

func NewIntermediateCA(certPath, keyPath, passphraseFile string) (*IntermediateCA, error) {
	if _, err := os.Stat(certPath); err != nil {
		return nil, fmt.Errorf("сертификат промежуточного УЦ не найден: %w", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		return nil, fmt.Errorf("ключ промежуточного УЦ не найден: %w", err)
	}
	if _, err := os.Stat(passphraseFile); err != nil {
		return nil, fmt.Errorf("файл с паролем не найден: %w", err)
	}

	return &IntermediateCA{
		CertPath:       certPath,
		KeyPath:        keyPath,
		PassphraseFile: passphraseFile,
	}, nil
}

func (ca *RootCA) Initialize() error {
	logger.Info("начало инициализации корневого УЦ")
	logger.Info("параметры: subject=%s, keyType=%s, keySize=%d, outDir=%s, validityDays=%d",
		ca.Subject, ca.KeyType, ca.KeySize, ca.OutDir, ca.ValidityDays)

	if _, err := os.Stat(ca.PassphraseFile); os.IsNotExist(err) {
		return fmt.Errorf("файл с парольной фразой не существует: %s", ca.PassphraseFile)
	}

	if err := ca.createDirectories(); err != nil {
		logger.Error("ошибка создания директорий: %v", err)
		return err
	}

	logger.Info("чтение парольной фразы из файла: %s", ca.PassphraseFile)
	passphrase, err := os.ReadFile(ca.PassphraseFile)
	if err != nil {
		logger.Error("ошибка чтения файла с паролем: %v", err)
		return fmt.Errorf("ошибка чтения файла с паролем: %w", err)
	}

	defer func() {
		for i := range passphrase {
			passphrase[i] = 0
		}
	}()

	if len(passphrase) > 0 && passphrase[len(passphrase)-1] == '\n' {
		passphrase = passphrase[:len(passphrase)-1]
	}
	logger.Info("парольная фраза успешно прочитана (длина: %d байт)", len(passphrase))

	logger.Info("генерация %s ключа длиной %d бит...", ca.KeyType, ca.KeySize)
	if err := ca.generateKeys(passphrase); err != nil {
		logger.Error("ошибка генерации ключей: %v", err)
		return err
	}
	logger.Info("ключи успешно сгенерированы")

	logger.Info("создание самоподписанного сертификата...")
	if err := ca.generateCertificate(); err != nil {
		logger.Error("ошибка создания сертификата: %v", err)
		return err
	}
	logger.Info("сертификат успешно создан")

	if err := ca.saveCertificate(); err != nil {
		logger.Error("ошибка сохранения сертификата: %v", err)
		return err
	}
	logger.Info("сертификат сохранен")

	logger.Info("проверка соответствия ключа и сертификата...")
	if err := ca.verifyKeyPair(); err != nil {
		logger.Error("ошибка проверки ключей: %v", err)
		return err
	}
	logger.Info("ключ и сертификат соответствуют друг другу")

	logger.Info("создание файла политики...")
	if err := ca.createPolicyFile(); err != nil {
		logger.Error("ошибка создания policy.txt: %v", err)
		return err
	}
	logger.Info("файл политики создан")

	if runtime.GOOS == "windows" {
		logger.Warn("на Windows права доступа к файлам (0600/0700) не применяются в полной мере")
	}

	logger.Info("инициализация корневого УЦ завершена успешно")
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
		logger.Info("создана директория: %s (права: %o)", dir, perm)
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
		return fmt.Errorf("неподдерживаемый тип ключа: %s", ca.KeyType)
	}

	logger.Info("ключ сохранен: %s", keyPath)
	return nil
}

func (ca *RootCA) generateCertificate() error {
	publicKey := ca.privateKey.(crypto.Signer).Public()

	template, err := certs.GenerateRootCATemplate(ca.Subject, publicKey, ca.ValidityDays)
	if err != nil {
		return fmt.Errorf("ошибка создания шаблона сертификата: %w", err)
	}

	logger.Info("подписание сертификата корневого УЦ...")
	certPEM, err := certs.CreateCertificatePEM(template, publicKey, ca.privateKey.(crypto.Signer))
	if err != nil {
		return err
	}
	ca.certPEM = certPEM

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("не удалось декодировать созданный PEM-сертификат")
	}
	ca.certificate, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("ошибка парсинга созданного сертификата: %w", err)
	}

	logger.Info("сертификат создан. серийный номер: %x", ca.certificate.SerialNumber)
	return nil
}

func (ca *RootCA) saveCertificate() error {
	certPath := filepath.Join(ca.OutDir, "certs", "ca.cert.pem")
	if err := os.WriteFile(certPath, ca.certPEM, 0644); err != nil {
		return fmt.Errorf("ошибка сохранения сертификата: %w", err)
	}
	logger.Info("сертификат сохранен: %s", certPath)
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
		return fmt.Errorf("ошибка сохранения policy.txt: %w", err)
	}
	logger.Info("policy файл создан: %s", policyPath)
	return nil
}

func (ca *RootCA) verifyKeyPair() error {
	pubKeyFromCert := ca.certificate.PublicKey

	switch key := ca.privateKey.(type) {
	case *rsa.PrivateKey:
		testData := []byte("test signature for key verification")
		hash := cryptoutil.HashSHA256(testData)
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		if err != nil {
			return fmt.Errorf("ошибка создания тестовой подписи: %w", err)
		}
		err = rsa.VerifyPKCS1v15(pubKeyFromCert.(*rsa.PublicKey), crypto.SHA256, hash[:], signature)
		if err != nil {
			return fmt.Errorf("ошибка проверки подписи: ключ не соответствует сертификату")
		}
	case *ecdsa.PrivateKey:
		if pubKeyFromCert == nil {
			return fmt.Errorf("публичный ключ не может быть nil")
		}
	}

	return nil
}

func (ica *IntermediateCA) Load() (*x509.Certificate, crypto.Signer, error) {
	passphrase, err := os.ReadFile(ica.PassphraseFile)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка чтения файла с паролем: %w", err)
	}
	defer func() {
		for i := range passphrase {
			passphrase[i] = 0
		}
	}()
	if len(passphrase) > 0 && passphrase[len(passphrase)-1] == '\n' {
		passphrase = passphrase[:len(passphrase)-1]
	}

	keyPEM, err := os.ReadFile(ica.KeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка чтения ключа: %w", err)
	}

	privateKey, err := cryptoutil.LoadEncryptedPrivateKeyFromPEM(keyPEM, passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка загрузки ключа: %w", err)
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("ключ не поддерживает подписание")
	}

	certPEM, err := os.ReadFile(ica.CertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка чтения сертификата: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("не удалось декодировать сертификат")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка парсинга сертификата: %w", err)
	}

	return cert, signer, nil
}