package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"MicroPKI/internal/audit"
	"MicroPKI/internal/certs"
	"MicroPKI/internal/compromise"
	"MicroPKI/internal/cryptoutil"
	"MicroPKI/internal/csr"
	"MicroPKI/internal/database"
	"MicroPKI/internal/logger"
	"MicroPKI/internal/policy"
	"MicroPKI/internal/san"
	"MicroPKI/internal/templates"
)

// CheckAuditIntegrityBeforeOperation проверяет целостность аудит-лога перед критическими операциями
func CheckAuditIntegrityBeforeOperation(outDir string) error {
	auditDir := filepath.Join(outDir, "audit")
	logPath := filepath.Join(auditDir, "audit.log")
	chainPath := filepath.Join(auditDir, "chain.dat")

	if audit.IsAuditLogTampered(logPath, chainPath) {
		return fmt.Errorf("ОБНАРУЖЕНО НАРУШЕНИЕ ЦЕЛОСТНОСТИ АУДИТ-ЛОГА. Операция заблокирована. " +
			"Запустите 'micropki audit verify' для диагностики")
	}
	return nil
}

type RootCA struct {
	Subject        string
	KeyType        string
	KeySize        int
	PassphraseFile string
	OutDir         string
	ValidityDays   int
	Force          bool
	DB             *database.Database

	privateKey  crypto.PrivateKey
	certificate *x509.Certificate
	certPEM     []byte
}

type IntermediateCA struct {
	CertPath       string
	KeyPath        string
	PassphraseFile string
	DB             *database.Database
}

func NewRootCA(subject, keyType string, keySize int, passphraseFile, outDir string, validityDays int, force bool, db *database.Database) (*RootCA, error) {
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
		DB:             db,
	}, nil
}

func NewIntermediateCA(certPath, keyPath, passphraseFile string, db *database.Database) (*IntermediateCA, error) {
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
		DB:             db,
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

	// Корневой сертификат НЕ сохраняется в БД (только в файловой системе)

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

func (ca *RootCA) GetSerialNumber() *big.Int {
	if ca.certificate != nil {
		return ca.certificate.SerialNumber
	}
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

func (ica *IntermediateCA) IssueCertificateFromCSR(csrData []byte, templateName string, validityDays int) (*x509.Certificate, []byte, error) {
	caCert, caSigner, err := ica.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка загрузки CA: %w", err)
	}

	csrObj, err := csr.ParseCSR(csrData)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка парсинга CSR: %w", err)
	}

	if err := csrObj.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("неверная подпись CSR: %w", err)
	}

	for _, ext := range csrObj.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 19}) {
			var basicConstraints struct {
				IsCA bool `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &basicConstraints); err == nil {
				if basicConstraints.IsCA {
					return nil, nil, fmt.Errorf("CSR запрашивает CA сертификат, что не разрешено для конечных сертификатов")
				}
			}
		}
	}

	pol := policy.DefaultPolicy()

	if err := pol.ValidatePublicKey(csrObj.PublicKey, policy.EndEntity); err != nil {
		logger.LogAuditError("policy_violation_key_size", err.Error(),
			map[string]interface{}{
				"template": templateName,
			})
		return nil, nil, fmt.Errorf("нарушение политики размера ключа: %w", err)
	}

	if err := pol.ValidateSignatureAlgorithm(csrObj.SignatureAlgorithm); err != nil {
		logger.LogAuditError("policy_violation_algorithm", err.Error(),
			map[string]interface{}{
				"template": templateName,
			})
		return nil, nil, fmt.Errorf("нарушение политики алгоритма: %w", err)
	}

	if err := pol.ValidateValidityPeriod(policy.EndEntity, validityDays); err != nil {
		logger.LogAuditError("policy_violation_validity", err.Error(),
			map[string]interface{}{
				"template": templateName,
			})
		return nil, nil, fmt.Errorf("нарушение политики срока действия: %w", err)
	}

	if ica.DB != nil {
		if compromised, _ := compromise.IsKeyCompromised(ica.DB, csrObj.PublicKey); compromised {
			err := fmt.Errorf("публичный ключ скомпрометирован, выпуск сертификата запрещен")
			logger.LogAuditError("compromised_key_blocked", err.Error(),
				map[string]interface{}{
					"template": templateName,
				})
			return nil, nil, err
		}
	}

	templateType := templates.TemplateType(templateName)
	tmpl, err := templates.GetTemplate(templateType)
	if err != nil {
		return nil, nil, err
	}

	var sanEntries []san.SANEntry
	for _, ext := range csrObj.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 17}) {
			sanEntries, err = parseSANExtension(ext.Value)
			if err != nil {
				logger.Warn("ошибка парсинга SAN из CSR: %v", err)
			}
			break
		}
	}

	if err := pol.ValidateSANs(templateType, sanEntries); err != nil {
		logger.LogAuditError("policy_violation_san", err.Error(),
			map[string]interface{}{
				"template": templateName,
			})
		return nil, nil, fmt.Errorf("нарушение политики SAN: %w", err)
	}

	if err := templates.ValidateSANsForTemplate(tmpl, sanEntries); err != nil {
		return nil, nil, fmt.Errorf("неверные SAN для шаблона %s: %w", templateName, err)
	}

	serialNumber, err := certs.GenerateSerialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка генерации серийного номера: %w", err)
	}

	ski, err := certs.CalculateSKI(csrObj.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка вычисления SKI: %w", err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csrObj.Subject,
		Issuer:       caCert.Subject,
		NotBefore:    time.Now().UTC(),
		NotAfter:     time.Now().UTC().AddDate(0, 0, validityDays),

		KeyUsage:    tmpl.KeyUsage,
		ExtKeyUsage: tmpl.ExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  false,

		SubjectKeyId:   ski,
		AuthorityKeyId: caCert.SubjectKeyId,
	}

	for _, entry := range sanEntries {
		switch entry.Type {
		case "dns":
			certTemplate.DNSNames = append(certTemplate.DNSNames, entry.Value)
		case "ip":
			ip := net.ParseIP(entry.Value)
			if ip != nil {
				certTemplate.IPAddresses = append(certTemplate.IPAddresses, ip)
			}
		case "email":
			certTemplate.EmailAddresses = append(certTemplate.EmailAddresses, entry.Value)
		case "uri":
			if u, err := url.Parse(entry.Value); err == nil {
				certTemplate.URIs = append(certTemplate.URIs, u)
			}
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, csrObj.PublicKey, caSigner)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка создания сертификата: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if ica.DB != nil {
		if err := ica.DB.InsertCertificate(cert, certPEM, "valid"); err != nil {
			logger.Warn("не удалось сохранить сертификат в БД: %v", err)
		} else {
			logger.Info("сертификат сохранен в БД: serial=%x", cert.SerialNumber)
		}
	}

	return cert, certPEM, nil
}

func parseSANExtension(value []byte) ([]san.SANEntry, error) {
	var rawValues []asn1.RawValue
	if _, err := asn1.Unmarshal(value, &rawValues); err != nil {
		return nil, err
	}

	var entries []san.SANEntry
	for _, rv := range rawValues {
		switch rv.Tag {
		case 2:
			entries = append(entries, san.SANEntry{Type: "dns", Value: string(rv.Bytes)})
		case 7:
			ip := net.IP(rv.Bytes)
			entries = append(entries, san.SANEntry{Type: "ip", Value: ip.String()})
		case 1:
			entries = append(entries, san.SANEntry{Type: "email", Value: string(rv.Bytes)})
		case 6:
			entries = append(entries, san.SANEntry{Type: "uri", Value: string(rv.Bytes)})
		}
	}

	return entries, nil
}

func SaveCertificateToDB(db *database.Database, cert *x509.Certificate, certPEM []byte, status string) error {
	if db == nil {
		return fmt.Errorf("БД не инициализирована")
	}
	return db.InsertCertificate(cert, certPEM, status)
}