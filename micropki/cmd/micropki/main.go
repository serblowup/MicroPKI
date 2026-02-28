package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"MicroPKI/internal/ca"
	"MicroPKI/internal/certs"
	"MicroPKI/internal/chain"
	"MicroPKI/internal/cryptoutil"
	"MicroPKI/internal/csr"
	"MicroPKI/internal/logger"
	"MicroPKI/internal/san"
	"MicroPKI/internal/templates"
)

var (
	rootCmd = &cobra.Command{
		Use:   "micropki",
		Short: "MicroPKI - минимальная реализация PKI",
		Long:  "MicroPKI - это образовательный проект по созданию инфраструктуры открытых ключей.",
	}

	caCmd = &cobra.Command{
		Use:   "ca",
		Short: "Управление удостоверяющими центрами",
	}

	caInitCmd = &cobra.Command{
		Use:   "init",
		Short: "Инициализация корневого УЦ",
		RunE:  runCAInit,
	}

	caIssueIntermediateCmd = &cobra.Command{
		Use:   "issue-intermediate",
		Short: "Создание промежуточного УЦ, подписанного корневым УЦ",
		RunE:  runCAIssueIntermediate,
	}

	caIssueCertCmd = &cobra.Command{
		Use:   "issue-cert",
		Short: "Выпуск конечного сертификата от промежуточного УЦ",
		RunE:  runCAIssueCert,
	}

	caVerifyCmd = &cobra.Command{
		Use:   "verify",
		Short: "Проверка цепочки сертификатов",
		RunE:  runCAVerify,
	}

	subject         string
	keyType         string
	keySize         int
	passphraseFile  string
	outDir          string
	validityDays    int
	logFile         string
	force           bool

	rootCert        string
	rootKey         string
	rootPassFile    string
	pathlen         int

	caCert          string
	caKey           string
	caPassFile      string
	template        string
	sanStrings      []string
	csrFile         string
)

func init() {
	rootCmd.AddCommand(caCmd)
	caCmd.AddCommand(caInitCmd)
	caCmd.AddCommand(caIssueIntermediateCmd)
	caCmd.AddCommand(caIssueCertCmd)
	caCmd.AddCommand(caVerifyCmd)

	caInitCmd.Flags().StringVar(&subject, "subject", "", "Distinguished Name (e.g., /CN=My Root CA)")
	caInitCmd.Flags().StringVar(&keyType, "key-type", "rsa", "Тип ключа: rsa или ecc")
	caInitCmd.Flags().IntVar(&keySize, "key-size", 4096, "Размер ключа в битах (для RSA: 4096, для ECC: 384)")
	caInitCmd.Flags().StringVar(&passphraseFile, "passphrase-file", "", "Файл с парольной фразой для шифрования ключа")
	caInitCmd.Flags().StringVar(&outDir, "out-dir", "./pki", "Выходная директория")
	caInitCmd.Flags().IntVar(&validityDays, "validity-days", 3650, "Срок действия в днях (по умолчанию 10 лет)")
	caInitCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов (по умолчанию stderr)")
	caInitCmd.Flags().BoolVar(&force, "force", false, "Принудительная перезапись существующих файлов")

	caInitCmd.MarkFlagRequired("subject")
	caInitCmd.MarkFlagRequired("passphrase-file")

	caIssueIntermediateCmd.Flags().StringVar(&rootCert, "root-cert", "", "Путь к сертификату корневого УЦ (PEM)")
	caIssueIntermediateCmd.Flags().StringVar(&rootKey, "root-key", "", "Путь к зашифрованному ключу корневого УЦ (PEM)")
	caIssueIntermediateCmd.Flags().StringVar(&rootPassFile, "root-pass-file", "", "Файл с парольной фразой для ключа корневого УЦ")
	caIssueIntermediateCmd.Flags().StringVar(&subject, "subject", "", "Отличительное имя для промежуточного УЦ")
	caIssueIntermediateCmd.Flags().StringVar(&keyType, "key-type", "rsa", "Тип ключа: rsa или ecc")
	caIssueIntermediateCmd.Flags().IntVar(&keySize, "key-size", 4096, "Размер ключа в битах")
	caIssueIntermediateCmd.Flags().StringVar(&passphraseFile, "passphrase-file", "", "Парольная фраза для ключа промежуточного УЦ")
	caIssueIntermediateCmd.Flags().StringVar(&outDir, "out-dir", "./pki", "Выходная директория")
	caIssueIntermediateCmd.Flags().IntVar(&validityDays, "validity-days", 1825, "Срок действия в днях (по умолчанию 5 лет)")
	caIssueIntermediateCmd.Flags().IntVar(&pathlen, "pathlen", 0, "Ограничение длины пути")
	caIssueIntermediateCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	caIssueIntermediateCmd.Flags().BoolVar(&force, "force", false, "Принудительная перезапись")

	caIssueIntermediateCmd.MarkFlagRequired("root-cert")
	caIssueIntermediateCmd.MarkFlagRequired("root-key")
	caIssueIntermediateCmd.MarkFlagRequired("root-pass-file")
	caIssueIntermediateCmd.MarkFlagRequired("subject")
	caIssueIntermediateCmd.MarkFlagRequired("passphrase-file")

	caIssueCertCmd.Flags().StringVar(&caCert, "ca-cert", "", "Сертификат промежуточного УЦ (PEM)")
	caIssueCertCmd.Flags().StringVar(&caKey, "ca-key", "", "Зашифрованный ключ промежуточного УЦ (PEM)")
	caIssueCertCmd.Flags().StringVar(&caPassFile, "ca-pass-file", "", "Парольная фраза для ключа промежуточного УЦ")
	caIssueCertCmd.Flags().StringVar(&template, "template", "", "Шаблон сертификата: server, client, code_signing")
	caIssueCertCmd.Flags().StringVar(&subject, "subject", "", "Отличительное имя для сертификата")
	caIssueCertCmd.Flags().StringSliceVar(&sanStrings, "san", []string{}, "Альтернативные имена субъекта (например, dns:example.com)")
	caIssueCertCmd.Flags().StringVar(&outDir, "out-dir", "./pki/certs", "Выходная директория")
	caIssueCertCmd.Flags().IntVar(&validityDays, "validity-days", 365, "Срок действия в днях")
	caIssueCertCmd.Flags().StringVar(&csrFile, "csr", "", "Подписать внешний CSR (опционально)")
	caIssueCertCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	caIssueCertCmd.Flags().BoolVar(&force, "force", false, "Принудительная перезапись")

	caIssueCertCmd.MarkFlagRequired("ca-cert")
	caIssueCertCmd.MarkFlagRequired("ca-key")
	caIssueCertCmd.MarkFlagRequired("ca-pass-file")
	caIssueCertCmd.MarkFlagRequired("template")
	caIssueCertCmd.MarkFlagRequired("subject")

	caVerifyCmd.Flags().StringVar(&rootCert, "root", "", "Путь к корневому сертификату")
	caVerifyCmd.Flags().StringVar(&caCert, "intermediate", "", "Путь к промежуточному сертификату")
	caVerifyCmd.Flags().StringVar(&outDir, "leaf", "", "Путь к конечному сертификату")

	caVerifyCmd.MarkFlagRequired("root")
	caVerifyCmd.MarkFlagRequired("intermediate")
	caVerifyCmd.MarkFlagRequired("leaf")
}

func runCAInit(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	if err := validateCAInitParams(); err != nil {
		logger.Error("%v", err)
		return err
	}

	if !force {
		if err := checkExistingFiles(); err != nil {
			logger.Error("%v", err)
			return err
		}
	}

	rootCA, err := ca.NewRootCA(
		subject,
		keyType,
		keySize,
		passphraseFile,
		outDir,
		validityDays,
		force,
	)
	if err != nil {
		logger.Error("ошибка создания корневого УЦ: %v", err)
		return fmt.Errorf("ошибка создания корневого УЦ: %w", err)
	}

	if err := rootCA.Initialize(); err != nil {
		logger.Error("ошибка инициализации УЦ: %v", err)
		return fmt.Errorf("ошибка инициализации УЦ: %w", err)
	}

	logger.Info("корневой УЦ успешно создан в директории: %s", outDir)
	fmt.Printf("\nКорневой УЦ успешно создан!\n")
	fmt.Printf("   Сертификат: %s\n", filepath.Join(outDir, "certs", "ca.cert.pem"))
	fmt.Printf("   Ключ: %s\n", filepath.Join(outDir, "private", "ca.key.pem"))
	fmt.Printf("   Политика: %s\n", filepath.Join(outDir, "policy.txt"))
	
	return nil
}

func runCAIssueIntermediate(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	logger.Info("начало создания промежуточного УЦ")

	if err := validateIntermediateParams(); err != nil {
		logger.Error("%v", err)
		return err
	}

	rootPass, err := os.ReadFile(rootPassFile)
	if err != nil {
		return fmt.Errorf("ошибка чтения файла с паролем корневого УЦ: %w", err)
	}
	defer func() {
		for i := range rootPass {
			rootPass[i] = 0
		}
	}()
	if len(rootPass) > 0 && rootPass[len(rootPass)-1] == '\n' {
		rootPass = rootPass[:len(rootPass)-1]
	}

	rootCertPEM, err := os.ReadFile(rootCert)
	if err != nil {
		return fmt.Errorf("ошибка чтения сертификата корневого УЦ: %w", err)
	}

	rootKeyPEM, err := os.ReadFile(rootKey)
	if err != nil {
		return fmt.Errorf("ошибка чтения ключа корневого УЦ: %w", err)
	}

	rootPrivateKey, err := cryptoutil.LoadEncryptedPrivateKeyFromPEM(rootKeyPEM, rootPass)
	if err != nil {
		return fmt.Errorf("ошибка загрузки ключа корневого УЦ: %w", err)
	}

	rootSigner, ok := rootPrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("ключ корневого УЦ не поддерживает подписание")
	}

	block, _ := pem.Decode(rootCertPEM)
	if block == nil {
		return fmt.Errorf("не удалось декодировать сертификат корневого УЦ")
	}
	rootCertificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("ошибка парсинга сертификата корневого УЦ: %w", err)
	}

	intermediatePass, err := os.ReadFile(passphraseFile)
	if err != nil {
		return fmt.Errorf("ошибка чтения файла с паролем промежуточного УЦ: %w", err)
	}
	defer func() {
		for i := range intermediatePass {
			intermediatePass[i] = 0
		}
	}()
	if len(intermediatePass) > 0 && intermediatePass[len(intermediatePass)-1] == '\n' {
		intermediatePass = intermediatePass[:len(intermediatePass)-1]
	}

	privateDir := filepath.Join(outDir, "private")
	if err := os.MkdirAll(privateDir, 0700); err != nil {
		return fmt.Errorf("ошибка создания директории private: %w", err)
	}

	certsDir := filepath.Join(outDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return fmt.Errorf("ошибка создания директории certs: %w", err)
	}

	csrDir := filepath.Join(outDir, "csrs")
	if err := os.MkdirAll(csrDir, 0755); err != nil {
		return fmt.Errorf("ошибка создания директории csrs: %w", err)
	}

	var intermediatePrivateKey crypto.PrivateKey
	var pubKey crypto.PublicKey

	logger.Info("генерация ключей промежуточного УЦ")

	switch keyType {
	case "rsa":
		if keySize != 4096 {
			return fmt.Errorf("для RSA размер ключа должен быть 4096 бит")
		}
		key, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return fmt.Errorf("ошибка генерации RSA ключа: %w", err)
		}
		intermediatePrivateKey = key
		pubKey = &key.PublicKey
		if err := cryptoutil.SaveEncryptedRSAPEM(filepath.Join(privateDir, "intermediate.key.pem"), key, intermediatePass); err != nil {
			return fmt.Errorf("ошибка сохранения ключа: %w", err)
		}
	case "ecc":
		if keySize != 384 {
			return fmt.Errorf("для ECC размер ключа должен быть 384 бита")
		}
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return fmt.Errorf("ошибка генерации ECC ключа: %w", err)
		}
		intermediatePrivateKey = key
		pubKey = &key.PublicKey
		if err := cryptoutil.SaveEncryptedECCPEM(filepath.Join(privateDir, "intermediate.key.pem"), key, intermediatePass); err != nil {
			return fmt.Errorf("ошибка сохранения ключа: %w", err)
		}
	default:
		return fmt.Errorf("неподдерживаемый тип ключа: %s", keyType)
	}

	logger.Info("генерация CSR для промежуточного УЦ")
	csrPEM, err := csr.GenerateIntermediateCSR(subject, pubKey, intermediatePrivateKey.(crypto.Signer), pathlen)
	if err != nil {
		return fmt.Errorf("ошибка генерации CSR: %w", err)
	}

	csrPath := filepath.Join(csrDir, "intermediate.csr.pem")
	if err := csr.SaveCSR(csrPath, csrPEM); err != nil {
		return fmt.Errorf("ошибка сохранения CSR: %w", err)
	}
	logger.Info("CSR сохранен: %s", csrPath)

	csrObj, err := csr.ParseCSR(csrPEM)
	if err != nil {
		return fmt.Errorf("ошибка парсинга CSR: %w", err)
	}

	logger.Info("подписание CSR корневым УЦ")
	serialNumber, err := certs.GenerateSerialNumber()
	if err != nil {
		return fmt.Errorf("ошибка генерации серийного номера: %w", err)
	}

	ski, err := certs.CalculateSKI(pubKey)
	if err != nil {
		return fmt.Errorf("ошибка вычисления SKI: %w", err)
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(0, 0, validityDays)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csrObj.Subject,
		Issuer:       rootCertificate.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            pathlen,
		MaxPathLenZero:        pathlen == 0,

		SubjectKeyId:   ski,
		AuthorityKeyId: rootCertificate.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCertificate, pubKey, rootSigner)
	if err != nil {
		return fmt.Errorf("ошибка создания сертификата: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	certPath := filepath.Join(certsDir, "intermediate.cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("ошибка сохранения сертификата: %w", err)
	}
	logger.Info("сертификат промежуточного УЦ сохранен: %s", certPath)

	if err := updatePolicyWithIntermediate(outDir, subject, serialNumber, notBefore, notAfter, keyType, keySize, pathlen, rootCertificate.Subject.String()); err != nil {
		logger.Warn("ошибка обновления policy.txt: %v", err)
	}

	logger.Info("промежуточный УЦ успешно создан")
	fmt.Printf("\nПромежуточный УЦ успешно создан!\n")
	fmt.Printf("   Сертификат: %s\n", certPath)
	fmt.Printf("   Ключ: %s\n", filepath.Join(privateDir, "intermediate.key.pem"))
	fmt.Printf("   CSR: %s\n", csrPath)
	
	return nil
}

func runCAIssueCert(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	logger.Info("начало выпуска конечного сертификата")

	if err := validateIssueCertParams(); err != nil {
		logger.Error("%v", err)
		return err
	}

	templateType := templates.TemplateType(template)
	tmpl, err := templates.GetTemplate(templateType)
	if err != nil {
		return err
	}

	sanEntries, err := san.ParseSANs(sanStrings)
	if err != nil {
		return fmt.Errorf("ошибка парсинга SAN: %w", err)
	}

	if err := san.ValidateSANs(sanEntries); err != nil {
		return fmt.Errorf("ошибка валидации SAN: %w", err)
	}

	if err := templates.ValidateSANsForTemplate(tmpl, sanEntries); err != nil {
		return fmt.Errorf("ошибка валидации SAN для шаблона: %w", err)
	}

	caPass, err := os.ReadFile(caPassFile)
	if err != nil {
		return fmt.Errorf("ошибка чтения файла с паролем УЦ: %w", err)
	}
	defer func() {
		for i := range caPass {
			caPass[i] = 0
		}
	}()
	if len(caPass) > 0 && caPass[len(caPass)-1] == '\n' {
		caPass = caPass[:len(caPass)-1]
	}

	caCertPEM, err := os.ReadFile(caCert)
	if err != nil {
		return fmt.Errorf("ошибка чтения сертификата УЦ: %w", err)
	}

	caKeyPEM, err := os.ReadFile(caKey)
	if err != nil {
		return fmt.Errorf("ошибка чтения ключа УЦ: %w", err)
	}

	caPrivateKey, err := cryptoutil.LoadEncryptedPrivateKeyFromPEM(caKeyPEM, caPass)
	if err != nil {
		return fmt.Errorf("ошибка загрузки ключа УЦ: %w", err)
	}

	caSigner, ok := caPrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("ключ УЦ не поддерживает подписание")
	}

	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return fmt.Errorf("не удалось декодировать сертификат УЦ")
	}
	caCertificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("ошибка парсинга сертификата УЦ: %w", err)
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("ошибка создания выходной директории: %w", err)
	}

	var pubKey crypto.PublicKey
	var commonName string

	if csrFile != "" {
		logger.Info("подписание внешнего CSR: %s", csrFile)
		csrPEM, err := os.ReadFile(csrFile)
		if err != nil {
			return fmt.Errorf("ошибка чтения CSR: %w", err)
		}
		csrObj, err := csr.ParseCSR(csrPEM)
		if err != nil {
			return fmt.Errorf("ошибка парсинга CSR: %w", err)
		}
		pubKey = csrObj.PublicKey
		commonName = csrObj.Subject.CommonName
		if commonName == "" {
			commonName = "cert"
		}
	} else {
		logger.Info("генерация новой пары ключей")
		name, err := certs.ParseDN(subject)
		if err != nil {
			return fmt.Errorf("ошибка парсинга subject: %w", err)
		}
		commonName = name.CommonName
		if commonName == "" {
			commonName = "cert"
		}

		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("ошибка генерации ключа: %w", err)
		}
		pubKey = &key.PublicKey

		keyPath := filepath.Join(outDir, commonName+".key.pem")
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			return fmt.Errorf("ошибка сохранения ключа: %w", err)
		}
		logger.Info("ключ сохранен: %s", keyPath)
		logger.Warn("внимание: закрытый ключ хранится незашифрованным")
		fmt.Printf("ВНИМАНИЕ: Закрытый ключ сохранен незашифрованным: %s\n", keyPath)
	}

	certTemplate, err := templates.BuildCertificateTemplate(
		templateType,
		subject,
		pubKey,
		sanEntries,
		validityDays,
		false,
		0,
	)
	if err != nil {
		return fmt.Errorf("ошибка создания шаблона сертификата: %w", err)
	}

	certTemplate.Issuer = caCertificate.Subject
	certTemplate.AuthorityKeyId = caCertificate.SubjectKeyId

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCertificate, pubKey, caSigner)
	if err != nil {
		return fmt.Errorf("ошибка создания сертификата: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	certPath := filepath.Join(outDir, commonName+".cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("ошибка сохранения сертификата: %w", err)
	}
	logger.Info("сертификат сохранен: %s", certPath)

	finalCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("ошибка парсинга созданного сертификата: %w", err)
	}

	logger.Info("сертификат успешно выпущен: серийный номер %x, шаблон %s, subject %s",
		finalCert.SerialNumber, template, subject)
	logger.Audit(finalCert.SerialNumber.String(), subject, template)

	fmt.Printf("\nСертификат успешно выпущен!\n")
	fmt.Printf("   Сертификат: %s\n", certPath)
	if csrFile == "" {
		fmt.Printf("   Ключ: %s\n", filepath.Join(outDir, commonName+".key.pem"))
	}
	
	return nil
}

func runCAVerify(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	logger.Info("проверка цепочки сертификатов")

	if err := chain.VerifyChain(outDir, caCert, rootCert); err != nil {
		logger.Error("ошибка проверки цепочки: %v", err)
		return fmt.Errorf("ошибка проверки цепочки: %w", err)
	}

	logger.Info("цепочка сертификатов успешно проверена")
	fmt.Println("Цепочка сертификатов действительна")

	if err := chain.VerifyWithOpenSSLCompatibility(outDir, caCert, rootCert); err != nil {
		logger.Warn("проверка совместимости с OpenSSL: %v", err)
		fmt.Printf("Предупреждение: %v\n", err)
	} else {
		logger.Info("проверка совместимости с OpenSSL пройдена")
	}

	return nil
}

func validateCAInitParams() error {
	if subject == "" {
		return fmt.Errorf("subject не может быть пустым")
	}
	if keyType != "rsa" && keyType != "ecc" {
		return fmt.Errorf("key-type должен быть 'rsa' или 'ecc', получено: %s", keyType)
	}
	if keyType == "rsa" && keySize != 4096 {
		return fmt.Errorf("для RSA размер ключа должен быть 4096 бит, получено: %d", keySize)
	}
	if keyType == "ecc" && keySize != 384 {
		return fmt.Errorf("для ECC размер ключа должен быть 384 бита, получено: %d", keySize)
	}
	if _, err := os.Stat(passphraseFile); os.IsNotExist(err) {
		return fmt.Errorf("файл с парольной фразой не существует: %s", passphraseFile)
	}
	if validityDays <= 0 {
		return fmt.Errorf("validity-days должен быть положительным числом, получено: %d", validityDays)
	}
	if validityDays > 36500 {
		return fmt.Errorf("validity-days не может превышать 36500 дней")
	}
	return nil
}

func validateIntermediateParams() error {
	if _, err := os.Stat(rootCert); err != nil {
		return fmt.Errorf("файл корневого сертификата не существует: %s", rootCert)
	}
	if _, err := os.Stat(rootKey); err != nil {
		return fmt.Errorf("файл корневого ключа не существует: %s", rootKey)
	}
	if _, err := os.Stat(rootPassFile); err != nil {
		return fmt.Errorf("файл с паролем корневого УЦ не существует: %s", rootPassFile)
	}
	if subject == "" {
		return fmt.Errorf("subject не может быть пустым")
	}
	if keyType != "rsa" && keyType != "ecc" {
		return fmt.Errorf("key-type должен быть 'rsa' или 'ecc'")
	}
	if keyType == "rsa" && keySize != 4096 {
		return fmt.Errorf("для RSA размер ключа должен быть 4096 бит")
	}
	if keyType == "ecc" && keySize != 384 {
		return fmt.Errorf("для ECC размер ключа должен быть 384 бита")
	}
	if _, err := os.Stat(passphraseFile); err != nil {
		return fmt.Errorf("файл с паролем промежуточного УЦ не существует: %s", passphraseFile)
	}
	if validityDays <= 0 {
		return fmt.Errorf("validity-days должен быть положительным")
	}
	if pathlen < 0 {
		return fmt.Errorf("pathlen не может быть отрицательным")
	}
	return nil
}

func validateIssueCertParams() error {
	if _, err := os.Stat(caCert); err != nil {
		return fmt.Errorf("файл сертификата УЦ не существует: %s", caCert)
	}
	if _, err := os.Stat(caKey); err != nil {
		return fmt.Errorf("файл ключа УЦ не существует: %s", caKey)
	}
	if _, err := os.Stat(caPassFile); err != nil {
		return fmt.Errorf("файл с паролем УЦ не существует: %s", caPassFile)
	}
	if template != "server" && template != "client" && template != "code_signing" {
		return fmt.Errorf("template должен быть server, client или code_signing")
	}
	if subject == "" {
		return fmt.Errorf("subject не может быть пустым")
	}
	if validityDays <= 0 {
		return fmt.Errorf("validity-days должен быть положительным")
	}
	if csrFile != "" {
		if _, err := os.Stat(csrFile); err != nil {
			return fmt.Errorf("файл CSR не существует: %s", csrFile)
		}
	}
	return nil
}

func checkExistingFiles() error {
	keyPath := filepath.Join(outDir, "private", "ca.key.pem")
	certPath := filepath.Join(outDir, "certs", "ca.cert.pem")
	policyPath := filepath.Join(outDir, "policy.txt")

	existing := []string{}
	if _, err := os.Stat(keyPath); err == nil {
		existing = append(existing, keyPath)
	}
	if _, err := os.Stat(certPath); err == nil {
		existing = append(existing, certPath)
	}
	if _, err := os.Stat(policyPath); err == nil {
		existing = append(existing, policyPath)
	}

	if len(existing) > 0 {
		fmt.Println("Следующие файлы уже существуют:")
		for _, f := range existing {
			fmt.Printf("  %s\n", f)
		}
		return fmt.Errorf("используйте --force для принудительной перезаписи")
	}
	return nil
}

func updatePolicyWithIntermediate(outDir, subject string, serialNumber *big.Int, notBefore, notAfter time.Time, keyType string, keySize, pathlen int, issuer string) error {
	policyPath := filepath.Join(outDir, "policy.txt")

	f, err := os.OpenFile(policyPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	section := fmt.Sprintf("\n[INTERMEDIATE CA INFORMATION]\nSubject: %s\nSerial Number: %x\nValidity Period:\n  Not Before: %s\n  Not After:  %s\nKey Algorithm: %s-%d\nPath Length Constraint: %d\nIssuer: %s\n",
		subject, serialNumber, notBefore.Format(time.RFC3339), notAfter.Format(time.RFC3339), keyType, keySize, pathlen, issuer)

	if _, err := f.WriteString(section); err != nil {
		return err
	}

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}