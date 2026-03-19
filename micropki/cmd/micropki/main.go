package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"MicroPKI/internal/ca"
	"MicroPKI/internal/certs"
	"MicroPKI/internal/chain"
	"MicroPKI/internal/cryptoutil"
	"MicroPKI/internal/csr"
	"MicroPKI/internal/database"
	"MicroPKI/internal/logger"
	"MicroPKI/internal/repository"
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

	dbCmd = &cobra.Command{
		Use:   "db",
		Short: "Управление базой данных сертификатов",
	}

	repoCmd = &cobra.Command{
		Use:   "repo",
		Short: "Управление HTTP репозиторием",
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

	caListCertsCmd = &cobra.Command{
		Use:   "list-certs",
		Short: "Список всех выпущенных сертификатов",
		RunE:  runCAListCerts,
	}

	caShowCertCmd = &cobra.Command{
		Use:   "show-cert [serial]",
		Short: "Показать сертификат по серийному номеру",
		Args:  cobra.ExactArgs(1),
		RunE:  runCAShowCert,
	}

	dbInitCmd = &cobra.Command{
		Use:   "init",
		Short: "Инициализация базы данных сертификатов",
		Long:  "Создает SQLite базу данных и необходимые таблицы для хранения сертификатов",
		RunE:  runDBInit,
	}

	repornServeCmd = &cobra.Command{
		Use:   "serve",
		Short: "Запуск HTTP репозитория сертификатов",
		RunE:  runRepoServe,
	}

	repoStatusCmd = &cobra.Command{
		Use:   "status",
		Short: "Проверка статуса HTTP репозитория",
		RunE:  runRepoStatus,
	}

	subject         string
	keyType         string
	keySize         int
	passphraseFile  string
	outDir          string
	validityDays    int
	logFile         string
	logJSON         string
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

	dbPath          string
	
	statusFilter    string
	format          string
	
	host            string
	port            int
	certDir         string
)

func init() {
	rootCmd.AddCommand(caCmd)
	rootCmd.AddCommand(dbCmd)
	rootCmd.AddCommand(repoCmd)
	
	caCmd.AddCommand(caInitCmd)
	caCmd.AddCommand(caIssueIntermediateCmd)
	caCmd.AddCommand(caIssueCertCmd)
	caCmd.AddCommand(caVerifyCmd)
	caCmd.AddCommand(caListCertsCmd)
	caCmd.AddCommand(caShowCertCmd)
	
	dbCmd.AddCommand(dbInitCmd)
	
	repoCmd.AddCommand(repornServeCmd)
	repoCmd.AddCommand(repoStatusCmd)

	caInitCmd.Flags().StringVar(&subject, "subject", "", "Distinguished Name (e.g., /CN=My Root CA)")
	caInitCmd.Flags().StringVar(&keyType, "key-type", "rsa", "Тип ключа: rsa или ecc")
	caInitCmd.Flags().IntVar(&keySize, "key-size", 4096, "Размер ключа в битах (для RSA: 4096, для ECC: 384)")
	caInitCmd.Flags().StringVar(&passphraseFile, "passphrase-file", "", "Файл с парольной фразой для шифрования ключа")
	caInitCmd.Flags().StringVar(&outDir, "out-dir", "./pki", "Выходная директория")
	caInitCmd.Flags().IntVar(&validityDays, "validity-days", 3650, "Срок действия в днях (по умолчанию 10 лет)")
	caInitCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов (по умолчанию stderr)")
	caInitCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")
	caInitCmd.Flags().BoolVar(&force, "force", false, "Принудительная перезапись существующих файлов")
	caInitCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")

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
	caIssueIntermediateCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")
	caIssueIntermediateCmd.Flags().BoolVar(&force, "force", false, "Принудительная перезапись")
	caIssueIntermediateCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")

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
	caIssueCertCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")
	caIssueCertCmd.Flags().BoolVar(&force, "force", false, "Принудительная перезапись")
	caIssueCertCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")

	caIssueCertCmd.MarkFlagRequired("ca-cert")
	caIssueCertCmd.MarkFlagRequired("ca-key")
	caIssueCertCmd.MarkFlagRequired("ca-pass-file")
	caIssueCertCmd.MarkFlagRequired("template")
	caIssueCertCmd.MarkFlagRequired("subject")

	caVerifyCmd.Flags().StringVar(&rootCert, "root", "", "Путь к корневому сертификату")
	caVerifyCmd.Flags().StringVar(&caCert, "intermediate", "", "Путь к промежуточному сертификату")
	caVerifyCmd.Flags().StringVar(&outDir, "leaf", "", "Путь к конечному сертификату")
	caVerifyCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	caVerifyCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")

	caVerifyCmd.MarkFlagRequired("root")
	caVerifyCmd.MarkFlagRequired("intermediate")
	caVerifyCmd.MarkFlagRequired("leaf")

	dbInitCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")
	dbInitCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	dbInitCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")
	dbInitCmd.Flags().BoolVar(&force, "force", false, "Принудительная перезапись (удалить существующую БД)")

	caListCertsCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")
	caListCertsCmd.Flags().StringVar(&statusFilter, "status", "", "Фильтр по статусу (valid, revoked, expired)")
	caListCertsCmd.Flags().StringVar(&format, "format", "table", "Формат вывода (table, json, csv)")
	caListCertsCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	caListCertsCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")

	caShowCertCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")
	caShowCertCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	caShowCertCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")

	repornServeCmd.Flags().StringVar(&host, "host", "127.0.0.1", "Адрес для привязки сервера")
	repornServeCmd.Flags().IntVar(&port, "port", 8080, "TCP порт")
	repornServeCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")
	repornServeCmd.Flags().StringVar(&certDir, "cert-dir", "./pki/certs", "Директория с PEM сертификатами")
	repornServeCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	repornServeCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")

	repoStatusCmd.Flags().StringVar(&host, "host", "127.0.0.1", "Адрес сервера")
	repoStatusCmd.Flags().IntVar(&port, "port", 8080, "TCP порт")
	repoStatusCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	repoStatusCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")
}

func openDatabase(dbPath string) (*database.Database, error) {
	db, err := database.NewDatabase(dbPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка открытия БД: %w", err)
	}
	
	initialized, err := db.IsInitialized()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("ошибка проверки БД: %w", err)
	}
	
	if !initialized {
		logger.Warn("БД не инициализирована. Запустите 'micropki db init'")
	}
	
	return db, nil
}

func runCAInit(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
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

	var db *database.Database
	if dbPath != "" {
		var err error
		db, err = openDatabase(dbPath)
		if err != nil {
			logger.Warn("не удалось открыть БД: %v", err)
		} else {
			defer db.Close()
			certs.InitSerialGenerator(db)
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
		db,
	)
	if err != nil {
		logger.Error("ошибка создания корневого УЦ: %v", err)
		return fmt.Errorf("ошибка создания корневого УЦ: %w", err)
	}

	if err := rootCA.Initialize(); err != nil {
		logger.Error("ошибка инициализации УЦ: %v", err)
		return fmt.Errorf("ошибка инициализации УЦ: %w", err)
	}

	if logJSON != "" {
		auditData := map[string]interface{}{
			"action":       "root_ca_init",
			"subject":      subject,
			"key_type":     keyType,
			"key_size":     keySize,
			"out_dir":      outDir,
			"validity_days": validityDays,
			"timestamp":    time.Now().UTC().Format(time.RFC3339),
		}
		logger.AuditJSON("root_ca_created", auditData)
	}

	logger.Info("корневой УЦ успешно создан в директории: %s", outDir)
	fmt.Printf("\nКорневой УЦ успешно создан!\n")
	fmt.Printf("   Сертификат: %s\n", filepath.Join(outDir, "certs", "ca.cert.pem"))
	fmt.Printf("   Ключ: %s\n", filepath.Join(outDir, "private", "ca.key.pem"))
	fmt.Printf("   Политика: %s\n", filepath.Join(outDir, "policy.txt"))
	
	return nil
}

func runCAIssueIntermediate(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	logger.Info("начало создания промежуточного УЦ")

	if err := validateIntermediateParams(); err != nil {
		logger.Error("%v", err)
		return err
	}

	var db *database.Database
	if dbPath != "" {
		var err error
		db, err = openDatabase(dbPath)
		if err != nil {
			logger.Warn("не удалось открыть БД: %v", err)
		} else {
			defer db.Close()
			certs.InitSerialGenerator(db)
		}
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

	tempCertPath := filepath.Join(certsDir, ".intermediate.cert.pem.tmp")
	if err := os.WriteFile(tempCertPath, certPEM, 0644); err != nil {
		return fmt.Errorf("ошибка сохранения временного сертификата: %w", err)
	}

	finalCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		os.Remove(tempCertPath)
		return fmt.Errorf("ошибка парсинга созданного сертификата: %w", err)
	}

	if db != nil {
		tx, err := db.BeginTx()
		if err != nil {
			os.Remove(tempCertPath)
			return fmt.Errorf("ошибка начала транзакции БД: %w", err)
		}

		if err := db.InsertCertificateTx(tx, finalCert, certPEM, "valid"); err != nil {
			tx.Rollback()
			os.Remove(tempCertPath)
			logger.Error("ошибка вставки промежуточного сертификата в БД: %v", err)
			return fmt.Errorf("ошибка вставки в БД: %w", err)
		}

		if err := tx.Commit(); err != nil {
			tx.Rollback()
			os.Remove(tempCertPath)
			return fmt.Errorf("ошибка коммита транзакции: %w", err)
		}

		certPath := filepath.Join(certsDir, "intermediate.cert.pem")
		if err := os.Rename(tempCertPath, certPath); err != nil {
			logger.Error("КРИТИЧЕСКАЯ ОШИБКА: сертификат в БД, но файл не сохранен: %v", err)
			if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
				return fmt.Errorf("катастрофическая ошибка: сертификат только в БД")
			}
		}
		logger.Info("промежуточный сертификат сохранен в БД и на диск")
	} else {
		certPath := filepath.Join(certsDir, "intermediate.cert.pem")
		if err := os.Rename(tempCertPath, certPath); err != nil {
			os.Remove(tempCertPath)
			return fmt.Errorf("ошибка сохранения сертификата: %w", err)
		}
		logger.Info("сертификат промежуточного УЦ сохранен: %s", certPath)
	}

	if err := updatePolicyWithIntermediate(outDir, subject, serialNumber, notBefore, notAfter, keyType, keySize, pathlen, rootCertificate.Subject.String()); err != nil {
		logger.Warn("ошибка обновления policy.txt: %v", err)
	}

	if logJSON != "" {
		auditData := map[string]interface{}{
			"action":        "intermediate_ca_issued",
			"subject":       subject,
			"serial_number": fmt.Sprintf("%x", serialNumber),
			"issuer":        rootCertificate.Subject.String(),
			"key_type":      keyType,
			"key_size":      keySize,
			"pathlen":       pathlen,
			"validity_days": validityDays,
			"timestamp":     time.Now().UTC().Format(time.RFC3339),
		}
		logger.AuditJSON("intermediate_ca_created", auditData)
	}

	logger.Info("промежуточный УЦ успешно создан")
	fmt.Printf("\nПромежуточный УЦ успешно создан!\n")
	fmt.Printf("   Сертификат: %s\n", filepath.Join(certsDir, "intermediate.cert.pem"))
	fmt.Printf("   Ключ: %s\n", filepath.Join(privateDir, "intermediate.key.pem"))
	fmt.Printf("   CSR: %s\n", csrPath)
	
	return nil
}

func runCAIssueCert(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	logger.Info("начало выпуска конечного сертификата")

	if err := validateIssueCertParams(); err != nil {
		logger.Error("%v", err)
		return err
	}

	var db *database.Database
	if dbPath != "" {
		var err error
		db, err = openDatabase(dbPath)
		if err != nil {
			logger.Warn("не удалось открыть БД: %v", err)
		} else {
			defer db.Close()
			certs.InitSerialGenerator(db)
		}
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
	var keyPath string

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

		keyPath = filepath.Join(outDir, commonName+".key.pem")
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

	tempCertPath := filepath.Join(outDir, "."+commonName+".cert.pem.tmp")
	if err := os.WriteFile(tempCertPath, certPEM, 0644); err != nil {
		if keyPath != "" {
			os.Remove(keyPath)
		}
		return fmt.Errorf("ошибка сохранения временного сертификата: %w", err)
	}
	logger.Info("временный сертификат сохранен: %s", tempCertPath)

	finalCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		os.Remove(tempCertPath)
		if keyPath != "" {
			os.Remove(keyPath)
		}
		return fmt.Errorf("ошибка парсинга созданного сертификата: %w", err)
	}

	if db != nil {
		tx, err := db.BeginTx()
		if err != nil {
			os.Remove(tempCertPath)
			if keyPath != "" {
				os.Remove(keyPath)
			}
			return fmt.Errorf("ошибка начала транзакции БД: %w", err)
		}
		
		if err := db.InsertCertificateTx(tx, finalCert, certPEM, "valid"); err != nil {
			tx.Rollback()
			os.Remove(tempCertPath)
			if keyPath != "" {
				os.Remove(keyPath)
			}
			logger.Error("ошибка вставки сертификата в БД: %v", err)
			return fmt.Errorf("ошибка сохранения в БД, операция отменена: %w", err)
		}
		
		if err := tx.Commit(); err != nil {
			tx.Rollback()
			os.Remove(tempCertPath)
			if keyPath != "" {
				os.Remove(keyPath)
			}
			return fmt.Errorf("ошибка коммита транзакции: %w", err)
		}
		
		certPath := filepath.Join(outDir, commonName+".cert.pem")
		if err := os.Rename(tempCertPath, certPath); err != nil {
			logger.Error("КРИТИЧЕСКАЯ ОШИБКА: сертификат в БД, но файл не сохранен: %v", err)
			if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
				return fmt.Errorf("катастрофическая ошибка: сертификат только в БД: %w", err)
			}
		}
		
		logger.Info("сертификат сохранен в БД и на диск: %s", certPath)
		
		if logJSON != "" {
			auditData := map[string]interface{}{
				"action":        "certificate_issued",
				"serial_number": fmt.Sprintf("%x", finalCert.SerialNumber),
				"subject":       subject,
				"template":      template,
				"sans":          sanStrings,
				"issuer":        caCertificate.Subject.String(),
				"validity_days": validityDays,
				"timestamp":     time.Now().UTC().Format(time.RFC3339),
			}
			logger.AuditJSON("certificate_issued", auditData)
		}
	} else {
		certPath := filepath.Join(outDir, commonName+".cert.pem")
		if err := os.Rename(tempCertPath, certPath); err != nil {
			os.Remove(tempCertPath)
			if keyPath != "" {
				os.Remove(keyPath)
			}
			return fmt.Errorf("ошибка сохранения сертификата: %w", err)
		}
		logger.Info("сертификат сохранен (без БД): %s", certPath)
	}

	logger.Info("сертификат успешно выпущен: серийный номер %x, шаблон %s, subject %s",
		finalCert.SerialNumber, template, subject)
	logger.Audit(finalCert.SerialNumber.String(), subject, template)

	fmt.Printf("\nСертификат успешно выпущен!\n")
	fmt.Printf("   Сертификат: %s\n", filepath.Join(outDir, commonName+".cert.pem"))
	if csrFile == "" {
		fmt.Printf("   Ключ: %s\n", keyPath)
	}
	fmt.Printf("   Серийный номер: %x\n", finalCert.SerialNumber)
	
	return nil
}

func runCAVerify(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
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

func runDBInit(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	logger.Info("инициализация базы данных: %s", dbPath)

	if _, err := os.Stat(dbPath); err == nil && !force {
		logger.Info("БД уже существует, пробуем применить миграции")
		
		db, err := database.NewDatabase(dbPath)
		if err != nil {
			return fmt.Errorf("ошибка открытия БД: %w", err)
		}
		defer db.Close()
		
		if err := db.ApplyMigrations(); err != nil {
			return fmt.Errorf("ошибка применения миграций: %w", err)
		}
		
		logger.Info("миграции успешно применены к существующей БД")
		fmt.Printf("Миграции успешно применены к БД: %s\n", dbPath)
		return nil
	}

	if force {
		if _, err := os.Stat(dbPath); err == nil {
			if err := os.Remove(dbPath); err != nil {
				return fmt.Errorf("ошибка удаления существующей БД: %w", err)
			}
			logger.Info("существующая БД удалена")
		}
		os.Remove(dbPath + "-journal")
		os.Remove(dbPath + "-wal")
		os.Remove(dbPath + "-shm")
	}

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		logger.Error("ошибка создания БД: %v", err)
		return fmt.Errorf("ошибка создания БД: %w", err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		logger.Error("ошибка инициализации схемы: %v", err)
		return fmt.Errorf("ошибка инициализации схемы: %w", err)
	}

	initialized, err := db.IsInitialized()
	if err != nil {
		return fmt.Errorf("ошибка проверки инициализации: %w", err)
	}
	if !initialized {
		return fmt.Errorf("схема не была создана")
	}

	if logJSON != "" {
		auditData := map[string]interface{}{
			"action":    "db_init",
			"db_path":   dbPath,
			"force":     force,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		logger.AuditJSON("database_initialized", auditData)
	}

	logger.Info("база данных успешно инициализирована: %s", dbPath)
	fmt.Printf("\nБаза данных успешно создана: %s\n", dbPath)
	return nil
}

func runCAListCerts(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	db, err := openDatabase(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	records, err := db.ListCertificates(statusFilter, "", 0)
	if err != nil {
		logger.Error("ошибка получения списка сертификатов: %v", err)
		return fmt.Errorf("ошибка получения списка сертификатов: %w", err)
	}

	switch format {
	case "json":
		printJSON(records)
	case "csv":
		printCSV(records)
	case "table":
		printTable(records)
	default:
		return fmt.Errorf("неподдерживаемый формат: %s", format)
	}

	logger.Info("выведено %d сертификатов", len(records))
	return nil
}

func runCAShowCert(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	serial := args[0]
	logger.Info("поиск сертификата по серийному номеру: %s", serial)

	db, err := openDatabase(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	record, err := db.GetCertificateBySerial(serial)
	if err != nil {
		logger.Error("ошибка получения сертификата: %v", err)
		return fmt.Errorf("ошибка получения сертификата: %w", err)
	}

	if record == nil {
		logger.Info("сертификат с серийным номером %s не найден", serial)
		return fmt.Errorf("сертификат с серийным номером %s не найден", serial)
	}

	fmt.Print(record.CertPEM)
	logger.Info("сертификат выведен: serial=%s", serial)
	return nil
}

func runRepoServe(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	logger.Info("запуск HTTP сервера на %s:%d", host, port)
	logger.Info("БД: %s", dbPath)
	logger.Info("директория с сертификатами: %s", certDir)

	db, err := openDatabase(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	server := repository.NewServer(host, port, db, certDir)
	
	fmt.Printf("HTTP сервер запущен на %s:%d\n", host, port)
	fmt.Printf("  - GET  /certificate/{serial} - получить сертификат по серийному номеру\n")
	fmt.Printf("  - GET  /ca/root               - получить корневой сертификат CA\n")
	fmt.Printf("  - GET  /ca/intermediate        - получить промежуточный сертификат CA\n")
	fmt.Printf("  - GET  /crl                    - получить CRL\n")
	fmt.Printf("  - GET  /health                 - проверка работоспособности\n")
	fmt.Printf("\nДля остановки нажмите Ctrl+C\n")

	if err := server.Start(); err != nil {
		logger.Error("ошибка работы сервера: %v", err)
		return fmt.Errorf("ошибка работы сервера: %w", err)
	}

	return nil
}

func runRepoStatus(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	address := fmt.Sprintf("%s:%d", host, port)
	
	if repository.IsRunning(host, port) {
		fmt.Printf("Сервер запущен на %s\n", address)
		logger.Info("сервер запущен на %s", address)
	} else {
		fmt.Printf("Сервер не запущен на %s\n", address)
		logger.Info("сервер не запущен на %s", address)
	}

	return nil
}

func printJSON(records []*database.CertificateRecord) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(records)
}

func printCSV(records []*database.CertificateRecord) {
	fmt.Println("Serial,Subject,Issuer,NotBefore,NotAfter,Status")
	for _, r := range records {
		fmt.Printf("%s,%s,%s,%s,%s,%s\n",
			r.SerialHex,
			escapeCSV(r.Subject),
			escapeCSV(r.Issuer),
			r.NotBefore.Format("2006-01-02"),
			r.NotAfter.Format("2006-01-02"),
			r.Status,
		)
	}
}

func escapeCSV(s string) string {
	return strings.ReplaceAll(s, ",", ";")
}

func printTable(records []*database.CertificateRecord) {
	if len(records) == 0 {
		fmt.Println("Нет сертификатов")
		return
	}

	fmt.Printf("%-20s %-30s %-30s %-12s %-12s %-10s\n",
		"SERIAL", "SUBJECT", "ISSUER", "NOT BEFORE", "NOT AFTER", "STATUS")
	fmt.Println(strings.Repeat("-", 120))

	for _, r := range records {
		subject := r.Subject
		if len(subject) > 30 {
			subject = subject[:27] + "..."
		}
		issuer := r.Issuer
		if len(issuer) > 30 {
			issuer = issuer[:27] + "..."
		}

		fmt.Printf("%-20s %-30s %-30s %-12s %-12s %-10s\n",
			truncate(r.SerialHex, 20),
			truncate(subject, 30),
			truncate(issuer, 30),
			r.NotBefore.Format("2006-01-02"),
			r.NotAfter.Format("2006-01-02"),
			r.Status,
		)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
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