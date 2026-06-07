package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"MicroPKI/internal/audit"
	"MicroPKI/internal/ca"
	"MicroPKI/internal/certs"
	"MicroPKI/internal/chain"
	"MicroPKI/internal/client"
	"MicroPKI/internal/compromise"
	"MicroPKI/internal/crl"
	"MicroPKI/internal/cryptoutil"
	"MicroPKI/internal/csr"
	"MicroPKI/internal/database"
	"MicroPKI/internal/logger"
	"MicroPKI/internal/ocsp"
	"MicroPKI/internal/policy"
	"MicroPKI/internal/repository"
	"MicroPKI/internal/revocation"
	"MicroPKI/internal/san"
	"MicroPKI/internal/templates"
	"MicroPKI/internal/transparency"
	"MicroPKI/internal/validation"
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

	auditCmd = &cobra.Command{
		Use:   "audit",
		Short: "Управление аудит-логами",
		Long:  "Запрос, проверка целостности и анализ аудит-логов",
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

	caRevokeCmd = &cobra.Command{
		Use:   "revoke [serial]",
		Short: "Отзыв сертификата",
		Args:  cobra.ExactArgs(1),
		RunE:  runCARevoke,
	}

	caGenCRLCmd = &cobra.Command{
		Use:   "gen-crl",
		Short: "Генерация списка отозванных сертификатов (CRL)",
		RunE:  runCAGenCRL,
	}

	caCheckRevokedCmd = &cobra.Command{
		Use:   "check-revoked [serial]",
		Short: "Проверка статуса отзыва сертификата",
		Args:  cobra.ExactArgs(1),
		RunE:  runCACheckRevoked,
	}

	caCompromiseCmd = &cobra.Command{
		Use:   "compromise",
		Short: "Симуляция компрометации приватного ключа",
		Long: `Симулирует компрометацию приватного ключа сертификата.
Отзывает сертификат с причиной keyCompromise и добавляет 
публичный ключ в таблицу скомпрометированных ключей.`,
		RunE: runCACompromise,
	}

	caIssueOCSPCertCmd = &cobra.Command{
		Use:   "issue-ocsp-cert",
		Short: "Выпуск сертификата OCSP-ответчика",
		RunE:  runCAIssueOCSPCert,
	}

	dbInitCmd = &cobra.Command{
		Use:   "init",
		Short: "Инициализация базы данных сертификатов",
		Long:  "Создает SQLite базу данных и необходимые таблицы для хранения сертификатов",
		RunE:  runDBInit,
	}

	repoServeCmd = &cobra.Command{
		Use:   "serve",
		Short: "Запуск HTTP репозитория сертификатов",
		RunE:  runRepoServe,
	}

	repoStatusCmd = &cobra.Command{
		Use:   "status",
		Short: "Проверка статуса HTTP репозитория",
		RunE:  runRepoStatus,
	}

	auditQueryCmd = &cobra.Command{
		Use:   "query",
		Short: "Запрос и фильтрация записей аудит-лога",
		Long: `Поиск и отображение записей аудит-лога с фильтрацией.
Поддерживает фильтры по времени, уровню, операции и серийному номеру.`,
		RunE: runAuditQuery,
	}

	auditVerifyCmd = &cobra.Command{
		Use:   "verify",
		Short: "Проверка целостности аудит-лога",
		Long: `Выполняет полную проверку целостности аудит-лога,
перестраивая и проверяя хеш-цепочку. Обнаруживает подделку,
удаление и изменение записей.`,
		RunE: runAuditVerify,
	}

	auditCtVerifyCmd = &cobra.Command{
		Use:   "ct-verify",
		Short: "Проверка наличия сертификата в CT логе",
		Long:  "Проверяет, присутствует ли сертификат в логе Certificate Transparency.",
		RunE:  runAuditCtVerify,
	}

	auditDetectAnomaliesCmd = &cobra.Command{
		Use:   "detect-anomalies",
		Short: "Обнаружение аномалий в аудит-логе",
		Long: `Выполняет эвристический анализ аудит-лога для обнаружения аномалий:
всплески частоты событий, высокая частота отзывов, компрометации ключей.`,
		RunE: runAuditDetectAnomalies,
	}

	ocspCmd = &cobra.Command{
		Use:   "ocsp",
		Short: "Управление OCSP-ответчиком",
	}

	ocspServeCmd = &cobra.Command{
		Use:   "serve",
		Short: "Запуск OCSP-ответчика",
		RunE:  runOCSPServe,
	}

	clientCmd = &cobra.Command{
		Use:   "client",
		Short: "Клиентские операции PKI",
		Long:  "Генерация CSR, запрос сертификатов, валидация и проверка статуса",
	}

	clientGenCSRCmd = &cobra.Command{
		Use:   "gen-csr",
		Short: "Генерация приватного ключа и CSR",
		RunE:  runClientGenCSR,
	}

	clientRequestCertCmd = &cobra.Command{
		Use:   "request-cert",
		Short: "Запрос сертификата у CA",
		RunE:  runClientRequestCert,
	}

	clientValidateCmd = &cobra.Command{
		Use:   "validate",
		Short: "Валидация цепочки сертификатов",
		RunE:  runClientValidate,
	}

	clientCheckStatusCmd = &cobra.Command{
		Use:   "check-status",
		Short: "Проверка статуса отзыва сертификата",
		RunE:  runClientCheckStatus,
	}

	configFile    string
	subject        string
	keyType        string
	keySize        int
	passphraseFile string
	outDir         string
	validityDays   int
	logFile        string
	logJSON        string
	force          bool
	dbPath         string

	rootCert     string
	rootKey      string
	rootPassFile string
	pathlen      int

	caCert     string
	caKey      string
	caPassFile string
	template   string
	sanStrings []string
	csrFile    string

	statusFilter string
	format       string

	host       string
	port       int
	certDir    string
	rateLimit  float64
	rateBurst  int

	reason string
	crlPath string

	nextUpdateDays int
	caName         string
	outCRLFile     string

	compromiseCert   string
	compromiseReason string

	auditFrom        string
	auditTo          string
	auditLevel       string
	auditOperation   string
	auditSerial      string
	auditFormat      string
	auditVerifyFlag  bool
	auditLogFile     string
	auditChainFile   string
	auditThreshold   int

	ctSerial      string
	ctFingerprint string
	ctLogFile     string

	ocspSubject      string
	ocspKeyType      string
	ocspKeySize      int
	ocspPassFile     string
	ocspOutDir       string
	ocspValidityDays int
	ocspSANS         []string

	ocspHost          string
	ocspPort          int
	ocspResponderCert string
	ocspResponderKey  string
	ocspCACert        string
	ocspCacheTTL      int
	ocspRateLimit     float64
	ocspRateBurst     int

	csrSubject string
	csrKeyType string
	csrKeySize int
	csrSANs    []string
	csrOutKey  string
	csrOutCSR  string

	reqCSRPath  string
	reqTemplate string
	reqCAURL    string
	reqOutCert  string
	reqAPIKey   string

	valCert      string
	valUntrusted []string
	valTrusted   string
	valCRL       string
	valOCSP      bool
	valMode      string
	valTime      string

	chkCert    string
	chkCACert  string
	chkCRL     string
	chkOCSPURL string
)

// loadedPolicy хранит загруженную из конфига политику
var loadedPolicy *policy.PolicyEngine

// getPolicy возвращает активную политику (из конфига или по умолчанию)
func getPolicy() *policy.PolicyEngine {
	if loadedPolicy != nil {
		return loadedPolicy
	}
	return policy.DefaultPolicy()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "Путь к конфигурационному файлу (YAML/JSON)")

	rootCmd.AddCommand(caCmd)
	rootCmd.AddCommand(dbCmd)
	rootCmd.AddCommand(repoCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(ocspCmd)
	rootCmd.AddCommand(clientCmd)

	caCmd.AddCommand(caInitCmd)
	caCmd.AddCommand(caIssueIntermediateCmd)
	caCmd.AddCommand(caIssueCertCmd)
	caCmd.AddCommand(caIssueOCSPCertCmd)
	caCmd.AddCommand(caVerifyCmd)
	caCmd.AddCommand(caListCertsCmd)
	caCmd.AddCommand(caShowCertCmd)
	caCmd.AddCommand(caRevokeCmd)
	caCmd.AddCommand(caGenCRLCmd)
	caCmd.AddCommand(caCheckRevokedCmd)
	caCmd.AddCommand(caCompromiseCmd)

	dbCmd.AddCommand(dbInitCmd)

	repoCmd.AddCommand(repoServeCmd)
	repoCmd.AddCommand(repoStatusCmd)

	auditCmd.AddCommand(auditQueryCmd)
	auditCmd.AddCommand(auditVerifyCmd)
	auditCmd.AddCommand(auditCtVerifyCmd)
	auditCmd.AddCommand(auditDetectAnomaliesCmd)

	ocspCmd.AddCommand(ocspServeCmd)

	clientCmd.AddCommand(clientGenCSRCmd)
	clientCmd.AddCommand(clientRequestCertCmd)
	clientCmd.AddCommand(clientValidateCmd)
	clientCmd.AddCommand(clientCheckStatusCmd)

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

	caIssueOCSPCertCmd.Flags().StringVar(&caCert, "ca-cert", "", "Сертификат CA для подписи (обязательно)")
	caIssueOCSPCertCmd.Flags().StringVar(&caKey, "ca-key", "", "Ключ CA (обязательно)")
	caIssueOCSPCertCmd.Flags().StringVar(&caPassFile, "ca-pass-file", "", "Файл с паролем CA ключа (обязательно)")
	caIssueOCSPCertCmd.Flags().StringVar(&subject, "subject", "", "Subject для OCSP-сертификата (обязательно)")
	caIssueOCSPCertCmd.Flags().StringVar(&keyType, "key-type", "rsa", "Тип ключа: rsa или ecc")
	caIssueOCSPCertCmd.Flags().IntVar(&keySize, "key-size", 2048, "Размер ключа (RSA: 2048+, ECC: 256+)")
	caIssueOCSPCertCmd.Flags().StringSliceVar(&sanStrings, "san", []string{}, "SAN (DNS имена)")
	caIssueOCSPCertCmd.Flags().StringVar(&outDir, "out-dir", "./pki/ocsp", "Выходная директория")
	caIssueOCSPCertCmd.Flags().IntVar(&validityDays, "validity-days", 365, "Срок действия в днях")
	caIssueOCSPCertCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	caIssueOCSPCertCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")
	caIssueOCSPCertCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")

	caIssueOCSPCertCmd.MarkFlagRequired("ca-cert")
	caIssueOCSPCertCmd.MarkFlagRequired("ca-key")
	caIssueOCSPCertCmd.MarkFlagRequired("ca-pass-file")
	caIssueOCSPCertCmd.MarkFlagRequired("subject")

	caVerifyCmd.Flags().StringVar(&rootCert, "root", "", "Путь к корневому сертификату")
	caVerifyCmd.Flags().StringVar(&caCert, "intermediate", "", "Путь к промежуточному сертификату")
	caVerifyCmd.Flags().StringVar(&outDir, "leaf", "", "Путь к конечному сертификату")
	caVerifyCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	caVerifyCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")

	caVerifyCmd.MarkFlagRequired("root")
	caVerifyCmd.MarkFlagRequired("intermediate")
	caVerifyCmd.MarkFlagRequired("leaf")

	caRevokeCmd.Flags().StringVar(&reason, "reason", "unspecified", "Причина отзыва")
	caRevokeCmd.Flags().StringVar(&crlPath, "crl", "", "Путь к CRL файлу для обновления")
	caRevokeCmd.Flags().BoolVar(&force, "force", false, "Пропустить подтверждение")
	caRevokeCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	caRevokeCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")
	caRevokeCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")

	caGenCRLCmd.Flags().StringVar(&caName, "ca", "", "УЦ: root или intermediate (или путь к сертификату)")
	caGenCRLCmd.Flags().IntVar(&nextUpdateDays, "next-update", 7, "Дней до следующего обновления CRL")
	caGenCRLCmd.Flags().StringVar(&outCRLFile, "out-file", "", "Выходной файл CRL")
	caGenCRLCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	caGenCRLCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")
	caGenCRLCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")
	caGenCRLCmd.Flags().StringVar(&caCert, "ca-cert", "", "Путь к сертификату УЦ (опционально)")
	caGenCRLCmd.Flags().StringVar(&caKey, "ca-key", "", "Путь к ключу УЦ (опционально)")
	caGenCRLCmd.Flags().StringVar(&caPassFile, "ca-pass-file", "", "Файл с паролем УЦ")

	caGenCRLCmd.MarkFlagRequired("ca")

	caCheckRevokedCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")
	caCheckRevokedCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	caCheckRevokedCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")

	caCompromiseCmd.Flags().StringVar(&compromiseCert, "cert", "", "Путь к сертификату для компрометации")
	caCompromiseCmd.Flags().StringVar(&compromiseReason, "reason", "keyCompromise", "Причина компрометации")
	caCompromiseCmd.Flags().BoolVar(&force, "force", false, "Пропустить подтверждение")
	caCompromiseCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")
	caCompromiseCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	caCompromiseCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")

	caCompromiseCmd.MarkFlagRequired("cert")

	caListCertsCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")
	caListCertsCmd.Flags().StringVar(&statusFilter, "status", "", "Фильтр по статусу (valid, revoked, expired)")
	caListCertsCmd.Flags().StringVar(&format, "format", "table", "Формат вывода (table, json, csv)")
	caListCertsCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	caListCertsCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")

	caShowCertCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")
	caShowCertCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	caShowCertCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")

	dbInitCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")
	dbInitCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	dbInitCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")
	dbInitCmd.Flags().BoolVar(&force, "force", false, "Принудительная перезапись (удалить существующую БД)")

	repoServeCmd.Flags().StringVar(&host, "host", "127.0.0.1", "Адрес для привязки сервера")
	repoServeCmd.Flags().IntVar(&port, "port", 8080, "TCP порт")
	repoServeCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")
	repoServeCmd.Flags().StringVar(&certDir, "cert-dir", "./pki/certs", "Директория с PEM сертификатами")
	repoServeCmd.Flags().Float64Var(&rateLimit, "rate-limit", 0, "Запросов в секунду на клиента (0 = отключено)")
	repoServeCmd.Flags().IntVar(&rateBurst, "rate-burst", 10, "Максимальный burst")
	repoServeCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	repoServeCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")

	repoStatusCmd.Flags().StringVar(&host, "host", "127.0.0.1", "Адрес сервера")
	repoStatusCmd.Flags().IntVar(&port, "port", 8080, "TCP порт")
	repoStatusCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	repoStatusCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")

	auditQueryCmd.Flags().StringVar(&auditFrom, "from", "", "Начальная временная метка (ISO 8601)")
	auditQueryCmd.Flags().StringVar(&auditTo, "to", "", "Конечная временная метка (ISO 8601)")
	auditQueryCmd.Flags().StringVar(&auditLevel, "level", "", "Уровень: AUDIT, INFO, WARNING, ERROR")
	auditQueryCmd.Flags().StringVar(&auditOperation, "operation", "", "Фильтр по типу операции")
	auditQueryCmd.Flags().StringVar(&auditSerial, "serial", "", "Фильтр по серийному номеру")
	auditQueryCmd.Flags().StringVar(&auditFormat, "format", "table", "Формат вывода: table, json, csv")
	auditQueryCmd.Flags().BoolVar(&auditVerifyFlag, "verify", false, "Проверить целостность найденных записей")
	auditQueryCmd.Flags().StringVar(&auditLogFile, "log-file", "./pki/audit/audit.log", "Путь к файлу аудит-лога")
	auditQueryCmd.Flags().StringVar(&logFile, "log-file-app", "", "Файл для логов приложения")

	auditVerifyCmd.Flags().StringVar(&auditLogFile, "log-file", "./pki/audit/audit.log", "Путь к файлу аудит-лога")
	auditVerifyCmd.Flags().StringVar(&auditChainFile, "chain-file", "./pki/audit/chain.dat", "Путь к файлу цепочки хешей")
	auditVerifyCmd.Flags().StringVar(&logFile, "log-file-app", "", "Файл для логов приложения")

	auditCtVerifyCmd.Flags().StringVar(&ctSerial, "serial", "", "Серийный номер сертификата")
	auditCtVerifyCmd.Flags().StringVar(&ctFingerprint, "fingerprint", "", "SHA-256 отпечаток сертификата")
	auditCtVerifyCmd.Flags().StringVar(&ctLogFile, "ct-log", "./pki/audit/ct.log", "Путь к CT логу")
	auditCtVerifyCmd.Flags().StringVar(&logFile, "log-file-app", "", "Файл для логов приложения")

	auditDetectAnomaliesCmd.Flags().StringVar(&auditLogFile, "log-file", "./pki/audit/audit.log", "Путь к файлу аудит-лога")
	auditDetectAnomaliesCmd.Flags().IntVar(&auditThreshold, "threshold", 100, "Порог событий в час для обнаружения аномалий")
	auditDetectAnomaliesCmd.Flags().StringVar(&logFile, "log-file-app", "", "Файл для логов приложения")

	ocspServeCmd.Flags().StringVar(&ocspHost, "host", "127.0.0.1", "Адрес для привязки")
	ocspServeCmd.Flags().IntVar(&ocspPort, "port", 8081, "TCP порт")
	ocspServeCmd.Flags().StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к SQLite базе данных")
	ocspServeCmd.Flags().StringVar(&ocspResponderCert, "responder-cert", "", "Сертификат OCSP-ответчика (PEM)")
	ocspServeCmd.Flags().StringVar(&ocspResponderKey, "responder-key", "", "Ключ OCSP-ответчика (PEM, незашифрованный)")
	ocspServeCmd.Flags().StringVar(&ocspCACert, "ca-cert", "", "Сертификат CA эмитента")
	ocspServeCmd.Flags().IntVar(&ocspCacheTTL, "cache-ttl", 60, "TTL кэша в секундах")
	ocspServeCmd.Flags().Float64Var(&ocspRateLimit, "rate-limit", 0, "Запросов в секунду на клиента (0 = отключено)")
	ocspServeCmd.Flags().IntVar(&ocspRateBurst, "rate-burst", 10, "Максимальный burst")
	ocspServeCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	ocspServeCmd.Flags().StringVar(&logJSON, "log-json", "", "Файл для JSON логов аудита")

	ocspServeCmd.MarkFlagRequired("responder-cert")
	ocspServeCmd.MarkFlagRequired("responder-key")
	ocspServeCmd.MarkFlagRequired("ca-cert")

	clientGenCSRCmd.Flags().StringVar(&csrSubject, "subject", "", "Distinguished Name (обязательно)")
	clientGenCSRCmd.Flags().StringVar(&csrKeyType, "key-type", "rsa", "Тип ключа: rsa или ecc")
	clientGenCSRCmd.Flags().IntVar(&csrKeySize, "key-size", 2048, "Размер ключа (RSA: 2048/4096, ECC: 256/384)")
	clientGenCSRCmd.Flags().StringSliceVar(&csrSANs, "san", []string{}, "Альтернативные имена (dns:example.com,ip:1.2.3.4)")
	clientGenCSRCmd.Flags().StringVar(&csrOutKey, "out-key", "./key.pem", "Выходной файл ключа")
	clientGenCSRCmd.Flags().StringVar(&csrOutCSR, "out-csr", "./request.csr.pem", "Выходной файл CSR")
	clientGenCSRCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	clientGenCSRCmd.MarkFlagRequired("subject")

	clientRequestCertCmd.Flags().StringVar(&reqCSRPath, "csr", "", "Путь к CSR файлу (обязательно)")
	clientRequestCertCmd.Flags().StringVar(&reqTemplate, "template", "", "Шаблон: server, client, code_signing (обязательно)")
	clientRequestCertCmd.Flags().StringVar(&reqCAURL, "ca-url", "http://localhost:8080", "URL CA сервера")
	clientRequestCertCmd.Flags().StringVar(&reqOutCert, "out-cert", "./cert.pem", "Выходной файл сертификата")
	clientRequestCertCmd.Flags().StringVar(&reqAPIKey, "api-key", "", "API ключ (опционально)")
	clientRequestCertCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	clientRequestCertCmd.MarkFlagRequired("csr")
	clientRequestCertCmd.MarkFlagRequired("template")

	clientValidateCmd.Flags().StringVar(&valCert, "cert", "", "Путь к конечному сертификату (обязательно)")
	clientValidateCmd.Flags().StringSliceVar(&valUntrusted, "untrusted", []string{}, "Промежуточные сертификаты")
	clientValidateCmd.Flags().StringVar(&valTrusted, "trusted", "./pki/certs/ca.cert.pem", "Доверенные корневые сертификаты")
	clientValidateCmd.Flags().StringVar(&valCRL, "crl", "", "CRL файл или URL")
	clientValidateCmd.Flags().BoolVar(&valOCSP, "ocsp", false, "Проверять через OCSP")
	clientValidateCmd.Flags().StringVar(&valMode, "mode", "full", "Режим: chain или full")
	clientValidateCmd.Flags().StringVar(&valTime, "validation-time", "", "Время валидации (RFC3339)")
	clientValidateCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	clientValidateCmd.MarkFlagRequired("cert")

	clientCheckStatusCmd.Flags().StringVar(&chkCert, "cert", "", "Путь к сертификату (обязательно)")
	clientCheckStatusCmd.Flags().StringVar(&chkCACert, "ca-cert", "", "Сертификат издателя (обязательно)")
	clientCheckStatusCmd.Flags().StringVar(&chkCRL, "crl", "", "CRL файл или URL")
	clientCheckStatusCmd.Flags().StringVar(&chkOCSPURL, "ocsp-url", "", "URL OCSP ответчика")
	clientCheckStatusCmd.Flags().StringVar(&logFile, "log-file", "", "Файл для логов")
	clientCheckStatusCmd.MarkFlagRequired("cert")
	clientCheckStatusCmd.MarkFlagRequired("ca-cert")
}

func loadConfig() {
	if configFile != "" {
		var err error
		loadedPolicy, err = policy.LoadPolicyFromFile(configFile)
		if err != nil {
			logger.Warn("не удалось загрузить конфигурационный файл %s: %v, используются политики по умолчанию", configFile, err)
			loadedPolicy = nil
		} else {
			logger.Info("политики загружены из %s", configFile)
		}
	}
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

func initAuditIfNeeded(outDir string) {
	if audit.GetAuditLogger() == nil {
		if err := logger.InitAudit(outDir); err != nil {
			logger.Warn("не удалось инициализировать аудит-логгер: %v", err)
		}
	}
}

func runCAInit(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	loadConfig()
	initAuditIfNeeded(outDir)

	pol := getPolicy()
	if err := pol.ValidateKeySize(keyType, keySize, policy.RootCA); err != nil {
		logger.Error("нарушение политики размера ключа: %v", err)
		logger.LogAuditError("policy_violation", err.Error(), map[string]interface{}{
			"key_type":  keyType,
			"key_size":  keySize,
			"cert_type": "root_ca",
		})
		return err
	}
	if err := pol.ValidateValidityPeriod(policy.RootCA, validityDays); err != nil {
		logger.Error("нарушение политики срока действия: %v", err)
		logger.LogAuditError("policy_violation", err.Error(), map[string]interface{}{
			"validity_days": validityDays,
			"cert_type":     "root_ca",
		})
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

	logger.LogAuditEvent("root_ca_init", "success",
		"Root CA initialized successfully",
		map[string]interface{}{
			"subject":       subject,
			"key_type":      keyType,
			"key_size":      keySize,
			"validity_days": validityDays,
			"serial":        fmt.Sprintf("%x", rootCA.GetSerialNumber()),
		})

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

	loadConfig()
	initAuditIfNeeded(outDir)

	pol := getPolicy()
	if err := pol.ValidateKeySize(keyType, keySize, policy.IntermediateCA); err != nil {
		logger.Error("нарушение политики размера ключа: %v", err)
		logger.LogAuditError("policy_violation", err.Error(), map[string]interface{}{
			"key_type":  keyType,
			"key_size":  keySize,
			"cert_type": "intermediate_ca",
		})
		return err
	}
	if err := pol.ValidateValidityPeriod(policy.IntermediateCA, validityDays); err != nil {
		logger.Error("нарушение политики срока действия: %v", err)
		logger.LogAuditError("policy_violation", err.Error(), map[string]interface{}{
			"validity_days": validityDays,
			"cert_type":     "intermediate_ca",
		})
		return err
	}
	if err := pol.ValidatePathLength(policy.IntermediateCA, pathlen, false); err != nil {
		logger.Error("нарушение политики длины пути: %v", err)
		logger.LogAuditError("policy_violation", err.Error(), map[string]interface{}{
			"pathlen": pathlen,
		})
		return err
	}

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

	certTemplate := &x509.Certificate{
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

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, rootCertificate, pubKey, rootSigner)
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

	ctLogger, err := transparency.NewCTLogger(outDir)
	if err == nil {
		ctLogger.AppendCertificate(finalCert)
	}

	logger.LogAuditEvent("intermediate_ca_issued", "success",
		"Intermediate CA certificate issued",
		map[string]interface{}{
			"serial":        fmt.Sprintf("%x", serialNumber),
			"subject":       subject,
			"issuer":        rootCertificate.Subject.String(),
			"key_type":      keyType,
			"key_size":      keySize,
			"pathlen":       pathlen,
			"validity_days": validityDays,
		})

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

	loadConfig()
	initAuditIfNeeded(filepath.Dir(filepath.Dir(outDir)))

	pol := getPolicy()

	if err := pol.ValidateValidityPeriod(policy.EndEntity, validityDays); err != nil {
		logger.Error("нарушение политики срока действия: %v", err)
		logger.LogAuditError("policy_violation", err.Error(), map[string]interface{}{
			"validity_days": validityDays,
			"cert_type":     "end_entity",
		})
		return err
	}

	sanEntries, err := san.ParseSANs(sanStrings)
	if err != nil {
		return fmt.Errorf("ошибка парсинга SAN: %w", err)
	}

	templateType := templates.TemplateType(template)
	if err := pol.ValidateSANs(templateType, sanEntries); err != nil {
		logger.Error("нарушение политики SAN: %v", err)
		logger.LogAuditError("policy_violation", err.Error(), map[string]interface{}{
			"template": template,
			"sans":     sanStrings,
		})
		return err
	}

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

	tmpl, err := templates.GetTemplate(templateType)
	if err != nil {
		return err
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

		if err := pol.ValidatePublicKey(csrObj.PublicKey, policy.EndEntity); err != nil {
			logger.Error("нарушение политики ключа в CSR: %v", err)
			logger.LogAuditError("policy_violation", err.Error(), map[string]interface{}{
				"csr_file": csrFile,
			})
			return err
		}

		if db != nil {
			if compromised, _ := compromise.IsKeyCompromised(db, csrObj.PublicKey); compromised {
				err := fmt.Errorf("публичный ключ скомпрометирован, выпуск сертификата запрещен")
				logger.Error("%v", err)
				logger.LogAuditError("compromised_key_blocked", err.Error(), map[string]interface{}{
					"csr_file": csrFile,
				})
				return err
			}
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

		ctLogger, err := transparency.NewCTLogger(filepath.Dir(outDir))
		if err == nil {
			ctLogger.AppendCertificate(finalCert)
		}

		logger.LogAuditEvent("certificate_issued", "success",
			fmt.Sprintf("Issued %s certificate for %s", template, subject),
			map[string]interface{}{
				"serial":        fmt.Sprintf("%x", finalCert.SerialNumber),
				"subject":       subject,
				"template":      template,
				"sans":          sanStrings,
				"issuer":        caCertificate.Subject.String(),
				"validity_days": validityDays,
			})
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

	fmt.Printf("\nСертификат успешно выпущен!\n")
	fmt.Printf("   Сертификат: %s\n", filepath.Join(outDir, commonName+".cert.pem"))
	if csrFile == "" {
		fmt.Printf("   Ключ: %s\n", keyPath)
	}
	fmt.Printf("   Серийный номер: %x\n", finalCert.SerialNumber)

	return nil
}

func runAuditQuery(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, ""); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	var filters audit.AuditFilters

	if auditFrom != "" {
		t, err := time.Parse(time.RFC3339, auditFrom)
		if err != nil {
			return fmt.Errorf("неверный формат --from: %w", err)
		}
		filters.From = t
	}

	if auditTo != "" {
		t, err := time.Parse(time.RFC3339, auditTo)
		if err != nil {
			return fmt.Errorf("неверный формат --to: %w", err)
		}
		filters.To = t
	}

	filters.Level = audit.AuditLevel(auditLevel)
	filters.Operation = auditOperation
	filters.Serial = auditSerial

	result, err := audit.QueryLog(auditLogFile, &filters)
	if err != nil {
		return fmt.Errorf("ошибка запроса аудит-лога: %w", err)
	}

	output, err := audit.FormatEntries(result.Entries, auditFormat)
	if err != nil {
		return fmt.Errorf("ошибка форматирования: %w", err)
	}

	fmt.Print(output)

	if auditVerifyFlag && len(result.Entries) > 0 {
		report, err := audit.VerifyHashChain(result.Entries)
		if err != nil {
			return fmt.Errorf("ошибка верификации: %w", err)
		}

		if !report.Valid {
			fmt.Printf("\nВНИМАНИЕ: Обнаружено нарушение целостности!\n")
			fmt.Printf("   %s\n", report.Error)
			os.Exit(1)
		} else {
			fmt.Printf("\nЦелостность найденных записей подтверждена (%d записей)\n", report.CheckedEntries)
		}
	}

	return nil
}

func runAuditVerify(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, ""); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	entries, err := audit.ReadAllEntries(auditLogFile)
	if err != nil {
		return fmt.Errorf("ошибка чтения лога: %w", err)
	}

	report, err := audit.VerifyHashChain(entries)
	if err != nil {
		return fmt.Errorf("ошибка верификации: %w", err)
	}

	if report.Valid {
		fmt.Printf("Аудит-лог целостен (%d записей проверено)\n", report.CheckedEntries)
		return nil
	}

	fmt.Printf("ОБНАРУЖЕНО НАРУШЕНИЕ ЦЕЛОСТНОСТИ!\n")
	fmt.Printf("   %s\n", report.Error)
	fmt.Printf("   Проверено записей: %d из %d\n", report.CheckedEntries, report.TotalEntries)

	if len(report.TamperDetails) > 0 {
		fmt.Printf("\n   Детали нарушений:\n")
		for _, detail := range report.TamperDetails {
			fmt.Printf("   - Запись %d: %s\n", detail.EntryIndex, detail.Type)
		}
	}

	os.Exit(1)
	return nil
}

func runAuditCtVerify(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, ""); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	var entries []transparency.CTLogEntry
	var err error

	if ctSerial != "" {
		entries, err = queryCTBySerial(ctLogFile, ctSerial)
	} else if ctFingerprint != "" {
		entries, err = queryCTByFingerprint(ctLogFile, ctFingerprint)
	} else {
		return fmt.Errorf("необходимо указать --serial или --fingerprint")
	}

	if err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Println("Сертификат не найден в CT логе")
		os.Exit(1)
		return nil
	}

	fmt.Printf("Сертификат найден в CT логе (%d записей):\n", len(entries))
	for _, entry := range entries {
		fmt.Printf("   Timestamp: %s\n", entry.Timestamp)
		fmt.Printf("   Serial:    %s\n", entry.SerialHex)
		fmt.Printf("   Subject:   %s\n", entry.SubjectDN)
		fmt.Printf("   Issuer:    %s\n", entry.IssuerDN)
		fmt.Printf("   Fingerprint: %s\n\n", entry.Fingerprint)
	}

	return nil
}

func runAuditDetectAnomalies(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, ""); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	report, err := audit.DetectAnomalies(auditLogFile, auditThreshold)
	if err != nil {
		return fmt.Errorf("ошибка анализа аномалий: %w", err)
	}

	formatted := audit.FormatAnomalyReport(report)
	fmt.Print(formatted)

	if len(report.Anomalies) > 0 {
		os.Exit(1)
	}

	return nil
}

func queryCTBySerial(logPath, serial string) ([]transparency.CTLogEntry, error) {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения CT лога: %w", err)
	}

	var entries []transparency.CTLogEntry
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var entry transparency.CTLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if strings.EqualFold(entry.SerialHex, serial) {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

func queryCTByFingerprint(logPath, fingerprint string) ([]transparency.CTLogEntry, error) {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения CT лога: %w", err)
	}

	var entries []transparency.CTLogEntry
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var entry transparency.CTLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if strings.EqualFold(entry.Fingerprint, fingerprint) {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

func runCACompromise(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	initAuditIfNeeded(filepath.Dir(dbPath))

	db, err := openDatabase(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if !force {
		fmt.Printf("ВНИМАНИЕ: Симуляция компрометации приватного ключа!\n")
		fmt.Printf("   Сертификат: %s\n", compromiseCert)
		fmt.Printf("   Причина: %s\n", compromiseReason)
		fmt.Printf("\nПродолжить? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Операция отменена")
			return nil
		}
	}

	result, err := compromise.SimulateKeyCompromise(db, compromiseCert, compromiseReason, true)
	if err != nil {
		return fmt.Errorf("ошибка симуляции компрометации: %w", err)
	}

	fmt.Printf("\nКомпрометация ключа симулирована:\n")
	fmt.Printf("   Серийный номер: %s\n", result.SerialHex)
	fmt.Printf("   Субъект: %s\n", result.Subject)
	fmt.Printf("   Хеш ключа: %s\n", result.PublicKeyHash)
	fmt.Printf("   Статус: отозван (причина: %s)\n", result.Reason)

	return nil
}

func runRepoServe(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	initAuditIfNeeded(filepath.Dir(dbPath))

	logger.Info("запуск HTTP сервера на %s:%d", host, port)
	logger.Info("БД: %s", dbPath)
	logger.Info("директория с сертификатами: %s", certDir)

	if rateLimit > 0 {
		logger.Info("ограничение частоты: %.1f запросов/сек, burst=%d", rateLimit, rateBurst)
	}

	db, err := openDatabase(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	crlDir := filepath.Join(filepath.Dir(dbPath), "crl")
	server := repository.NewServer(host, port, db, certDir, crlDir, rateLimit, rateBurst)

	fmt.Printf("HTTP сервер запущен на %s:%d\n", host, port)
	fmt.Printf("  - GET  /certificate/{serial} - получить сертификат по серийному номеру\n")
	fmt.Printf("  - GET  /ca/root               - получить корневой сертификат CA\n")
	fmt.Printf("  - GET  /ca/intermediate       - получить промежуточный сертификат CA\n")
	fmt.Printf("  - POST /request-cert          - запрос сертификата из CSR\n")
	fmt.Printf("  - GET  /crl                   - получить CRL (параметр ?ca=root|intermediate)\n")
	fmt.Printf("  - GET  /health                - проверка работоспособности\n")
	if rateLimit > 0 {
		fmt.Printf("  - Rate limiting: %.1f req/s, burst %d\n", rateLimit, rateBurst)
	}
	fmt.Printf("\nДля остановки нажмите Ctrl+C\n")

	logger.LogAuditEvent("repo_server_started", "success",
		fmt.Sprintf("Repository server started on %s:%d", host, port),
		map[string]interface{}{
			"host":       host,
			"port":       port,
			"rate_limit": rateLimit,
			"rate_burst": rateBurst,
		})

	if err := server.Start(); err != nil {
		logger.Error("ошибка работы сервера: %v", err)
		logger.LogAuditError("repo_server_error", err.Error(), nil)
		return fmt.Errorf("ошибка работы сервера: %w", err)
	}

	logger.LogAuditEvent("repo_server_stopped", "success", "Repository server stopped", nil)
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

func runCARevoke(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	initAuditIfNeeded(filepath.Dir(dbPath))

	serialHex := args[0]
	logger.Info("отзыв сертификата: serial=%s, reason=%s", serialHex, reason)

	reasonCode, err := revocation.ReasonCodeToInt(reason)
	if err != nil {
		logger.Error("неверный код причины: %v", err)
		return err
	}

	db, err := openDatabase(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	record, err := db.GetCertificateBySerial(serialHex)
	if err != nil {
		logger.Error("ошибка поиска сертификата: %v", err)
		return fmt.Errorf("ошибка поиска сертификата: %w", err)
	}
	if record == nil {
		logger.Error("сертификат с серийным номером %s не найден", serialHex)
		return fmt.Errorf("сертификат с серийным номером %s не найден", serialHex)
	}

	if record.Status == "revoked" {
		logger.Warn("сертификат %s уже отозван", serialHex)
		fmt.Printf("Сертификат %s уже отозван\n", serialHex)
		return nil
	}

	if !force {
		fmt.Printf("Вы уверены, что хотите отозвать сертификат %s (subject=%s)? [y/N]: ", serialHex, record.Subject)
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			logger.Info("отзыв отменен пользователем")
			fmt.Println("Отзыв отменен")
			return nil
		}
	}

	err = revocation.RevokeCertificate(db, serialHex, reasonCode, force)
	if err != nil {
		logger.Error("ошибка отзыва сертификата: %v", err)
		return err
	}

	logger.LogAuditEvent("certificate_revoked", "success",
		fmt.Sprintf("Certificate %s revoked", serialHex),
		map[string]interface{}{
			"serial": serialHex,
			"reason": reason,
			"subject": record.Subject,
		})

	fmt.Printf("Сертификат %s успешно отозван\n", serialHex)
	return nil
}

func runCAGenCRL(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	logger.Info("генерация CRL для УЦ: %s", caName)

	var certPath, keyPath, passPath string

	if caCert != "" && caKey != "" && caPassFile != "" {
		certPath = caCert
		keyPath = caKey
		passPath = caPassFile
	} else {
		switch caName {
		case "root":
			certPath = filepath.Join(filepath.Dir(dbPath), "certs", "ca.cert.pem")
			keyPath = filepath.Join(filepath.Dir(dbPath), "private", "ca.key.pem")
			passPath = filepath.Join(filepath.Dir(dbPath), "root.pass")
		case "intermediate":
			certPath = filepath.Join(filepath.Dir(dbPath), "certs", "intermediate.cert.pem")
			keyPath = filepath.Join(filepath.Dir(dbPath), "private", "intermediate.key.pem")
			passPath = filepath.Join(filepath.Dir(dbPath), "inter.pass")
		default:
			return fmt.Errorf("неизвестный УЦ: %s", caName)
		}
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("ошибка чтения сертификата УЦ: %w", err)
	}

	passphrase, err := os.ReadFile(passPath)
	if err != nil {
		return fmt.Errorf("ошибка чтения файла пароля: %w", err)
	}
	defer func() {
		for i := range passphrase {
			passphrase[i] = 0
		}
	}()
	if len(passphrase) > 0 && passphrase[len(passphrase)-1] == '\n' {
		passphrase = passphrase[:len(passphrase)-1]
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("ошибка чтения ключа УЦ: %w", err)
	}

	caPrivateKey, err := cryptoutil.LoadEncryptedPrivateKeyFromPEM(keyPEM, passphrase)
	if err != nil {
		return fmt.Errorf("ошибка загрузки ключа УЦ: %w", err)
	}

	caSigner, ok := caPrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("ключ УЦ не поддерживает подписание")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("не удалось декодировать сертификат УЦ")
	}
	caCertificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("ошибка парсинга сертификата УЦ: %w", err)
	}

	db, err := openDatabase(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	revokedRecords, err := db.GetRevokedCertificatesByIssuer(caCertificate.Subject.String())
	if err != nil {
		return fmt.Errorf("ошибка получения отозванных сертификатов: %w", err)
	}

	revokedCerts := make([]crl.RevokedCertInfo, 0, len(revokedRecords))
	for _, r := range revokedRecords {
		serialBytes, _ := hex.DecodeString(r.SerialHex)
		serial := new(big.Int).SetBytes(serialBytes)
		reasonCode, _ := revocation.ReasonCodeToInt(r.RevocationReason.String)
		revokedCerts = append(revokedCerts, crl.RevokedCertInfo{
			SerialNumber:   serial,
			RevocationTime: r.RevocationDate.Time,
			ReasonCode:     reasonCode,
		})
	}

	crlNumber, err := crl.GetNextCRLNumber(db, caCertificate.Subject.String())
	if err != nil {
		return fmt.Errorf("ошибка получения номера CRL: %w", err)
	}

	crlPEM, err := crl.GenerateCRL(caCertificate, caSigner, revokedCerts, crlNumber, nextUpdateDays)
	if err != nil {
		return fmt.Errorf("ошибка генерации CRL: %w", err)
	}

	baseDir := filepath.Dir(dbPath)
	crlDir := filepath.Join(baseDir, "crl")
	if err := os.MkdirAll(crlDir, 0755); err != nil {
		return fmt.Errorf("ошибка создания директории crl: %w", err)
	}

	var crlPath string
	if outCRLFile != "" {
		crlPath = outCRLFile
		if err := os.MkdirAll(filepath.Dir(crlPath), 0755); err != nil {
			return fmt.Errorf("ошибка создания директории для CRL: %w", err)
		}
	} else {
		crlPath = filepath.Join(crlDir, fmt.Sprintf("%s.crl.pem", caName))
	}

	if err := os.WriteFile(crlPath, crlPEM, 0644); err != nil {
		return fmt.Errorf("ошибка сохранения CRL: %w", err)
	}

	nextUpdate := time.Now().UTC().AddDate(0, 0, nextUpdateDays)
	if err := crl.UpdateCRLMetadata(db, caCertificate.Subject.String(), crlNumber, nextUpdate, crlPath); err != nil {
		logger.Warn("ошибка обновления метаданных CRL: %v", err)
	}

	logger.LogAuditEvent("crl_generated", "success",
		fmt.Sprintf("CRL generated for %s", caName),
		map[string]interface{}{
			"ca":             caName,
			"crl_number":     crlNumber,
			"revoked_count":  len(revokedCerts),
			"next_update":    nextUpdate.Format(time.RFC3339),
		})

	fmt.Printf("CRL успешно сгенерирован:\n")
	fmt.Printf("   Файл: %s\n", crlPath)
	fmt.Printf("   Номер: %d\n", crlNumber)
	fmt.Printf("   Отозванных сертификатов: %d\n", len(revokedCerts))
	fmt.Printf("   Следующее обновление: %s\n", nextUpdate.Format(time.RFC3339))

	return nil
}

func runCACheckRevoked(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	serialHex := args[0]
	logger.Info("проверка статуса отзыва: serial=%s", serialHex)

	db, err := openDatabase(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	isRevoked, info, err := revocation.CheckRevoked(db, serialHex)
	if err != nil {
		logger.Error("ошибка проверки статуса: %v", err)
		return err
	}

	if isRevoked {
		fmt.Printf("Сертификат %s ОТОЗВАН\n", serialHex)
		fmt.Printf("   Причина: %s (код %d)\n", info.ReasonString, info.ReasonCode)
		fmt.Printf("   Дата отзыва: %s\n", info.RevocationTime.Format(time.RFC3339))
	} else {
		fmt.Printf("Сертификат %s ДЕЙСТВИТЕЛЕН (не отозван)\n", serialHex)
	}

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

	logger.LogAuditEvent("database_initialized", "success",
		"Database initialized",
		map[string]interface{}{
			"db_path": dbPath,
		})

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

func runCAIssueOCSPCert(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	logger.Info("начало выпуска сертификата OCSP-ответчика")

	if keyType != "rsa" && keyType != "ecc" {
		return fmt.Errorf("key-type должен быть rsa или ecc")
	}
	if keyType == "rsa" && keySize < 2048 {
		return fmt.Errorf("для RSA размер ключа должен быть не менее 2048 бит")
	}
	if keyType == "ecc" && keySize < 256 {
		return fmt.Errorf("для ECC размер ключа должен быть не менее 256 бит")
	}

	caPass, err := os.ReadFile(caPassFile)
	if err != nil {
		return fmt.Errorf("ошибка чтения файла пароля CA: %w", err)
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
		return fmt.Errorf("ошибка чтения сертификата CA: %w", err)
	}

	caKeyPEM, err := os.ReadFile(caKey)
	if err != nil {
		return fmt.Errorf("ошибка чтения ключа CA: %w", err)
	}

	caPrivateKey, err := cryptoutil.LoadEncryptedPrivateKeyFromPEM(caKeyPEM, caPass)
	if err != nil {
		return fmt.Errorf("ошибка загрузки ключа CA: %w", err)
	}

	caSigner, ok := caPrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("ключ CA не поддерживает подписание")
	}

	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return fmt.Errorf("не удалось декодировать сертификат CA")
	}
	caCertificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("ошибка парсинга сертификата CA: %w", err)
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("ошибка создания выходной директории: %w", err)
	}

	logger.Info("генерация ключа OCSP-ответчика (незашифрованного)")
	var ocspPrivateKey crypto.PrivateKey
	var pubKey crypto.PublicKey

	switch keyType {
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return fmt.Errorf("ошибка генерации RSA ключа: %w", err)
		}
		ocspPrivateKey = key
		pubKey = &key.PublicKey
	case "ecc":
		var curve elliptic.Curve
		switch keySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		default:
			return fmt.Errorf("неподдерживаемый размер ECC ключа: %d", keySize)
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return fmt.Errorf("ошибка генерации ECC ключа: %w", err)
		}
		ocspPrivateKey = key
		pubKey = &key.PublicKey
	}

	keyPath := filepath.Join(outDir, "ocsp.key.pem")
	var keyPEM []byte
	switch k := ocspPrivateKey.(type) {
	case *rsa.PrivateKey:
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	case *ecdsa.PrivateKey:
		keyBytes, _ := x509.MarshalECPrivateKey(k)
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("ошибка сохранения ключа: %w", err)
	}
	logger.Warn("внимание: закрытый ключ OCSP-ответчика сохранен незашифрованным: %s", keyPath)
	fmt.Printf("ВНИМАНИЕ: Закрытый ключ OCSP-ответчика сохранен незашифрованным: %s\n", keyPath)

	certTemplate, err := certs.GenerateOCSPResponderTemplate(subject, pubKey, validityDays, sanStrings)
	if err != nil {
		return fmt.Errorf("ошибка создания шаблона: %w", err)
	}

	certTemplate.Issuer = caCertificate.Subject
	certTemplate.AuthorityKeyId = caCertificate.SubjectKeyId

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCertificate, pubKey, caSigner)
	if err != nil {
		return fmt.Errorf("ошибка подписания сертификата: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certPath := filepath.Join(outDir, "ocsp.cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("ошибка сохранения сертификата: %w", err)
	}

	if dbPath != "" {
		db, err := openDatabase(dbPath)
		if err == nil {
			defer db.Close()
			cert, _ := x509.ParseCertificate(certDER)
			if err := db.InsertCertificate(cert, certPEM, "valid"); err != nil {
				logger.Warn("не удалось сохранить сертификат в БД: %v", err)
			}
		}
	}

	logger.Info("сертификат OCSP-ответчика успешно создан")
	fmt.Printf("\nСертификат OCSP-ответчика успешно создан!\n")
	fmt.Printf("   Сертификат: %s\n", certPath)
	fmt.Printf("   Ключ: %s\n", keyPath)
	fmt.Printf("   Subject: %s\n", subject)

	return nil
}

func runOCSPServe(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	logger.Info("запуск OCSP-ответчика на %s:%d", ocspHost, ocspPort)
	logger.Info("БД: %s", dbPath)
	logger.Info("сертификат ответчика: %s", ocspResponderCert)
	logger.Info("CA сертификат: %s", ocspCACert)
	logger.Info("TTL кэша: %d секунд", ocspCacheTTL)

	if ocspRateLimit > 0 {
		logger.Info("ограничение частоты OCSP: %.1f запросов/сек, burst=%d", ocspRateLimit, ocspRateBurst)
	}

	db, err := openDatabase(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	responder, err := ocsp.NewOCSPResponder(
		db,
		ocspResponderCert,
		ocspResponderKey,
		ocspCACert,
		ocspCacheTTL,
		ocspHost,
		ocspPort,
	)
	if err != nil {
		return fmt.Errorf("ошибка создания OCSP-ответчика: %w", err)
	}

	if ocspRateLimit > 0 {
		responder.SetRateLimit(ocspRateLimit, ocspRateBurst)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", responder.HandleOCSPRequest)
	mux.HandleFunc("/ocsp", responder.HandleOCSPRequest)

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", ocspHost, ocspPort),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Info("OCSP-ответчик запущен на http://%s:%d", ocspHost, ocspPort)
		fmt.Printf("\nOCSP-ответчик запущен на %s:%d\n", ocspHost, ocspPort)
		fmt.Printf("  POST / - OCSP запросы\n")
		fmt.Printf("  POST /ocsp - альтернативный путь\n")
		if ocspRateLimit > 0 {
			fmt.Printf("  Rate limiting: %.1f req/s, burst %d\n", ocspRateLimit, ocspRateBurst)
		}
		fmt.Printf("\nДля остановки нажмите Ctrl+C\n")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("ошибка HTTP сервера: %v", err)
		}
	}()

	<-stop
	logger.Info("получен сигнал завершения, останавливаем OCSP-ответчика...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("ошибка при остановке сервера: %v", err)
		return err
	}

	logger.Info("OCSP-ответчик остановлен")
	return nil
}

func runClientGenCSR(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	client.InitClientLogger("")
	defer client.CloseClientLogger()

	cfg := &client.CSRConfig{
		Subject: csrSubject,
		KeyType: csrKeyType,
		KeySize: csrKeySize,
		SANs:    csrSANs,
		OutKey:  csrOutKey,
		OutCSR:  csrOutCSR,
	}

	logger.Info("генерация CSR: subject=%s, key-type=%s, key-size=%d", csrSubject, csrKeyType, csrKeySize)

	generated, err := client.GenerateCSR(cfg)
	if err != nil {
		client.LogClientOperation("gen_csr", map[string]interface{}{
			"subject": csrSubject,
		}, err)
		return err
	}

	if err := client.SaveCSR(generated, csrOutKey, csrOutCSR); err != nil {
		client.LogClientOperation("gen_csr", map[string]interface{}{
			"subject": csrSubject,
		}, err)
		return err
	}

	client.LogClientOperation("gen_csr", map[string]interface{}{
		"subject":  csrSubject,
		"key_file": csrOutKey,
		"csr_file": csrOutCSR,
	}, nil)

	fmt.Printf("ВНИМАНИЕ: Закрытый ключ сохранен незашифрованным: %s\n", csrOutKey)
	fmt.Printf("CSR успешно сгенерирован:\n")
	fmt.Printf("  Ключ: %s\n", csrOutKey)
	fmt.Printf("  CSR:  %s\n", csrOutCSR)

	return nil
}

func runClientRequestCert(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	client.InitClientLogger("")
	defer client.CloseClientLogger()

	req := &client.CertificateRequest{
		CSRPath:  reqCSRPath,
		Template: reqTemplate,
		CAURL:    reqCAURL,
		OutCert:  reqOutCert,
		APIKey:   reqAPIKey,
	}

	logger.Info("запрос сертификата: csr=%s, template=%s, ca=%s", reqCSRPath, reqTemplate, reqCAURL)

	if err := client.RequestCertificate(req); err != nil {
		client.LogClientOperation("request_cert", map[string]interface{}{
			"csr":      reqCSRPath,
			"template": reqTemplate,
			"ca_url":   reqCAURL,
		}, err)
		return err
	}

	client.LogClientOperation("request_cert", map[string]interface{}{
		"csr":      reqCSRPath,
		"template": reqTemplate,
		"ca_url":   reqCAURL,
		"out_cert": reqOutCert,
	}, nil)

	fmt.Printf("Сертификат успешно получен и сохранен: %s\n", reqOutCert)

	return nil
}

func runClientValidate(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	leaf, err := chain.LoadCertificate(valCert)
	if err != nil {
		return fmt.Errorf("ошибка загрузки конечного сертификата: %w", err)
	}

	builder := validation.NewChainBuilder()

	trustedCerts, err := loadCertificatesFromFile(valTrusted)
	if err != nil {
		return fmt.Errorf("ошибка загрузки доверенных сертификатов: %w", err)
	}
	for _, cert := range trustedCerts {
		builder.AddTrustedRoot(cert)
	}

	for _, untrustedPath := range valUntrusted {
		interCerts, err := loadCertificatesFromFile(untrustedPath)
		if err != nil {
			return fmt.Errorf("ошибка загрузки промежуточных сертификатов: %w", err)
		}
		for _, cert := range interCerts {
			builder.AddIntermediate(cert)
		}
	}

	path, err := builder.BuildChain(leaf)
	if err != nil {
		return fmt.Errorf("ошибка построения цепочки: %w", err)
	}

	fmt.Printf("Построена цепочка из %d сертификатов:\n", len(path))
	for i, cert := range path {
		fmt.Printf("  %d: %s\n", i+1, cert.Subject.String())
	}

	var currentTime time.Time
	if valTime != "" {
		currentTime, err = time.Parse(time.RFC3339, valTime)
		if err != nil {
			return fmt.Errorf("неверный формат времени: %w", err)
		}
	}

	validators := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: currentTime,
	})

	result, err := validators.ValidatePath(path)
	if err != nil {
		fmt.Printf("\nВалидация провалена: %v\n", err)

		for _, step := range result.Steps {
			status := "YES"
			if !step.Passed {
				status = "NO"
			}
			if step.Error != "" {
				fmt.Printf("  %s %s: %s\n", status, step.Check, step.Error)
			}
		}
		return err
	}

	fmt.Println("\nЦепочка сертификатов валидна!")

	if valMode == "full" && (valOCSP || valCRL != "") {
		fmt.Println("\nПроверка статуса отзыва...")

		if len(path) < 2 {
			fmt.Println("  Недостаточно сертификатов для проверки отзыва")
		} else {
			issuer := path[1]

			checker := revocation.NewRevocationChecker()
			revResult, err := checker.CheckStatus(&revocation.RevocationCheckOptions{
				Cert:          leaf,
				Issuer:        issuer,
				CRLSource:     valCRL,
				PreferOCSP:    valOCSP,
				FallbackToCRL: valCRL != "",
			})

			if err != nil {
				fmt.Printf("  Ошибка проверки отзыва: %v\n", err)
			} else {
				fmt.Printf("  Метод: %s\n", revResult.Method)
				fmt.Printf("  Статус: %s\n", revResult.Status)
				if revResult.Status == "revoked" {
					fmt.Printf("  Дата отзыва: %s\n", revResult.RevokedAt.Format(time.RFC3339))
					fmt.Printf("  Причина: %s\n", revResult.Reason)
				}
				if revResult.Error != "" {
					fmt.Printf("  Предупреждение: %s\n", revResult.Error)
				}
			}

			result.Revocation = revResult
		}
	}

	if logJSON != "" {
		jsonData, _ := result.ToJSON()
		os.WriteFile(logJSON, jsonData, 0644)
	}

	return nil
}

func runClientCheckStatus(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile, logJSON); err != nil {
		return fmt.Errorf("ошибка инициализации логгера: %w", err)
	}
	defer logger.Close()

	cert, err := chain.LoadCertificate(chkCert)
	if err != nil {
		return fmt.Errorf("ошибка загрузки сертификата: %w", err)
	}

	issuer, err := chain.LoadCertificate(chkCACert)
	if err != nil {
		return fmt.Errorf("ошибка загрузки сертификата издателя: %w", err)
	}

	fmt.Printf("Проверка статуса сертификата:\n")
	fmt.Printf("  Subject: %s\n", cert.Subject.String())
	fmt.Printf("  Serial:  %x\n", cert.SerialNumber)

	ocspURL := chkOCSPURL
	preferOCSP := ocspURL != ""
	if !preferOCSP {
		ocspURL, _ = validation.ExtractOCSPURL(cert)
		preferOCSP = ocspURL != ""
	}

	checker := revocation.NewRevocationChecker()
	result, err := checker.CheckStatus(&revocation.RevocationCheckOptions{
		Cert:          cert,
		Issuer:        issuer,
		OCSPURL:       ocspURL,
		CRLSource:     chkCRL,
		PreferOCSP:    preferOCSP,
		FallbackToCRL: true,
	})

	if err != nil {
		return fmt.Errorf("ошибка проверки: %w", err)
	}

	fmt.Printf("\nРезультат проверки:\n")
	if result.Method != "" {
		fmt.Printf("  Метод:  %s\n", result.Method)
	}
	fmt.Printf("  Статус: %s\n", result.Status)

	if result.Status == "revoked" {
		fmt.Printf("  Отозван: %s\n", result.RevokedAt.Format(time.RFC3339))
		fmt.Printf("  Причина: %s\n", result.Reason)
	}

	if result.Error != "" {
		fmt.Printf("  Предупреждение: %s\n", result.Error)
	}

	return nil
}

func loadCertificatesFromFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
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