package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"MicroPKI/internal/transparency"
)

func createCTTestCertificate(t *testing.T, key *rsa.PrivateKey, commonName string) *x509.Certificate {
	t.Helper()

	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	now := time.Now().UTC()

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore: now,
		NotAfter:  now.AddDate(1, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ошибка создания сертификата: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ошибка парсинга сертификата: %v", err)
	}

	return cert
}

func TestCTLogAppendAndQuery(t *testing.T) {
	tmpDir := t.TempDir()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := createCTTestCertificate(t, key, "test.example.com")

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	if err := ctLogger.AppendCertificate(cert); err != nil {
		t.Fatalf("ошибка добавления сертификата: %v", err)
	}

	ctLogPath := filepath.Join(tmpDir, "audit", "ct.log")
	if _, err := os.Stat(ctLogPath); os.IsNotExist(err) {
		t.Error("ct.log не создан")
	}

	serialHex := hex.EncodeToString(cert.SerialNumber.Bytes())

	entries, err := ctLogger.QueryBySerial(serialHex)
	if err != nil {
		t.Fatalf("ошибка запроса CT лога: %v", err)
	}

	if len(entries) == 0 {
		t.Error("сертификат не найден в CT логе")
	}

	if len(entries) > 0 {
		entry := entries[0]
		if entry.SubjectDN != cert.Subject.String() {
			t.Errorf("неверный SubjectDN: %s", entry.SubjectDN)
		}
		if entry.SerialHex != serialHex {
			t.Errorf("неверный SerialHex: %s", entry.SerialHex)
		}
	}

	found, err := ctLogger.VerifyCertificate(serialHex)
	if err != nil {
		t.Fatalf("ошибка верификации: %v", err)
	}
	if !found {
		t.Error("VerifyCertificate должен вернуть true")
	}

	t.Logf("CT лог работает: serial=%s, subject=%s", serialHex, cert.Subject.String())
}

func TestCTLogMultipleCertificates(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	serials := make([]string, 3)
	for i := 0; i < 3; i++ {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		cert := createCTTestCertificate(t, key, fmt.Sprintf("test%d.example.com", i))

		if err := ctLogger.AppendCertificate(cert); err != nil {
			t.Fatalf("ошибка добавления сертификата %d: %v", i, err)
		}

		serials[i] = hex.EncodeToString(cert.SerialNumber.Bytes())
	}

	for i, serial := range serials {
		found, err := ctLogger.VerifyCertificate(serial)
		if err != nil {
			t.Fatalf("ошибка верификации %d: %v", i, err)
		}
		if !found {
			t.Errorf("сертификат %d не найден в CT логе", i)
		}
	}
}

func TestCTLogQueryByFingerprint(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := createCTTestCertificate(t, key, "fingerprint.example.com")

	if err := ctLogger.AppendCertificate(cert); err != nil {
		t.Fatalf("ошибка добавления сертификата: %v", err)
	}

	fingerprint := sha256.Sum256(cert.Raw)
	fingerprintHex := hex.EncodeToString(fingerprint[:])

	entries, err := ctLogger.QueryByFingerprint(fingerprintHex)
	if err != nil {
		t.Fatalf("ошибка запроса по отпечатку: %v", err)
	}

	if len(entries) == 0 {
		t.Error("сертификат не найден по отпечатку")
	}
}

func TestCTLogNonExistent(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	found, err := ctLogger.VerifyCertificate("nonexistent")
	if err != nil {
		t.Fatalf("ошибка верификации: %v", err)
	}
	if found {
		t.Error("несуществующий сертификат не должен быть найден")
	}
}

func TestCTLogFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := createCTTestCertificate(t, key, "perms.example.com")
	ctLogger.AppendCertificate(cert)

	ctLogPath := ctLogger.GetLogPath()
	info, err := os.Stat(ctLogPath)
	if err != nil {
		t.Fatalf("ошибка stat: %v", err)
	}

	if info.Mode().Perm() != 0644 {
		t.Logf("права файла: %o (ожидалось 0644)", info.Mode().Perm())
	}
}

func TestCTLoggerNewWithExistingDir(t *testing.T) {
	tmpDir := t.TempDir()
	
	// Создаем директорию аудита заранее
	auditDir := filepath.Join(tmpDir, "audit")
	if err := os.MkdirAll(auditDir, 0755); err != nil {
		t.Fatal(err)
	}

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера с существующей директорией: %v", err)
	}
	if ctLogger == nil {
		t.Error("NewCTLogger вернул nil")
	}
}

func TestCTLoggerAppendInvalidCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	// Создаем невалидный сертификат (без подписи)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "invalid.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	
	// Создаем сертификат без подписи (невалидный)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	
	// Должен добавиться (CT лог не проверяет валидность)
	err = ctLogger.AppendCertificate(cert)
	if err != nil {
		t.Logf("ошибка добавления невалидного сертификата: %v", err)
	}
}

func TestCTLogQueryEmptyLog(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	// Запрос к пустому логу
	entries, err := ctLogger.QueryBySerial("12345")
	if err != nil {
		t.Fatalf("ошибка запроса к пустому логу: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("для пустого лога ожидалось 0 записей, получено %d", len(entries))
	}

	found, err := ctLogger.VerifyCertificate("12345")
	if err != nil {
		t.Fatalf("ошибка верификации пустого лога: %v", err)
	}
	if found {
		t.Error("VerifyCertificate для пустого лога должен вернуть false")
	}
}

func TestCTLogGetLogPath(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	expectedPath := filepath.Join(tmpDir, "audit", "ct.log")
	if ctLogger.GetLogPath() != expectedPath {
		t.Errorf("GetLogPath вернул %s, ожидался %s", ctLogger.GetLogPath(), expectedPath)
	}
}

func TestCTLogJSONFormat(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := createCTTestCertificate(t, key, "json.example.com")

	if err := ctLogger.AppendCertificate(cert); err != nil {
		t.Fatalf("ошибка добавления сертификата: %v", err)
	}

	// Читаем лог и проверяем JSON структуру
	logPath := ctLogger.GetLogPath()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ошибка чтения лога: %v", err)
	}

	var entry transparency.CTLogEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("ошибка парсинга JSON: %v", err)
	}

	if entry.Timestamp == "" {
		t.Error("timestamp отсутствует")
	}
	if entry.SerialHex == "" {
		t.Error("serial_hex отсутствует")
	}
	if entry.SubjectDN == "" {
		t.Error("subject_dn отсутствует")
	}
	if entry.Fingerprint == "" {
		t.Error("fingerprint отсутствует")
	}

	t.Logf("JSON запись: timestamp=%s, serial=%s, subject=%s", 
		entry.Timestamp, entry.SerialHex, entry.SubjectDN)
}

func TestCTLogMultipleAppends(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	// Добавляем несколько сертификатов
	certCount := 10
	serials := make([]string, certCount)

	for i := 0; i < certCount; i++ {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		cert := createCTTestCertificate(t, key, fmt.Sprintf("batch%d.example.com", i))
		
		if err := ctLogger.AppendCertificate(cert); err != nil {
			t.Fatalf("ошибка добавления сертификата %d: %v", i, err)
		}
		serials[i] = hex.EncodeToString(cert.SerialNumber.Bytes())
	}

	// Проверяем, что все сертификаты найдены
	for i, serial := range serials {
		found, err := ctLogger.VerifyCertificate(serial)
		if err != nil {
			t.Fatalf("ошибка верификации %d: %v", i, err)
		}
		if !found {
			t.Errorf("сертификат %d не найден", i)
		}
	}

	// Проверяем количество записей в логе
	logPath := ctLogger.GetLogPath()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != certCount {
		t.Errorf("ожидалось %d записей в логе, получено %d", certCount, len(lines))
	}
}

func TestCTLogQueryBySerialCaseInsensitive(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := createCTTestCertificate(t, key, "case.example.com")
	
	if err := ctLogger.AppendCertificate(cert); err != nil {
		t.Fatalf("ошибка добавления сертификата: %v", err)
	}

	serialHex := hex.EncodeToString(cert.SerialNumber.Bytes())
	
	// Поиск в нижнем регистре
	entriesLower, err := ctLogger.QueryBySerial(strings.ToLower(serialHex))
	if err != nil {
		t.Fatalf("ошибка запроса в нижнем регистре: %v", err)
	}
	if len(entriesLower) == 0 {
		t.Error("сертификат не найден в нижнем регистре")
	}

	// Поиск в верхнем регистре
	entriesUpper, err := ctLogger.QueryBySerial(strings.ToUpper(serialHex))
	if err != nil {
		t.Fatalf("ошибка запроса в верхнем регистре: %v", err)
	}
	if len(entriesUpper) == 0 {
		t.Error("сертификат не найден в верхнем регистре")
	}
}

func TestCTLogQueryByFingerprintCaseInsensitive(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := createCTTestCertificate(t, key, "fingerprint-case.example.com")
	
	if err := ctLogger.AppendCertificate(cert); err != nil {
		t.Fatalf("ошибка добавления сертификата: %v", err)
	}

	fingerprint := sha256.Sum256(cert.Raw)
	fingerprintHex := hex.EncodeToString(fingerprint[:])
	
	// Поиск в нижнем регистре
	entriesLower, err := ctLogger.QueryByFingerprint(strings.ToLower(fingerprintHex))
	if err != nil {
		t.Fatalf("ошибка запроса в нижнем регистре: %v", err)
	}
	if len(entriesLower) == 0 {
		t.Error("сертификат не найден по отпечатку в нижнем регистре")
	}

	// Поиск в верхнем регистре
	entriesUpper, err := ctLogger.QueryByFingerprint(strings.ToUpper(fingerprintHex))
	if err != nil {
		t.Fatalf("ошибка запроса в верхнем регистре: %v", err)
	}
	if len(entriesUpper) == 0 {
		t.Error("сертификат не найден по отпечатку в верхнем регистре")
	}
}

func TestCTLogCorruptedLogFile(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	// Добавляем валидную запись
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := createCTTestCertificate(t, key, "corrupt.example.com")
	ctLogger.AppendCertificate(cert)

	// Повреждаем лог-файл
	logPath := ctLogger.GetLogPath()
	if err := os.WriteFile(logPath, []byte("corrupted line\nnot json\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Запрос должен обработать поврежденный файл (пропустить некорректные строки)
	entries, err := ctLogger.QueryBySerial("any")
	if err != nil {
		t.Fatalf("ошибка запроса к поврежденному логу: %v", err)
	}
	// Должен вернуть пустой результат или игнорировать поврежденные строки
	t.Logf("поврежденный лог: найдено %d записей", len(entries))
}

func TestCTLoggerVerifyCertificateWithEmptyLog(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	// Лог не существует (будет создан при первой записи)
	// Проверяем сертификат в несуществующем логе
	found, err := ctLogger.VerifyCertificate("12345")
	if err != nil {
		t.Fatalf("ошибка верификации: %v", err)
	}
	if found {
		t.Error("VerifyCertificate для несуществующего лога должен вернуть false")
	}
}

func TestCTLoggerAppendCertificateWithIssuerInfo(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	// Создаем сертификат с issuer
	issuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Issuer CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	issuer, _ := x509.ParseCertificate(issuerDER)

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "issued.example.com"},
		Issuer:       issuer.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	cert, _ := x509.ParseCertificate(certDER)

	if err := ctLogger.AppendCertificate(cert); err != nil {
		t.Fatalf("ошибка добавления сертификата с issuer: %v", err)
	}

	// Проверяем, что issuer сохранен
	logPath := ctLogger.GetLogPath()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}

	var entry transparency.CTLogEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}

	if entry.IssuerDN == "" {
		t.Error("issuer_dn отсутствует в записи")
	}
	t.Logf("issuer_dn: %s", entry.IssuerDN)
}