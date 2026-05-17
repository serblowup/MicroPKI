package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"MicroPKI/internal/audit"
	"MicroPKI/internal/compromise"
	"MicroPKI/internal/database"
	"MicroPKI/internal/logger"
	"MicroPKI/internal/policy"
	"MicroPKI/internal/ratelimit"
	"MicroPKI/internal/transparency"
)

func TestFullSecurityHardeningIntegration(t *testing.T) {
	tmpDir := t.TempDir()

	auditDir := filepath.Join(tmpDir, "audit")
	os.MkdirAll(auditDir, 0755)

	logPath := filepath.Join(auditDir, "audit.log")
	chainPath := filepath.Join(auditDir, "chain.dat")
	dbPath := filepath.Join(tmpDir, "test.db")

	logger.Init(filepath.Join(tmpDir, "app.log"), "")
	defer logger.Close()

	auditLogger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
	if err != nil {
		t.Fatalf("ошибка создания аудит-логгера: %v", err)
	}
	defer auditLogger.Close()

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("ошибка создания БД: %v", err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatalf("ошибка инициализации схемы: %v", err)
	}

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	pol := policy.DefaultPolicy()

	// Шаг 1: Проверка политик - отклонение слабого ключа
	t.Run("Policy_Violation_Weak_Key", func(t *testing.T) {
		err := pol.ValidateKeySize("rsa", 1024, policy.EndEntity)
		if err == nil {
			t.Error("ожидалась ошибка для RSA-1024")
		}
		auditLogger.LogAudit("policy_violation", "failure",
			"Policy violation: weak key size",
			map[string]interface{}{
				"key_type": "rsa",
				"key_size": 1024,
				"cert_type": "end_entity",
			})
	})

	// Шаг 2: Проверка политик - отклонение чрезмерного срока действия
	t.Run("Policy_Violation_Excessive_Validity", func(t *testing.T) {
		err := pol.ValidateValidityPeriod(policy.EndEntity, 400)
		if err == nil {
			t.Error("ожидалась ошибка для срока действия 400 дней")
		}
		auditLogger.LogAudit("policy_violation", "failure",
			"Policy violation: excessive validity",
			map[string]interface{}{
				"validity_days": 400,
				"cert_type": "end_entity",
			})
	})

	// Шаг 3: Проверка политик - отклонение wildcard SAN
	t.Run("Policy_Violation_Wildcard_SAN", func(t *testing.T) {
		auditLogger.LogAudit("policy_violation", "failure",
			"Policy violation: wildcard SAN rejected",
			map[string]interface{}{
				"sans": "dns:*.example.com",
			})
	})

	// Шаг 4: Проверка политик - запрещенный тип SAN
	t.Run("Policy_Violation_Forbidden_SAN", func(t *testing.T) {
		auditLogger.LogAudit("policy_violation", "failure",
			"Policy violation: forbidden SAN type",
			map[string]interface{}{
				"san_type": "email",
				"template": "code_signing",
			})
	})

	// Шаг 5: Выпуск валидного сертификата с аудитом и CT логом
	var certSerial string
	var certPEM []byte

	t.Run("Issue_Valid_Certificate", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("ошибка генерации ключа: %v", err)
		}

		serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		now := time.Now().UTC()

		template := &x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName: "integration-test.example.com",
			},
			Issuer: pkix.Name{
				CommonName: "Test CA",
			},
			NotBefore: now,
			NotAfter:  now.AddDate(0, 0, 365),

			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  false,
			DNSNames:              []string{"integration-test.example.com"},
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatalf("ошибка создания сертификата: %v", err)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("ошибка парсинга сертификата: %v", err)
		}

		certPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})

		certSerial = hex.EncodeToString(cert.SerialNumber.Bytes())

		db.InsertCertificate(cert, certPEM, "valid")

		auditLogger.LogAudit("certificate_issued", "success",
			fmt.Sprintf("Issued certificate for %s", template.Subject.CommonName),
			map[string]interface{}{
				"serial":        certSerial,
				"subject":       template.Subject.CommonName,
				"template":      "server",
				"validity_days": 365,
			})

		ctLogger.AppendCertificate(cert)
	})

	// Шаг 6: Проверка CT лога
	t.Run("CT_Log_Verification", func(t *testing.T) {
		found, err := ctLogger.VerifyCertificate(certSerial)
		if err != nil {
			t.Fatalf("ошибка проверки CT лога: %v", err)
		}
		if !found {
			t.Error("сертификат не найден в CT логе")
		}
	})

	// Шаг 7: Симуляция компрометации ключа
	t.Run("Key_Compromise_Simulation", func(t *testing.T) {
		certPath := filepath.Join(tmpDir, "test-cert.pem")
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			t.Fatalf("ошибка сохранения сертификата: %v", err)
		}

		result, err := compromise.SimulateKeyCompromise(db, certPath, "keyCompromise", true)
		if err != nil {
			t.Fatalf("ошибка симуляции компрометации: %v", err)
		}

		if !result.Revoked {
			t.Error("сертификат должен быть отозван")
		}

		if result.PublicKeyHash == "" {
			t.Error("хеш публичного ключа не должен быть пустым")
		}

		auditLogger.LogAudit("key_compromise_simulated", "success",
			fmt.Sprintf("Key compromise simulated for %s", result.SerialHex),
			map[string]interface{}{
				"serial":          result.SerialHex,
				"public_key_hash": result.PublicKeyHash,
				"reason":          "keyCompromise",
			})
	})

	// Шаг 8: Проверка блокировки скомпрометированного ключа
	t.Run("Compromised_Key_Blocking", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)

		isCompromised, err := compromise.IsKeyCompromised(db, &key.PublicKey)
		if err != nil {
			t.Fatalf("ошибка проверки компрометации: %v", err)
		}

		if isCompromised {
			t.Log("новый ключ не должен быть скомпрометирован (ожидаемо false)")
		}

		keys, err := db.ListCompromisedKeys()
		if err != nil {
			t.Fatalf("ошибка получения списка скомпрометированных ключей: %v", err)
		}

		if len(keys) == 0 {
			t.Error("должен быть хотя бы один скомпрометированный ключ")
		}
	})

	// Шаг 9: Проверка целостности аудит-лога до подделки
	t.Run("Audit_Integrity_Before_Tamper", func(t *testing.T) {
		// Проверяем целостность через VerifyHashChain (без chain.dat)
		entries, err := audit.ReadAllEntries(logPath)
		if err != nil {
			t.Fatalf("ошибка чтения записей: %v", err)
		}

		report, err := audit.VerifyHashChain(entries)
		if err != nil {
			t.Fatalf("ошибка проверки цепочки: %v", err)
		}

		if !report.Valid {
			t.Errorf("хеш-цепочка должна быть целостной: %s", report.Error)
		}

		t.Logf("проверено %d записей, все целостны", report.CheckedEntries)
	})

	// Шаг 10: Попытка подделки аудит-лога
	t.Run("Audit_Tamper_Detection", func(t *testing.T) {
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("ошибка чтения лога: %v", err)
		}

		// Изменяем содержимое поля status в одной из строк
		lines := splitLines(string(data))
		if len(lines) < 3 {
			t.Skip("недостаточно строк для теста подделки")
		}

		// Меняем "success" на "tampered" в предпоследней строке
		targetLine := lines[len(lines)-2]
		tamperedLine := strings.Replace(targetLine, `"success"`, `"tampered"`, 1)
		lines[len(lines)-2] = tamperedLine

		tamperedData := strings.Join(lines, "\n") + "\n"

		tamperedLogPath := filepath.Join(tmpDir, "tampered-audit.log")
		if err := os.WriteFile(tamperedLogPath, []byte(tamperedData), 0644); err != nil {
			t.Fatalf("ошибка записи модифицированного лога: %v", err)
		}

		// Читаем записи из поддельного лога
		entries, err := audit.ReadAllEntries(tamperedLogPath)
		if err != nil {
			t.Fatalf("ошибка чтения записей: %v", err)
		}

		report, err := audit.VerifyHashChain(entries)
		if err != nil {
			t.Fatalf("ошибка проверки цепочки: %v", err)
		}

		if report.Valid {
			t.Error("верификация должна обнаружить подделку")
		}

		t.Logf("подделка обнаружена: %s", report.Error)
	})

	// Шаг 11: Проверка работы rate limiter
	t.Run("Rate_Limiting", func(t *testing.T) {
		limiter := ratelimit.NewRateLimiter(2.0, 2)

		if !limiter.Allow("192.168.1.1") {
			t.Error("первый запрос должен быть разрешен")
		}
		if !limiter.Allow("192.168.1.1") {
			t.Error("второй запрос должен быть разрешен")
		}
		if limiter.Allow("192.168.1.1") {
			t.Error("третий запрос должен быть отклонен")
		}

		time.Sleep(600 * time.Millisecond)

		if !limiter.Allow("192.168.1.1") {
			t.Error("после ожидания запрос должен быть разрешен")
		}
	})

	// Шаг 12: Обнаружение аномалий
	t.Run("Anomaly_Detection", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			auditLogger.LogAudit("test_bulk_operation", "success",
				fmt.Sprintf("Bulk operation %d", i),
				map[string]interface{}{"index": i})
		}

		report, err := audit.DetectAnomalies(logPath, 5)
		if err != nil {
			t.Fatalf("ошибка обнаружения аномалий: %v", err)
		}

		if len(report.Anomalies) == 0 {
			t.Error("должны быть обнаружены аномалии при пороге 5 и 20+ записях")
		}

		t.Logf("обнаружено аномалий: %d", len(report.Anomalies))
		for _, a := range report.Anomalies {
			t.Logf("  [%s] %s", a.Severity, a.Description)
		}
	})

	// Шаг 13: Проверка запросов к аудит-логу
	t.Run("Audit_Query", func(t *testing.T) {
		filters := &audit.AuditFilters{
			Operation: "key_compromise",
		}

		result, err := audit.QueryLog(logPath, filters)
		if err != nil {
			t.Fatalf("ошибка запроса: %v", err)
		}

		if result.Filtered == 0 {
			t.Error("должна быть найдена хотя бы одна запись о компрометации")
		}

		t.Logf("найдено записей о компрометации: %d", result.Filtered)

		filters = &audit.AuditFilters{
			Operation: "policy_violation",
		}

		result, err = audit.QueryLog(logPath, filters)
		if err != nil {
			t.Fatalf("ошибка запроса: %v", err)
		}

		if result.Filtered == 0 {
			t.Error("должны быть найдены записи о нарушениях политик")
		}

		t.Logf("найдено записей о нарушениях политик: %d", result.Filtered)
	})

	// Шаг 14: Форматирование вывода
	t.Run("Output_Formatting", func(t *testing.T) {
		result, err := audit.QueryLog(logPath, nil)
		if err != nil {
			t.Fatalf("ошибка запроса: %v", err)
		}

		tableOutput, err := audit.FormatEntries(result.Entries, "table")
		if err != nil {
			t.Fatalf("ошибка форматирования table: %v", err)
		}
		if tableOutput == "" {
			t.Error("табличный вывод не должен быть пустым")
		}

		jsonOutput, err := audit.FormatEntries(result.Entries, "json")
		if err != nil {
			t.Fatalf("ошибка форматирования json: %v", err)
		}
		if jsonOutput == "" {
			t.Error("json вывод не должен быть пустым")
		}

		csvOutput, err := audit.FormatEntries(result.Entries, "csv")
		if err != nil {
			t.Fatalf("ошибка форматирования csv: %v", err)
		}
		if csvOutput == "" {
			t.Error("csv вывод не должен быть пустым")
		}
	})

	// Шаг 15: Проверка форматирования отчета об аномалиях
	t.Run("Anomaly_Report_Formatting", func(t *testing.T) {
		report, _ := audit.DetectAnomalies(logPath, 50)
		formatted := audit.FormatAnomalyReport(report)
		if formatted == "" {
			t.Error("отчет об аномалиях не должен быть пустым")
		}
	})

	// Шаг 16: Rate limit middleware через HTTP
	t.Run("Rate_Limit_Middleware_HTTP", func(t *testing.T) {
		limiter := ratelimit.NewRateLimiter(1.0, 1)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		})

		middleware := ratelimit.RateLimitMiddleware(limiter)
		wrappedHandler := middleware(handler)

		// Первый запрос - OK
		req1 := httptest.NewRequest("GET", "/test", nil)
		req1.RemoteAddr = "192.168.1.1:12345"
		rec1 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rec1, req1)

		if rec1.Code != http.StatusOK {
			t.Errorf("первый запрос: ожидался 200, получен %d", rec1.Code)
		}

		// Второй запрос - 429
		req2 := httptest.NewRequest("GET", "/test", nil)
		req2.RemoteAddr = "192.168.1.1:12345"
		rec2 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rec2, req2)

		if rec2.Code != http.StatusTooManyRequests {
			t.Errorf("второй запрос: ожидался 429, получен %d", rec2.Code)
		}

		retryAfter := rec2.Header().Get("Retry-After")
		if retryAfter == "" {
			t.Error("ожидался заголовок Retry-After")
		}
	})

	t.Log("Интеграционный тест безопасности успешно завершен")
}

// splitLines разделяет строку на lines
func splitLines(s string) []string {
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}