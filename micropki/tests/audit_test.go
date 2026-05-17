package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"MicroPKI/internal/audit"
)

func TestAuditLoggerInitialization(t *testing.T) {
	tmpDir := t.TempDir()
	auditDir := filepath.Join(tmpDir, "audit")
	os.MkdirAll(auditDir, 0755)

	logPath := filepath.Join(auditDir, "audit.log")
	chainPath := filepath.Join(auditDir, "chain.dat")

	logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
	if err != nil {
		t.Fatalf("ошибка создания аудит-логгера: %v", err)
	}
	defer logger.Close()

	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("файл audit.log не создан")
	}
	if _, err := os.Stat(chainPath); os.IsNotExist(err) {
		t.Error("файл chain.dat не создан")
	}

	entries, err := audit.ReadAllEntries(logPath)
	if err != nil {
		t.Fatalf("ошибка чтения записей: %v", err)
	}

	if len(entries) == 0 {
		t.Fatal("нет записей в логе")
	}

	firstEntry := entries[0]
	if firstEntry.Integrity.PrevHash != "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Errorf("неверный prev_hash первой записи: %s", firstEntry.Integrity.PrevHash)
	}

	if firstEntry.Operation != "audit_log_initialized" {
		t.Errorf("неверная операция первой записи: %s", firstEntry.Operation)
	}
}

func TestAuditLogHashChain(t *testing.T) {
	tmpDir := t.TempDir()
	auditDir := filepath.Join(tmpDir, "audit")
	os.MkdirAll(auditDir, 0755)

	logPath := filepath.Join(auditDir, "audit.log")
	chainPath := filepath.Join(auditDir, "chain.dat")

	logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
	if err != nil {
		t.Fatalf("ошибка создания аудит-логгера: %v", err)
	}

	for i := 0; i < 5; i++ {
		err := logger.LogAudit("test_operation", "success",
			fmt.Sprintf("Test message %d", i),
			map[string]interface{}{
				"test_index": i,
			})
		if err != nil {
			t.Fatalf("ошибка записи в лог: %v", err)
		}
	}
	logger.Close()

	// Читаем записи напрямую
	entries, err := audit.ReadAllEntries(logPath)
	if err != nil {
		t.Fatalf("ошибка чтения записей: %v", err)
	}

	if len(entries) < 6 {
		t.Fatalf("недостаточно записей: %d, ожидалось минимум 6", len(entries))
	}

	// Проверяем что хеши не пустые
	for i, entry := range entries {
		if entry.Integrity.Hash == "" {
			t.Errorf("запись %d: хеш пустой", i)
		}
		if i > 0 && entry.Integrity.PrevHash == "" {
			t.Errorf("запись %d: prev_hash пустой", i)
		}
	}

	// Проверяем хеш-цепочку
	report, err := audit.VerifyHashChain(entries)
	if err != nil {
		t.Fatalf("ошибка проверки цепочки: %v", err)
	}

	if !report.Valid {
		t.Errorf("хеш-цепочка должна быть целостной: %s", report.Error)
	}

	if report.CheckedEntries < 5 {
		t.Errorf("проверено записей: %d, ожидалось минимум 5", report.CheckedEntries)
	}
}

func TestAuditLogTamperDetection(t *testing.T) {
	tmpDir := t.TempDir()
	auditDir := filepath.Join(tmpDir, "audit")
	os.MkdirAll(auditDir, 0755)

	logPath := filepath.Join(auditDir, "audit.log")
	chainPath := filepath.Join(auditDir, "chain.dat")

	logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
	if err != nil {
		t.Fatalf("ошибка создания аудит-логгера: %v", err)
	}

	for i := 0; i < 5; i++ {
		logger.LogAudit("test_operation", "success",
			fmt.Sprintf("Test message %d", i),
			map[string]interface{}{"index": i})
	}
	logger.Close()

	// Читаем лог как текст и модифицируем поле status в одной из строк
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ошибка чтения лога: %v", err)
	}

	lines := splitLinesTest(string(data))
	if len(lines) < 3 {
		t.Fatal("недостаточно строк для теста подделки")
	}

	// Меняем "success" на "tampered" в предпоследней строке
	targetLine := lines[len(lines)-2]
	tamperedLine := strings.Replace(targetLine, `"success"`, `"tampered"`, 1)
	lines[len(lines)-2] = tamperedLine

	tamperedData := strings.Join(lines, "\n") + "\n"

	if err := os.WriteFile(logPath, []byte(tamperedData), 0644); err != nil {
		t.Fatalf("ошибка записи модифицированного лога: %v", err)
	}

	report, err := audit.VerifyLogFile(logPath, chainPath)
	if err != nil {
		t.Fatalf("ошибка верификации: %v", err)
	}

	if report.Valid {
		t.Error("верификация должна обнаружить подделку, но лог считается целостным")
	}

	t.Logf("Обнаружено нарушение: %s", report.Error)
}

func TestAuditLogMissingEntry(t *testing.T) {
	tmpDir := t.TempDir()
	auditDir := filepath.Join(tmpDir, "audit")
	os.MkdirAll(auditDir, 0755)

	logPath := filepath.Join(auditDir, "audit.log")
	chainPath := filepath.Join(auditDir, "chain.dat")

	logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
	if err != nil {
		t.Fatalf("ошибка создания аудит-логгера: %v", err)
	}

	logger.LogAudit("test", "success", "Entry A", map[string]interface{}{"entry": "A"})
	logger.LogAudit("test", "success", "Entry B", map[string]interface{}{"entry": "B"})
	logger.LogAudit("test", "success", "Entry C", map[string]interface{}{"entry": "C"})
	logger.Close()

	entries, err := audit.ReadAllEntries(logPath)
	if err != nil {
		t.Fatalf("ошибка чтения записей: %v", err)
	}

	if len(entries) >= 4 {
		newEntries := append(entries[:2], entries[3:]...)

		f, err := os.Create(logPath)
		if err != nil {
			t.Fatalf("ошибка создания файла: %v", err)
		}
		defer f.Close()

		for _, entry := range newEntries {
			data, _ := marshalEntry(entry)
			f.Write(append(data, '\n'))
		}
	}

	report, err := audit.VerifyLogFile(logPath, chainPath)
	if err != nil {
		t.Fatalf("ошибка верификации: %v", err)
	}

	if report.Valid {
		t.Error("верификация должна обнаружить отсутствующую запись")
	}

	t.Logf("Обнаружено нарушение: %s", report.Error)
}

func TestAuditLogQuery(t *testing.T) {
	tmpDir := t.TempDir()
	auditDir := filepath.Join(tmpDir, "audit")
	os.MkdirAll(auditDir, 0755)

	logPath := filepath.Join(auditDir, "audit.log")
	chainPath := filepath.Join(auditDir, "chain.dat")

	logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
	if err != nil {
		t.Fatalf("ошибка создания аудит-логгера: %v", err)
	}

	baseTime := time.Now().UTC()

	logger.LogAudit("issue_certificate", "success", "Issued cert 1",
		map[string]interface{}{"serial": "abc123"})
	time.Sleep(10 * time.Millisecond)

	logger.LogAudit("revoke_certificate", "success", "Revoked cert 2",
		map[string]interface{}{"serial": "def456"})
	time.Sleep(10 * time.Millisecond)

	logger.LogAudit("issue_certificate", "success", "Issued cert 3",
		map[string]interface{}{"serial": "ghi789"})

	logger.Close()

	filters := &audit.AuditFilters{
		Operation: "revoke",
	}
	result, err := audit.QueryLog(logPath, filters)
	if err != nil {
		t.Fatalf("ошибка запроса: %v", err)
	}

	if result.Filtered != 1 {
		t.Errorf("ожидалась 1 запись с операцией revoke, получено: %d", result.Filtered)
	}

	filters = &audit.AuditFilters{
		Serial: "abc123",
	}
	result, err = audit.QueryLog(logPath, filters)
	if err != nil {
		t.Fatalf("ошибка запроса: %v", err)
	}

	if result.Filtered != 1 {
		t.Errorf("ожидалась 1 запись с serial abc123, получено: %d", result.Filtered)
	}

	filters = &audit.AuditFilters{
		From: baseTime,
	}
	result, err = audit.QueryLog(logPath, filters)
	if err != nil {
		t.Fatalf("ошибка запроса: %v", err)
	}

	if result.Filtered < 3 {
		t.Errorf("ожидалось минимум 3 записи после %s, получено: %d",
			baseTime.Format(time.RFC3339), result.Filtered)
	}
}

func TestAnomalyDetection(t *testing.T) {
	tmpDir := t.TempDir()
	auditDir := filepath.Join(tmpDir, "audit")
	os.MkdirAll(auditDir, 0755)

	logPath := filepath.Join(auditDir, "audit.log")
	chainPath := filepath.Join(auditDir, "chain.dat")

	logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
	if err != nil {
		t.Fatalf("ошибка создания аудит-логгера: %v", err)
	}

	for i := 0; i < 50; i++ {
		logger.LogAudit("test_operation", "success",
			fmt.Sprintf("Bulk test %d", i),
			map[string]interface{}{"index": i})
	}
	logger.Close()

	report, err := audit.DetectAnomalies(logPath, 10)
	if err != nil {
		t.Fatalf("ошибка обнаружения аномалий: %v", err)
	}

	if len(report.Anomalies) == 0 {
		t.Error("должна быть обнаружена хотя бы одна аномалия при пороге 10 и 50 записях")
	}

	t.Logf("Найдено аномалий: %d", len(report.Anomalies))
	for _, a := range report.Anomalies {
		t.Logf("  [%s] %s: %s", a.Severity, a.Type, a.Description)
	}
}

func TestAnomalyReportFormatting(t *testing.T) {
	tmpDir := t.TempDir()
	auditDir := filepath.Join(tmpDir, "audit")
	os.MkdirAll(auditDir, 0755)

	logPath := filepath.Join(auditDir, "audit.log")
	chainPath := filepath.Join(auditDir, "chain.dat")

	logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
	if err != nil {
		t.Fatalf("ошибка создания аудит-логгера: %v", err)
	}

	logger.LogAudit("issue_certificate", "success", "Issued cert", map[string]interface{}{"serial": "abc"})
	logger.LogAudit("revoke_certificate", "success", "Revoked cert", map[string]interface{}{"serial": "def"})
	logger.LogAudit("key_compromise", "success", "Key compromised", map[string]interface{}{"serial": "ghi"})
	logger.LogError("test_error", "failure", "Test error", nil)
	logger.Close()

	report, err := audit.DetectAnomalies(logPath, 1)
	if err != nil {
		t.Fatalf("ошибка обнаружения аномалий: %v", err)
	}

	formatted := audit.FormatAnomalyReport(report)
	if formatted == "" {
		t.Error("форматированный отчет не должен быть пустым")
	}

	t.Logf("Отчет:\n%s", formatted)
}

func marshalEntry(entry audit.AuditEntry) ([]byte, error) {
	return json.Marshal(entry)
}

func splitLinesTest(s string) []string {
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}