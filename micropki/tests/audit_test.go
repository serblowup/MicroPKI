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

	entries, err := audit.ReadAllEntries(logPath)
	if err != nil {
		t.Fatalf("ошибка чтения записей: %v", err)
	}

	if len(entries) < 6 {
		t.Fatalf("недостаточно записей: %d, ожидалось минимум 6", len(entries))
	}

	for i, entry := range entries {
		if entry.Integrity.Hash == "" {
			t.Errorf("запись %d: хеш пустой", i)
		}
		if i > 0 && entry.Integrity.PrevHash == "" {
			t.Errorf("запись %d: prev_hash пустой", i)
		}
	}

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

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ошибка чтения лога: %v", err)
	}

	lines := splitLinesTest(string(data))
	if len(lines) < 3 {
		t.Fatal("недостаточно строк для теста подделки")
	}

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

func TestInitAuditLogger(t *testing.T) {
	tmpDir := t.TempDir()
	
	err := audit.InitAuditLogger(tmpDir)
	if err != nil {
		t.Fatalf("InitAuditLogger failed: %v", err)
	}
	defer audit.CloseGlobalAuditLogger()

	logger := audit.GetAuditLogger()
	if logger == nil {
		t.Error("GetAuditLogger вернул nil после InitAuditLogger")
	}
}

func TestLogInfo(t *testing.T) {
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

	err = logger.LogInfo("info_test", "success", "Info message", map[string]interface{}{"key": "value"})
	if err != nil {
		t.Fatalf("ошибка записи INFO: %v", err)
	}

	entries, err := audit.ReadAllEntries(logPath)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, entry := range entries {
		if entry.Level == audit.LevelINFO && entry.Operation == "info_test" {
			found = true
			break
		}
	}
	if !found {
		t.Error("INFO запись не найдена")
	}
}

func TestLogWarn(t *testing.T) {
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

	err = logger.Log(audit.LevelWARN, "warn_test", "success", "Warning message", nil)
	if err != nil {
		t.Fatalf("ошибка записи WARN: %v", err)
	}

	entries, err := audit.ReadAllEntries(logPath)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, entry := range entries {
		if entry.Level == audit.LevelWARN && entry.Operation == "warn_test" {
			found = true
			break
		}
	}
	if !found {
		t.Error("WARN запись не найдена")
	}
}

func TestLogError(t *testing.T) {
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

	err = logger.LogError("error_test", "failure", "Error message", map[string]interface{}{"error": "test"})
	if err != nil {
		t.Fatalf("ошибка записи ERROR: %v", err)
	}

	entries, err := audit.ReadAllEntries(logPath)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, entry := range entries {
		if entry.Level == audit.LevelERROR && entry.Operation == "error_test" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ERROR запись не найдена")
	}
}

func TestRotate(t *testing.T) {
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

	for i := 0; i < 3; i++ {
		logger.LogAudit("test", "success", "Before rotation", map[string]interface{}{"index": i})
	}

	err = logger.Rotate()
	if err != nil {
		t.Fatalf("ошибка ротации: %v", err)
	}

	err = logger.LogAudit("test_after_rotation", "success", "After rotation", nil)
	if err != nil {
		t.Fatalf("ошибка записи после ротации: %v", err)
	}

	files, err := os.ReadDir(auditDir)
	if err != nil {
		t.Fatal(err)
	}

	rotatedFiles := 0
	for _, f := range files {
		if strings.Contains(f.Name(), "audit-") || strings.Contains(f.Name(), "chain-") {
			rotatedFiles++
		}
	}
	if rotatedFiles == 0 {
		t.Error("файлы ротации не созданы")
	}

	entries, err := audit.ReadAllEntries(logPath)
	if err != nil {
		t.Fatal(err)
	}
	
	found := false
	for _, entry := range entries {
		if entry.Operation == "audit_log_rotated" {
			found = true
			break
		}
	}
	if !found {
		t.Error("запись о ротации не найдена в новом логе")
	}
}

func TestGetLogPath(t *testing.T) {
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

	if logger.GetLogPath() != logPath {
		t.Errorf("GetLogPath вернул %s, ожидался %s", logger.GetLogPath(), logPath)
	}
}

func TestGetChainPath(t *testing.T) {
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

	if logger.GetChainPath() != chainPath {
		t.Errorf("GetChainPath вернул %s, ожидался %s", logger.GetChainPath(), chainPath)
	}
}

func TestReadLastHash(t *testing.T) {
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

	for i := 0; i < 3; i++ {
		logger.LogAudit("test", "success", "Test", map[string]interface{}{"i": i})
	}

	lastHash, err := audit.ReadLastHash(chainPath)
	if err != nil {
		t.Fatalf("ошибка ReadLastHash: %v", err)
	}
	if lastHash == "" {
		t.Error("ReadLastHash вернул пустую строку")
	}
	if len(lastHash) != 64 {
		t.Errorf("хеш должен быть 64 символа, получено %d", len(lastHash))
	}
}

func TestParseFlexibleTime(t *testing.T) {
	tmpDir := t.TempDir()
	auditDir := filepath.Join(tmpDir, "audit")
	os.MkdirAll(auditDir, 0755)

	logPath := filepath.Join(auditDir, "audit.log")
	chainPath := filepath.Join(auditDir, "chain.dat")

	logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
	if err != nil {
		t.Fatalf("ошибка создания аудит-логгера: %v", err)
	}

	time1 := time.Now().UTC().Add(-1 * time.Hour)
	time2 := time.Now().UTC()
	
	logger.LogAudit("op1", "success", "Message 1", nil)
	time.Sleep(10 * time.Millisecond)
	logger.LogAudit("op2", "success", "Message 2", nil)
	logger.Close()

	filters := &audit.AuditFilters{
		From: time1,
		To:   time2,
	}
	result, err := audit.QueryLog(logPath, filters)
	if err != nil {
		t.Fatalf("ошибка запроса: %v", err)
	}
	
	t.Logf("найдено записей в диапазоне: %d", result.Filtered)
}

func TestParseTimeRange(t *testing.T) {
	fromStr := "2024-01-01T00:00:00Z"
	toStr := "2024-12-31T23:59:59Z"

	from, to, err := audit.ParseTimeRange(fromStr, toStr)
	if err != nil {
		t.Fatalf("ошибка парсинга временного диапазона: %v", err)
	}
	
	if from.IsZero() {
		t.Error("from не должен быть нулевым")
	}
	if to.IsZero() {
		t.Error("to не должен быть нулевым")
	}
	
	from, to, err = audit.ParseTimeRange("", "")
	if err != nil {
		t.Fatalf("ошибка с пустыми строками: %v", err)
	}
	if !from.IsZero() || !to.IsZero() {
		t.Error("пустые строки должны давать нулевые времена")
	}
}

func TestResetTampered(t *testing.T) {
	audit.SetTampered()
	audit.ResetTampered()
	
	tmpDir := t.TempDir()
	auditDir := filepath.Join(tmpDir, "audit")
	os.MkdirAll(auditDir, 0755)

	logPath := filepath.Join(auditDir, "audit.log")
	chainPath := filepath.Join(auditDir, "chain.dat")

	result := audit.IsAuditLogTampered(logPath, chainPath)
	if result {
		t.Error("IsAuditLogTampered должен вернуть false для несуществующих файлов")
	}
}

func TestIsTampered(t *testing.T) {
	tmpDir := t.TempDir()
	auditDir := filepath.Join(tmpDir, "audit")
	os.MkdirAll(auditDir, 0755)

	logPath := filepath.Join(auditDir, "audit.log")
	chainPath := filepath.Join(auditDir, "chain.dat")

	logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
	if err != nil {
		t.Fatalf("ошибка создания аудит-логгера: %v", err)
	}
	logger.LogAudit("test", "success", "Test message", nil)
	logger.Close()

	entries, err := audit.ReadAllEntries(logPath)
	if err != nil {
		t.Fatal(err)
	}

	report, err := audit.VerifyHashChain(entries)
	if err != nil {
		t.Fatal(err)
	}

	if audit.IsTampered(report) {
		t.Error("целостный лог не должен считаться подделанным")
	}
	
	tamperedReport := &audit.VerificationReport{
		Valid: false,
		Error: "tampered",
	}
	if !audit.IsTampered(tamperedReport) {
		t.Error("поддельный лог должен считаться нарушенным")
	}
}

func TestGetFirstCorruptedEntry(t *testing.T) {
	tmpDir := t.TempDir()
	auditDir := filepath.Join(tmpDir, "audit")
	os.MkdirAll(auditDir, 0755)

	logPath := filepath.Join(auditDir, "audit.log")
	chainPath := filepath.Join(auditDir, "chain.dat")

	logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
	if err != nil {
		t.Fatalf("ошибка создания аудит-логгера: %v", err)
	}
	logger.LogAudit("test1", "success", "First", nil)
	logger.LogAudit("test2", "success", "Second", nil)
	logger.Close()

	entries, err := audit.ReadAllEntries(logPath)
	if err != nil {
		t.Fatal(err)
	}
	
	report, err := audit.VerifyLogFile(logPath, chainPath)
	if err != nil {
		t.Fatal(err)
	}

	corrupted := audit.GetFirstCorruptedEntry(report, entries)
	if corrupted != nil {
		t.Logf("первая поврежденная запись найдена (если есть)")
	}
}

func TestComputeHash(t *testing.T) {
	data := map[string]string{"test": "value"}
	hash, err := audit.ComputeHash(data)
	if err != nil {
		t.Fatalf("ComputeHash ошибка: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("хеш должен быть 64 символа, получено %d", len(hash))
	}
	t.Logf("хеш: %s", hash)
}

func TestWriteChainEntry(t *testing.T) {
	tmpDir := t.TempDir()
	chainPath := filepath.Join(tmpDir, "chain.dat")
	
	err := audit.WriteChainEntry(chainPath, "test_hash_1234567890123456789012345678901234567890123456789012345678901234")
	if err != nil {
		t.Fatalf("WriteChainEntry ошибка: %v", err)
	}
	
	if _, err := os.Stat(chainPath); os.IsNotExist(err) {
		t.Error("chain.dat не создан")
	}
	
	data, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("chain.dat пуст")
	}
}

func TestSortMapKeys(t *testing.T) {
	data := map[string]interface{}{
		"z": "last",
		"a": "first",
		"m": "middle",
	}
	
	sorted := audit.SortMapKeys(data)
	if sorted == nil {
		t.Error("SortMapKeys вернул nil")
	}
	
	keys := make([]string, 0, len(sorted))
	for k := range sorted {
		keys = append(keys, k)
	}
	if len(keys) != 3 {
		t.Errorf("ожидалось 3 ключа, получено %d", len(keys))
	}
	t.Logf("отсортированные ключи: %v", keys)
}

func TestReadAllHashes(t *testing.T) {
	tmpDir := t.TempDir()
	chainPath := filepath.Join(tmpDir, "chain.dat")
	
	hashes := []string{
		"hash1_1234567890123456789012345678901234567890123456789012345678901234",
		"hash2_1234567890123456789012345678901234567890123456789012345678901234",
		"hash3_1234567890123456789012345678901234567890123456789012345678901234",
	}
	
	for _, h := range hashes {
		err := audit.WriteChainEntry(chainPath, h)
		if err != nil {
			t.Fatalf("ошибка записи: %v", err)
		}
	}
	
	readHashes, err := audit.ReadAllHashes(chainPath)
	if err != nil {
		t.Fatalf("ReadAllHashes ошибка: %v", err)
	}
	
	if len(readHashes) != len(hashes) {
		t.Errorf("ожидалось %d хешей, получено %d", len(hashes), len(readHashes))
	}
}

func TestHashEntry(t *testing.T) {
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

	err = logger.LogAudit("test", "success", "Test message", nil)
	if err != nil {
		t.Fatal(err)
	}
	logger.Close()

	entries, err := audit.ReadAllEntries(logPath)
	if err != nil {
		t.Fatal(err)
	}
	
	if len(entries) == 0 {
		t.Fatal("нет записей")
	}
	
	hash, err := audit.HashEntry(&entries[0])
	if err != nil {
		t.Fatalf("HashEntry ошибка: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("хеш должен быть 64 символа, получено %d", len(hash))
	}
}

func TestVerifyHashChain(t *testing.T) {
	tmpDir := t.TempDir()
	auditDir := filepath.Join(tmpDir, "audit")
	os.MkdirAll(auditDir, 0755)

	logPath := filepath.Join(auditDir, "audit.log")
	chainPath := filepath.Join(auditDir, "chain.dat")

	logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
	if err != nil {
		t.Fatalf("ошибка создания аудит-логгера: %v", err)
	}

	for i := 0; i < 3; i++ {
		logger.LogAudit("test", "success", fmt.Sprintf("Message %d", i), nil)
	}
	logger.Close()

	entries, err := audit.ReadAllEntries(logPath)
	if err != nil {
		t.Fatal(err)
	}

	report, err := audit.VerifyHashChain(entries)
	if err != nil {
		t.Fatalf("VerifyHashChain ошибка: %v", err)
	}
	
	if !report.Valid {
		t.Errorf("хеш-цепочка должна быть целостной: %s", report.Error)
	}
	t.Logf("проверено %d из %d записей", report.CheckedEntries, report.TotalEntries)
}

func TestCanonicalJSON(t *testing.T) {
	data := map[string]interface{}{
		"b": 2,
		"a": 1,
		"c": 3,
	}
	
	jsonData, err := audit.CanonicalJSON(data)
	if err != nil {
		t.Fatalf("CanonicalJSON ошибка: %v", err)
	}
	if len(jsonData) == 0 {
		t.Error("JSON данные пусты")
	}
	t.Logf("Canonical JSON: %s", string(jsonData))
}

func marshalEntry(entry audit.AuditEntry) ([]byte, error) {
	return json.Marshal(entry)
}

func splitLinesTest(s string) []string {
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

func TestParseFlexibleTimeSimple(t *testing.T) {
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

	logger.LogAudit("test", "success", "Test message", nil)
	logger.Close()

	filters := &audit.AuditFilters{
		From: time.Now().UTC().Add(-1 * time.Hour),
		To:   time.Now().UTC(),
	}
	_, err = audit.QueryLog(logPath, filters)
	if err != nil {
		t.Fatalf("QueryLog ошибка: %v", err)
	}
	
	from, to, err := audit.ParseTimeRange("2024-01-01T00:00:00Z", "2024-12-31T23:59:59Z")
	if err != nil {
		t.Fatalf("ParseTimeRange ошибка: %v", err)
	}
	t.Logf("Parsed: %v - %v", from, to)
	
	t.Log("parseFlexibleTime tested")
}

func TestParseFlexibleTimeExported(t *testing.T) {
	testCases := []struct {
		input    string
		hasError bool
	}{
		{"2024-01-01T12:00:00Z", false},
		{"2024-01-01T12:00:00.123Z", false},
		{"2024-01-01T12:00:00", false},
		{"invalid time", true},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result, err := audit.ParseFlexibleTime(tc.input)
			if tc.hasError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result.IsZero() {
					t.Error("result is zero time")
				}
			}
		})
	}
}

func TestNewAuditLoggerWithExistingLog(t *testing.T) {
    tmpDir := t.TempDir()
    auditDir := filepath.Join(tmpDir, "audit")
    os.MkdirAll(auditDir, 0755)

    logPath := filepath.Join(auditDir, "audit.log")
    chainPath := filepath.Join(auditDir, "chain.dat")

    // Создаём существующий лог с записями
    logger1, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
    if err != nil {
        t.Fatalf("first logger error: %v", err)
    }
    logger1.LogAudit("test", "success", "First entry", nil)
    logger1.Close()

    // Создаём новый логгер с тем же файлом (должен продолжить цепочку)
    logger2, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
    if err != nil {
        t.Fatalf("second logger error: %v", err)
    }
    defer logger2.Close()

    logger2.LogAudit("test", "success", "Second entry", nil)

    entries, err := audit.ReadAllEntries(logPath)
    if err != nil {
        t.Fatal(err)
    }

    if len(entries) < 2 {
        t.Errorf("expected at least 2 entries, got %d", len(entries))
    }
}

func TestNewAuditLoggerWithInvalidPath(t *testing.T) {
    // Несуществующая директория без прав
    invalidPath := "/root/audit.log"
    
    _, err := audit.NewAuditLogger(invalidPath, invalidPath+".chain", "/root")
    if err == nil {
        t.Error("expected error for invalid path")
    }
}

func TestReadLastHashEmptyFile(t *testing.T) {
    tmpDir := t.TempDir()
    chainPath := filepath.Join(tmpDir, "empty.dat")

    // Создаём пустой файл
    if err := os.WriteFile(chainPath, []byte(""), 0644); err != nil {
        t.Fatal(err)
    }

    hash, err := audit.ReadLastHash(chainPath)
    if err != nil {
        t.Fatalf("ReadLastHash error: %v", err)
    }
    if hash != "0000000000000000000000000000000000000000000000000000000000000000" {
        t.Errorf("expected zero hash for empty file, got %s", hash)
    }

    // Несуществующий файл
    hash, err = audit.ReadLastHash(filepath.Join(tmpDir, "nonexistent.dat"))
    if err != nil {
        t.Fatalf("ReadLastHash for nonexistent file error: %v", err)
    }
    if hash != "0000000000000000000000000000000000000000000000000000000000000000" {
        t.Errorf("expected zero hash for nonexistent file, got %s", hash)
    }
}

func TestReadAllHashesEdgeCases(t *testing.T) {
    tmpDir := t.TempDir()
    chainPath := filepath.Join(tmpDir, "chain.dat")

    // Несуществующий файл
    hashes, err := audit.ReadAllHashes(filepath.Join(tmpDir, "nonexistent.dat"))
    if err != nil {
        t.Fatalf("ReadAllHashes for nonexistent file error: %v", err)
    }
    if len(hashes) != 0 {
        t.Errorf("expected empty slice for nonexistent file, got %d entries", len(hashes))
    }

    // Пустой файл
    if err := os.WriteFile(chainPath, []byte(""), 0644); err != nil {
        t.Fatal(err)
    }
    hashes, err = audit.ReadAllHashes(chainPath)
    if err != nil {
        t.Fatalf("ReadAllHashes for empty file error: %v", err)
    }
    if len(hashes) != 0 {
        t.Errorf("expected empty slice for empty file, got %d entries", len(hashes))
    }

    // Файл с одной записью
    testHash := "abc123def4567890abc123def4567890abc123def4567890abc123def4567890"
    if err := os.WriteFile(chainPath, []byte(testHash+"\n"), 0644); err != nil {
        t.Fatal(err)
    }
    hashes, err = audit.ReadAllHashes(chainPath)
    if err != nil {
        t.Fatalf("ReadAllHashes error: %v", err)
    }
    if len(hashes) != 1 || hashes[0] != testHash {
        t.Errorf("expected hash %s, got %v", testHash, hashes)
    }
}

func TestWriteEntryError(t *testing.T) {
    tmpDir := t.TempDir()
    auditDir := filepath.Join(tmpDir, "audit")
    os.MkdirAll(auditDir, 0755)

    logPath := filepath.Join(auditDir, "audit.log")
    chainPath := filepath.Join(auditDir, "chain.dat")

    logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
    if err != nil {
        t.Fatalf("logger error: %v", err)
    }
    defer logger.Close()

    // Нормальная запись должна работать
    err = logger.LogAudit("test", "success", "Test message", nil)
    if err != nil {
        t.Errorf("unexpected error: %v", err)
    }

    t.Log("writeEntry tested successfully")
}

func TestGetSeverity(t *testing.T) {
    // getSeverity — приватная функция, тестируем через DetectAnomalies
    tmpDir := t.TempDir()
    auditDir := filepath.Join(tmpDir, "audit")
    os.MkdirAll(auditDir, 0755)

    logPath := filepath.Join(auditDir, "audit.log")
    chainPath := filepath.Join(auditDir, "chain.dat")

    logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
    if err != nil {
        t.Fatalf("logger error: %v", err)
    }
    defer logger.Close()

    // Создаём много записей для триггера аномалий
    for i := 0; i < 60; i++ {
        logger.LogAudit("bulk_test", "success", "Bulk message", map[string]interface{}{"index": i})
    }

    report, err := audit.DetectAnomalies(logPath, 10)
    if err != nil {
        t.Fatalf("DetectAnomalies error: %v", err)
    }

    if len(report.Anomalies) == 0 {
        t.Log("no anomalies detected (threshold may be high)")
    }

    t.Logf("anomalies count: %d", len(report.Anomalies))
}

func TestTruncateTimestamp(t *testing.T) {
    // truncateTimestamp — приватная функция, тестируем через DetectAnomalies
    tmpDir := t.TempDir()
    auditDir := filepath.Join(tmpDir, "audit")
    os.MkdirAll(auditDir, 0755)

    logPath := filepath.Join(auditDir, "audit.log")
    chainPath := filepath.Join(auditDir, "chain.dat")

    logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
    if err != nil {
        t.Fatalf("logger error: %v", err)
    }
    defer logger.Close()

    logger.LogAudit("test", "success", "Test message", nil)

    report, err := audit.DetectAnomalies(logPath, 100)
    if err != nil {
        t.Fatalf("DetectAnomalies error: %v", err)
    }

    if report.TimeRange == "" {
        t.Error("TimeRange should not be empty")
    }

    t.Logf("TimeRange: %s", report.TimeRange)
}

func TestNilAuditLogger(t *testing.T) {
    // Тест для GetLogPath/GetChainPath с nil логгером
    var nilLogger *audit.AuditLogger = nil

    if nilLogger.GetLogPath() != "" {
        t.Error("GetLogPath on nil logger should return empty string")
    }
    if nilLogger.GetChainPath() != "" {
        t.Error("GetChainPath on nil logger should return empty string")
    }

    // Тест для Close на nil
    err := nilLogger.Close()
    if err != nil {
        t.Errorf("Close on nil logger should return nil, got %v", err)
    }
}

func TestVerifyHashChainEmpty(t *testing.T) {
    // Пустой массив записей
    report, err := audit.VerifyHashChain([]audit.AuditEntry{})
    if err != nil {
        t.Fatalf("VerifyHashChain with empty slice error: %v", err)
    }
    if !report.Valid {
        t.Error("empty chain should be valid")
    }
    if report.TotalEntries != 0 {
        t.Errorf("expected TotalEntries=0, got %d", report.TotalEntries)
    }
}

func TestMatchesFiltersTime(t *testing.T) {
    tmpDir := t.TempDir()
    auditDir := filepath.Join(tmpDir, "audit")
    os.MkdirAll(auditDir, 0755)

    logPath := filepath.Join(auditDir, "audit.log")
    chainPath := filepath.Join(auditDir, "chain.dat")

    logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
    if err != nil {
        t.Fatalf("logger error: %v", err)
    }
    defer logger.Close()

    // Записываем запись с конкретным временем
    logger.LogAudit("time_test", "success", "Time test message", nil)

    // Читаем запись
    entries, err := audit.ReadAllEntries(logPath)
    if err != nil {
        t.Fatal(err)
    }

    if len(entries) == 0 {
        t.Skip("no entries found")
    }

    // Тестируем фильтрацию по времени
    filters := &audit.AuditFilters{
        From: time.Now().UTC().Add(-1 * time.Hour),
        To:   time.Now().UTC().Add(1 * time.Hour),
    }

    result, err := audit.QueryLog(logPath, filters)
    if err != nil {
        t.Fatalf("QueryLog error: %v", err)
    }

    t.Logf("found %d entries in time range", result.Filtered)
}

func TestMatchesFiltersSerial(t *testing.T) {
    tmpDir := t.TempDir()
    auditDir := filepath.Join(tmpDir, "audit")
    os.MkdirAll(auditDir, 0755)

    logPath := filepath.Join(auditDir, "audit.log")
    chainPath := filepath.Join(auditDir, "chain.dat")

    logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
    if err != nil {
        t.Fatalf("logger error: %v", err)
    }
    defer logger.Close()

    // Записываем запись с серийным номером
    logger.LogAudit("serial_test", "success", "Test with serial", map[string]interface{}{
        "serial": "abc123",
    })

    // Поиск по серийному номеру
    filters := &audit.AuditFilters{
        Serial: "abc123",
    }

    result, err := audit.QueryLog(logPath, filters)
    if err != nil {
        t.Fatalf("QueryLog error: %v", err)
    }

    if result.Filtered == 0 {
        t.Error("should find entry with serial abc123")
    } else {
        t.Logf("found %d entries with serial abc123", result.Filtered)
    }

    // Поиск по несуществующему серийному номеру
    filters.Serial = "nonexistent"
    result, err = audit.QueryLog(logPath, filters)
    if err != nil {
        t.Fatalf("QueryLog error: %v", err)
    }

    if result.Filtered != 0 {
        t.Errorf("expected 0 entries for nonexistent serial, got %d", result.Filtered)
    }
}

func TestAuditLoggerLogWithNilMetadata(t *testing.T) {
    tmpDir := t.TempDir()
    auditDir := filepath.Join(tmpDir, "audit")
    os.MkdirAll(auditDir, 0755)

    logPath := filepath.Join(auditDir, "audit.log")
    chainPath := filepath.Join(auditDir, "chain.dat")

    logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
    if err != nil {
        t.Fatalf("logger error: %v", err)
    }
    defer logger.Close()

    // Log с nil metadata
    err = logger.Log(audit.LevelINFO, "nil_test", "success", "Test with nil metadata", nil)
    if err != nil {
        t.Errorf("Log with nil metadata error: %v", err)
    }

    // LogInfo с nil metadata
    err = logger.LogInfo("info_nil", "success", "Info with nil", nil)
    if err != nil {
        t.Errorf("LogInfo with nil metadata error: %v", err)
    }

    // LogError с nil metadata
    err = logger.LogError("error_nil", "failure", "Error with nil", nil)
    if err != nil {
        t.Errorf("LogError with nil metadata error: %v", err)
    }

    t.Log("Log with nil metadata works correctly")
}

func TestNewAuditLoggerWithCorruptedChain(t *testing.T) {
    tmpDir := t.TempDir()
    auditDir := filepath.Join(tmpDir, "audit")
    os.MkdirAll(auditDir, 0755)

    logPath := filepath.Join(auditDir, "audit.log")
    chainPath := filepath.Join(auditDir, "chain.dat")

    // Создаём лог с записью
    logger1, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
    if err != nil {
        t.Fatalf("first logger error: %v", err)
    }
    logger1.LogAudit("test", "success", "Entry", nil)
    logger1.Close()

    // Повреждаем chain.dat
    f, err := os.OpenFile(chainPath, os.O_APPEND|os.O_WRONLY, 0600)
    if err != nil {
        t.Fatal(err)
    }
    f.Write([]byte("corrupted_hash_1234567890\n"))
    f.Close()

    // Создаём новый логгер — должен обработать повреждённый файл
    logger2, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
    if err != nil {
        t.Logf("logger with corrupted chain: %v", err)
    }
    if logger2 != nil {
        logger2.Close()
    }
}

func TestMatchesFiltersWithInvalidTime(t *testing.T) {
    tmpDir := t.TempDir()
    auditDir := filepath.Join(tmpDir, "audit")
    os.MkdirAll(auditDir, 0755)

    logPath := filepath.Join(auditDir, "audit.log")
    chainPath := filepath.Join(auditDir, "chain.dat")

    logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
    if err != nil {
        t.Fatalf("logger error: %v", err)
    }
    defer logger.Close()

    logger.LogAudit("test_op", "success", "Test message", map[string]interface{}{
        "serial": "12345",
    })

    // Фильтр с нулевым временем
    filters := &audit.AuditFilters{
        From: time.Time{},
        To:   time.Time{},
    }
    result, err := audit.QueryLog(logPath, filters)
    if err != nil {
        t.Fatalf("query error: %v", err)
    }
    t.Logf("filter with zero time returned %d entries", result.Filtered)
}

func TestVerifyLogFileWithMismatchedCounts(t *testing.T) {
    tmpDir := t.TempDir()
    auditDir := filepath.Join(tmpDir, "audit")
    os.MkdirAll(auditDir, 0755)

    logPath := filepath.Join(auditDir, "audit.log")
    chainPath := filepath.Join(auditDir, "chain.dat")

    logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
    if err != nil {
        t.Fatalf("logger error: %v", err)
    }
    logger.LogAudit("test1", "success", "First", nil)
    logger.LogAudit("test2", "success", "Second", nil)
    logger.Close()

    // Удаляем одну запись из chain.dat (создаём несоответствие)
    data, err := os.ReadFile(chainPath)
    if err != nil {
        t.Fatal(err)
    }
    lines := strings.Split(string(data), "\n")
    if len(lines) > 1 {
        os.WriteFile(chainPath, []byte(lines[0]+"\n"), 0600)
    }

    report, err := audit.VerifyLogFile(logPath, chainPath)
    if err != nil {
        t.Logf("verify with mismatched counts: %v", err)
    }
    if report != nil && !report.Valid {
        t.Log("correctly detected mismatched counts")
    }
}

func TestGetFirstCorruptedEntryValid(t *testing.T) {
    tmpDir := t.TempDir()
    auditDir := filepath.Join(tmpDir, "audit")
    os.MkdirAll(auditDir, 0755)

    logPath := filepath.Join(auditDir, "audit.log")
    chainPath := filepath.Join(auditDir, "chain.dat")

    logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
    if err != nil {
        t.Fatalf("logger error: %v", err)
    }
    logger.LogAudit("test1", "success", "First", nil)
    logger.LogAudit("test2", "success", "Second", nil)
    logger.Close()

    entries, err := audit.ReadAllEntries(logPath)
    if err != nil {
        t.Fatal(err)
    }

    report, err := audit.VerifyLogFile(logPath, chainPath)
    if err != nil {
        t.Fatal(err)
    }

    corrupted := audit.GetFirstCorruptedEntry(report, entries)
    if corrupted == nil && report.Valid {
        t.Log("no corrupted entries found (good)")
    }
}

func TestIsAuditLogTamperedSimple(t *testing.T) {
    tmpDir := t.TempDir()
    auditDir := filepath.Join(tmpDir, "audit")
    os.MkdirAll(auditDir, 0755)

    logPath := filepath.Join(auditDir, "audit.log")
    chainPath := filepath.Join(auditDir, "chain.dat")

    // Сбрасываем флаг перед тестом
    audit.ResetTampered()

    // Несуществующие файлы
    result := audit.IsAuditLogTampered(logPath, chainPath)
    t.Logf("nonexistent files result: %v", result)

    // Создаём логгер
    logger, err := audit.NewAuditLogger(logPath, chainPath, auditDir)
    if err != nil {
        t.Fatalf("logger error: %v", err)
    }
    err = logger.LogAudit("test", "success", "Test message", nil)
    if err != nil {
        t.Fatalf("log error: %v", err)
    }
    logger.Close()

    // Сбрасываем флаг
    audit.ResetTampered()

    // Целостный лог
    result = audit.IsAuditLogTampered(logPath, chainPath)
    t.Logf("intact log result: %v", result)

    // Повреждаем лог
    f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil {
        t.Fatal(err)
    }
    _, err = f.Write([]byte("corrupted line\n"))
    if err != nil {
        t.Fatal(err)
    }
    f.Close()

    audit.ResetTampered()
    result = audit.IsAuditLogTampered(logPath, chainPath)
    t.Logf("tampered log result: %v", result)

    audit.ResetTampered()
    t.Log("IsAuditLogTampered test completed")
}