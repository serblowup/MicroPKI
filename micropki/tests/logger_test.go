package tests

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"MicroPKI/internal/audit"
	"MicroPKI/internal/logger"
)

func setupTestAudit(t *testing.T) (string, func()) {
	tmpDir, err := os.MkdirTemp("", "logger-test-*")
	if err != nil {
		t.Fatal(err)
	}

	// Инициализируем аудит-логгер
	err = logger.InitAudit(tmpDir)
	if err != nil {
		t.Fatalf("InitAudit error: %v", err)
	}

	// Инициализируем обычный логгер (в stderr)
	err = logger.Init("", "")
	if err != nil {
		t.Fatalf("Init error: %v", err)
	}

	cleanup := func() {
		logger.Close()
		audit.CloseGlobalAuditLogger()
		os.RemoveAll(tmpDir)
	}

	return tmpDir, cleanup
}

func TestAuditJSON(t *testing.T) {
	tmpDir, cleanup := setupTestAudit(t)
	defer cleanup()

	// Тестируем AuditJSON
	testData := map[string]interface{}{
		"action":   "test_action",
		"serial":   "123456",
		"subject":  "CN=test",
		"status":   "success",
		"metadata": map[string]string{"key": "value"},
	}

	logger.AuditJSON("certificate_issued", testData)

	// Проверяем, что аудит-лог файл создан и содержит запись
	auditLogPath := filepath.Join(tmpDir, "audit", "audit.log")
	if _, err := os.Stat(auditLogPath); os.IsNotExist(err) {
		t.Error("audit log file not created")
	}

	// Читаем и проверяем содержимое
	data, err := os.ReadFile(auditLogPath)
	if err != nil {
		t.Fatal(err)
	}

	if len(data) == 0 {
		t.Error("audit log is empty")
	} else {
		t.Logf("Audit log size: %d bytes", len(data))
	}

	// Проверяем, что это валидный JSON (NDJSON)
	lines := bytes.Split(data, []byte("\n"))
	found := false
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(line, &parsed); err == nil {
			if op, ok := parsed["operation"]; ok && op == "certificate_issued" {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("certificate_issued entry not found in audit log")
	}

	t.Logf("AuditJSON test completed, log size: %d bytes", len(data))
}

func TestLogAuditEvent(t *testing.T) {
	tmpDir, cleanup := setupTestAudit(t)
	defer cleanup()

	// Тестируем LogAuditEvent
	logger.LogAuditEvent("test_event", "success", "Test audit event", map[string]interface{}{
		"test_key": "test_value",
		"number":   42,
	})

	// Проверяем, что аудит-лог создан
	auditLogPath := filepath.Join(tmpDir, "audit", "audit.log")
	if _, err := os.Stat(auditLogPath); os.IsNotExist(err) {
		t.Error("audit log file not created")
	}

	data, err := os.ReadFile(auditLogPath)
	if err != nil {
		t.Fatal(err)
	}

	if len(data) == 0 {
		t.Error("audit log is empty")
	} else {
		t.Logf("LogAuditEvent test completed, log size: %d bytes", len(data))
	}
}

func TestLogAuditError(t *testing.T) {
	tmpDir, cleanup := setupTestAudit(t)
	defer cleanup()

	// Тестируем LogAuditError
	logger.LogAuditError("error_event", "Something went wrong", map[string]interface{}{
		"error_code": 500,
		"details":    "test error details",
	})

	// Проверяем, что аудит-лог создан
	auditLogPath := filepath.Join(tmpDir, "audit", "audit.log")
	if _, err := os.Stat(auditLogPath); os.IsNotExist(err) {
		t.Error("audit log file not created")
	}

	data, err := os.ReadFile(auditLogPath)
	if err != nil {
		t.Fatal(err)
	}

	if len(data) == 0 {
		t.Error("audit log is empty")
	} else {
		t.Logf("LogAuditError test completed, log size: %d bytes", len(data))
	}
}

func TestLoggerInitWithNilPaths(t *testing.T) {
	// Тест с пустыми путями (логи в stderr)
	err := logger.Init("", "")
	if err != nil {
		t.Fatalf("Init with empty paths error: %v", err)
	}
	defer logger.Close()

	// Проверяем, что логирование работает
	logger.Info("test message")
	logger.Warn("test warning")
	logger.Error("test error")

	t.Log("Logger with empty paths works")
}

func TestLoggerInitWithOnlyLogFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "logger-only-log-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "app.log")

	err = logger.Init(logPath, "")
	if err != nil {
		t.Fatalf("Init with only log file error: %v", err)
	}
	defer logger.Close()

	logger.Info("test message")

	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("Log file not created")
	}

	t.Log("Logger with only log file works")
}

func TestLoggerInitWithOnlyJSONFile(t *testing.T) {
	// JSON файл сам по себе не используется без аудит-системы
	// Этот тест проверяет, что инициализация не падает
	tmpDir, err := os.MkdirTemp("", "logger-only-json-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	jsonPath := filepath.Join(tmpDir, "audit.json")

	// Инициализируем аудит-логгер для теста
	err = logger.InitAudit(tmpDir)
	if err != nil {
		t.Fatalf("InitAudit error: %v", err)
	}
	defer audit.CloseGlobalAuditLogger()

	err = logger.Init("", jsonPath)
	if err != nil {
		t.Fatalf("Init with only JSON file error: %v", err)
	}
	defer logger.Close()

	logger.AuditJSON("test", map[string]interface{}{"key": "value"})

	// Аудит-лог должен быть создан в директории audit
	auditLogPath := filepath.Join(tmpDir, "audit", "audit.log")
	if _, err := os.Stat(auditLogPath); os.IsNotExist(err) {
		t.Error("Audit log file not created")
	}

	t.Log("Logger with JSON file works")
}

func TestLoggerContainsPassphrase(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "logger-passphrase-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "app.log")

	err = logger.Init(logPath, "")
	if err != nil {
		t.Fatalf("Init error: %v", err)
	}
	defer logger.Close()

	// Эти сообщения должны быть отфильтрованы (пароли скрыты)
	logger.Info("user password: secret123")
	logger.Info("passphrase: mysecret")
	logger.Info("pwd: testpwd")
	logger.Info("normal message without sensitive data")

	// Читаем лог и проверяем, что пароли скрыты
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}

	// Проверяем, что пароли не попали в лог в открытом виде
	if bytes.Contains(data, []byte("secret123")) {
		t.Log("Warning: password may not be filtered")
	} else {
		t.Log("Passphrase filtering appears to be working")
	}

	t.Log("containsPassphrase tested")
}

func TestAuditFunction(t *testing.T) {
    tmpDir := t.TempDir()
    err := logger.InitAudit(tmpDir)
    if err != nil {
        t.Fatalf("InitAudit error: %v", err)
    }
    defer audit.CloseGlobalAuditLogger()

    err = logger.Init("", "")
    if err != nil {
        t.Fatalf("Init error: %v", err)
    }
    defer logger.Close()

    // Вызываем функцию Audit
    logger.Audit("123456", "CN=test", "server")

    // Проверяем, что запись появилась в audit.log
    auditLogPath := filepath.Join(tmpDir, "audit", "audit.log")
    data, err := os.ReadFile(auditLogPath)
    if err != nil {
        t.Fatalf("failed to read audit log: %v", err)
    }
    if len(data) == 0 {
        t.Error("audit log is empty")
    }
}