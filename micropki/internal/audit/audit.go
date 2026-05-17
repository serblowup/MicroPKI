package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// AuditLevel определяет уровень важности аудита
type AuditLevel string

const (
	LevelAUDIT AuditLevel = "AUDIT"
	LevelINFO  AuditLevel = "INFO"
	LevelERROR AuditLevel = "ERROR"
	LevelWARN  AuditLevel = "WARNING"
)

// AuditEntry представляет одну запись в журнале аудита
type AuditEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     AuditLevel             `json:"level"`
	Operation string                 `json:"operation"`
	Status    string                 `json:"status"`
	Message   string                 `json:"message"`
	Metadata  map[string]interface{} `json:"metadata"`
	Integrity IntegrityInfo          `json:"integrity"`
}

// IntegrityInfo содержит информацию о целостности записи
type IntegrityInfo struct {
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// AuditLogger - основной логгер аудита с хеш-цепочкой
type AuditLogger struct {
	mu          sync.Mutex
	logFile     *os.File
	chainFile   *os.File
	logPath     string
	chainPath   string
	auditDir    string
	lastHash    string
	initialized bool
}

var globalAuditLogger *AuditLogger

// InitAuditLogger инициализирует глобальный аудит-логгер
func InitAuditLogger(outDir string) error {
	auditDir := filepath.Join(outDir, "audit")
	if err := os.MkdirAll(auditDir, 0755); err != nil {
		return fmt.Errorf("ошибка создания директории аудита: %w", err)
	}

	logPath := filepath.Join(auditDir, "audit.log")
	chainPath := filepath.Join(auditDir, "chain.dat")

	logger, err := NewAuditLogger(logPath, chainPath, auditDir)
	if err != nil {
		return fmt.Errorf("ошибка инициализации аудит-логгера: %w", err)
	}

	globalAuditLogger = logger
	return nil
}

// GetAuditLogger возвращает глобальный аудит-логгер
func GetAuditLogger() *AuditLogger {
	return globalAuditLogger
}

// NewAuditLogger создает новый экземпляр AuditLogger
func NewAuditLogger(logPath, chainPath, auditDir string) (*AuditLogger, error) {
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("ошибка открытия файла аудит-лога: %w", err)
	}

	chainFile, err := os.OpenFile(chainPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		logFile.Close()
		return nil, fmt.Errorf("ошибка открытия файла цепочки: %w", err)
	}

	logger := &AuditLogger{
		logFile:   logFile,
		chainFile: chainFile,
		logPath:   logPath,
		chainPath: chainPath,
		auditDir:  auditDir,
	}

	fileInfo, err := logFile.Stat()
	if err != nil {
		logFile.Close()
		chainFile.Close()
		return nil, fmt.Errorf("ошибка получения информации о файле: %w", err)
	}

	if fileInfo.Size() == 0 {
		logger.lastHash = "0000000000000000000000000000000000000000000000000000000000000000"
		logger.initialized = true

		initEntry := AuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Level:     LevelAUDIT,
			Operation: "audit_log_initialized",
			Status:    "success",
			Message:   "Audit log initialized",
			Metadata: map[string]interface{}{
				"log_path":   logPath,
				"chain_path": chainPath,
			},
			Integrity: IntegrityInfo{
				PrevHash: logger.lastHash,
				Hash:     "",
			},
		}

		if err := logger.writeEntry(&initEntry); err != nil {
			logFile.Close()
			chainFile.Close()
			return nil, fmt.Errorf("ошибка записи начальной записи: %w", err)
		}
	} else {
		lastHash, err := readLastHash(chainPath)
		if err != nil {
			logFile.Close()
			chainFile.Close()
			return nil, fmt.Errorf("ошибка чтения последнего хеша: %w", err)
		}
		logger.lastHash = lastHash
		logger.initialized = true
	}

	return logger, nil
}

// Rotate выполняет ротацию аудит-лога
func (al *AuditLogger) Rotate() error {
	if al == nil {
		return fmt.Errorf("аудит-логгер не инициализирован")
	}

	al.mu.Lock()
	defer al.mu.Unlock()

	// Закрываем текущие файлы
	if al.logFile != nil {
		al.logFile.Close()
		al.logFile = nil
	}
	if al.chainFile != nil {
		al.chainFile.Close()
		al.chainFile = nil
	}

	// Формируем имена для ротации
	timestamp := time.Now().UTC().Format("2006-01-02T15-04-05")
	rotatedLogPath := filepath.Join(al.auditDir, fmt.Sprintf("audit-%s.log", timestamp))
	rotatedChainPath := filepath.Join(al.auditDir, fmt.Sprintf("chain-%s.dat", timestamp))

	// Переименовываем текущие файлы
	if err := os.Rename(al.logPath, rotatedLogPath); err != nil {
		return fmt.Errorf("ошибка ротации audit.log: %w", err)
	}
	if err := os.Rename(al.chainPath, rotatedChainPath); err != nil {
		// Откатываем переименование лога
		os.Rename(rotatedLogPath, al.logPath)
		return fmt.Errorf("ошибка ротации chain.dat: %w", err)
	}

	// Создаем новые файлы
	logFile, err := os.OpenFile(al.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("ошибка создания нового audit.log: %w", err)
	}

	chainFile, err := os.OpenFile(al.chainPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		logFile.Close()
		return fmt.Errorf("ошибка создания нового chain.dat: %w", err)
	}

	al.logFile = logFile
	al.chainFile = chainFile
	al.lastHash = "0000000000000000000000000000000000000000000000000000000000000000"

	// Записываем начальную запись в новый лог
	initEntry := AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     LevelAUDIT,
		Operation: "audit_log_rotated",
		Status:    "success",
		Message:   fmt.Sprintf("Audit log rotated from %s", rotatedLogPath),
		Metadata: map[string]interface{}{
			"previous_log":   rotatedLogPath,
			"previous_chain": rotatedChainPath,
			"log_path":       al.logPath,
			"chain_path":     al.chainPath,
		},
		Integrity: IntegrityInfo{
			PrevHash: al.lastHash,
			Hash:     "",
		},
	}

	if err := al.writeEntry(&initEntry); err != nil {
		return fmt.Errorf("ошибка записи записи о ротации: %w", err)
	}

	return nil
}

// GetLogPath возвращает путь к файлу лога
func (al *AuditLogger) GetLogPath() string {
	if al == nil {
		return ""
	}
	return al.logPath
}

// GetChainPath возвращает путь к файлу цепочки
func (al *AuditLogger) GetChainPath() string {
	if al == nil {
		return ""
	}
	return al.chainPath
}

// Log записывает аудит-запись в лог
func (al *AuditLogger) Log(level AuditLevel, operation, status, message string, metadata map[string]interface{}) error {
	if al == nil {
		return fmt.Errorf("аудит-логгер не инициализирован")
	}

	entry := AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level,
		Operation: operation,
		Status:    status,
		Message:   message,
		Metadata:  metadata,
		Integrity: IntegrityInfo{
			PrevHash: "",
			Hash:     "",
		},
	}

	if metadata == nil {
		entry.Metadata = make(map[string]interface{})
	}

	return al.writeEntry(&entry)
}

// LogAudit записывает запись уровня AUDIT
func (al *AuditLogger) LogAudit(operation, status, message string, metadata map[string]interface{}) error {
	return al.Log(LevelAUDIT, operation, status, message, metadata)
}

// LogInfo записывает запись уровня INFO
func (al *AuditLogger) LogInfo(operation, status, message string, metadata map[string]interface{}) error {
	return al.Log(LevelINFO, operation, status, message, metadata)
}

// LogError записывает запись уровня ERROR
func (al *AuditLogger) LogError(operation, status, message string, metadata map[string]interface{}) error {
	return al.Log(LevelERROR, operation, status, message, metadata)
}

// writeEntry записывает запись в лог с вычислением хеша
func (al *AuditLogger) writeEntry(entry *AuditEntry) error {
	entry.Integrity.PrevHash = al.lastHash

	hash, err := computeEntryHash(entry)
	if err != nil {
		return fmt.Errorf("ошибка вычисления хеша: %w", err)
	}

	entry.Integrity.Hash = hash

	jsonData, err := marshalEntrySorted(entry)
	if err != nil {
		return fmt.Errorf("ошибка маршалинга записи: %w", err)
	}

	if _, err := al.logFile.Write(append(jsonData, '\n')); err != nil {
		return fmt.Errorf("ошибка записи в лог: %w", err)
	}

	if err := al.logFile.Sync(); err != nil {
		return fmt.Errorf("ошибка синхронизации лога: %w", err)
	}

	if _, err := al.chainFile.Write([]byte(hash + "\n")); err != nil {
		return fmt.Errorf("ошибка записи в цепочку: %w", err)
	}

	if err := al.chainFile.Sync(); err != nil {
		return fmt.Errorf("ошибка синхронизации цепочки: %w", err)
	}

	al.lastHash = hash

	return nil
}

// marshalEntrySorted сериализует запись с отсортированными ключами
func marshalEntrySorted(entry *AuditEntry) ([]byte, error) {
	sortedMetadata := sortMetadata(entry.Metadata)

	entryCopy := AuditEntry{
		Timestamp: entry.Timestamp,
		Level:     entry.Level,
		Operation: entry.Operation,
		Status:    entry.Status,
		Message:   entry.Message,
		Metadata:  sortedMetadata,
		Integrity: entry.Integrity,
	}

	return json.Marshal(entryCopy)
}

// sortMetadata сортирует ключи metadata для детерминированного JSON
func sortMetadata(metadata map[string]interface{}) map[string]interface{} {
	if metadata == nil {
		return make(map[string]interface{})
	}

	keys := make([]string, 0, len(metadata))
	for k := range metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	result := make(map[string]interface{})
	for _, k := range keys {
		result[k] = metadata[k]
	}
	return result
}

// computeEntryHash вычисляет SHA-256 хеш записи (без поля integrity.hash)
func computeEntryHash(entry *AuditEntry) (string, error) {
	sortedMetadata := sortMetadata(entry.Metadata)

	entryCopy := AuditEntry{
		Timestamp: entry.Timestamp,
		Level:     entry.Level,
		Operation: entry.Operation,
		Status:    entry.Status,
		Message:   entry.Message,
		Metadata:  sortedMetadata,
		Integrity: IntegrityInfo{
			PrevHash: entry.Integrity.PrevHash,
			Hash:     "",
		},
	}

	jsonData, err := json.Marshal(entryCopy)
	if err != nil {
		return "", fmt.Errorf("ошибка маршалинга для хеша: %w", err)
	}

	hash := sha256.Sum256(jsonData)
	return hex.EncodeToString(hash[:]), nil
}

// readLastHash читает последний хеш из chain.dat
func readLastHash(chainPath string) (string, error) {
	data, err := os.ReadFile(chainPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "0000000000000000000000000000000000000000000000000000000000000000", nil
		}
		return "", fmt.Errorf("ошибка чтения chain.dat: %w", err)
	}

	if len(data) == 0 {
		return "0000000000000000000000000000000000000000000000000000000000000000", nil
	}

	lines := splitLines(string(data))
	for i := len(lines) - 1; i >= 0; i-- {
		if len(lines[i]) == 64 {
			return lines[i], nil
		}
	}

	return "0000000000000000000000000000000000000000000000000000000000000000", nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 {
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		line := s[start:]
		if len(line) > 0 {
			lines = append(lines, line)
		}
	}
	return lines
}

// Close закрывает файлы логгера
func (al *AuditLogger) Close() error {
	if al == nil {
		return nil
	}

	al.mu.Lock()
	defer al.mu.Unlock()

	var lastErr error
	if al.logFile != nil {
		if err := al.logFile.Close(); err != nil {
			lastErr = err
		}
		al.logFile = nil
	}
	if al.chainFile != nil {
		if err := al.chainFile.Close(); err != nil {
			lastErr = err
		}
		al.chainFile = nil
	}
	return lastErr
}

// CloseGlobalAuditLogger закрывает глобальный аудит-логгер
func CloseGlobalAuditLogger() {
	if globalAuditLogger != nil {
		globalAuditLogger.Close()
		globalAuditLogger = nil
	}
}