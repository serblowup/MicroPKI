package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

var (
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
	logFile     *os.File
	jsonLogger  *log.Logger
	jsonLogFile *os.File
)

func Init(logFilePath string, jsonLogPath string) error {
	var writer io.Writer

	if logFilePath != "" {
		file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("ошибка открытия файла лога: %w", err)
		}
		logFile = file
		writer = file
	} else {
		writer = os.Stderr
	}

	infoLogger = log.New(writer, "", 0)
	warnLogger = log.New(writer, "", 0)
	errorLogger = log.New(writer, "", 0)

	if jsonLogPath != "" {
		file, err := os.OpenFile(jsonLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("ошибка открытия файла JSON лога: %w", err)
		}
		jsonLogFile = file
		jsonLogger = log.New(file, "", 0)
	}

	return nil
}

func Close() {
	if logFile != nil {
		logFile.Close()
	}
	if jsonLogFile != nil {
		jsonLogFile.Close()
	}
}

func formatMessage(level, msg string) string {
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	return fmt.Sprintf("%s [%s] %s", timestamp, level, msg)
}

func Info(format string, v ...interface{}) {
	if infoLogger != nil {
		msg := fmt.Sprintf(format, v...)
		if containsPassphrase(msg) {
			msg = "[REDACTED: потенциальная парольная фраза]"
		}
		infoLogger.Println(formatMessage("INFO", msg))
	}
}

func Warn(format string, v ...interface{}) {
	if warnLogger != nil {
		msg := fmt.Sprintf(format, v...)
		if containsPassphrase(msg) {
			msg = "[REDACTED: потенциальная парольная фраза]"
		}
		warnLogger.Println(formatMessage("WARN", msg))
	}
}

func Error(format string, v ...interface{}) {
	if errorLogger != nil {
		msg := fmt.Sprintf(format, v...)
		if containsPassphrase(msg) {
			msg = "[REDACTED: потенциальная парольная фраза]"
		}
		errorLogger.Println(formatMessage("ERROR", msg))
	}
}

func Audit(serial, subject, template string) {
	if infoLogger != nil {
		msg := fmt.Sprintf("audit: issued certificate serial=%x subject=%s template=%s timestamp=%s",
			serial, subject, template, time.Now().UTC().Format(time.RFC3339))
		infoLogger.Println(formatMessage("INFO", msg))
	}
}

type JSONLogEntry struct {
	Timestamp string      `json:"timestamp"`
	Level     string      `json:"level"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data,omitempty"`
}

func AuditJSON(action string, data map[string]interface{}) {
	if jsonLogger == nil {
		return
	}
	
	entry := JSONLogEntry{
		Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Level:     "AUDIT",
		Message:   action,
		Data:      data,
	}
	
	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		Error("ошибка маршалинга JSON лога: %v", err)
		return
	}
	
	jsonLogger.Println(string(jsonBytes))
}

func containsPassphrase(msg string) bool {
	patterns := []struct {
		pattern string
		context bool
	}{
		{"passphrase", true},
		{"password", true},
		{"pwd", true},
		{"secret", true},
		{"pass:", false},
		{"pass=", false},
	}
	
	msgLower := stringsToLower(msg)
	
	for _, p := range patterns {
		if !stringsContains(msgLower, p.pattern) {
			continue
		}
		
		if p.context {
			idx := strings.Index(msgLower, p.pattern)
			if idx > 0 {
				prevChar := msgLower[idx-1]
				nextIdx := idx + len(p.pattern)
				if nextIdx < len(msgLower) {
					nextChar := msgLower[nextIdx]
					if isLetter(prevChar) && isLetter(nextChar) {
						continue
					}
				}
			}
		}
		
		return true
	}
	
	return false
}

func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func stringsToLower(s string) string {
	result := make([]rune, len(s))
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			result[i] = r + 32
		} else {
			result[i] = r
		}
	}
	return string(result)
}

func stringsContains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(s) {
		return false
	}
	
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}