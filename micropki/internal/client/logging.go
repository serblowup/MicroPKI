package client

import (
    "encoding/json"
    "fmt"
    "log"
    "os"
    "path/filepath"
    "time"
)

var clientLogger *log.Logger
var clientLogFile *os.File

// InitClientLogger инициализирует логгер для клиентских операций
func InitClientLogger(logPath string) error {
    if logPath == "" {
        homeDir, err := os.UserHomeDir()
        if err != nil {
            return fmt.Errorf("не удалось определить домашнюю директорию: %w", err)
        }
        logPath = filepath.Join(homeDir, ".micropki", "client.log")
    }
    
    // Создаем директорию если не существует
    logDir := filepath.Dir(logPath)
    if err := os.MkdirAll(logDir, 0755); err != nil {
        return fmt.Errorf("ошибка создания директории логов: %w", err)
    }
    
    file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return fmt.Errorf("ошибка открытия файла логов: %w", err)
    }
    
    clientLogFile = file
    clientLogger = log.New(file, "", 0)
    return nil
}

func CloseClientLogger() {
    if clientLogFile != nil {
        clientLogFile.Close()
    }
}

// LogClientOperation логирует клиентскую операцию
func LogClientOperation(operation string, details map[string]interface{}, err error) {
    if clientLogger == nil {
        return
    }
    
    entry := map[string]interface{}{
        "timestamp": time.Now().UTC().Format(time.RFC3339),
        "operation": operation,
        "details":   details,
    }
    
    if err != nil {
        entry["error"] = err.Error()
        entry["status"] = "failed"
    } else {
        entry["status"] = "success"
    }
    
    jsonData, _ := json.Marshal(entry)
    clientLogger.Println(string(jsonData))
}