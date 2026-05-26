package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AuditFilters содержит фильтры для запроса к логу
type AuditFilters struct {
	From      time.Time
	To        time.Time
	Level     AuditLevel
	Operation string
	Serial    string
}

// QueryResult содержит результат запроса
type QueryResult struct {
	Entries  []AuditEntry `json:"entries"`
	Total    int          `json:"total"`
	Filtered int          `json:"filtered"`
}

// QueryLog выполняет запрос к аудит-логу с фильтрацией
func QueryLog(logPath string, filters *AuditFilters) (*QueryResult, error) {
	entries, err := ReadAllEntries(logPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения лога: %w", err)
	}

	result := &QueryResult{
		Total: len(entries),
	}

	for _, entry := range entries {
		if matchesFilters(&entry, filters) {
			result.Entries = append(result.Entries, entry)
		}
	}

	result.Filtered = len(result.Entries)
	return result, nil
}

// matchesFilters проверяет, соответствует ли запись фильтрам
func matchesFilters(entry *AuditEntry, filters *AuditFilters) bool {
	if filters == nil {
		return true
	}

	// Фильтр по времени начала
	if !filters.From.IsZero() {
		entryTime, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
		if err != nil {
			// Пробуем другие форматы
			entryTime, err = ParseFlexibleTime(entry.Timestamp)
			if err != nil {
				return false
			}
		}
		if entryTime.Before(filters.From) {
			return false
		}
	}

	// Фильтр по времени окончания
	if !filters.To.IsZero() {
		entryTime, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
		if err != nil {
			entryTime, err = ParseFlexibleTime(entry.Timestamp)
			if err != nil {
				return false
			}
		}
		if entryTime.After(filters.To) {
			return false
		}
	}

	// Фильтр по уровню
	if filters.Level != "" && entry.Level != filters.Level {
		return false
	}

	// Фильтр по операции
	if filters.Operation != "" && !strings.Contains(entry.Operation, filters.Operation) {
		return false
	}

	// Фильтр по серийному номеру
	if filters.Serial != "" {
		if serial, ok := entry.Metadata["serial"]; ok {
			serialStr := fmt.Sprintf("%v", serial)
			if !strings.Contains(strings.ToLower(serialStr), strings.ToLower(filters.Serial)) {
				return false
			}
		} else if serial, ok := entry.Metadata["serial_number"]; ok {
			serialStr := fmt.Sprintf("%v", serial)
			if !strings.Contains(strings.ToLower(serialStr), strings.ToLower(filters.Serial)) {
				return false
			}
		} else {
			return false
		}
	}

	return true
}

// ParseFlexibleTime парсит время в разных форматах
func ParseFlexibleTime(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
	}
	
	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}
	
	return time.Time{}, fmt.Errorf("не удалось распарсить время: %s", s)
}

// FormatEntries форматирует записи в указанном формате
func FormatEntries(entries []AuditEntry, format string) (string, error) {
	switch format {
	case "json":
		return formatJSON(entries)
	case "csv":
		return formatCSV(entries)
	case "table":
		return formatTable(entries)
	default:
		return formatTable(entries)
	}
}

func formatJSON(entries []AuditEntry) (string, error) {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func formatCSV(entries []AuditEntry) (string, error) {
	var sb strings.Builder
	sb.WriteString("Timestamp,Level,Operation,Status,Message,Serial\n")
	
	for _, entry := range entries {
		serial := ""
		if s, ok := entry.Metadata["serial"]; ok {
			serial = fmt.Sprintf("%v", s)
		} else if s, ok := entry.Metadata["serial_number"]; ok {
			serial = fmt.Sprintf("%v", s)
		}
		
		sb.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s\n",
			entry.Timestamp,
			entry.Level,
			escapeCSV(entry.Operation),
			entry.Status,
			escapeCSV(entry.Message),
			serial,
		))
	}
	
	return sb.String(), nil
}

func formatTable(entries []AuditEntry) (string, error) {
	var sb strings.Builder
	
	sb.WriteString(fmt.Sprintf("%-30s %-8s %-25s %-8s %-40s %-20s\n",
		"TIMESTAMP", "LEVEL", "OPERATION", "STATUS", "MESSAGE", "SERIAL"))
	sb.WriteString(strings.Repeat("-", 135) + "\n")
	
	for _, entry := range entries {
		// Обрезаем timestamp до секунд
		ts := entry.Timestamp
		if len(ts) > 19 {
			ts = ts[:19] + "Z"
		}
		
		serial := "-"
		if s, ok := entry.Metadata["serial"]; ok {
			serial = truncate(fmt.Sprintf("%v", s), 20)
		} else if s, ok := entry.Metadata["serial_number"]; ok {
			serial = truncate(fmt.Sprintf("%v", s), 20)
		}
		
		op := truncate(entry.Operation, 25)
		msg := truncate(entry.Message, 40)
		
		sb.WriteString(fmt.Sprintf("%-30s %-8s %-25s %-8s %-40s %-20s\n",
			ts, entry.Level, op, entry.Status, msg, serial))
	}
	
	return sb.String(), nil
}

func escapeCSV(s string) string {
	return strings.ReplaceAll(s, ",", ";")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}