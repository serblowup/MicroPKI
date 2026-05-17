package audit

import (
	"fmt"
	"strings"
	"time"
)

// AnomalyReport содержит результаты анализа аномалий
type AnomalyReport struct {
	TotalEntries    int
	TimeRange       string
	Anomalies       []Anomaly
	HourlyCounts    map[string]int
	OperationCounts map[string]int
}

// Anomaly описывает обнаруженную аномалию
type Anomaly struct {
	Type        string
	Description string
	Severity    string
	Details     map[string]interface{}
}

// DetectAnomalies выполняет простой эвристический анализ аудит-лога
func DetectAnomalies(logPath string, thresholdPerHour int) (*AnomalyReport, error) {
	entries, err := ReadAllEntries(logPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения лога: %w", err)
	}

	report := &AnomalyReport{
		TotalEntries:    len(entries),
		HourlyCounts:    make(map[string]int),
		OperationCounts: make(map[string]int),
	}

	if len(entries) == 0 {
		return report, nil
	}

	// Группируем по часам
	for _, entry := range entries {
		// Извлекаем час из timestamp
		ts := entry.Timestamp
		if len(ts) >= 13 {
			hourKey := ts[:13] // YYYY-MM-DDTHH
			report.HourlyCounts[hourKey]++
		}

		// Считаем операции
		report.OperationCounts[entry.Operation]++
	}

	// Устанавливаем временной диапазон
	if len(entries) > 0 {
		firstTs := entries[0].Timestamp
		lastTs := entries[len(entries)-1].Timestamp
		report.TimeRange = fmt.Sprintf("%s - %s",
			truncateTimestamp(firstTs),
			truncateTimestamp(lastTs))
	}

	// Проверяем аномалии по порогу событий в час
	if thresholdPerHour > 0 {
		for hour, count := range report.HourlyCounts {
			if count > thresholdPerHour {
				report.Anomalies = append(report.Anomalies, Anomaly{
					Type:        "high_event_rate",
					Description: fmt.Sprintf("Высокая частота событий: %d событий за час %s", count, hour),
					Severity:    getSeverity(count, thresholdPerHour),
					Details: map[string]interface{}{
						"hour":      hour,
						"count":     count,
						"threshold": thresholdPerHour,
					},
				})
			}
		}
	}

	// Проверяем всплески отзывов
	revokeCount := 0
	compromiseCount := 0
	for _, entry := range entries {
		if strings.Contains(entry.Operation, "revoked") || strings.Contains(entry.Operation, "revoke") {
			revokeCount++
		}
		if strings.Contains(entry.Operation, "compromise") {
			compromiseCount++
		}
	}

	totalEntries := len(entries)
	if totalEntries > 0 {
		revokeRatio := float64(revokeCount) / float64(totalEntries)
		if revokeRatio > 0.3 && revokeCount > 5 {
			report.Anomalies = append(report.Anomalies, Anomaly{
				Type:        "high_revocation_rate",
				Description: fmt.Sprintf("Подозрительно высокая частота отзывов: %d из %d записей (%.1f%%)",
					revokeCount, totalEntries, revokeRatio*100),
				Severity: "HIGH",
				Details: map[string]interface{}{
					"revoke_count":  revokeCount,
					"total_entries": totalEntries,
					"ratio":         revokeRatio,
				},
			})
		}
	}

	if compromiseCount > 0 {
		report.Anomalies = append(report.Anomalies, Anomaly{
			Type:        "key_compromise_detected",
			Description: fmt.Sprintf("Обнаружено %d событий компрометации ключей", compromiseCount),
			Severity:    "CRITICAL",
			Details: map[string]interface{}{
				"compromise_count": compromiseCount,
			},
		})
	}

	// Проверяем ошибки (failed операции)
	errorCount := 0
	for _, entry := range entries {
		if entry.Status == "failure" || entry.Status == "error" {
			errorCount++
		}
	}
	if errorCount > 0 {
		errorRatio := float64(errorCount) / float64(totalEntries)
		if errorRatio > 0.2 && errorCount > 3 {
			report.Anomalies = append(report.Anomalies, Anomaly{
				Type:        "high_error_rate",
				Description: fmt.Sprintf("Высокая частота ошибок: %d из %d операций (%.1f%%)",
					errorCount, totalEntries, errorRatio*100),
				Severity: "MEDIUM",
				Details: map[string]interface{}{
					"error_count":   errorCount,
					"total_entries": totalEntries,
					"ratio":         errorRatio,
				},
			})
		}
	}

	// Проверяем операции с уровнем ERROR
	errorLevelCount := 0
	for _, entry := range entries {
		if entry.Level == LevelERROR {
			errorLevelCount++
		}
	}
	if errorLevelCount > 10 {
		report.Anomalies = append(report.Anomalies, Anomaly{
			Type:        "multiple_errors",
			Description: fmt.Sprintf("Обнаружено %d записей с уровнем ERROR", errorLevelCount),
			Severity:    "HIGH",
			Details: map[string]interface{}{
				"error_count": errorLevelCount,
			},
		})
	}

	return report, nil
}

func getSeverity(count, threshold int) string {
	ratio := float64(count) / float64(threshold)
	switch {
	case ratio > 5:
		return "CRITICAL"
	case ratio > 3:
		return "HIGH"
	case ratio > 2:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func truncateTimestamp(ts string) string {
	if len(ts) >= 19 {
		return ts[:19]
	}
	return ts
}

// FormatAnomalyReport форматирует отчет об аномалиях
func FormatAnomalyReport(report *AnomalyReport) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Анализ аудит-лога\n"))
	sb.WriteString(fmt.Sprintf("==================\n"))
	sb.WriteString(fmt.Sprintf("Всего записей: %d\n", report.TotalEntries))
	sb.WriteString(fmt.Sprintf("Временной диапазон: %s\n\n", report.TimeRange))

	if len(report.Anomalies) == 0 {
		sb.WriteString("Аномалий не обнаружено\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("Обнаружено аномалий: %d\n\n", len(report.Anomalies)))

	for i, anomaly := range report.Anomalies {
		sb.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, anomaly.Severity, anomaly.Type))
		sb.WriteString(fmt.Sprintf("   %s\n", anomaly.Description))
		if len(anomaly.Details) > 0 {
			for k, v := range anomaly.Details {
				sb.WriteString(fmt.Sprintf("   %s: %v\n", k, v))
			}
		}
		sb.WriteString("\n")
	}

	// Статистика по часам
	if len(report.HourlyCounts) > 0 {
		sb.WriteString("Почасовая статистика:\n")
		// Сортируем часы
		hours := make([]string, 0, len(report.HourlyCounts))
		for hour := range report.HourlyCounts {
			hours = append(hours, hour)
		}
		// Простая сортировка
		for i := 0; i < len(hours); i++ {
			for j := i + 1; j < len(hours); j++ {
				if hours[i] > hours[j] {
					hours[i], hours[j] = hours[j], hours[i]
				}
			}
		}
		for _, hour := range hours {
			sb.WriteString(fmt.Sprintf("  %s: %d событий\n", hour, report.HourlyCounts[hour]))
		}
	}

	// Статистика по операциям
	if len(report.OperationCounts) > 0 {
		sb.WriteString("\nСтатистика по операциям:\n")
		for op, count := range report.OperationCounts {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", op, count))
		}
	}

	return sb.String()
}

// ParseTimeRange парсит временной диапазон из строк
func ParseTimeRange(fromStr, toStr string) (time.Time, time.Time, error) {
	var from, to time.Time
	var err error

	if fromStr != "" {
		from, err = time.Parse(time.RFC3339, fromStr)
		if err != nil {
			return from, to, fmt.Errorf("неверный формат from: %w", err)
		}
	}

	if toStr != "" {
		to, err = time.Parse(time.RFC3339, toStr)
		if err != nil {
			return from, to, fmt.Errorf("неверный формат to: %w", err)
		}
	}

	return from, to, nil
}