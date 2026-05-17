package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// tamperedFlag хранит состояние целостности аудит-лога
var (
	tamperedFlag bool
	tamperedMu   sync.RWMutex
)

// SetTampered устанавливает флаг нарушения целостности
func SetTampered() {
	tamperedMu.Lock()
	defer tamperedMu.Unlock()
	tamperedFlag = true
}

// ResetTampered сбрасывает флаг нарушения целостности
func ResetTampered() {
	tamperedMu.Lock()
	defer tamperedMu.Unlock()
	tamperedFlag = false
}

// IsAuditLogTampered проверяет, был ли аудит-лог подделан
// Возвращает true, если целостность нарушена
// Если аудит-лог или chain.dat не существует, возвращает false
func IsAuditLogTampered(logPath, chainPath string) bool {
	tamperedMu.RLock()
	if tamperedFlag {
		tamperedMu.RUnlock()
		return true
	}
	tamperedMu.RUnlock()

	// Если лог не существует - это не нарушение, а новый лог
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		return false
	}

	// Если chain.dat не существует - это не нарушение (лог мог быть удален или еще не создан)
	if _, err := os.Stat(chainPath); os.IsNotExist(err) {
		return false
	}

	report, err := VerifyLogFile(logPath, chainPath)
	if err != nil {
		// Если ошибка верификации - считаем нарушением
		SetTampered()
		return true
	}

	if IsTampered(report) {
		SetTampered()
		return true
	}

	return false
}

// VerifyLogFile выполняет полную проверку целостности аудит-лога
func VerifyLogFile(logPath, chainPath string) (*VerificationReport, error) {
	// Читаем все записи из лога
	entries, err := ReadAllEntries(logPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения лога: %w", err)
	}

	// Читаем все хеши из chain.dat
	storedHashes, err := ReadAllHashes(chainPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения цепочки: %w", err)
	}

	report := &VerificationReport{
		TotalEntries: len(entries),
	}

	// Проверяем количество записей
	if len(entries) != len(storedHashes) {
		report.Valid = false
		report.Error = fmt.Sprintf("количество записей в логе (%d) не совпадает с количеством хешей в chain.dat (%d)",
			len(entries), len(storedHashes))
		
		if len(entries) > len(storedHashes) {
			report.TamperDetails = append(report.TamperDetails, TamperDetail{
				EntryIndex: len(storedHashes),
				Type:       "missing_chain_entries",
			})
			SetTampered()
		} else {
			report.FirstCorrupted = len(entries)
			report.TamperDetails = append(report.TamperDetails, TamperDetail{
				EntryIndex: len(entries),
				Type:       "missing_log_entries",
			})
			SetTampered()
		}
		return report, nil
	}

	// Проверяем хеш-цепочку
	chainReport, err := VerifyHashChain(entries)
	if err != nil {
		return nil, err
	}

	// Проверяем совпадение хешей с chain.dat
	for i, entry := range entries {
		if i >= len(storedHashes) {
			break
		}
		if entry.Integrity.Hash != storedHashes[i] {
			report.Valid = false
			report.Error = fmt.Sprintf("запись %d: хеш не совпадает с chain.dat. В логе: %s, в chain.dat: %s",
				i, entry.Integrity.Hash, storedHashes[i])
			if report.FirstCorrupted == 0 || i < report.FirstCorrupted {
				report.FirstCorrupted = i
			}
			report.TamperDetails = append(report.TamperDetails, TamperDetail{
				EntryIndex:   i,
				ExpectedHash: storedHashes[i],
				ActualHash:   entry.Integrity.Hash,
				Type:         "chain_mismatch",
			})
			SetTampered()
		}
	}

	// Объединяем результаты
	if !chainReport.Valid {
		report.Valid = false
		if report.Error == "" {
			report.Error = chainReport.Error
		}
		if report.FirstCorrupted == 0 || chainReport.FirstCorrupted < report.FirstCorrupted {
			report.FirstCorrupted = chainReport.FirstCorrupted
		}
		report.TamperDetails = append(report.TamperDetails, chainReport.TamperDetails...)
		SetTampered()
	}

	report.CheckedEntries = chainReport.CheckedEntries

	if report.Valid {
		report.Error = ""
	}

	return report, nil
}

// ReadAllEntries читает все записи из NDJSON файла
func ReadAllEntries(logPath string) ([]AuditEntry, error) {
	file, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditEntry{}, nil
		}
		return nil, fmt.Errorf("ошибка открытия файла: %w", err)
	}
	defer file.Close()

	var entries []AuditEntry
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var entry AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("ошибка парсинга строки %d: %w", lineNum, err)
		}

		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("ошибка чтения файла: %w", err)
	}

	return entries, nil
}

// GetFirstCorruptedEntry возвращает первую поврежденную запись
func GetFirstCorruptedEntry(report *VerificationReport, entries []AuditEntry) *AuditEntry {
	if report.Valid || report.FirstCorrupted >= len(entries) {
		return nil
	}
	return &entries[report.FirstCorrupted]
}

// IsTampered проверяет, был ли лог подделан
func IsTampered(report *VerificationReport) bool {
	return !report.Valid
}