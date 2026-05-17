package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// ComputeHash вычисляет SHA-256 хеш для произвольных данных в каноническом JSON
func ComputeHash(data interface{}) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("ошибка маршалинга: %w", err)
	}
	hash := sha256.Sum256(jsonData)
	return hex.EncodeToString(hash[:]), nil
}

// WriteChainEntry добавляет хеш в файл цепочки
func WriteChainEntry(chainPath string, hash string) error {
	f, err := os.OpenFile(chainPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("ошибка открытия chain.dat: %w", err)
	}
	defer f.Close()

	if _, err := f.Write([]byte(hash + "\n")); err != nil {
		return fmt.Errorf("ошибка записи в chain.dat: %w", err)
	}
	return nil
}

// ReadLastHash читает последний хеш из chain.dat
func ReadLastHash(chainPath string) (string, error) {
	return readLastHash(chainPath)
}

// ReadAllHashes читает все хеши из chain.dat
func ReadAllHashes(chainPath string) ([]string, error) {
	data, err := os.ReadFile(chainPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("ошибка чтения chain.dat: %w", err)
	}

	return splitLines(string(data)), nil
}

// CanonicalJSON создает каноническое JSON представление
func CanonicalJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// SortMapKeys сортирует ключи map для канонического представления
func SortMapKeys(m map[string]interface{}) map[string]interface{} {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	result := make(map[string]interface{})
	for _, k := range keys {
		result[k] = m[k]
	}
	return result
}

// HashEntry вычисляет хеш AuditEntry
func HashEntry(entry *AuditEntry) (string, error) {
	return computeEntryHash(entry)
}

// VerifyHashChain проверяет целостность цепочки хешей
func VerifyHashChain(entries []AuditEntry) (*VerificationReport, error) {
	report := &VerificationReport{
		Valid:     true,
		TotalEntries: len(entries),
		CheckedEntries: 0,
	}

	if len(entries) == 0 {
		return report, nil
	}

	expectedPrevHash := "0000000000000000000000000000000000000000000000000000000000000000"

	for i, entry := range entries {
		// Проверяем prev_hash
		if entry.Integrity.PrevHash != expectedPrevHash {
			report.Valid = false
			report.FirstCorrupted = i
			report.Error = fmt.Sprintf("запись %d: prev_hash не совпадает. Ожидался %s, получен %s",
				i, expectedPrevHash, entry.Integrity.PrevHash)
			
			report.TamperDetails = append(report.TamperDetails, TamperDetail{
				EntryIndex:    i,
				ExpectedHash:  expectedPrevHash,
				ActualHash:    entry.Integrity.PrevHash,
				Type:          "hash_mismatch",
			})
			break
		}

		// Проверяем hash записи
		computedHash, err := HashEntry(&entry)
		if err != nil {
			return nil, fmt.Errorf("ошибка вычисления хеша для записи %d: %w", i, err)
		}

		if computedHash != entry.Integrity.Hash {
			report.Valid = false
			report.FirstCorrupted = i
			report.Error = fmt.Sprintf("запись %d: hash не совпадает. Ожидался %s, вычислен %s",
				i, entry.Integrity.Hash, computedHash)
			
			report.TamperDetails = append(report.TamperDetails, TamperDetail{
				EntryIndex:    i,
				ExpectedHash:  entry.Integrity.Hash,
				ActualHash:    computedHash,
				Type:          "content_modified",
			})
			break
		}

		expectedPrevHash = computedHash
		report.CheckedEntries++
	}

	return report, nil
}

// VerificationReport содержит результаты проверки целостности
type VerificationReport struct {
	Valid           bool           `json:"valid"`
	TotalEntries    int            `json:"total_entries"`
	CheckedEntries  int            `json:"checked_entries"`
	FirstCorrupted  int            `json:"first_corrupted,omitempty"`
	Error           string         `json:"error,omitempty"`
	TamperDetails   []TamperDetail `json:"tamper_details,omitempty"`
}

// TamperDetail описывает детали нарушения целостности
type TamperDetail struct {
	EntryIndex    int    `json:"entry_index"`
	ExpectedHash  string `json:"expected_hash"`
	ActualHash    string `json:"actual_hash"`
	Type          string `json:"type"`
}