package transparency

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CTLogEntry представляет запись в CT логе
type CTLogEntry struct {
	Timestamp   string `json:"timestamp"`
	SerialHex   string `json:"serial_hex"`
	SubjectDN   string `json:"subject_dn"`
	Fingerprint string `json:"sha256_fingerprint"`
	IssuerDN    string `json:"issuer_dn,omitempty"`
}

// CTLogger управляет CT логом
type CTLogger struct {
	logPath string
}

// NewCTLogger создает новый CT логгер
func NewCTLogger(outDir string) (*CTLogger, error) {
	auditDir := filepath.Join(outDir, "audit")
	if err := os.MkdirAll(auditDir, 0755); err != nil {
		return nil, fmt.Errorf("ошибка создания директории: %w", err)
	}

	logPath := filepath.Join(auditDir, "ct.log")
	
	return &CTLogger{
		logPath: logPath,
	}, nil
}

// AppendCertificate добавляет сертификат в CT лог
func (ctl *CTLogger) AppendCertificate(cert *x509.Certificate) error {
	fingerprint := sha256.Sum256(cert.Raw)
	
	entry := CTLogEntry{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		SerialHex:   hex.EncodeToString(cert.SerialNumber.Bytes()),
		SubjectDN:   cert.Subject.String(),
		Fingerprint: hex.EncodeToString(fingerprint[:]),
		IssuerDN:    cert.Issuer.String(),
	}

	// Добавляем в JSON формат
	jsonData, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("ошибка маршалинга CT записи: %w", err)
	}

	f, err := os.OpenFile(ctl.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("ошибка открытия ct.log: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(append(jsonData, '\n')); err != nil {
		return fmt.Errorf("ошибка записи в ct.log: %w", err)
	}

	return nil
}

// QueryBySerial ищет сертификат в CT логе по серийному номеру
func (ctl *CTLogger) QueryBySerial(serialHex string) ([]CTLogEntry, error) {
	data, err := os.ReadFile(ctl.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("ошибка чтения ct.log: %w", err)
	}

	var entries []CTLogEntry
	lines := strings.Split(string(data), "\n")
	
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		
		var entry CTLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		
		if strings.EqualFold(entry.SerialHex, serialHex) {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// QueryByFingerprint ищет сертификат в CT логе по SHA-256 отпечатку
func (ctl *CTLogger) QueryByFingerprint(fingerprint string) ([]CTLogEntry, error) {
	data, err := os.ReadFile(ctl.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("ошибка чтения ct.log: %w", err)
	}

	var entries []CTLogEntry
	lines := strings.Split(string(data), "\n")
	
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		
		var entry CTLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		
		if strings.EqualFold(entry.Fingerprint, fingerprint) {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// VerifyCertificate проверяет наличие сертификата в CT логе
func (ctl *CTLogger) VerifyCertificate(serialHex string) (bool, error) {
	entries, err := ctl.QueryBySerial(serialHex)
	if err != nil {
		return false, err
	}
	return len(entries) > 0, nil
}

// GetLogPath возвращает путь к CT логу
func (ctl *CTLogger) GetLogPath() string {
	return ctl.logPath
}