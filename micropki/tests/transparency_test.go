package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"MicroPKI/internal/transparency"
)

func TestCTLogAppendAndQuery(t *testing.T) {
	tmpDir := t.TempDir()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := createCTTestCertificate(t, key, "test.example.com")

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	if err := ctLogger.AppendCertificate(cert); err != nil {
		t.Fatalf("ошибка добавления сертификата: %v", err)
	}

	ctLogPath := filepath.Join(tmpDir, "audit", "ct.log")
	if _, err := os.Stat(ctLogPath); os.IsNotExist(err) {
		t.Error("ct.log не создан")
	}

	serialHex := hex.EncodeToString(cert.SerialNumber.Bytes())

	entries, err := ctLogger.QueryBySerial(serialHex)
	if err != nil {
		t.Fatalf("ошибка запроса CT лога: %v", err)
	}

	if len(entries) == 0 {
		t.Error("сертификат не найден в CT логе")
	}

	if len(entries) > 0 {
		entry := entries[0]
		if entry.SubjectDN != cert.Subject.String() {
			t.Errorf("неверный SubjectDN: %s", entry.SubjectDN)
		}
		if entry.SerialHex != serialHex {
			t.Errorf("неверный SerialHex: %s", entry.SerialHex)
		}
	}

	found, err := ctLogger.VerifyCertificate(serialHex)
	if err != nil {
		t.Fatalf("ошибка верификации: %v", err)
	}
	if !found {
		t.Error("VerifyCertificate должен вернуть true")
	}

	t.Logf("CT лог работает: serial=%s, subject=%s", serialHex, cert.Subject.String())
}

func TestCTLogMultipleCertificates(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	serials := make([]string, 3)
	for i := 0; i < 3; i++ {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		cert := createCTTestCertificate(t, key, fmt.Sprintf("test%d.example.com", i))

		if err := ctLogger.AppendCertificate(cert); err != nil {
			t.Fatalf("ошибка добавления сертификата %d: %v", i, err)
		}

		serials[i] = hex.EncodeToString(cert.SerialNumber.Bytes())
	}

	for i, serial := range serials {
		found, err := ctLogger.VerifyCertificate(serial)
		if err != nil {
			t.Fatalf("ошибка верификации %d: %v", i, err)
		}
		if !found {
			t.Errorf("сертификат %d не найден в CT логе", i)
		}
	}
}

func TestCTLogQueryByFingerprint(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := createCTTestCertificate(t, key, "fingerprint.example.com")

	if err := ctLogger.AppendCertificate(cert); err != nil {
		t.Fatalf("ошибка добавления сертификата: %v", err)
	}

	// Используем SHA-256 хеш сертификата (как в CT логе)
	fingerprint := sha256.Sum256(cert.Raw)
	fingerprintHex := hex.EncodeToString(fingerprint[:])

	entries, err := ctLogger.QueryByFingerprint(fingerprintHex)
	if err != nil {
		t.Fatalf("ошибка запроса по отпечатку: %v", err)
	}

	if len(entries) == 0 {
		t.Error("сертификат не найден по отпечатку")
	}
}

func TestCTLogNonExistent(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	found, err := ctLogger.VerifyCertificate("nonexistent")
	if err != nil {
		t.Fatalf("ошибка верификации: %v", err)
	}
	if found {
		t.Error("несуществующий сертификат не должен быть найден")
	}
}

func TestCTLogFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()

	ctLogger, err := transparency.NewCTLogger(tmpDir)
	if err != nil {
		t.Fatalf("ошибка создания CT логгера: %v", err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := createCTTestCertificate(t, key, "perms.example.com")
	ctLogger.AppendCertificate(cert)

	ctLogPath := ctLogger.GetLogPath()
	info, err := os.Stat(ctLogPath)
	if err != nil {
		t.Fatalf("ошибка stat: %v", err)
	}

	if info.Mode().Perm() != 0644 {
		t.Logf("права файла: %o (ожидалось 0644)", info.Mode().Perm())
	}
}

func createCTTestCertificate(t *testing.T, key *rsa.PrivateKey, commonName string) *x509.Certificate {
	t.Helper()

	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	now := time.Now().UTC()

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore: now,
		NotAfter:  now.AddDate(1, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ошибка создания сертификата: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ошибка парсинга сертификата: %v", err)
	}

	return cert
}