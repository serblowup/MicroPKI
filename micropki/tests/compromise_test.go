package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"MicroPKI/internal/compromise"
	"MicroPKI/internal/database"
)

func TestCompromiseSimulation(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("ошибка создания БД: %v", err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatalf("ошибка инициализации схемы: %v", err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := createCompromiseTestCert(t, key)
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	if err := db.InsertCertificate(cert, certPEM, "valid"); err != nil {
		t.Fatalf("ошибка сохранения сертификата: %v", err)
	}

	certPath := filepath.Join(tmpDir, "test.cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("ошибка сохранения файла: %v", err)
	}

	result, err := compromise.SimulateKeyCompromise(db, certPath, "keyCompromise", true)
	if err != nil {
		t.Fatalf("ошибка симуляции компрометации: %v", err)
	}

	if !result.Revoked {
		t.Error("сертификат должен быть отозван")
	}

	if result.Reason != "keyCompromise" {
		t.Errorf("неверная причина: %s", result.Reason)
	}

	compromised, err := db.IsKeyCompromised(result.PublicKeyHash)
	if err != nil {
		t.Fatalf("ошибка проверки compromised_keys: %v", err)
	}

	if !compromised {
		t.Error("ключ должен быть в таблице compromised_keys")
	}

	t.Logf("Компрометация успешна: serial=%s, hash=%s", result.SerialHex, result.PublicKeyHash)
}

func TestCompromisedKeyBlocking(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("ошибка создания БД: %v", err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatalf("ошибка инициализации схемы: %v", err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := createCompromiseTestCert(t, key)
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	db.InsertCertificate(cert, certPEM, "valid")

	certPath := filepath.Join(tmpDir, "test.cert.pem")
	os.WriteFile(certPath, certPEM, 0644)

	result, _ := compromise.SimulateKeyCompromise(db, certPath, "keyCompromise", true)

	isCompromised, err := compromise.IsKeyCompromised(db, &key.PublicKey)
	if err != nil {
		t.Fatalf("ошибка проверки: %v", err)
	}

	if !isCompromised {
		t.Error("публичный ключ должен быть определен как скомпрометированный")
	}

	compromised, err := db.IsKeyCompromised(result.PublicKeyHash)
	if err != nil {
		t.Fatalf("ошибка проверки БД: %v", err)
	}

	if !compromised {
		t.Error("БД должна подтверждать компрометацию")
	}
}

func TestCompromisedKeyList(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("ошибка создания БД: %v", err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatalf("ошибка инициализации схемы: %v", err)
	}

	for i := 0; i < 3; i++ {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		cert := createCompromiseTestCert(t, key)
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

		db.InsertCertificate(cert, certPEM, "valid")

		certPath := filepath.Join(tmpDir, fmt.Sprintf("test%d.cert.pem", i))
		os.WriteFile(certPath, certPEM, 0644)

		compromise.SimulateKeyCompromise(db, certPath, "keyCompromise", true)
	}

	keys, err := db.ListCompromisedKeys()
	if err != nil {
		t.Fatalf("ошибка получения списка: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("ожидалось 3 скомпрометированных ключа, получено: %d", len(keys))
	}
}

func createCompromiseTestCert(t *testing.T, key *rsa.PrivateKey) *x509.Certificate {
	t.Helper()

	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	now := time.Now().UTC()

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "test.example.com",
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