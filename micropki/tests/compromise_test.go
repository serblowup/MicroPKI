package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"crypto/ecdsa"
    "crypto/elliptic"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"MicroPKI/internal/compromise"
	"MicroPKI/internal/database"
)

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

func TestComputePublicKeyHash(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	
	cert := createCompromiseTestCert(t, key)
	
	hash, err := compromise.ComputePublicKeyHash(cert)
	if err != nil {
		t.Fatalf("ComputePublicKeyHash ошибка: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("хеш должен быть 64 символа, получено %d", len(hash))
	}
	t.Logf("хеш публичного ключа: %s", hash)
}

func TestComputePublicKeyHashFromCSR(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	
	hash, err := compromise.ComputePublicKeyHashFromCSR(csr)
	if err != nil {
		t.Fatalf("ComputePublicKeyHashFromCSR ошибка: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("хеш должен быть 64 символа, получено %d", len(hash))
	}
	t.Logf("хеш публичного ключа из CSR: %s", hash)
}

func TestGetKeyType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	
	keyType := compromise.GetKeyType(&rsaKey.PublicKey)
	if keyType != "rsa" {
		t.Errorf("ожидался 'rsa', получен '%s'", keyType)
	}
	t.Logf("тип ключа: %s", keyType)
}

func TestSimulateKeyCompromiseWithInvalidCert(t *testing.T) {
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

	// Несуществующий файл сертификата
	_, err = compromise.SimulateKeyCompromise(db, "/nonexistent/cert.pem", "keyCompromise", true)
	if err == nil {
		t.Error("ожидалась ошибка для несуществующего сертификата")
	}
}

func TestGetKeyTypeFullCoverage(t *testing.T) {
    // RSA ключ
    rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }
    keyType := compromise.GetKeyType(&rsaKey.PublicKey)
    if keyType != "rsa" {
        t.Errorf("expected 'rsa', got '%s'", keyType)
    }
    t.Logf("RSA key type: %s", keyType)

    // ECC ключ
    eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    keyType = compromise.GetKeyType(&eccKey.PublicKey)
    if keyType != "ecc" {
        t.Errorf("expected 'ecc', got '%s'", keyType)
    }
    t.Logf("ECC key type: %s", keyType)

    // Nil (unknown)
    keyType = compromise.GetKeyType(nil)
    if keyType != "unknown" {
        t.Errorf("expected 'unknown', got '%s'", keyType)
    }
    t.Logf("Nil key type: %s", keyType)
}