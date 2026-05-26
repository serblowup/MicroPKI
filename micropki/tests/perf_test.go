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

	"MicroPKI/internal/database"
)

func TestPerformance1000Certificates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "perf-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}

	// Создаём CA ключ и сертификат
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Perf Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := db.InsertCertificate(caCert, caPEM, "valid"); err != nil {
		t.Fatal(err)
	}

	// Выпускаем 1000 сертификатов
	certCount := 1000
	startTime := time.Now()

	for i := 0; i < certCount; i++ {
		leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate key for cert %d: %v", i, err)
		}
		leafSerial := big.NewInt(int64(10000 + i))
		leafTemplate := &x509.Certificate{
			SerialNumber: leafSerial,
			Subject:      pkix.Name{CommonName: fmt.Sprintf("cert-%d.example.com", i)},
			Issuer:       caCert.Subject,
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(1, 0, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
		if err != nil {
			t.Fatalf("failed to create cert %d: %v", i, err)
		}
		leafCert, err := x509.ParseCertificate(leafDER)
		if err != nil {
			t.Fatalf("failed to parse cert %d: %v", i, err)
		}
		leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

		if err := db.InsertCertificate(leafCert, leafPEM, "valid"); err != nil {
			t.Fatalf("failed to insert cert %d: %v", i, err)
		}
	}

	elapsed := time.Since(startTime)
	certsPerSec := float64(certCount) / elapsed.Seconds()

	t.Logf("=== PERFORMANCE TEST RESULTS ===")
	t.Logf("Issued %d certificates in %v", certCount, elapsed)
	t.Logf("Issuance rate: %.2f certs/sec", certsPerSec)

	// Проверяем все сертификаты
	startValidate := time.Now()
	records, err := db.ListCertificates("", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	validateElapsed := time.Since(startValidate)

	t.Logf("Listed %d certificates in %v", len(records), validateElapsed)

	// Убеждаемся, что все сертификаты сохранены
	if len(records) < certCount {
		t.Errorf("expected at least %d certificates, got %d", certCount, len(records))
	}
}