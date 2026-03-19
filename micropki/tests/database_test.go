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

func setupTestDB(t *testing.T) (*database.Database, func()) {
	tmpDir, err := os.MkdirTemp("", "db-test-*")
	if err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := database.NewDatabase(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatal(err)
	}

	if err := db.InitSchema(); err != nil {
		db.Close()
		os.RemoveAll(tmpDir)
		t.Fatal(err)
	}

	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}

	return db, cleanup
}

func createTestCertForDB(t *testing.T) (*x509.Certificate, []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	serial := big.NewInt(12345)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert, certPEM
}

func TestDatabaseInit(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	initialized, err := db.IsInitialized()
	if err != nil {
		t.Fatal(err)
	}
	if !initialized {
		t.Error("БД должна быть инициализирована")
	}
}

func TestInsertAndGetCertificate(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	cert, certPEM := createTestCertForDB(t)

	err := db.InsertCertificate(cert, certPEM, "valid")
	if err != nil {
		t.Fatal(err)
	}

	serialHex := "3039"
	record, err := db.GetCertificateBySerial(serialHex)
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatal("сертификат не найден")
	}

	if record.Subject != cert.Subject.String() {
		t.Errorf("ожидался subject %s, получен %s", cert.Subject.String(), record.Subject)
	}
	if record.Status != "valid" {
		t.Errorf("ожидался статус valid, получен %s", record.Status)
	}
}

func TestListCertificates(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	for i := 0; i < 3; i++ {
		cert, certPEM := createTestCertForDB(t)
		cert.SerialNumber = big.NewInt(int64(12345 + i))
		err := db.InsertCertificate(cert, certPEM, "valid")
		if err != nil {
			t.Fatal(err)
		}
	}

	records, err := db.ListCertificates("", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Errorf("ожидалось 3 сертификата, получено %d", len(records))
	}

	records, err = db.ListCertificates("valid", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Errorf("ожидалось 3 valid сертификата, получено %d", len(records))
	}

	records, err = db.ListCertificates("revoked", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Errorf("ожидалось 0 revoked сертификатов, получено %d", len(records))
	}
}

func TestUpdateCertificateStatus(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	cert, certPEM := createTestCertForDB(t)
	err := db.InsertCertificate(cert, certPEM, "valid")
	if err != nil {
		t.Fatal(err)
	}

	serialHex := "3039"
	err = db.UpdateCertificateStatus(serialHex, "revoked", "key compromise")
	if err != nil {
		t.Fatal(err)
	}

	record, err := db.GetCertificateBySerial(serialHex)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != "revoked" {
		t.Errorf("ожидался статус revoked, получен %s", record.Status)
	}
	if !record.RevocationReason.Valid || record.RevocationReason.String != "key compromise" {
		t.Errorf("ожидалась причина отзыва 'key compromise', получена %v", record.RevocationReason)
	}
}

func TestGetRevokedCertificates(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	for i := 0; i < 2; i++ {
		cert, certPEM := createTestCertForDB(t)
		cert.SerialNumber = big.NewInt(int64(10000 + i))
		err := db.InsertCertificate(cert, certPEM, "valid")
		if err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < 3; i++ {
		cert, certPEM := createTestCertForDB(t)
		serialNum := int64(20000 + i)
		cert.SerialNumber = big.NewInt(serialNum)
		err := db.InsertCertificate(cert, certPEM, "valid")
		if err != nil {
			t.Fatal(err)
		}
		
		serialHex := big.NewInt(serialNum).Text(16)
		err = db.UpdateCertificateStatus(serialHex, "revoked", "test reason")
		if err != nil {
			t.Fatal(err)
		}
	}

	revoked, err := db.GetRevokedCertificates()
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 3 {
		t.Errorf("ожидалось 3 revoked сертификата, получено %d", len(revoked))
	}
}

func TestDuplicateSerial(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	cert1, certPEM1 := createTestCertForDB(t)
	err := db.InsertCertificate(cert1, certPEM1, "valid")
	if err != nil {
		t.Fatal(err)
	}

	cert2, certPEM2 := createTestCertForDB(t)
	cert2.SerialNumber = cert1.SerialNumber

	err = db.InsertCertificate(cert2, certPEM2, "valid")
	if err == nil {
		t.Error("ожидалась ошибка при вставке дубликата серийного номера")
	}
}

func TestGetNonExistentCertificate(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	record, err := db.GetCertificateBySerial("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if record != nil {
		t.Error("для несуществующего сертификата должен возвращаться nil")
	}
}

func TestSerialUniquenessStress(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск стресс-теста в коротком режиме")
	}
	
	db, cleanup := setupTestDB(t)
	defer cleanup()
	
	certCount := 100
	serials := make(map[string]bool)
	
	t.Logf("запуск стресс-теста на %d сертификатов...", certCount)
	startTime := time.Now()
	
	for i := 0; i < certCount; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		
		serial := big.NewInt(int64(i + 10000))
		template := &x509.Certificate{
			SerialNumber: serial,
			Subject: pkix.Name{
				CommonName:   fmt.Sprintf("test-%d.example.com", i),
				Organization: []string{"Test Org"},
			},
			Issuer: pkix.Name{
				CommonName: "Test CA",
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(1, 0, 0),
			KeyUsage:  x509.KeyUsageDigitalSignature,
		}
		
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})
		
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatal(err)
		}
		
		err = db.InsertCertificate(cert, certPEM, "valid")
		if err != nil {
			t.Fatalf("ошибка вставки сертификата %d: %v", i, err)
		}
		
		serialHex := fmt.Sprintf("%x", serial)
		if serials[serialHex] {
			t.Errorf("дубликат серийного номера: %s", serialHex)
		}
		serials[serialHex] = true
	}
	
	elapsedTime := time.Since(startTime)
	
	records, err := db.ListCertificates("", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	
	if len(records) != certCount {
		t.Errorf("ожидалось %d сертификатов, получено %d", certCount, len(records))
	}
	
	t.Logf("   стресс-тест пройден: %d уникальных серийных номеров за %v", certCount, elapsedTime)
	t.Logf("   средняя скорость: %.2f сертификатов/сек", float64(certCount)/elapsedTime.Seconds())
}

func TestTransactionAtomicity(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	cert1, certPEM1 := createTestCertForDB(t)
	cert2, certPEM2 := createTestCertForDB(t)
	cert2.SerialNumber = big.NewInt(54321)

	serialHex1 := "3039"
	serialHex2 := "d431"

	t.Run("commit - данные должны сохраниться", func(t *testing.T) {
		tx, err := db.BeginTx()
		if err != nil {
			t.Fatal(err)
		}

		err = db.InsertCertificateTx(tx, cert1, certPEM1, "valid")
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}

		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}

		record, err := db.GetCertificateBySerial(serialHex1)
		if err != nil {
			t.Fatal(err)
		}
		if record == nil {
			t.Error("сертификат должен быть виден ПОСЛЕ коммита")
		}
	})

	t.Run("rollback - данные не должны сохраниться", func(t *testing.T) {
		tx, err := db.BeginTx()
		if err != nil {
			t.Fatal(err)
		}

		err = db.InsertCertificateTx(tx, cert2, certPEM2, "valid")
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}

		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}

		record, err := db.GetCertificateBySerial(serialHex2)
		if err != nil {
			t.Fatal(err)
		}
		if record != nil {
			t.Error("сертификат не должен быть виден после rollback")
		}
	})
}
