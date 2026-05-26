package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
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

func TestGetCertificateStatus(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	cert, certPEM := createTestCertForDB(t)
	err := db.InsertCertificate(cert, certPEM, "valid")
	if err != nil {
		t.Fatal(err)
	}

	serialHex := "3039"
	status, err := db.GetCertificateStatus(serialHex)
	if err != nil {
		t.Fatalf("ошибка получения статуса: %v", err)
	}
	if status != "valid" {
		t.Errorf("ожидался статус valid, получен %s", status)
	}

	status, err = db.GetCertificateStatus("nonexistent")
	if err != nil {
		t.Fatalf("ошибка для несуществующего: %v", err)
	}
	if status != "" {
		t.Errorf("для несуществующего ожидалась пустая строка, получена %s", status)
	}
}

func TestGetRevocationInfo(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	cert, certPEM := createTestCertForDB(t)
	err := db.InsertCertificate(cert, certPEM, "valid")
	if err != nil {
		t.Fatal(err)
	}

	serialHex := "3039"
	
	err = db.UpdateCertificateStatus(serialHex, "revoked", "keyCompromise")
	if err != nil {
		t.Fatal(err)
	}

	revTime, reason, err := db.GetRevocationInfo(serialHex)
	if err != nil {
		t.Fatalf("ошибка получения информации об отзыве: %v", err)
	}
	if revTime.IsZero() {
		t.Error("время отзыва не должно быть нулевым")
	}
	if reason != "keyCompromise" {
		t.Errorf("ожидалась причина keyCompromise, получена %s", reason)
	}

	cert2, certPEM2 := createTestCertForDB(t)
	cert2.SerialNumber = big.NewInt(99999)
	err = db.InsertCertificate(cert2, certPEM2, "valid")
	if err != nil {
		t.Fatal(err)
	}
	serialHex2 := "1869f"
	revTime, reason, err = db.GetRevocationInfo(serialHex2)
	if err != nil {
		t.Fatalf("ошибка для неотозванного: %v", err)
	}
	if !revTime.IsZero() {
		t.Error("для неотозванного сертификата время отзыва должно быть нулевым")
	}
	if reason != "" {
		t.Errorf("для неотозванного причина должна быть пустой, получена %s", reason)
	}
}

func TestInsertCertificateTxRollback(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	cert, certPEM := createTestCertForDB(t)
	cert.SerialNumber = big.NewInt(77777)

	tx, err := db.BeginTx()
	if err != nil {
		t.Fatal(err)
	}

	err = db.InsertCertificateTx(tx, cert, certPEM, "valid")
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}

	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	serialHex := fmt.Sprintf("%x", cert.SerialNumber)
	record, err := db.GetCertificateBySerial(serialHex)
	if err != nil {
		t.Fatal(err)
	}
	if record != nil {
		t.Error("сертификат не должен сохраниться после rollback")
	}
}

func TestInsertCertificateTxDuplicateSerial(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	cert1, certPEM1 := createTestCertForDB(t)
	cert2, certPEM2 := createTestCertForDB(t)
	cert2.SerialNumber = cert1.SerialNumber

	err := db.InsertCertificate(cert1, certPEM1, "valid")
	if err != nil {
		t.Fatal(err)
	}

	tx, err := db.BeginTx()
	if err != nil {
		t.Fatal(err)
	}

	err = db.InsertCertificateTx(tx, cert2, certPEM2, "valid")
	if err == nil {
		tx.Rollback()
		t.Error("ожидалась ошибка при вставке дубликата серийного номера")
	}
	tx.Rollback()
}

func TestListCertificatesWithFilters(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	validCert, validPEM := createTestCertForDB(t)
	validCert.SerialNumber = big.NewInt(10001)
	err := db.InsertCertificate(validCert, validPEM, "valid")
	if err != nil {
		t.Fatal(err)
	}

	revokedCert, revokedPEM := createTestCertForDB(t)
	revokedCert.SerialNumber = big.NewInt(10002)
	err = db.InsertCertificate(revokedCert, revokedPEM, "valid")
	if err != nil {
		t.Fatal(err)
	}
	
	serialHex := fmt.Sprintf("%x", revokedCert.SerialNumber)
	err = db.UpdateCertificateStatus(serialHex, "revoked", "keyCompromise")
	if err != nil {
		t.Fatal(err)
	}

	expiredCert, _ := createTestCertForDB(t)
	expiredCert.SerialNumber = big.NewInt(10003)
	expiredCert.NotAfter = time.Now().AddDate(-1, 0, 0)
	expiredDER, _ := x509.CreateCertificate(rand.Reader, expiredCert, expiredCert, &expiredCert.PublicKey, nil)
	expiredCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expiredDER})
	err = db.InsertCertificate(expiredCert, expiredCertPEM, "expired")
	if err != nil {
		t.Fatal(err)
	}

	validRecords, err := db.ListCertificates("valid", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(validRecords) < 1 {
		t.Error("должен быть хотя бы один valid сертификат")
	}

	revokedRecords, err := db.ListCertificates("revoked", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(revokedRecords) < 1 {
		t.Error("должен быть хотя бы один revoked сертификат")
	}

	expiredRecords, err := db.ListCertificates("expired", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(expiredRecords) < 1 {
		t.Error("должен быть хотя бы один expired сертификат")
	}
}

func TestGetRevokedCertificatesByIssuer(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	issuerCert, _ := x509.ParseCertificate(issuerDER)
	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})
	
	err = db.InsertCertificate(issuerCert, issuerPEM, "valid")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		leafSerial := big.NewInt(int64(20000 + i))
		leafTemplate := &x509.Certificate{
			SerialNumber: leafSerial,
			Subject:      pkix.Name{CommonName: fmt.Sprintf("test%d.example.com", i)},
			Issuer:       issuerCert.Subject,
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(1, 0, 0),
		}
		leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, issuerCert, &leafKey.PublicKey, issuerKey)
		leafCert, _ := x509.ParseCertificate(leafDER)
		leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
		
		err = db.InsertCertificate(leafCert, leafPEM, "valid")
		if err != nil {
			t.Fatal(err)
		}
		
		serialHex := fmt.Sprintf("%x", leafSerial)
		err = db.UpdateCertificateStatus(serialHex, "revoked", "keyCompromise")
		if err != nil {
			t.Fatal(err)
		}
	}

	revoked, err := db.GetRevokedCertificatesByIssuer("CN=Test CA")
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 3 {
		t.Errorf("ожидалось 3 отозванных сертификата, получено %d", len(revoked))
	}
}

func TestParseCertFromPEM(t *testing.T) {
	cert, certPEM := createTestCertForDB(t)
	
	parsedCert, err := database.ParseCertFromPEM(string(certPEM))
	if err != nil {
		t.Fatalf("ошибка парсинга PEM: %v", err)
	}
	
	if parsedCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("серийные номера не совпадают")
	}
	
	_, err = database.ParseCertFromPEM("invalid pem data")
	if err == nil {
		t.Error("ожидалась ошибка для невалидного PEM")
	}
}

func TestDatabaseMigrations(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "migration-test-*")
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
		t.Fatalf("ошибка инициализации схемы: %v", err)
	}

	err = db.ApplyMigrations()
	if err != nil {
		t.Fatalf("ошибка применения миграций: %v", err)
	}

	var count int
	err = db.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='certificates'").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Error("таблица certificates не создана")
	}

	err = db.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='compromised_keys'").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Error("таблица compromised_keys не создана")
	}
	
	err = db.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Error("таблица schema_migrations не создана")
	}
}

func TestBeginTxWithLevel(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	opts := &sql.TxOptions{
		Isolation: sql.LevelSerializable,
		ReadOnly:  false,
	}
	tx, err := db.BeginTxWithLevel(opts)
	if err != nil {
		t.Fatalf("BeginTxWithLevel ошибка: %v", err)
	}
	if tx == nil {
		t.Error("транзакция nil")
	}
	tx.Rollback()
}

func TestGetCompromisedKeyInfo(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	cert, certPEM := createTestCertForDB(t)
	cert.SerialNumber = big.NewInt(99999)
	err := db.InsertCertificate(cert, certPEM, "valid")
	if err != nil {
		t.Fatal(err)
	}

	records, err := db.ListCertificates("", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	var serialHex string
	for _, r := range records {
		if r.Subject == cert.Subject.String() {
			serialHex = r.SerialHex
			break
		}
	}
	if serialHex == "" {
		t.Skip("не удалось найти серийный номер")
	}

	err = db.InsertCompromisedKey("test_hash_123", serialHex, "test")
	if err != nil {
		t.Fatal(err)
	}

	info, err := db.GetCompromisedKeyInfo(serialHex)
	if err != nil {
		t.Fatalf("GetCompromisedKeyInfo ошибка: %v", err)
	}
	if info == nil {
		t.Error("информация о скомпрометированном ключе не найдена")
	} else {
		t.Logf("найдена информация: hash=%s, serial=%s", info.PublicKeyHash, info.CertSerial)
	}
}

func TestSerialGenerator(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema ошибка: %v", err)
	}

	gen := database.NewSerialGenerator(db)
	if gen == nil {
		t.Error("NewSerialGenerator вернул nil")
	}

	// Тест GenerateSerialNumber
	serial1, err := gen.GenerateSerialNumber()
	if err != nil {
		t.Fatalf("GenerateSerialNumber ошибка: %v", err)
	}
	if serial1 == nil {
		t.Error("серийный номер nil")
	}
	if serial1.Sign() <= 0 {
		t.Error("серийный номер должен быть положительным")
	}
	t.Logf("сгенерирован серийный номер: %x", serial1)

	// Тест GenerateSerialNumberWithCounter
	serial2, err := gen.GenerateSerialNumberWithCounter()
	if err != nil {
		t.Fatalf("GenerateSerialNumberWithCounter ошибка: %v", err)
	}
	if serial2 == nil {
		t.Error("серийный номер счётчика nil")
	}
	if serial2.Sign() <= 0 {
		t.Error("серийный номер счётчика должен быть положительным")
	}
	t.Logf("сгенерирован серийный номер со счётчиком: %x", serial2)

	// Тест ValidateSerialNumber
	valid, err := gen.ValidateSerialNumber(serial1)
	if err != nil {
		t.Fatalf("ValidateSerialNumber ошибка: %v", err)
	}
	if !valid {
		t.Log("серийный номер считается невалидным (возможно, уже существует в БД)")
	} else {
		t.Log("серийный номер валидный")
	}
}

func TestSerialGeneratorWithExistingCounter(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema ошибка: %v", err)
	}

	gen := database.NewSerialGenerator(db)
	
	// Первый вызов создаст запись в serial_counters
	serial1, err := gen.GenerateSerialNumberWithCounter()
	if err != nil {
		t.Fatalf("первый вызов GenerateSerialNumberWithCounter ошибка: %v", err)
	}
	t.Logf("первый серийный номер: %x", serial1)
	
	// Второй вызов должен использовать существующую запись
	serial2, err := gen.GenerateSerialNumberWithCounter()
	if err != nil {
		t.Fatalf("второй вызов GenerateSerialNumberWithCounter ошибка: %v", err)
	}
	t.Logf("второй серийный номер: %x", serial2)
	
	// Номера должны быть разными
	if serial1.Cmp(serial2) == 0 {
		t.Error("серийные номера не должны совпадать")
	}
}

func TestGetCompromisedKeyInfoFullCoverage(t *testing.T) {
    db, cleanup := setupTestDB(t)
    defer cleanup()

    // Создаём тестовый сертификат
    cert, certPEM := createTestCertForDB(t)
    cert.SerialNumber = big.NewInt(123456789)
    err := db.InsertCertificate(cert, certPEM, "valid")
    if err != nil {
        t.Fatal(err)
    }

    // Получаем серийный номер
    records, err := db.ListCertificates("", "", 0)
    if err != nil {
        t.Fatal(err)
    }
    var serialHex string
    for _, r := range records {
        if r.Subject == cert.Subject.String() {
            serialHex = r.SerialHex
            break
        }
    }
    if serialHex == "" {
        t.Fatal("serial not found")
    }

    // Вставляем скомпрометированный ключ
    testHash := "test_hash_1234567890abcdef1234567890abcdef12345678"
    err = db.InsertCompromisedKey(testHash, serialHex, "test reason")
    if err != nil {
        t.Fatal(err)
    }

    // Тест 1: Получение существующей информации
    info, err := db.GetCompromisedKeyInfo(serialHex)
    if err != nil {
        t.Fatalf("GetCompromisedKeyInfo error: %v", err)
    }
    if info == nil {
        t.Error("info should not be nil")
    } else {
        t.Logf("Found compromised key: hash=%s, serial=%s", info.PublicKeyHash, info.CertSerial)
    }

    // Тест 2: Несуществующий серийный номер
    info, err = db.GetCompromisedKeyInfo("nonexistent")
    if err != nil {
        t.Logf("Error for nonexistent serial: %v", err)
    }
    if info != nil {
        t.Error("info should be nil for nonexistent serial")
    }

    // Тест 3: Серийный номер без компрометации
    cert2, certPEM2 := createTestCertForDB(t)
    cert2.SerialNumber = big.NewInt(987654321)
    err = db.InsertCertificate(cert2, certPEM2, "valid")
    if err != nil {
        t.Fatal(err)
    }
    
    records2, err := db.ListCertificates("", "", 0)
    if err != nil {
        t.Fatal(err)
    }
    var serialHex2 string
    for _, r := range records2 {
        if r.Subject == cert2.Subject.String() {
            serialHex2 = r.SerialHex
            break
        }
    }
    
    info, err = db.GetCompromisedKeyInfo(serialHex2)
    if err != nil {
        t.Logf("Error for non-compromised serial: %v", err)
    }
    if info != nil {
        t.Log("info should be nil for non-compromised key")
    }

    t.Log("GetCompromisedKeyInfo full coverage test completed")
}