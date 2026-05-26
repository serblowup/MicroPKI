package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"MicroPKI/internal/crl"
	"MicroPKI/internal/database"
)

func TestGenerateCRL(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4, 5},
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	revocationTime := time.Now().UTC()
	revokedCerts := []crl.RevokedCertInfo{
		{
			SerialNumber:   big.NewInt(100),
			RevocationTime: revocationTime,
			ReasonCode:     1,
		},
		{
			SerialNumber:   big.NewInt(200),
			RevocationTime: revocationTime,
			ReasonCode:     4,
		},
	}

	crlPEM, err := crl.GenerateCRL(caCert, caKey, revokedCerts, 1, 7)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("не удалось декодировать CRL PEM")
	}
	if block.Type != "X509 CRL" {
		t.Errorf("ожидался тип X509 CRL, получен %s", block.Type)
	}

	crlList, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if crlList.Number.Int64() != 1 {
		t.Errorf("ожидался номер CRL 1, получен %d", crlList.Number.Int64())
	}

	if len(crlList.RevokedCertificates) != 2 {
		t.Errorf("ожидалось 2 отозванных сертификата, получено %d", len(crlList.RevokedCertificates))
	}
}

func TestGenerateCRLWithNoRevokedCerts(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4, 5},
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	crlPEM, err := crl.GenerateCRL(caCert, caKey, []crl.RevokedCertInfo{}, 5, 14)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("не удалось декодировать CRL PEM")
	}
	crlList, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if crlList.Number.Int64() != 5 {
		t.Errorf("ожидался номер CRL 5, получен %d", crlList.Number.Int64())
	}

	if len(crlList.RevokedCertificates) != 0 {
		t.Errorf("ожидалось 0 отозванных сертификатов, получено %d", len(crlList.RevokedCertificates))
	}

	expectedNextUpdate := crlList.ThisUpdate.AddDate(0, 0, 14)
	if crlList.NextUpdate.Sub(expectedNextUpdate).Abs() > time.Second {
		t.Errorf("NextUpdate не соответствует ожидаемому: ожидалось %v, получено %v", expectedNextUpdate, crlList.NextUpdate)
	}
}

func TestGenerateCRLWithReasonCodes(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4, 5},
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	revocationTime := time.Now().UTC()
	revokedCerts := []crl.RevokedCertInfo{
		{SerialNumber: big.NewInt(1), RevocationTime: revocationTime, ReasonCode: 1},
		{SerialNumber: big.NewInt(2), RevocationTime: revocationTime, ReasonCode: 2},
		{SerialNumber: big.NewInt(3), RevocationTime: revocationTime, ReasonCode: 4},
		{SerialNumber: big.NewInt(4), RevocationTime: revocationTime, ReasonCode: 8},
	}

	crlPEM, err := crl.GenerateCRL(caCert, caKey, revokedCerts, 1, 7)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("не удалось декодировать CRL PEM")
	}
	crlList, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(crlList.RevokedCertificates) != 4 {
		t.Fatalf("ожидалось 4 записи, получено %d", len(crlList.RevokedCertificates))
	}
}

func setupCRLTestDB(t *testing.T) (*database.Database, string, func()) {
	tmpDir, err := os.MkdirTemp("", "crl-db-test-*")
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

	return db, tmpDir, cleanup
}

func TestGetNextCRLNumber(t *testing.T) {
	db, _, cleanup := setupCRLTestDB(t)
	defer cleanup()

	number, err := crl.GetNextCRLNumber(db, "CN=Test CA")
	if err != nil {
		t.Fatalf("ошибка получения номера CRL: %v", err)
	}
	if number != 1 {
		t.Errorf("ожидался номер 1, получен %d", number)
	}

	err = crl.UpdateCRLMetadata(db, "CN=Test CA", 1, time.Now().AddDate(0, 0, 7), "/path/to/crl.pem")
	if err != nil {
		t.Fatalf("ошибка обновления метаданных: %v", err)
	}

	number, err = crl.GetNextCRLNumber(db, "CN=Test CA")
	if err != nil {
		t.Fatalf("ошибка получения номера CRL: %v", err)
	}
	if number != 2 {
		t.Errorf("ожидался номер 2, получен %d", number)
	}

	number, err = crl.GetNextCRLNumber(db, "CN=Nonexistent")
	if err != nil {
		t.Fatalf("ошибка для несуществующего CA: %v", err)
	}
	if number != 1 {
		t.Errorf("для нового CA ожидался номер 1, получен %d", number)
	}
}

func TestUpdateCRLMetadata(t *testing.T) {
	db, _, cleanup := setupCRLTestDB(t)
	defer cleanup()

	caSubject := "CN=Test Intermediate CA"
	crlNumber := int64(5)
	nextUpdate := time.Now().UTC().AddDate(0, 0, 14)
	crlPath := "/pki/crl/intermediate.crl.pem"

	err := crl.UpdateCRLMetadata(db, caSubject, crlNumber, nextUpdate, crlPath)
	if err != nil {
		t.Fatalf("ошибка обновления метаданных: %v", err)
	}

	newNumber := int64(6)
	err = crl.UpdateCRLMetadata(db, caSubject, newNumber, nextUpdate, crlPath)
	if err != nil {
		t.Fatalf("ошибка обновления существующей записи: %v", err)
	}
}

func TestGetCRLMetadata(t *testing.T) {
	db, _, cleanup := setupCRLTestDB(t)
	defer cleanup()

	caSubject := "CN=Test CA"
	crlNumber := int64(10)
	nextUpdate := time.Now().UTC().AddDate(0, 0, 7)
	crlPath := "/pki/crl/ca.crl.pem"

	metadata, err := crl.GetCRLMetadata(db, caSubject)
	if err != nil {
		t.Fatalf("ошибка получения метаданных: %v", err)
	}
	if metadata != nil {
		t.Error("для несуществующей записи должно вернуться nil")
	}

	err = crl.UpdateCRLMetadata(db, caSubject, crlNumber, nextUpdate, crlPath)
	if err != nil {
		t.Fatalf("ошибка добавления метаданных: %v", err)
	}

	metadata, err = crl.GetCRLMetadata(db, caSubject)
	if err != nil {
		t.Fatalf("ошибка получения метаданных: %v", err)
	}
	if metadata == nil {
		t.Fatal("метаданные не найдены")
	}
	if metadata.CRLNumber != crlNumber {
		t.Errorf("ожидался номер %d, получен %d", crlNumber, metadata.CRLNumber)
	}
	if metadata.CRLPath != crlPath {
		t.Errorf("ожидался путь %s, получен %s", crlPath, metadata.CRLPath)
	}
}

func TestCRLMetadataMultipleCAs(t *testing.T) {
	db, _, cleanup := setupCRLTestDB(t)
	defer cleanup()

	cas := []struct {
		subject string
		number  int64
		path    string
	}{
		{"CN=Root CA", 1, "/pki/crl/root.crl.pem"},
		{"CN=Intermediate CA", 5, "/pki/crl/intermediate.crl.pem"},
		{"CN=Signing CA", 3, "/pki/crl/signing.crl.pem"},
	}

	for _, ca := range cas {
		err := crl.UpdateCRLMetadata(db, ca.subject, ca.number, time.Now().AddDate(0, 0, 7), ca.path)
		if err != nil {
			t.Fatalf("ошибка добавления метаданных для %s: %v", ca.subject, err)
		}
	}

	for _, ca := range cas {
		metadata, err := crl.GetCRLMetadata(db, ca.subject)
		if err != nil {
			t.Fatalf("ошибка получения метаданных для %s: %v", ca.subject, err)
		}
		if metadata == nil {
			t.Errorf("метаданные не найдены для %s", ca.subject)
			continue
		}
		if metadata.CRLNumber != ca.number {
			t.Errorf("для %s ожидался номер %d, получен %d", ca.subject, ca.number, metadata.CRLNumber)
		}
	}

	for _, ca := range cas {
		nextNumber, err := crl.GetNextCRLNumber(db, ca.subject)
		if err != nil {
			t.Fatalf("ошибка получения следующего номера для %s: %v", ca.subject, err)
		}
		expected := ca.number + 1
		if nextNumber != expected {
			t.Errorf("для %s ожидался следующий номер %d, получен %d", ca.subject, expected, nextNumber)
		}
	}
}

func TestCRLGenerationWithLargeNumberOfRevokedCerts(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4, 5},
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	revocationTime := time.Now().UTC()
	revokedCerts := make([]crl.RevokedCertInfo, 100)
	for i := 0; i < 100; i++ {
		revokedCerts[i] = crl.RevokedCertInfo{
			SerialNumber:   big.NewInt(int64(1000 + i)),
			RevocationTime: revocationTime,
			ReasonCode:     i%10 + 1,
		}
	}

	crlPEM, err := crl.GenerateCRL(caCert, caKey, revokedCerts, 1, 7)
	if err != nil {
		t.Fatalf("ошибка генерации CRL с 100 отозванными: %v", err)
	}

	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("не удалось декодировать CRL PEM")
	}
	crlList, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(crlList.RevokedCertificates) != 100 {
		t.Errorf("ожидалось 100 отозванных, получено %d", len(crlList.RevokedCertificates))
	}
}

func TestCRLWithDifferentNextUpdateValues(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4, 5},
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		nextUpdateDays int
		expectedDays   int
	}{
		{1, 1},
		{7, 7},
		{14, 14},
		{30, 30},
		{90, 90},
	}

	for _, tt := range tests {
		crlPEM, err := crl.GenerateCRL(caCert, caKey, []crl.RevokedCertInfo{}, 1, tt.nextUpdateDays)
		if err != nil {
			t.Fatalf("ошибка генерации CRL с nextUpdate=%d: %v", tt.nextUpdateDays, err)
		}

		block, _ := pem.Decode(crlPEM)
		if block == nil {
			t.Fatal("не удалось декодировать CRL PEM")
		}
		crlList, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}

		expectedNextUpdate := crlList.ThisUpdate.AddDate(0, 0, tt.expectedDays)
		if crlList.NextUpdate.Sub(expectedNextUpdate).Abs() > time.Second*10 {
			t.Errorf("для nextUpdateDays=%d: ожидалось %v, получено %v",
				tt.nextUpdateDays, expectedNextUpdate, crlList.NextUpdate)
		}
	}
}

func TestCRLWithZeroRevokedCertificates(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4, 5},
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	crlPEM, err := crl.GenerateCRL(caCert, caKey, []crl.RevokedCertInfo{}, 3, 7)
	if err != nil {
		t.Fatalf("ошибка генерации CRL: %v", err)
	}

	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("не удалось декодировать CRL PEM")
	}
	crlList, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if crlList.Number.Int64() != 3 {
		t.Errorf("ожидался номер CRL 3, получен %d", crlList.Number.Int64())
	}
	if len(crlList.RevokedCertificates) != 0 {
		t.Errorf("ожидалось 0 отозванных сертификатов, получено %d", len(crlList.RevokedCertificates))
	}
}