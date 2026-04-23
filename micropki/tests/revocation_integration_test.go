package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"MicroPKI/internal/crl"
	"MicroPKI/internal/database"
	"MicroPKI/internal/revocation"
)

func setupRevocationTest(t *testing.T) (*database.Database, *x509.Certificate, *rsa.PrivateKey, func()) {
	tmpDir, err := os.MkdirTemp("", "revocation-test-*")
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

	// Создаем CA
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}

	return db, caCert, caKey, cleanup
}

func createLeafCert(t *testing.T, db *database.Database, caCert *x509.Certificate, caKey *rsa.PrivateKey, serial int64, status string) (*x509.Certificate, string) {
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafSerial := big.NewInt(serial)
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "test.example.com"},
		Issuer:       caCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)
	
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	
	db.InsertCertificate(leafCert, leafPEM, status)
	
	// Получаем серийный номер из БД, чтобы формат совпадал
	serialHex := strings.ToLower(hex.EncodeToString(leafSerial.Bytes()))
	return leafCert, serialHex
}

func TestCRLChecker(t *testing.T) {
	db, caCert, caKey, cleanup := setupRevocationTest(t)
	defer cleanup()

	// Создаем и отзываем сертификат
	_, serialHex := createLeafCert(t, db, caCert, caKey, 12345, "valid")
	
	// Отзываем
	revocation.RevokeCertificate(db, serialHex, 1, true)

	// Получаем отозванные сертификаты
	revokedRecords, _ := db.GetRevokedCertificatesByIssuer(caCert.Subject.String())
	
	revokedCerts := make([]crl.RevokedCertInfo, 0)
	for _, r := range revokedRecords {
		serialBytes, _ := hex.DecodeString(r.SerialHex)
		serial := new(big.Int).SetBytes(serialBytes)
		
		revocationTime := time.Now()
		if r.RevocationDate.Valid {
			revocationTime = r.RevocationDate.Time
		}
		
		reasonCode := 0
		if r.RevocationReason.Valid {
			reasonCode, _ = revocation.ReasonCodeToInt(r.RevocationReason.String)
		}
		
		revokedCerts = append(revokedCerts, crl.RevokedCertInfo{
			SerialNumber:   serial,
			RevocationTime: revocationTime,
			ReasonCode:     reasonCode,
		})
	}

	// Генерируем CRL
	crlPEM, err := crl.GenerateCRL(caCert, caKey, revokedCerts, 1, 7)
	if err != nil {
		t.Fatalf("ошибка генерации CRL: %v", err)
	}

	if len(crlPEM) == 0 {
		t.Error("CRL не сгенерирован")
	}

	t.Logf("CRL успешно сгенерирован, размер: %d байт", len(crlPEM))
}

func TestRevocationFallbackLogic(t *testing.T) {
	db, caCert, caKey, cleanup := setupRevocationTest(t)
	defer cleanup()

	// Создаем сертификат
	leafCert, serialHex := createLeafCert(t, db, caCert, caKey, 67890, "valid")

	// Проверяем статус до отзыва
	isRevoked, info, err := revocation.CheckRevoked(db, serialHex)
	if err != nil {
		t.Fatal(err)
	}
	if isRevoked {
		t.Error("сертификат не должен быть отозван")
	}
	t.Logf("статус до отзыва: revoked=%v", isRevoked)

	// Отзываем
	err = revocation.RevokeCertificate(db, serialHex, 1, true)
	if err != nil {
		t.Fatal(err)
	}

	// Проверяем статус после отзыва
	isRevoked, info, err = revocation.CheckRevoked(db, serialHex)
	if err != nil {
		t.Fatal(err)
	}
	if !isRevoked {
		t.Error("сертификат должен быть отозван")
	}
	if info.ReasonCode != 1 {
		t.Errorf("ожидался код причины 1, получен %d", info.ReasonCode)
	}
	t.Logf("статус после отзыва: revoked=%v, reason=%s", isRevoked, info.ReasonString)

	_ = leafCert
}

func TestRevocationReasonCodes(t *testing.T) {
	tests := []struct {
		reason   string
		expected int
	}{
		{"unspecified", 0},
		{"keyCompromise", 1},
		{"cACompromise", 2},
		{"affiliationChanged", 3},
		{"superseded", 4},
		{"cessationOfOperation", 5},
		{"certificateHold", 6},
		{"removeFromCRL", 8},
		{"privilegeWithdrawn", 9},
		{"aACompromise", 10},
	}

	for _, tt := range tests {
		code, err := revocation.ReasonCodeToInt(tt.reason)
		if err != nil {
			t.Errorf("ошибка для %s: %v", tt.reason, err)
		}
		if code != tt.expected {
			t.Errorf("для %s ожидался код %d, получен %d", tt.reason, tt.expected, code)
		}
		
		// Обратное преобразование
		str := revocation.ReasonCodeToString(code)
		if str != tt.reason {
			t.Logf("обратное преобразование: %d -> %s", code, str)
		}
	}
}

func TestMultipleRevocations(t *testing.T) {
	db, caCert, caKey, cleanup := setupRevocationTest(t)
	defer cleanup()

	// Создаем несколько сертификатов
	serials := []int64{1001, 1002, 1003}
	serialHexes := make([]string, 0, len(serials))
	
	for i, serial := range serials {
		_, serialHex := createLeafCert(t, db, caCert, caKey, serial, "valid")
		serialHexes = append(serialHexes, serialHex)
		
		// Отзываем с разными причинами
		reason := i + 1
		err := revocation.RevokeCertificate(db, serialHex, reason, true)
		if err != nil {
			t.Errorf("ошибка отзыва %d: %v", serial, err)
		}
	}

	// Проверяем все отозванные
	for _, serialHex := range serialHexes {
		isRevoked, _, err := revocation.CheckRevoked(db, serialHex)
		if err != nil {
			t.Errorf("ошибка проверки %s: %v", serialHex, err)
		}
		if !isRevoked {
			t.Errorf("сертификат %s должен быть отозван", serialHex)
		}
	}
	
	revoked, err := db.GetRevokedCertificates()
	if err != nil {
		t.Fatal(err)
	}
	
	if len(revoked) != 3 {
		t.Errorf("ожидалось 3 отозванных, получено %d", len(revoked))
	}
	
	t.Logf("отозвано %d сертификатов", len(revoked))
}

func TestCRLNumberIncrement(t *testing.T) {
	db, caCert, caKey, cleanup := setupRevocationTest(t)
	defer cleanup()

	// Первый CRL
	crlPEM1, _ := crl.GenerateCRL(caCert, caKey, []crl.RevokedCertInfo{}, 1, 7)
	block1, _ := pem.Decode(crlPEM1)
	crl1, _ := x509.ParseRevocationList(block1.Bytes)
	
	if crl1.Number.Int64() != 1 {
		t.Errorf("ожидался номер 1, получен %d", crl1.Number.Int64())
	}

	// Второй CRL
	crlPEM2, _ := crl.GenerateCRL(caCert, caKey, []crl.RevokedCertInfo{}, 2, 7)
	block2, _ := pem.Decode(crlPEM2)
	crl2, _ := x509.ParseRevocationList(block2.Bytes)
	
	if crl2.Number.Int64() != 2 {
		t.Errorf("ожидался номер 2, получен %d", crl2.Number.Int64())
	}
	
	t.Logf("CRL номера корректно инкрементируются: %d -> %d", crl1.Number.Int64(), crl2.Number.Int64())

	_ = db
}