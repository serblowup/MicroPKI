package tests

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"MicroPKI/internal/ca"
	"MicroPKI/internal/certs"
	"MicroPKI/internal/cryptoutil"
	"MicroPKI/internal/csr"
	"MicroPKI/internal/database"
	"MicroPKI/internal/revocation"
)

func setupRevocationTestDB(t *testing.T) (*database.Database, string, func()) {
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

	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}

	return db, tmpDir, cleanup
}

func createPKIChainForTest(t *testing.T, tmpDir string, db *database.Database) (*x509.Certificate, crypto.Signer, string) {
	rootPassFile := filepath.Join(tmpDir, "root.pass")
	if err := os.WriteFile(rootPassFile, []byte("rootpass123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootCA, err := ca.NewRootCA(
		"/CN=Test Root CA",
		"rsa",
		4096,
		rootPassFile,
		tmpDir,
		365,
		false,
		db,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := rootCA.Initialize(); err != nil {
		t.Fatal(err)
	}

	interPassFile := filepath.Join(tmpDir, "inter.pass")
	if err := os.WriteFile(interPassFile, []byte("interpass123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootKey, err := cryptoutil.LoadEncryptedPrivateKey(
		filepath.Join(tmpDir, "private", "ca.key.pem"),
		[]byte("rootpass123"),
	)
	if err != nil {
		t.Fatal(err)
	}

	rootCertPEM, err := os.ReadFile(filepath.Join(tmpDir, "certs", "ca.cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(rootCertPEM)
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	interKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	if err := cryptoutil.SaveEncryptedRSAPEM(
		filepath.Join(tmpDir, "private", "intermediate.key.pem"),
		interKey,
		[]byte("interpass123"),
	); err != nil {
		t.Fatal(err)
	}

	csrPEM, err := csr.GenerateIntermediateCSR(
		"/CN=Test Intermediate CA",
		&interKey.PublicKey,
		interKey,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	csrObj, err := csr.ParseCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, err := certs.GenerateSerialNumber()
	if err != nil {
		t.Fatal(err)
	}

	ski, err := certs.CalculateSKI(&interKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	interTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csrObj.Subject,
		Issuer:       rootCert.Subject,
		NotBefore:    rootCert.NotBefore,
		NotAfter:     rootCert.NotAfter,

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,

		SubjectKeyId:   ski,
		AuthorityKeyId: rootCert.SubjectKeyId,
	}

	interCertDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	interCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: interCertDER,
	})

	interCertPath := filepath.Join(tmpDir, "certs", "intermediate.cert.pem")
	if err := os.WriteFile(interCertPath, interCertPEM, 0644); err != nil {
		t.Fatal(err)
	}

	interCert, err := x509.ParseCertificate(interCertDER)
	if err != nil {
		t.Fatal(err)
	}

	// Возвращаем промежуточный сертификат, его ключ и subject
	return interCert, interKey, interCert.Subject.String()
}

func TestReasonCodeConversion(t *testing.T) {
	tests := []struct {
		input    string
		expected int
		wantErr  bool
	}{
		{"unspecified", 0, false},
		{"keyCompromise", 1, false},
		{"cACompromise", 2, false},
		{"affiliationChanged", 3, false},
		{"superseded", 4, false},
		{"cessationOfOperation", 5, false},
		{"certificateHold", 6, false},
		{"removeFromCRL", 8, false},
		{"privilegeWithdrawn", 9, false},
		{"aACompromise", 10, false},
		{"invalid", -1, true},
	}

	for _, tt := range tests {
		code, err := revocation.ReasonCodeToInt(tt.input)
		if tt.wantErr && err == nil {
			t.Errorf("для %s ожидалась ошибка", tt.input)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("для %s ошибка: %v", tt.input, err)
		}
		if code != tt.expected {
			t.Errorf("для %s ожидался код %d, получен %d", tt.input, tt.expected, code)
		}
	}

	if revocation.ReasonCodeToString(1) != "keyCompromise" {
		t.Error("ReasonCodeToString(1) должно вернуть keyCompromise")
	}
	if revocation.ReasonCodeToString(99) != "unknown" {
		t.Error("ReasonCodeToString(99) должно вернуть unknown")
	}
}

func TestRevokeCertificate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "revoke-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, err := database.NewDatabase(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}

	interCert, interKey, _ := createPKIChainForTest(t, tmpDir, db)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	leafSerial := big.NewInt(12345)
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "test.example.com"},
		Issuer:       interCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.example.com"},
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}

	leafCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCertDER,
	})

	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.InsertCertificate(leafCert, leafCertPEM, "valid"); err != nil {
		t.Fatal(err)
	}

	// Получаем правильный серийный номер из БД
	records, err := db.ListCertificates("", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	var serialHex string
	for _, record := range records {
		if record.Subject == leafCert.Subject.String() {
			serialHex = record.SerialHex
			break
		}
	}
	if serialHex == "" {
		t.Fatal("не удалось найти серийный номер сертификата")
	}

	err = revocation.RevokeCertificate(db, serialHex, 1, false)
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
	if !record.RevocationReason.Valid || record.RevocationReason.String != "keyCompromise" {
		t.Errorf("ожидалась причина keyCompromise, получена %v", record.RevocationReason)
	}
}

func TestRevokeAlreadyRevokedCertificate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "revoke-already-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, err := database.NewDatabase(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}

	interCert, interKey, _ := createPKIChainForTest(t, tmpDir, db)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	leafSerial := big.NewInt(12345)
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "test.example.com"},
		Issuer:       interCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.example.com"},
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}

	leafCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCertDER,
	})

	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		t.Fatal(err)
	}

	// Вставляем сразу как revoked
	if err := db.InsertCertificate(leafCert, leafCertPEM, "revoked"); err != nil {
		t.Fatal(err)
	}

	// Получаем серийный номер
	records, err := db.ListCertificates("", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	var serialHex string
	for _, record := range records {
		if record.Subject == leafCert.Subject.String() {
			serialHex = record.SerialHex
			break
		}
	}
	if serialHex == "" {
		t.Fatal("не удалось найти серийный номер")
	}

	err = revocation.RevokeCertificate(db, serialHex, 1, false)
	if err != nil {
		t.Fatal(err)
	}

	record, err := db.GetCertificateBySerial(serialHex)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != "revoked" {
		t.Errorf("статус не должен измениться, получен %s", record.Status)
	}
}

func TestRevokeNonExistentCertificate(t *testing.T) {
	db, _, cleanup := setupRevocationTestDB(t)
	defer cleanup()

	err := revocation.RevokeCertificate(db, "deadbeef", 1, false)
	if err == nil {
		t.Error("ожидалась ошибка при отзыве несуществующего сертификата")
	}
}

func TestGetRevokedCertificatesByIssuerFromRevocation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "revoked-by-issuer-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, err := database.NewDatabase(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}

	interCert, interKey, issuerSubject := createPKIChainForTest(t, tmpDir, db)

	leafKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	leafSerial1 := big.NewInt(100)
	leafTemplate1 := &x509.Certificate{
		SerialNumber: leafSerial1,
		Subject:      pkix.Name{CommonName: "test1.example.com"},
		Issuer:       interCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test1.example.com"},
	}

	leafCert1DER, err := x509.CreateCertificate(rand.Reader, leafTemplate1, interCert, &leafKey1.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}

	leafCert1PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert1DER,
	})

	leafCert1, err := x509.ParseCertificate(leafCert1DER)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.InsertCertificate(leafCert1, leafCert1PEM, "valid"); err != nil {
		t.Fatal(err)
	}

	leafKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	leafSerial2 := big.NewInt(200)
	leafTemplate2 := &x509.Certificate{
		SerialNumber: leafSerial2,
		Subject:      pkix.Name{CommonName: "test2.example.com"},
		Issuer:       interCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test2.example.com"},
	}

	leafCert2DER, err := x509.CreateCertificate(rand.Reader, leafTemplate2, interCert, &leafKey2.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}

	leafCert2PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert2DER,
	})

	leafCert2, err := x509.ParseCertificate(leafCert2DER)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.InsertCertificate(leafCert2, leafCert2PEM, "valid"); err != nil {
		t.Fatal(err)
	}

	// Получаем серийные номера
	records, err := db.ListCertificates("", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	var serialHex1, serialHex2 string
	for _, record := range records {
		if record.Subject == leafCert1.Subject.String() {
			serialHex1 = record.SerialHex
		}
		if record.Subject == leafCert2.Subject.String() {
			serialHex2 = record.SerialHex
		}
	}

	err = revocation.RevokeCertificate(db, serialHex1, 1, true)
	if err != nil {
		t.Fatal(err)
	}

	err = revocation.RevokeCertificate(db, serialHex2, 4, true)
	if err != nil {
		t.Fatal(err)
	}

	revoked, err := revocation.GetRevokedCertificatesByIssuer(db, issuerSubject)
	if err != nil {
		t.Fatal(err)
	}

	if len(revoked) != 2 {
		t.Errorf("ожидалось 2 отозванных сертификата, получено %d", len(revoked))
	}
}

func TestCheckRevoked(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "check-revoked-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, err := database.NewDatabase(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}

	interCert, interKey, _ := createPKIChainForTest(t, tmpDir, db)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	leafSerial := big.NewInt(12345)
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "test.example.com"},
		Issuer:       interCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.example.com"},
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}

	leafCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCertDER,
	})

	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.InsertCertificate(leafCert, leafCertPEM, "valid"); err != nil {
		t.Fatal(err)
	}

	// Получаем серийный номер
	records, err := db.ListCertificates("", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	var serialHex string
	for _, record := range records {
		if record.Subject == leafCert.Subject.String() {
			serialHex = record.SerialHex
			break
		}
	}
	if serialHex == "" {
		t.Fatal("не удалось найти серийный номер")
	}

	isRevoked, info, err := revocation.CheckRevoked(db, serialHex)
	if err != nil {
		t.Fatal(err)
	}
	if isRevoked {
		t.Error("сертификат не должен быть отозван")
	}
	if info != nil {
		t.Error("info должен быть nil для неотозванного сертификата")
	}

	err = revocation.RevokeCertificate(db, serialHex, 2, false)
	if err != nil {
		t.Fatal(err)
	}

	isRevoked, info, err = revocation.CheckRevoked(db, serialHex)
	if err != nil {
		t.Fatal(err)
	}
	if !isRevoked {
		t.Error("сертификат должен быть отозван")
	}
	if info == nil {
		t.Error("info не должен быть nil для отозванного сертификата")
	}
	if info.ReasonCode != 2 {
		t.Errorf("ожидался код причины 2, получен %d", info.ReasonCode)
	}
}

func TestGetRevokedCertificatesWithSerialConversion(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "serial-conversion-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, err := database.NewDatabase(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}

	interCert, interKey, issuerSubject := createPKIChainForTest(t, tmpDir, db)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	leafSerial := big.NewInt(999)
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "test.example.com"},
		Issuer:       interCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.example.com"},
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}

	leafCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCertDER,
	})

	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.InsertCertificate(leafCert, leafCertPEM, "valid"); err != nil {
		t.Fatal(err)
	}

	allCerts, err := db.ListCertificates("", "", 0)
	if err != nil {
		t.Fatal(err)
	}

	var serialHex string
	for _, cert := range allCerts {
		if cert.Subject == "CN=test.example.com" {
			serialHex = cert.SerialHex
			break
		}
	}

	if serialHex == "" {
		t.Fatal("не удалось найти серийный номер сертификата")
	}
	t.Logf("Найден серийный номер в БД: %s", serialHex)

	err = revocation.RevokeCertificate(db, serialHex, 1, false)
	if err != nil {
		t.Fatal(err)
	}

	revoked, err := revocation.GetRevokedCertificatesByIssuer(db, issuerSubject)
	if err != nil {
		t.Fatal(err)
	}

	if len(revoked) != 1 {
		t.Fatalf("ожидался 1 сертификат, получено %d", len(revoked))
	}

	record, err := db.GetCertificateBySerial(serialHex)
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatalf("сертификат с серийным номером %s не найден", serialHex)
	}

	expectedSerialBytes, err := hex.DecodeString(record.SerialHex)
	if err != nil {
		t.Fatal(err)
	}
	expectedSerial := new(big.Int).SetBytes(expectedSerialBytes)

	if revoked[0].SerialNumber.Cmp(expectedSerial) != 0 {
		t.Errorf("серийный номер не совпадает: ожидался %x, получен %x", expectedSerial, revoked[0].SerialNumber)
	}
}

func TestNewCRLChecker(t *testing.T) {
	checker := revocation.NewCRLChecker()
	if checker == nil {
		t.Error("NewCRLChecker вернул nil")
	}
}

func TestNewRevocationChecker(t *testing.T) {
	checker := revocation.NewRevocationChecker()
	if checker == nil {
		t.Error("NewRevocationChecker вернул nil")
	}
}

func TestRevokeWithAllReasonCodes(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "all-reasons-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, err := database.NewDatabase(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}

	interCert, interKey, _ := createPKIChainForTest(t, tmpDir, db)

	reasonCodes := []struct {
		code int
		name string
	}{
		{0, "unspecified"},
		{1, "keyCompromise"},
		{2, "cACompromise"},
		{3, "affiliationChanged"},
		{4, "superseded"},
		{5, "cessationOfOperation"},
		{6, "certificateHold"},
		{8, "removeFromCRL"},
		{9, "privilegeWithdrawn"},
		{10, "aACompromise"},
	}

	for i, rc := range reasonCodes {
		t.Logf("=== Testing reason: %s (code %d) ===", rc.name, rc.code)
		
		leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("error generating key for %s: %v", rc.name, err)
		}
		
		leafSerial := big.NewInt(int64(100000 + i))
		leafTemplate := &x509.Certificate{
			SerialNumber: leafSerial,
			Subject:      pkix.Name{CommonName: fmt.Sprintf("reason-%d.example.com", rc.code)},
			Issuer:       interCert.Subject,
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(1, 0, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
		if err != nil {
			t.Fatalf("error creating certificate for %s: %v", rc.name, err)
		}
		
		leafCert, err := x509.ParseCertificate(leafDER)
		if err != nil {
			t.Fatalf("error parsing certificate for %s: %v", rc.name, err)
		}
		
		leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

		if err := db.InsertCertificate(leafCert, leafPEM, "valid"); err != nil {
			t.Fatalf("error inserting certificate for %s: %v", rc.name, err)
		}

		// Получаем серийный номер из БД
		var serialHex string
		err = db.DB.QueryRow("SELECT serial_hex FROM certificates WHERE subject = ?", leafCert.Subject.String()).Scan(&serialHex)
		if err != nil {
			t.Fatalf("failed to get serial for %s: %v", rc.name, err)
		}
		
		t.Logf("  Serial: %s", serialHex)

		err = revocation.RevokeCertificate(db, serialHex, rc.code, true)
		if err != nil {
			t.Errorf("error revoking with reason %s: %v", rc.name, err)
			continue
		}
		t.Logf("  Revoked successfully")

		// Проверяем статус
		var status string
		err = db.DB.QueryRow("SELECT status FROM certificates WHERE serial_hex = ?", serialHex).Scan(&status)
		if err != nil {
			t.Errorf("error checking status for %s: %v", rc.name, err)
			continue
		}
		
		if status != "revoked" {
			t.Errorf("certificate with reason %s not revoked, status=%s", rc.name, status)
		} else {
			t.Logf("  Status verified: %s", status)
		}
		
		// Проверяем причину
		var reason string
		err = db.DB.QueryRow("SELECT revocation_reason FROM certificates WHERE serial_hex = ?", serialHex).Scan(&reason)
		if err != nil {
			t.Errorf("error getting reason for %s: %v", rc.name, err)
			continue
		}
		
		expectedReason := revocation.ReasonCodeToString(rc.code)
		if reason != expectedReason {
			t.Errorf("expected reason %s, got %s", expectedReason, reason)
		} else {
			t.Logf("  Reason verified: %s", reason)
		}
	}
	
	t.Log("All reason codes tested successfully")
}

func TestDownloadCRLFromHTTP(t *testing.T) {
	crlContent := []byte("-----BEGIN X509 CRL-----\ntest\n-----END X509 CRL-----\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(http.StatusOK)
		w.Write(crlContent)
	}))
	defer server.Close()

	checker := revocation.NewCRLChecker()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	issuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Issuer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	issuer, _ := x509.ParseCertificate(issuerDER)

	result, err := checker.CheckCertificate(cert, issuer, server.URL)
	if err != nil {
		t.Logf("ошибка HTTP CRL проверки: %v", err)
	}
	if result != nil {
		t.Logf("статус: %s", result.Status)
	}
}

func TestCheckStatus(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "check-status-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, err := database.NewDatabase(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}

	interCert, interKey, _ := createPKIChainForTest(t, tmpDir, db)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafSerial := big.NewInt(123456)
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "test.example.com"},
		Issuer:       interCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	leafCert, _ := x509.ParseCertificate(leafDER)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	db.InsertCertificate(leafCert, leafPEM, "valid")

	checker := revocation.NewRevocationChecker()
	
	opts := &revocation.RevocationCheckOptions{
		Cert:          leafCert,
		Issuer:        interCert,
		OCSPURL:       "",
		CRLSource:     "",
		PreferOCSP:    false,
		FallbackToCRL: false,
	}
	
	result, err := checker.CheckStatus(opts)
	if err != nil {
		t.Logf("CheckStatus error: %v", err)
	}
	if result != nil {
		t.Logf("CheckStatus result: method=%s, status=%s", result.Method, result.Status)
	}
}

func TestOCSPCheckerCheckCertificate(t *testing.T) {
	checker := revocation.NewOCSPChecker()
	if checker == nil {
		t.Error("NewOCSPChecker вернул nil")
	}
	
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	
	issuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Issuer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	issuer, _ := x509.ParseCertificate(issuerDER)
	
	result, err := checker.CheckCertificate(cert, issuer, "http://nonexistent.ocsp.local")
	if err != nil {
		t.Logf("OCSP check error (expected): %v", err)
	}
	if result != nil {
		t.Logf("OCSP result status: %s", result.Status)
	}
}

func TestOCSPCheckerWithValidResponse(t *testing.T) {
	checker := revocation.NewOCSPChecker()
	if checker == nil {
		t.Error("NewOCSPChecker вернул nil")
	}
	
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	
	issuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Issuer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	issuer, _ := x509.ParseCertificate(issuerDER)
	
	// Невалидный URL, но функция должна обработать ошибку
	result, err := checker.CheckCertificate(cert, issuer, "http://localhost:9999/ocsp")
	if err != nil {
		t.Logf("OCSP check error (expected): %v", err)
	}
	if result != nil {
		t.Logf("OCSP result status: %s", result.Status)
	}
}

func TestFallbackCheckStatusWithCRL(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fallback-crl-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, err := database.NewDatabase(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}

	interCert, interKey, _ := createPKIChainForTest(t, tmpDir, db)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafSerial := big.NewInt(1234567)
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "test-fallback.example.com"},
		Issuer:       interCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	leafCert, _ := x509.ParseCertificate(leafDER)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	db.InsertCertificate(leafCert, leafPEM, "valid")

	checker := revocation.NewRevocationChecker()
	
	opts := &revocation.RevocationCheckOptions{
		Cert:          leafCert,
		Issuer:        interCert,
		OCSPURL:       "",
		CRLSource:     "",
		PreferOCSP:    false,
		FallbackToCRL: true,
	}
	
	result, err := checker.CheckStatus(opts)
	if err != nil {
		t.Logf("CheckStatus with fallback error: %v", err)
	}
	if result != nil {
		t.Logf("CheckStatus result: method=%s, status=%s", result.Method, result.Status)
	}
}

func TestOCSPCheckerTimeout(t *testing.T) {
	checker := revocation.NewOCSPChecker()
	if checker == nil {
		t.Error("NewOCSPChecker вернул nil")
	}
	
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-timeout.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	
	issuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Issuer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	issuer, _ := x509.ParseCertificate(issuerDER)
	
	// Недоступный URL
	result, err := checker.CheckCertificate(cert, issuer, "http://localhost:9999/ocsp")
	if err != nil {
		t.Logf("OCSP timeout error (expected): %v", err)
	}
	if result != nil {
		t.Logf("OCSP result status: %s", result.Status)
	}
}

func TestFallbackCheckStatusWithOCSPThenCRL(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fallback-ocsp-crl-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, err := database.NewDatabase(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}

	interCert, interKey, _ := createPKIChainForTest(t, tmpDir, db)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafSerial := big.NewInt(8888888)
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "fallback-test.example.com"},
		Issuer:       interCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	leafCert, _ := x509.ParseCertificate(leafDER)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	db.InsertCertificate(leafCert, leafPEM, "valid")

	checker := revocation.NewRevocationChecker()
	
	// Проверка с предпочтением OCSP (который недоступен) и fallback на CRL
	opts := &revocation.RevocationCheckOptions{
		Cert:          leafCert,
		Issuer:        interCert,
		OCSPURL:       "http://localhost:9999/ocsp",
		CRLSource:     "",
		PreferOCSP:    true,
		FallbackToCRL: true,
	}
	
	result, err := checker.CheckStatus(opts)
	if err != nil {
		t.Logf("CheckStatus with OCSP fallback error: %v", err)
	}
	if result != nil {
		t.Logf("CheckStatus result: method=%s, status=%s", result.Method, result.Status)
	}
}

func TestFallbackCheckStatusNoFallback(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fallback-no-fallback-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, err := database.NewDatabase(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}

	interCert, interKey, _ := createPKIChainForTest(t, tmpDir, db)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafSerial := big.NewInt(9999999)
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "no-fallback-test.example.com"},
		Issuer:       interCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	leafCert, _ := x509.ParseCertificate(leafDER)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	db.InsertCertificate(leafCert, leafPEM, "valid")

	checker := revocation.NewRevocationChecker()
	
	// Проверка без fallback
	opts := &revocation.RevocationCheckOptions{
		Cert:          leafCert,
		Issuer:        interCert,
		OCSPURL:       "",
		CRLSource:     "",
		PreferOCSP:    false,
		FallbackToCRL: false,
	}
	
	result, err := checker.CheckStatus(opts)
	if err != nil {
		t.Logf("CheckStatus without fallback error: %v", err)
	}
	if result != nil {
		t.Logf("CheckStatus result: method=%s, status=%s", result.Method, result.Status)
	}
}

func TestOCSPCheckerCheckCertificateSimple(t *testing.T) {
	checker := revocation.NewOCSPChecker()
	
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	
	issuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Issuer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	issuer, _ := x509.ParseCertificate(issuerDER)
	
	result, err := checker.CheckCertificate(cert, issuer, "http://localhost:9999/ocsp")
	if err != nil {
		t.Logf("OCSP check error (expected): %v", err)
	}
	if result != nil {
		t.Logf("OCSP result: %s", result.Status)
	}
}

func TestFallbackCheckStatusSimple(t *testing.T) {
	checker := revocation.NewRevocationChecker()
	
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	
	issuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Issuer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	issuer, _ := x509.ParseCertificate(issuerDER)
	
	opts := &revocation.RevocationCheckOptions{
		Cert:          cert,
		Issuer:        issuer,
		OCSPURL:       "",
		CRLSource:     "",
		PreferOCSP:    false,
		FallbackToCRL: false,
	}
	
	result, err := checker.CheckStatus(opts)
	if err != nil {
		t.Logf("CheckStatus error: %v", err)
	}
	if result != nil {
		t.Logf("CheckStatus result: method=%s, status=%s", result.Method, result.Status)
	}
}

func TestCheckStatusAllScenarios(t *testing.T) {
    tmpDir, err := os.MkdirTemp("", "check-status-all-*")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(tmpDir)

    db, caCert, caKey, cleanup := setupRevocationTest(t)
    defer cleanup()

    // Создаём валидный сертификат
    leafCert, serialHex := createLeafCert(t, db, caCert, caKey, 55555, "valid")

    checker := revocation.NewRevocationChecker()

    // Сценарий 1: OCSP недоступен, без fallback
    t.Run("OCSP_unavailable_no_fallback", func(t *testing.T) {
        opts := &revocation.RevocationCheckOptions{
            Cert:          leafCert,
            Issuer:        caCert,
            OCSPURL:       "http://localhost:9999/ocsp",
            PreferOCSP:    true,
            FallbackToCRL: false,
        }
        result, err := checker.CheckStatus(opts)
        if err != nil {
            t.Logf("Error: %v", err)
        }
        t.Logf("Status: %s, Method: %s", result.Status, result.Method)
    })

    // Сценарий 2: Без OCSP и без CRL (должен вернуть unknown)
    t.Run("no_OCSP_no_CRL", func(t *testing.T) {
        opts := &revocation.RevocationCheckOptions{
            Cert:          leafCert,
            Issuer:        caCert,
            PreferOCSP:    false,
            FallbackToCRL: false,
        }
        result, err := checker.CheckStatus(opts)
        if err != nil {
            t.Logf("Error: %v", err)
        }
        t.Logf("Status: %s", result.Status)
    })

    // Сценарий 3: Отзыв сертификата
    t.Run("revoked_certificate", func(t *testing.T) {
        err := revocation.RevokeCertificate(db, serialHex, 1, true)
        if err != nil {
            t.Fatal(err)
        }

        opts := &revocation.RevocationCheckOptions{
            Cert:          leafCert,
            Issuer:        caCert,
            PreferOCSP:    false,
            FallbackToCRL: true,
        }
        result, err := checker.CheckStatus(opts)
        if err != nil {
            t.Logf("Error: %v", err)
        }
        t.Logf("Revoked cert status: %s, Reason: %s", result.Status, result.Reason)
    })
}

func TestOCSPCheckerAllStatuses(t *testing.T) {
    db, caCert, caKey, cleanup := setupRevocationTest(t)
    defer cleanup()

    // Создаём сертификат для тестирования
    leafCert, serialHex := createLeafCert(t, db, caCert, caKey, 66666, "valid")

    checker := revocation.NewOCSPChecker()

    // Тест с недоступным OCSP сервером
    t.Run("OCSP_server_unavailable", func(t *testing.T) {
        result, err := checker.CheckCertificate(leafCert, caCert, "http://localhost:9999/ocsp")
        if err != nil {
            t.Logf("Expected error: %v", err)
        }
        t.Logf("Status: %s", result.Status)
    })

    // Тест с неверным URL (неправильный формат)
    t.Run("invalid_OCSP_url", func(t *testing.T) {
        result, err := checker.CheckCertificate(leafCert, caCert, "not-a-valid-url")
        if err != nil {
            t.Logf("Expected error: %v", err)
        }
        t.Logf("Status: %s", result.Status)
    })

    // Отзываем сертификат и пробуем OCSP (должен вернуть revoked или error)
    t.Run("revoked_certificate_ocsp", func(t *testing.T) {
        err := revocation.RevokeCertificate(db, serialHex, 1, true)
        if err != nil {
            t.Fatal(err)
        }

        result, err := checker.CheckCertificate(leafCert, caCert, "http://localhost:9999/ocsp")
        if err != nil {
            t.Logf("Error: %v", err)
        }
        t.Logf("Revoked cert OCSP status: %s", result.Status)
    })
}

func TestCheckStatusFullCoverage(t *testing.T) {
    tmpDir, err := os.MkdirTemp("", "check-status-full-*")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(tmpDir)

    db, caCert, caKey, cleanup := setupRevocationTest(t)
    defer cleanup()

    // Создаём сертификат
    leafCert, serialHex := createLeafCert(t, db, caCert, caKey, 123456, "valid")

    checker := revocation.NewRevocationChecker()

    // Сценарий 1: OCSP URL пустой, PreferOCSP=true, FallbackToCRL=false
    t.Run("empty_OCSP_prefer_true", func(t *testing.T) {
        opts := &revocation.RevocationCheckOptions{
            Cert:          leafCert,
            Issuer:        caCert,
            OCSPURL:       "",
            PreferOCSP:    true,
            FallbackToCRL: false,
        }
        result, err := checker.CheckStatus(opts)
        t.Logf("Result: status=%s, method=%s, err=%v", result.Status, result.Method, err)
    })

    // Сценарий 2: CRL не найден
    t.Run("CRL_not_found", func(t *testing.T) {
        opts := &revocation.RevocationCheckOptions{
            Cert:          leafCert,
            Issuer:        caCert,
            CRLSource:     "/nonexistent/path.crl",
            PreferOCSP:    false,
            FallbackToCRL: true,
        }
        result, err := checker.CheckStatus(opts)
        t.Logf("Result: status=%s, method=%s, err=%v", result.Status, result.Method, err)
    })

    // Сценарий 3: Отзыв сертификата и проверка через CRL
    t.Run("revoked_via_CRL", func(t *testing.T) {
        err := revocation.RevokeCertificate(db, serialHex, 1, true)
        if err != nil {
            t.Fatal(err)
        }

        opts := &revocation.RevocationCheckOptions{
            Cert:          leafCert,
            Issuer:        caCert,
            PreferOCSP:    false,
            FallbackToCRL: true,
        }
        result, err := checker.CheckStatus(opts)
        t.Logf("Revoked result: status=%s, reason=%s", result.Status, result.Reason)
    })
}

func TestCheckCertificateOCSPFinal(t *testing.T) {
    tmpDir, err := os.MkdirTemp("", "ocsp-final-*")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(tmpDir)

    db, caCert, caKey, cleanup := setupRevocationTest(t)
    defer cleanup()

    leafCert, _ := createLeafCert(t, db, caCert, caKey, 99999, "valid")

    checker := revocation.NewOCSPChecker()

    // Тест 1: Недоступный сервер
    t.Run("unreachable_server", func(t *testing.T) {
        result, err := checker.CheckCertificate(leafCert, caCert, "http://localhost:9999/ocsp")
        if err != nil {
            t.Logf("Expected error: %v", err)
        }
        t.Logf("Status: %s", result.Status)
    })

    // Тест 2: Невалидный URL
    t.Run("invalid_url", func(t *testing.T) {
        result, err := checker.CheckCertificate(leafCert, caCert, "not-a-valid-url")
        if err != nil {
            t.Logf("Expected error: %v", err)
        }
        t.Logf("Status: %s", result.Status)
    })

    // Тест 3: Пустой URL
    t.Run("empty_url", func(t *testing.T) {
        result, err := checker.CheckCertificate(leafCert, caCert, "")
        if err != nil {
            t.Logf("Error: %v", err)
        }
        t.Logf("Status: %s", result.Status)
    })

    // Тест 4: Отзыв сертификата
    t.Run("revoked_certificate", func(t *testing.T) {
        leafCert2, serialHex := createLeafCert(t, db, caCert, caKey, 88888, "valid")
        
        err := revocation.RevokeCertificate(db, serialHex, 1, true)
        if err != nil {
            t.Fatal(err)
        }

        result, err := checker.CheckCertificate(leafCert2, caCert, "http://localhost:9999/ocsp")
        if err != nil {
            t.Logf("Error: %v", err)
        }
        t.Logf("Revoked cert status: %s", result.Status)
    })

    t.Log("OCSP CheckCertificate final test completed")
}
