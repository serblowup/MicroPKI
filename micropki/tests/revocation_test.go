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

	interCert, interKey, issuerSubject := createPKIChainForTest(t, tmpDir, db)

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

	serialHex := fmt.Sprintf("%x", leafSerial)

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

	_ = issuerSubject
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

	if err := db.InsertCertificate(leafCert, leafCertPEM, "revoked"); err != nil {
		t.Fatal(err)
	}

	serialHex := fmt.Sprintf("%x", leafSerial)

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

func TestGetRevokedCertificatesByIssuer(t *testing.T) {
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

	serialHex1 := fmt.Sprintf("%x", leafSerial1)
	serialHex2 := fmt.Sprintf("%x", leafSerial2)

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

	serialHex := fmt.Sprintf("%x", leafSerial)

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
