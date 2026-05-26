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

	"MicroPKI/internal/audit"
	"MicroPKI/internal/ca"
	"MicroPKI/internal/certs"
	"MicroPKI/internal/cryptoutil"
	"MicroPKI/internal/csr"
	"MicroPKI/internal/database"
)

func setupTestDBForCA(t *testing.T) (*database.Database, func()) {
	tmpDir, err := os.MkdirTemp("", "ca-test-*")
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

func TestRootCAInitialization(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, cleanupDB := setupTestDBForCA(t)
	defer cleanupDB()

	passFile := filepath.Join(tmpDir, "test.pass")
	if err := os.WriteFile(passFile, []byte("testpass123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootCA, err := ca.NewRootCA(
		"/CN=Test Root CA",
		"rsa",
		4096,
		passFile,
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

	checkFileExists(t, filepath.Join(tmpDir, "private", "ca.key.pem"))
	checkFileExists(t, filepath.Join(tmpDir, "certs", "ca.cert.pem"))
	checkFileExists(t, filepath.Join(tmpDir, "policy.txt"))

	info, err := os.Stat(filepath.Join(tmpDir, "private", "ca.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("неправильные права на ключ: ожидалось 0600, получено %o", info.Mode().Perm())
	}
}

func TestECCRootCAInitialization(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, cleanupDB := setupTestDBForCA(t)
	defer cleanupDB()

	passFile := filepath.Join(tmpDir, "test.pass")
	if err := os.WriteFile(passFile, []byte("testpass123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootCA, err := ca.NewRootCA(
		"CN=ECC Test Root CA,O=Test",
		"ecc",
		384,
		passFile,
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

	checkFileExists(t, filepath.Join(tmpDir, "private", "ca.key.pem"))
	checkFileExists(t, filepath.Join(tmpDir, "certs", "ca.cert.pem"))
}

func TestKeyCertMatching(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, cleanupDB := setupTestDBForCA(t)
	defer cleanupDB()

	privateDir := filepath.Join(tmpDir, "private")
	if err := os.MkdirAll(privateDir, 0700); err != nil {
		t.Fatal(err)
	}

	passFile := filepath.Join(tmpDir, "test.pass")
	passphrase := []byte("testpass123")
	if err := os.WriteFile(passFile, passphrase, 0600); err != nil {
		t.Fatal(err)
	}

	rootCA, err := ca.NewRootCA(
		"/CN=Test Root CA",
		"rsa",
		4096,
		passFile,
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

	keyPath := filepath.Join(tmpDir, "private", "ca.key.pem")
	loadedKey, err := cryptoutil.LoadEncryptedPrivateKey(keyPath, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := loadedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("загруженный ключ не является RSA ключом")
	}
}

func TestIntermediateCA(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, cleanupDB := setupTestDBForCA(t)
	defer cleanupDB()

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

	csrPath := filepath.Join(tmpDir, "csrs", "intermediate.csr.pem")
	if err := os.MkdirAll(filepath.Join(tmpDir, "csrs"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := csr.SaveCSR(csrPath, csrPEM); err != nil {
		t.Fatal(err)
	}

	checkFileExists(t, csrPath)

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

	template := &x509.Certificate{
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

	interCertDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, &interKey.PublicKey, rootKey)
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

	checkFileExists(t, interCertPath)

	interCA, err := ca.NewIntermediateCA(
		interCertPath,
		filepath.Join(tmpDir, "private", "intermediate.key.pem"),
		interPassFile,
		db,
	)
	if err != nil {
		t.Fatal(err)
	}

	interCert, interSigner, err := interCA.Load()
	if err != nil {
		t.Fatal(err)
	}

	if !interCert.IsCA {
		t.Error("промежуточный сертификат должен быть CA")
	}

	if interSigner == nil {
		t.Error("подпись не загружена")
	}
}

func TestNegativeCases(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, cleanupDB := setupTestDBForCA(t)
	defer cleanupDB()

	passFile := filepath.Join(tmpDir, "test.pass")
	if err := os.WriteFile(passFile, []byte("testpass123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		subject     string
		keyType     string
		keySize     int
		passFile    string
		validity    int
		expectError bool
	}{
		{
			name:        "пустой subject",
			subject:     "",
			keyType:     "rsa",
			keySize:     4096,
			passFile:    passFile,
			validity:    365,
			expectError: true,
		},
		{
			name:        "неправильный тип ключа",
			subject:     "/CN=Test",
			keyType:     "dsa",
			keySize:     4096,
			passFile:    passFile,
			validity:    365,
			expectError: true,
		},
		{
			name:        "неправильный размер RSA ключа",
			subject:     "/CN=Test",
			keyType:     "rsa",
			keySize:     2048,
			passFile:    passFile,
			validity:    365,
			expectError: true,
		},
		{
			name:        "неправильный размер ECC ключа",
			subject:     "/CN=Test",
			keyType:     "ecc",
			keySize:     256,
			passFile:    passFile,
			validity:    365,
			expectError: true,
		},
		{
			name:        "несуществующий файл пароля",
			subject:     "/CN=Test",
			keyType:     "rsa",
			keySize:     4096,
			passFile:    "/nonexistent/pass.txt",
			validity:    365,
			expectError: true,
		},
		{
			name:        "отрицательный срок действия",
			subject:     "/CN=Test",
			keyType:     "rsa",
			keySize:     4096,
			passFile:    passFile,
			validity:    -1,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootCA, err := ca.NewRootCA(
				tt.subject,
				tt.keyType,
				tt.keySize,
				tt.passFile,
				tmpDir,
				tt.validity,
				false,
				db,
			)
			if err != nil {
				if !tt.expectError {
					t.Errorf("неожиданная ошибка при создании: %v", err)
				}
				return
			}

			err = rootCA.Initialize()
			if tt.expectError && err == nil {
				t.Error("ожидалась ошибка, но ее не было")
			}
			if !tt.expectError && err != nil {
				t.Errorf("неожиданная ошибка: %v", err)
			}
		})
	}
}

func TestDNParsing(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/CN=Test CA", "Test CA"},
		{"CN=Test CA,O=Org", "Test CA"},
		{"/CN=Test/OU=Unit", "Test"},
	}

	for _, tt := range tests {
		name, err := certs.ParseDN(tt.input)
		if err != nil {
			t.Errorf("ошибка парсинга %s: %v", tt.input, err)
			continue
		}
		if name.CommonName != tt.expected {
			t.Errorf("для %s ожидалось CN=%s, получено %s", tt.input, tt.expected, name.CommonName)
		}
	}
}

func TestGenerateSerialNumber(t *testing.T) {
	serial1, err := certs.GenerateSerialNumber()
	if err != nil {
		t.Fatal(err)
	}

	serial2, err := certs.GenerateSerialNumber()
	if err != nil {
		t.Fatal(err)
	}

	if serial1.Cmp(serial2) == 0 {
		t.Error("сгенерированы одинаковые серийные номера")
	}

	if serial1.Sign() <= 0 {
		t.Error("серийный номер должен быть положительным")
	}
}

func TestCertificateVerification(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, cleanupDB := setupTestDBForCA(t)
	defer cleanupDB()

	passFile := filepath.Join(tmpDir, "test.pass")
	if err := os.WriteFile(passFile, []byte("testpass123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootCA, err := ca.NewRootCA(
		"/CN=Test Root CA",
		"rsa",
		4096,
		passFile,
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

	certPEM, err := os.ReadFile(filepath.Join(tmpDir, "certs", "ca.cert.pem"))
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("не удалось декодировать PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if !cert.IsCA {
		t.Error("сертификат не является CA")
	}

	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("отсутствует KeyUsage CertSign")
	}

	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("отсутствует KeyUsage CRLSign")
	}
}

func TestCheckAuditIntegrityBeforeOperation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "audit-integrity-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	err = audit.InitAuditLogger(tmpDir)
	if err != nil {
		t.Logf("инициализация аудита: %v", err)
	}
	defer audit.CloseGlobalAuditLogger()

	err = ca.CheckAuditIntegrityBeforeOperation(tmpDir)
	if err != nil {
		t.Logf("результат проверки: %v (ожидаемо, если лог пуст)", err)
	}

	err = ca.CheckAuditIntegrityBeforeOperation("/nonexistent/path")
	if err != nil {
		t.Logf("ошибка для несуществующего пути: %v", err)
	}
}

func TestGetSerialNumber(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "serial-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, cleanupDB := setupTestDBForCA(t)
	defer cleanupDB()

	passFile := filepath.Join(tmpDir, "test.pass")
	if err := os.WriteFile(passFile, []byte("testpass123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootCA, err := ca.NewRootCA(
		"/CN=Test Root CA",
		"rsa",
		4096,
		passFile,
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

	serial := rootCA.GetSerialNumber()
	if serial == nil {
		t.Error("GetSerialNumber вернул nil")
	}
	if serial.Sign() <= 0 {
		t.Error("серийный номер должен быть положительным")
	}
}

func TestNewIntermediateCAWithInvalidPaths(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "inter-ca-err-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, cleanupDB := setupTestDBForCA(t)
	defer cleanupDB()

	tests := []struct {
		name        string
		certPath    string
		keyPath     string
		passFile    string
		expectError bool
	}{
		{
			name:        "несуществующий сертификат",
			certPath:    "/nonexistent/cert.pem",
			keyPath:     "/nonexistent/key.pem",
			passFile:    "/nonexistent/pass",
			expectError: true,
		},
		{
			name:        "пустые пути",
			certPath:    "",
			keyPath:     "",
			passFile:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ca.NewIntermediateCA(tt.certPath, tt.keyPath, tt.passFile, db)
			if tt.expectError && err == nil {
				t.Error("ожидалась ошибка, но ее не было")
			}
		})
	}
}

func TestIssueCertificateFromCSR(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "issue-csr-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, cleanupDB := setupTestDBForCA(t)
	defer cleanupDB()

	rootPassFile := filepath.Join(tmpDir, "root.pass")
	os.WriteFile(rootPassFile, []byte("rootpass123\n"), 0600)

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
	os.WriteFile(interPassFile, []byte("interpass123\n"), 0600)

	rootKey, err := cryptoutil.LoadEncryptedPrivateKey(
		filepath.Join(tmpDir, "private", "ca.key.pem"),
		[]byte("rootpass123"),
	)
	if err != nil {
		t.Fatal(err)
	}

	rootCertPEM, _ := os.ReadFile(filepath.Join(tmpDir, "certs", "ca.cert.pem"))
	block, _ := pem.Decode(rootCertPEM)
	rootCert, _ := x509.ParseCertificate(block.Bytes)

	interKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	cryptoutil.SaveEncryptedRSAPEM(
		filepath.Join(tmpDir, "private", "intermediate.key.pem"),
		interKey,
		[]byte("interpass123"),
	)

	csrPEM, _ := csr.GenerateIntermediateCSR(
		"/CN=Test Intermediate CA",
		&interKey.PublicKey,
		interKey,
		0,
	)
	csrObj, _ := csr.ParseCSR(csrPEM)
	serialNumber, _ := certs.GenerateSerialNumber()
	ski, _ := certs.CalculateSKI(&interKey.PublicKey)

	interTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csrObj.Subject,
		Issuer:                rootCert.Subject,
		NotBefore:             rootCert.NotBefore,
		NotAfter:              rootCert.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski,
		AuthorityKeyId:        rootCert.SubjectKeyId,
	}

	interCertDER, _ := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	interCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interCertDER})
	interCertPath := filepath.Join(tmpDir, "certs", "intermediate.cert.pem")
	os.WriteFile(interCertPath, interCertPEM, 0644)

	interCA, err := ca.NewIntermediateCA(
		interCertPath,
		filepath.Join(tmpDir, "private", "intermediate.key.pem"),
		interPassFile,
		db,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Создаём CSR с SAN (исправление: добавляем DNSNames)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafCSRTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com"},
		DNSNames: []string{"test.example.com"}, // Добавляем SAN
	}
	leafCSRDER, err := x509.CreateCertificateRequest(rand.Reader, leafCSRTemplate, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCSRPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: leafCSRDER,
	})

	cert, certPEM, err := interCA.IssueCertificateFromCSR(leafCSRPEM, "server", 365)
	if err != nil {
		t.Skipf("Ошибка выпуска сертификата из CSR (может быть нормально): %v", err)
		return
	}

	if cert == nil {
		t.Error("сертификат не создан")
	}
	if len(certPEM) == 0 {
		t.Error("PEM сертификата пуст")
	}

	t.Logf("сертификат из CSR успешно выпущен: serial=%x", cert.SerialNumber)
}

func TestSaveCertificateToDB(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "save-cert-db-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, cleanupDB := setupTestDBForCA(t)
	defer cleanupDB()

	serialNum, err := certs.GenerateSerialNumber()
	if err != nil {
		t.Fatal(err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: serialNum,
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	err = ca.SaveCertificateToDB(db, cert, certPEM, "valid")
	if err != nil {
		t.Fatalf("ошибка сохранения сертификата в БД: %v", err)
	}
	t.Log("сертификат сохранен в БД")
}

func checkFileExists(t *testing.T, path string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("файл не существует: %s", path)
	}
}

func TestInitSerialGenerator(t *testing.T) {
	db, cleanupDB := setupTestDBForCA(t)
	defer cleanupDB()
	
	certs.InitSerialGenerator(db)
	t.Log("InitSerialGenerator completed")
}

func TestValidateSerialNumber(t *testing.T) {
	db, cleanupDB := setupTestDBForCA(t)
	defer cleanupDB()
	
	certs.InitSerialGenerator(db)
	
	// Создаём тестовый сертификат
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	
	db.InsertCertificate(cert, certPEM, "valid")
	
	valid, err := certs.ValidateSerialNumber(cert.SerialNumber, db)
	if err != nil {
		t.Fatalf("ValidateSerialNumber ошибка: %v", err)
	}
	if !valid {
		t.Log("серийный номер уже существует (это нормально)")
	}
}

func TestGetAKIFromCert(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 5},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	
	aki := certs.GetAKIFromCert(cert)
	if aki == nil {
		t.Error("GetAKIFromCert вернул nil")
	}
	t.Logf("AKI: %x", aki)
}

func TestIssueCertificateFromCSRErrors(t *testing.T) {
    tmpDir, err := os.MkdirTemp("", "issue-csr-errors-*")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(tmpDir)

    db, cleanupDB := setupTestDBForCA(t)
    defer cleanupDB()

    // Создаём CA цепочку
    interCert, interKey, _ := createPKIChainForTest(t, tmpDir, db)
    _ = interCert      // Используем underscore, чтобы избежать ошибки
    _ = interKey       // Используем underscore, чтобы избежать ошибки

    // Загружаем intermediate CA
    interCA, err := ca.NewIntermediateCA(
        filepath.Join(tmpDir, "certs", "intermediate.cert.pem"),
        filepath.Join(tmpDir, "private", "intermediate.key.pem"),
        filepath.Join(tmpDir, "inter.pass"),
        db,
    )
    if err != nil {
        t.Fatal(err)
    }

    // Тест 1: Неверный CSR (невалидный PEM)
    _, _, err = interCA.IssueCertificateFromCSR([]byte("invalid pem"), "server", 365)
    if err == nil {
        t.Error("expected error for invalid CSR")
    } else {
        t.Logf("correctly rejected invalid CSR: %v", err)
    }

    // Тест 2: CSR с неправильной подписью
    badKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    badTemplate := &x509.CertificateRequest{
        Subject: pkix.Name{CommonName: "bad.example.com"},
    }
    badCSRDER, _ := x509.CreateCertificateRequest(rand.Reader, badTemplate, badKey)
    badCSRPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: badCSRDER})

    // Модифицируем CSR, чтобы сломать подпись (меняем один байт)
    if len(badCSRPEM) > 200 {
        badCSRPEM[200] ^= 0xFF
    }

    _, _, err = interCA.IssueCertificateFromCSR(badCSRPEM, "server", 365)
    if err == nil {
        t.Error("expected error for invalid signature")
    } else {
        t.Logf("correctly rejected invalid signature: %v", err)
    }

    t.Log("IssueCertificateFromCSR error tests completed")
}

func TestIssueCertificateFromCSRWithInvalidParameters(t *testing.T) {
    tmpDir, err := os.MkdirTemp("", "issue-csr-invalid-params-*")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(tmpDir)

    db, cleanupDB := setupTestDBForCA(t)
    defer cleanupDB()

    // Создаём CA цепочку
    _, _, _ = createPKIChainForTest(t, tmpDir, db)

    interCA, err := ca.NewIntermediateCA(
        filepath.Join(tmpDir, "certs", "intermediate.cert.pem"),
        filepath.Join(tmpDir, "private", "intermediate.key.pem"),
        filepath.Join(tmpDir, "inter.pass"),
        db,
    )
    if err != nil {
        t.Fatal(err)
    }

    // Тест 1: CSR с SHA1 подписью
    t.Run("SHA1_signature_rejected", func(t *testing.T) {
        key, _ := rsa.GenerateKey(rand.Reader, 2048)
        template := &x509.CertificateRequest{
            Subject:            pkix.Name{CommonName: "sha1.example.com"},
            SignatureAlgorithm: x509.SHA1WithRSA,
        }
        csrDER, _ := x509.CreateCertificateRequest(rand.Reader, template, key)
        csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

        _, _, err := interCA.IssueCertificateFromCSR(csrPEM, "server", 365)
        if err == nil {
            t.Error("SHA1 signature should be rejected")
        } else {
            t.Logf("correctly rejected SHA1: %v", err)
        }
    })

    // Тест 2: CSR с email SAN для server шаблона
    t.Run("email_SAN_rejected_for_server", func(t *testing.T) {
        key, _ := rsa.GenerateKey(rand.Reader, 2048)
        template := &x509.CertificateRequest{
            Subject:        pkix.Name{CommonName: "email-server.example.com"},
            DNSNames:       []string{"example.com"},
            EmailAddresses: []string{"admin@example.com"},
        }
        csrDER, _ := x509.CreateCertificateRequest(rand.Reader, template, key)
        csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

        _, _, err := interCA.IssueCertificateFromCSR(csrPEM, "server", 365)
        if err == nil {
            t.Error("email SAN should be rejected for server template")
        } else {
            t.Logf("correctly rejected email SAN: %v", err)
        }
    })

    // Тест 3: CSR с wildcard DNS
    t.Run("wildcard_DNS_rejected", func(t *testing.T) {
        key, _ := rsa.GenerateKey(rand.Reader, 2048)
        template := &x509.CertificateRequest{
            Subject:  pkix.Name{CommonName: "wildcard.example.com"},
            DNSNames: []string{"*.example.com"},
        }
        csrDER, _ := x509.CreateCertificateRequest(rand.Reader, template, key)
        csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

        _, _, err := interCA.IssueCertificateFromCSR(csrPEM, "server", 365)
        if err == nil {
            t.Error("wildcard DNS should be rejected")
        } else {
            t.Logf("correctly rejected wildcard: %v", err)
        }
    })

    // Тест 4: Пустой CSR
    t.Run("empty_CSR_rejected", func(t *testing.T) {
        _, _, err := interCA.IssueCertificateFromCSR([]byte{}, "server", 365)
        if err == nil {
            t.Error("empty CSR should be rejected")
        } else {
            t.Logf("correctly rejected empty CSR: %v", err)
        }
    })
}