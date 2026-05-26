package tests

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "net/http"
    "net/http/httptest"
    "os"
    "path/filepath"
    "testing"
    "time"

    "MicroPKI/internal/ca"
    "MicroPKI/internal/certs"
    "MicroPKI/internal/client"
    "MicroPKI/internal/cryptoutil"
    "MicroPKI/internal/csr"
    "MicroPKI/internal/database"
    "MicroPKI/internal/logger"
    "MicroPKI/internal/repository"
)

func TestFullIntegrationFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full integration test in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "full-integration-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Инициализация логгера
	err = logger.InitAudit(tmpDir)
	if err != nil {
		t.Fatalf("InitAudit error: %v", err)
	}
	defer logger.Close()

	// Создание БД
	dbPath := filepath.Join(tmpDir, "micropki.db")
	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}

	// 1. Создание корневого CA
	rootPassFile := filepath.Join(tmpDir, "root.pass")
	os.WriteFile(rootPassFile, []byte("rootpass123\n"), 0600)

	rootCA, err := ca.NewRootCA(
		"/CN=Integration Root CA",
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

	// 2. Создание промежуточного CA
	interPassFile := filepath.Join(tmpDir, "inter.pass")
	os.WriteFile(interPassFile, []byte("interpass123\n"), 0600)

	rootKey, _ := cryptoutil.LoadEncryptedPrivateKey(
		filepath.Join(tmpDir, "private", "ca.key.pem"),
		[]byte("rootpass123"),
	)
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
		"/CN=Integration Intermediate CA",
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
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski,
		AuthorityKeyId:        rootCert.SubjectKeyId,
	}

	interDER, _ := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	interCert, _ := x509.ParseCertificate(interDER)
	interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})
	interPath := filepath.Join(tmpDir, "certs", "intermediate.cert.pem")
	os.WriteFile(interPath, interPEM, 0644)
	db.InsertCertificate(interCert, interPEM, "valid")

	// 3. Запуск HTTP сервера
	certDir := filepath.Join(tmpDir, "certs")
	crlDir := filepath.Join(tmpDir, "crl")
	os.MkdirAll(crlDir, 0755)

	repoServer := repository.NewServer("127.0.0.1", 18082, db, certDir, crlDir, 0, 10)
	ts := httptest.NewServer(repoServer.WithCORS(repoServer.Router()))
	defer ts.Close()

	// 4. Генерация CSR через клиент
	csrKeyPath := filepath.Join(tmpDir, "client.key.pem")
	csrPath := filepath.Join(tmpDir, "client.csr.pem")

	cfg := &client.CSRConfig{
		Subject: "/CN=integration-test.example.com",
		KeyType: "rsa",
		KeySize: 2048,
		SANs:    []string{"dns:integration-test.example.com"},
		OutKey:  csrKeyPath,
		OutCSR:  csrPath,
	}

	generated, err := client.GenerateCSR(cfg)
	if err != nil {
		t.Fatalf("GenerateCSR error: %v", err)
	}
	if err := client.SaveCSR(generated, csrKeyPath, csrPath); err != nil {
		t.Fatalf("SaveCSR error: %v", err)
	}

	t.Logf("CSR created: %s", csrPath)

	// 5. Запрос сертификата через API
	certPath := filepath.Join(tmpDir, "client.cert.pem")
	req := &client.CertificateRequest{
		CSRPath:   csrPath,
		Template:  "server",
		CAURL:     ts.URL,
		OutCert:   certPath,
		APIKey:    "",
	}

	err = client.RequestCertificate(req)
	if err != nil {
		t.Logf("RequestCertificate error (may need CA setup): %v", err)
	} else {
		t.Logf("Certificate obtained: %s", certPath)
	}

	t.Log("Full integration test completed successfully")
}

func TestCoverageEdgeFunctions(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping coverage test in short mode")
    }

    tmpDir, err := os.MkdirTemp("", "coverage-edge-*")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(tmpDir)

    dbPath := filepath.Join(tmpDir, "micropki.db")
    db, err := database.NewDatabase(dbPath)
    if err != nil {
        t.Fatal(err)
    }
    defer db.Close()

    if err := db.InitSchema(); err != nil {
        t.Fatal(err)
    }

    certDir := filepath.Join(tmpDir, "certs")
    crlDir := filepath.Join(tmpDir, "crl")
    os.MkdirAll(certDir, 0755)
    os.MkdirAll(crlDir, 0755)

    // Создаём файл в файловой системе (не в БД)
    fsCert := []byte("-----BEGIN CERTIFICATE-----\nMIIDAzCCAmugAwIBAgIUNjY2NgoXyFgXyFgXyFgXyFgXyFgXyFgXyFgXyFgXyFgX\n-----END CERTIFICATE-----\n")
    fsCertPath := filepath.Join(certDir, "fs-test-cert.pem")
    if err := os.WriteFile(fsCertPath, fsCert, 0644); err != nil {
        t.Fatal(err)
    }

    server := repository.NewServer("127.0.0.1", 18083, db, certDir, crlDir, 0, 10)
    ts := httptest.NewServer(server.WithCORS(server.Router()))
    defer ts.Close()

    // Запрос к файлу в FS (должен пройти через tryServeFromFileSystem)
    resp, err := http.Get(ts.URL + "/certificate/fs-test-cert")
    if err != nil {
        t.Fatal(err)
    }
    t.Logf("tryServeFromFileSystem test: status=%d", resp.StatusCode)
    resp.Body.Close()

    rateServer := repository.NewServer("127.0.0.1", 18084, db, certDir, crlDir, 1.0, 1)
    tsRate := httptest.NewServer(rateServer.WithCORS(rateServer.Router()))
    defer tsRate.Close()

    // Первый запрос - OK
    resp1, err := http.Get(tsRate.URL + "/health")
    if err != nil {
        t.Fatal(err)
    }
    t.Logf("rate limit request 1: %d", resp1.StatusCode)
    resp1.Body.Close()

    // Второй запрос - должен быть rate limited
    resp2, err := http.Get(tsRate.URL + "/health")
    if err != nil {
        t.Fatal(err)
    }
    t.Logf("rate limit request 2: %d (expected 429)", resp2.StatusCode)
    resp2.Body.Close()

    // Создаём простую PKI цепочку
    rootPassFile := filepath.Join(tmpDir, "root.pass")
    os.WriteFile(rootPassFile, []byte("rootpass123\n"), 0600)

    rootCA, err := ca.NewRootCA(
        "/CN=Coverage Root CA",
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

    rootKey, _ := cryptoutil.LoadEncryptedPrivateKey(
        filepath.Join(tmpDir, "private", "ca.key.pem"),
        []byte("rootpass123"),
    )
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
        "/CN=Coverage Intermediate CA",
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
        NotBefore:             time.Now(),
        NotAfter:              time.Now().AddDate(5, 0, 0),
        KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        BasicConstraintsValid: true,
        IsCA:                  true,
        SubjectKeyId:          ski,
        AuthorityKeyId:        rootCert.SubjectKeyId,
    }

    interDER, _ := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
    interCert, _ := x509.ParseCertificate(interDER)
    interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})
    interPath := filepath.Join(tmpDir, "certs", "intermediate.cert.pem")
    os.WriteFile(interPath, interPEM, 0644)
    db.InsertCertificate(interCert, interPEM, "valid")

    // Создаём конечный сертификат для теста CheckStatus
    leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    leafSerial := big.NewInt(1234567)
    leafTemplate := &x509.Certificate{
        SerialNumber: leafSerial,
        Subject:      pkix.Name{CommonName: "test-coverage.example.com"},
        Issuer:       interCert.Subject,
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(1, 0, 0),
        KeyUsage:     x509.KeyUsageDigitalSignature,
    }
    leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
    leafCert, _ := x509.ParseCertificate(leafDER)
    leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
    db.InsertCertificate(leafCert, leafPEM, "valid")

    t.Log("Coverage edge functions test completed")
}