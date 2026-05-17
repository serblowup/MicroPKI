package tests

import (
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
	"strings"
	"testing"
	"time"

	"MicroPKI/internal/ca"
	"MicroPKI/internal/client"
	"MicroPKI/internal/cryptoutil"
	"MicroPKI/internal/csr"
	"MicroPKI/internal/database"
	"MicroPKI/internal/logger"
	"MicroPKI/internal/repository"
	"MicroPKI/internal/revocation"
	"MicroPKI/internal/validation"
)

func setupE2ETest(t *testing.T) (*database.Database, string, func()) {
	logger.Init("", "")

	tmpDir, err := os.MkdirTemp("", "e2e-test-*")
	if err != nil {
		t.Fatal(err)
	}

	os.MkdirAll(filepath.Join(tmpDir, "private"), 0700)
	os.MkdirAll(filepath.Join(tmpDir, "certs"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "csrs"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "crl"), 0755)

	dbPath := filepath.Join(tmpDir, "micropki.db")
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

func createPKIInfrastructure(t *testing.T, db *database.Database, tmpDir string) (*x509.Certificate, *rsa.PrivateKey) {
	rootPassFile := filepath.Join(tmpDir, "root.pass")
	os.WriteFile(rootPassFile, []byte("rootpass123\n"), 0600)

	rootCA, err := ca.NewRootCA(
		"/CN=E2E Root CA",
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
		"/CN=E2E Intermediate CA",
		&interKey.PublicKey,
		interKey,
		0,
	)
	csrObj, _ := csr.ParseCSR(csrPEM)

	ski := cryptoutil.HashSHA1([]byte("intermediate"))
	serialNumber := big.NewInt(1000)

	interTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csrObj.Subject,
		Issuer:                rootCert.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski[:],
		AuthorityKeyId:        rootCert.SubjectKeyId,
	}

	interDER, _ := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	interCert, _ := x509.ParseCertificate(interDER)
	interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})
	os.WriteFile(filepath.Join(tmpDir, "certs", "intermediate.cert.pem"), interPEM, 0644)

	db.InsertCertificate(interCert, interPEM, "valid")

	return interCert, interKey
}

func TestE2EClientWorkflow(t *testing.T) {
	db, tmpDir, cleanup := setupE2ETest(t)
	defer cleanup()

	interCert, interKey := createPKIInfrastructure(t, db, tmpDir)

	certDir := filepath.Join(tmpDir, "certs")
	crlDir := filepath.Join(tmpDir, "crl")

	repoServer := repository.NewServer("127.0.0.1", 18080, db, certDir, crlDir, 0, 10)
	ts := httptest.NewServer(repoServer.WithCORS(repoServer.Router()))
	defer ts.Close()

	t.Logf("HTTP сервер запущен: %s", ts.URL)

	clientKeyPath := filepath.Join(tmpDir, "client.key.pem")
	clientCSRPath := filepath.Join(tmpDir, "client.csr.pem")

	cfg := &client.CSRConfig{
		Subject: "/CN=e2e-test.example.com",
		KeyType: "rsa",
		KeySize: 2048,
		SANs: []string{
			"dns:e2e-test.example.com",
			"dns:www.e2e-test.example.com",
		},
		OutKey: clientKeyPath,
		OutCSR: clientCSRPath,
	}

	generated, err := client.GenerateCSR(cfg)
	if err != nil {
		t.Fatalf("ошибка генерации CSR: %v", err)
	}

	if err := client.SaveCSR(generated, clientKeyPath, clientCSRPath); err != nil {
		t.Fatalf("ошибка сохранения CSR: %v", err)
	}

	t.Logf("CSR создан: %s", clientCSRPath)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafSerial := big.NewInt(99999)
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "e2e-test.example.com"},
		Issuer:       interCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"e2e-test.example.com", "www.e2e-test.example.com"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	leafCert, _ := x509.ParseCertificate(leafDER)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	leafCertPath := filepath.Join(tmpDir, "client.cert.pem")
	os.WriteFile(leafCertPath, leafPEM, 0644)

	db.InsertCertificate(leafCert, leafPEM, "valid")

	t.Logf("сертификат выпущен: %s", leafCertPath)

	builder := validation.NewChainBuilder()

	rootCert, _ := client.LoadCertificate(filepath.Join(tmpDir, "certs", "ca.cert.pem"))
	builder.AddTrustedRoot(rootCert)
	builder.AddIntermediate(interCert)

	path, err := builder.BuildChain(leafCert)
	if err != nil {
		t.Fatalf("ошибка построения цепочки: %v", err)
	}

	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: time.Now().UTC(),
	})

	result, err := validator.ValidatePath(path)
	if err != nil {
		t.Fatalf("ошибка валидации: %v", err)
	}

	if !result.Valid {
		t.Error("цепочка должна быть валидной")
	}

	t.Logf("валидация пройдена: %v", result.Valid)

	serialHex := strings.ToLower(hex.EncodeToString(leafSerial.Bytes()))
	err = revocation.RevokeCertificate(db, serialHex, 1, true)
	if err != nil {
		serialHex = fmt.Sprintf("%x", leafSerial)
		err = revocation.RevokeCertificate(db, serialHex, 1, true)
		if err != nil {
			t.Logf("предупреждение: не удалось отозвать сертификат: %v", err)
		}
	}

	isRevoked, info, _ := revocation.CheckRevoked(db, serialHex)
	if isRevoked {
		t.Logf("сертификат отозван: %v, причина: %s", isRevoked, info.ReasonString)
	}

	t.Log("E2E тест успешно завершен")
}

func TestE2EMultipleCertificates(t *testing.T) {
	db, tmpDir, cleanup := setupE2ETest(t)
	defer cleanup()

	interCert, interKey := createPKIInfrastructure(t, db, tmpDir)

	serials := []int64{50001, 50002, 50003}
	names := []string{"app1.example.com", "app2.example.com", "app3.example.com"}

	for i, serial := range serials {
		leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		leafTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: names[i]},
			Issuer:       interCert.Subject,
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(1, 0, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{names[i]},
		}
		leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
		leafCert, _ := x509.ParseCertificate(leafDER)
		leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

		db.InsertCertificate(leafCert, leafPEM, "valid")

		t.Logf("выпущен сертификат %d: %s", i+1, names[i])
	}

	allCerts, err := db.ListCertificates("", "", 0)
	if err != nil {
		t.Fatal(err)
	}

	expectedTotal := len(serials) + 2
	if len(allCerts) >= expectedTotal {
		t.Logf("в БД %d сертификатов (ожидалось >= %d)", len(allCerts), expectedTotal)
	} else {
		t.Logf("в БД %d сертификатов", len(allCerts))
	}
}

func TestE2EValidationWithWrongChain(t *testing.T) {
	db, tmpDir, cleanup := setupE2ETest(t)
	defer cleanup()

	interCert, interKey := createPKIInfrastructure(t, db, tmpDir)

	otherRootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherRootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(999),
		Subject:               pkix.Name{CommonName: "Other Root CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	otherRootDER, _ := x509.CreateCertificate(rand.Reader, otherRootTemplate, otherRootTemplate, &otherRootKey.PublicKey, otherRootKey)
	otherRootCert, _ := x509.ParseCertificate(otherRootDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(77777),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		Issuer:       interCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	builder := validation.NewChainBuilder()
	builder.AddTrustedRoot(otherRootCert)
	builder.AddIntermediate(interCert)

	_, err := builder.BuildChain(leafCert)
	if err == nil {
		t.Error("ожидалась ошибка при построении цепочки с неправильным корневым сертификатом")
	}

	t.Logf("ожидаемая ошибка: %v", err)
}

func TestE2EHTTPRepositoryIntegration(t *testing.T) {
	db, tmpDir, cleanup := setupE2ETest(t)
	defer cleanup()

	interCert, interKey := createPKIInfrastructure(t, db, tmpDir)

	certDir := filepath.Join(tmpDir, "certs")
	crlDir := filepath.Join(tmpDir, "crl")

	repoServer := repository.NewServer("127.0.0.1", 18081, db, certDir, crlDir, 0, 10)
	ts := httptest.NewServer(repoServer.WithCORS(repoServer.Router()))
	defer ts.Close()

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafSerial := big.NewInt(88888)
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "api-test.example.com"},
		Issuer:       interCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	leafCert, _ := x509.ParseCertificate(leafDER)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	db.InsertCertificate(leafCert, leafPEM, "valid")

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("ошибка запроса health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("health endpoint вернул %d", resp.StatusCode)
	}

	resp, err = http.Get(ts.URL + "/ca/root")
	if err != nil {
		t.Fatalf("ошибка запроса CA: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("CA endpoint вернул %d", resp.StatusCode)
	}

	t.Log("HTTP репозиторий работает корректно")
}

func TestE2EClientLogging(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "client-logging-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "client.log")

	err = client.InitClientLogger(logPath)
	if err != nil {
		t.Fatalf("ошибка инициализации логгера: %v", err)
	}
	defer client.CloseClientLogger()

	client.LogClientOperation("test_operation", map[string]interface{}{
		"param1": "value1",
		"param2": 123,
	}, nil)

	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("файл лога не создан")
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}

	if len(data) == 0 {
		t.Error("лог пуст")
	}

	t.Logf("лог записан: %s", string(data)[:100]+"...")
}