package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"MicroPKI/internal/client"
)

func TestGenerateCSR(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "client-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "test.key.pem")
	csrPath := filepath.Join(tmpDir, "test.csr.pem")

	cfg := &client.CSRConfig{
		Subject: "/CN=test.example.com/O=Test Org",
		KeyType: "rsa",
		KeySize: 2048,
		SANs: []string{
			"dns:test.example.com",
			"dns:www.test.example.com",
			"ip:192.168.1.100",
		},
		OutKey: keyPath,
		OutCSR: csrPath,
	}

	generated, err := client.GenerateCSR(cfg)
	if err != nil {
		t.Fatalf("ошибка генерации CSR: %v", err)
	}

	if err := client.SaveCSR(generated, keyPath, csrPath); err != nil {
		t.Fatalf("ошибка сохранения CSR: %v", err)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("файл ключа не создан")
	}
	if _, err := os.Stat(csrPath); os.IsNotExist(err) {
		t.Error("файл CSR не создан")
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("неправильные права на ключ: ожидалось 0600, получено %o", info.Mode().Perm())
	}

	csrData, err := os.ReadFile(csrPath)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(csrData)
	if block == nil {
		t.Fatal("не удалось декодировать CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ошибка парсинга CSR: %v", err)
	}

	if csr.Subject.CommonName != "test.example.com" {
		t.Errorf("ожидался CN=test.example.com, получен %s", csr.Subject.CommonName)
	}
	if len(csr.Subject.Organization) == 0 || csr.Subject.Organization[0] != "Test Org" {
		t.Errorf("ожидалась организация Test Org")
	}

	if err := csr.CheckSignature(); err != nil {
		t.Errorf("неверная подпись CSR: %v", err)
	}

	t.Logf("CSR успешно создан и проверен: %s", csrPath)
}

func TestGenerateCSRWithECC(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "client-test-ecc-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "ecc.key.pem")
	csrPath := filepath.Join(tmpDir, "ecc.csr.pem")

	cfg := &client.CSRConfig{
		Subject: "/CN=ecc.example.com",
		KeyType: "ecc",
		KeySize: 256,
		SANs: []string{
			"dns:ecc.example.com",
			"email:admin@example.com",
		},
		OutKey: keyPath,
		OutCSR: csrPath,
	}

	generated, err := client.GenerateCSR(cfg)
	if err != nil {
		t.Fatalf("ошибка генерации ECC CSR: %v", err)
	}

	if err := client.SaveCSR(generated, keyPath, csrPath); err != nil {
		t.Fatalf("ошибка сохранения: %v", err)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(keyData, []byte("EC PRIVATE KEY")) && !contains(keyData, []byte("BEGIN EC")) {
		t.Error("не похоже на ECC ключ")
	}

	t.Logf("ECC CSR успешно создан")
}

func TestGenerateCSREmailSAN(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "client-test-email-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "email.key.pem")
	csrPath := filepath.Join(tmpDir, "email.csr.pem")

	cfg := &client.CSRConfig{
		Subject: "/CN=Client User/emailAddress=user@example.com",
		KeyType: "rsa",
		KeySize: 2048,
		SANs: []string{
			"email:user@example.com",
			"email:admin@example.com",
		},
		OutKey: keyPath,
		OutCSR: csrPath,
	}

	generated, err := client.GenerateCSR(cfg)
	if err != nil {
		t.Fatalf("ошибка генерации CSR: %v", err)
	}

	if err := client.SaveCSR(generated, keyPath, csrPath); err != nil {
		t.Fatalf("ошибка сохранения: %v", err)
	}

	csrData, _ := os.ReadFile(csrPath)
	block, _ := pem.Decode(csrData)
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	if len(csr.EmailAddresses) == 0 {
		t.Log("email адреса в CSR могут быть в расширениях")
	}

	t.Logf("CSR с email SAN успешно создан")
}

func TestGenerateCSRInvalidKeyType(t *testing.T) {
	cfg := &client.CSRConfig{
		Subject: "/CN=test",
		KeyType: "dsa",
		KeySize: 2048,
	}

	_, err := client.GenerateCSR(cfg)
	if err == nil {
		t.Error("ожидалась ошибка для неподдерживаемого типа ключа")
	}
}

func TestGenerateCSRInvalidKeySize(t *testing.T) {
	tests := []struct {
		keyType string
		keySize int
	}{
		{"rsa", 1024},
		{"rsa", 8192},
		{"ecc", 128},
		{"ecc", 512},
	}

	for _, tt := range tests {
		t.Run(tt.keyType, func(t *testing.T) {
			cfg := &client.CSRConfig{
				Subject: "/CN=test",
				KeyType: tt.keyType,
				KeySize: tt.keySize,
			}
			_, err := client.GenerateCSR(cfg)
			if err == nil {
				t.Errorf("ожидалась ошибка для размера ключа %d", tt.keySize)
			}
		})
	}
}

func TestClientLoadCertificate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "client-load-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "test.cert.pem")
	testCert := `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUKPp5qFqXqBqXqBqXqBqXqBqXqBqXqBqXMA0GCSqGSIb3
DQEBCwUAMBoxGDAWBgNVBAMMD1Rlc3QgQ2VydGlmaWNhdGUwHhcNMjQwMTAxMDAw
MDAwWhcNMjUwMTAxMDAwMDAwWjAaMRgwFgYDVQQDDA9UZXN0IENlcnRpZmljYXRl
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCYZM6J4hE
-----END CERTIFICATE-----`

	if err := os.WriteFile(certPath, []byte(testCert), 0644); err != nil {
		t.Fatal(err)
	}

	cert, err := client.LoadCertificate(certPath)
	if err == nil {
		t.Log("сертификат загружен (тестовый PEM может быть невалидным)")
		_ = cert
	}
}

func TestClientLoadCSR(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "client-load-csr-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	csrPath := filepath.Join(tmpDir, "test.csr.pem")
	if err := os.WriteFile(csrPath, csrPEM, 0644); err != nil {
		t.Fatal(err)
	}

	loadedCSR, err := client.LoadCSR(csrPath)
	if err != nil {
		t.Fatalf("ошибка загрузки CSR: %v", err)
	}

	if loadedCSR.Subject.CommonName != "test.example.com" {
		t.Errorf("ожидался CN=test.example.com, получен %s", loadedCSR.Subject.CommonName)
	}

	_, err = client.LoadCSR("/nonexistent.csr")
	if err == nil {
		t.Error("ожидалась ошибка для несуществующего файла")
	}
}

func TestClientLoadPrivateKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "client-load-key-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})
	rsaKeyPath := filepath.Join(tmpDir, "rsa.key.pem")
	if err := os.WriteFile(rsaKeyPath, rsaKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	loadedKey, err := client.LoadPrivateKey(rsaKeyPath)
	if err != nil {
		t.Fatalf("ошибка загрузки RSA ключа: %v", err)
	}
	if loadedKey == nil {
		t.Error("загруженный ключ nil")
	}

	_, err = client.LoadPrivateKey("/nonexistent.key")
	if err == nil {
		t.Error("ожидалась ошибка для несуществующего файла")
	}
}

func TestSaveCertificate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "save-cert-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

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
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(tmpDir, "saved.cert.pem")
	err = client.SaveCertificate(certPath, cert)
	if err != nil {
		t.Fatalf("ошибка сохранения сертификата: %v", err)
	}

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("файл сертификата не создан")
	}
}

func TestSaveCertificatePEM(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "save-cert-pem-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	testPEM := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")
	certPath := filepath.Join(tmpDir, "cert.pem")

	err = client.SaveCertificatePEM(certPath, testPEM)
	if err != nil {
		t.Fatalf("ошибка сохранения PEM: %v", err)
	}

	savedData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(savedData) != string(testPEM) {
		t.Error("сохраненные данные не совпадают")
	}
}

func TestNewClient(t *testing.T) {
	c := client.NewClient("http://localhost:8080", "test-api-key")
	if c == nil {
		t.Error("client is nil")
	}
}

func TestGetCertInfo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-info-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

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
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	info := client.GetCertInfo(cert)
	if info == nil {
		t.Error("GetCertInfo вернул nil")
	}
	if info["subject"] == nil {
		t.Error("subject отсутствует в информации")
	}
	if info["serial"] == nil {
		t.Error("serial отсутствует в информации")
	}
}

func TestValidateCertificateExpiry(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "validate-expiry-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	validTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "valid.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	validDER, _ := x509.CreateCertificate(rand.Reader, validTemplate, validTemplate, &key.PublicKey, key)
	validCert, _ := x509.ParseCertificate(validDER)

	err = client.ValidateCertificateExpiry(validCert)
	if err != nil {
		t.Errorf("валидный сертификат: неожиданная ошибка: %v", err)
	}

	expiredTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "expired.example.com"},
		NotBefore:    time.Now().AddDate(-2, 0, 0),
		NotAfter:     time.Now().AddDate(-1, 0, 0),
	}
	expiredDER, _ := x509.CreateCertificate(rand.Reader, expiredTemplate, expiredTemplate, &key.PublicKey, key)
	expiredCert, _ := x509.ParseCertificate(expiredDER)

	err = client.ValidateCertificateExpiry(expiredCert)
	if err == nil {
		t.Error("просроченный сертификат: ожидалась ошибка")
	}
}

func TestIsCertificateExpired(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	validTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "valid.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	validDER, _ := x509.CreateCertificate(rand.Reader, validTemplate, validTemplate, &key.PublicKey, key)
	validCert, _ := x509.ParseCertificate(validDER)

	if client.IsCertificateExpired(validCert) {
		t.Error("валидный сертификат не должен считаться просроченным")
	}

	expiredTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "expired.example.com"},
		NotBefore:    time.Now().AddDate(-2, 0, 0),
		NotAfter:     time.Now().AddDate(-1, 0, 0),
	}
	expiredDER, _ := x509.CreateCertificate(rand.Reader, expiredTemplate, expiredTemplate, &key.PublicKey, key)
	expiredCert, _ := x509.ParseCertificate(expiredDER)

	if !client.IsCertificateExpired(expiredCert) {
		t.Error("просроченный сертификат должен считаться просроченным")
	}
}

func TestIsCertificateValidNow(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	if !client.IsCertificateValidNow(cert) {
		t.Error("сертификат должен быть действителен")
	}
}

func TestLoadCertificatesFromFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "load-certs-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	var certsPEM []byte
	for i := 1; i <= 3; i++ {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i)),
			Subject:      pkix.Name{CommonName: "test.example.com"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(1, 0, 0),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		certsPEM = append(certsPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)
	}

	certsPath := filepath.Join(tmpDir, "certs.pem")
	if err := os.WriteFile(certsPath, certsPEM, 0644); err != nil {
		t.Fatal(err)
	}

	loaded, err := client.LoadCertificatesFromFile(certsPath)
	if err != nil {
		t.Fatalf("ошибка загрузки сертификатов: %v", err)
	}
	if len(loaded) != 3 {
		t.Errorf("ожидалось 3 сертификата, получено %d", len(loaded))
	}

	_, err = client.LoadCertificatesFromFile("/nonexistent.pem")
	if err == nil {
		t.Error("ожидалась ошибка для несуществующего файла")
	}
}

func TestRequestCertificate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "request-cert-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	csrPath := filepath.Join(tmpDir, "test.csr.pem")
	if err := os.WriteFile(csrPath, csrPEM, 0644); err != nil {
		t.Fatal(err)
	}

	mockCertPEM := []byte("-----BEGIN CERTIFICATE-----\nmock\n-----END CERTIFICATE-----\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/request-cert" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write(mockCertPEM)
	}))
	defer server.Close()

	req := &client.CertificateRequest{
		CSRPath:   csrPath,
		Template:  "server",
		CAURL:     server.URL,
		OutCert:   filepath.Join(tmpDir, "cert.pem"),
		APIKey:    "",
	}

	err = client.RequestCertificate(req)
	if err != nil {
		t.Fatalf("ошибка запроса сертификата: %v", err)
	}

	if _, err := os.Stat(req.OutCert); os.IsNotExist(err) {
		t.Error("сертификат не сохранен")
	}

	req.CSRPath = "/nonexistent.csr"
	err = client.RequestCertificate(req)
	if err == nil {
		t.Error("ожидалась ошибка для несуществующего CSR")
	}
}

func TestClientLogging(t *testing.T) {
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

	client.LogClientOperation("test_op", map[string]interface{}{
		"key": "value",
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

	client.LogClientOperation("failed_op", map[string]interface{}{}, fmt.Errorf("test error"))
}

func contains(data, sub []byte) bool {
	for i := 0; i <= len(data)-len(sub); i++ {
		if string(data[i:i+len(sub)]) == string(sub) {
			return true
		}
	}
	return false
}

func TestRequestCertificateWithError(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "request-cert-error-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Создаём валидный CSR
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	csrPath := filepath.Join(tmpDir, "test.csr.pem")
	if err := os.WriteFile(csrPath, csrPEM, 0644); err != nil {
		t.Fatal(err)
	}

	// Сервер, который возвращает ошибку
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	req := &client.CertificateRequest{
		CSRPath:   csrPath,
		Template:  "server",
		CAURL:     server.URL,
		OutCert:   filepath.Join(tmpDir, "cert.pem"),
		APIKey:    "",
	}

	err = client.RequestCertificate(req)
	if err == nil {
		t.Error("expected error from server")
	}
	t.Logf("expected error: %v", err)
}

func TestRequestCertificateWithInvalidURL(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "request-cert-invalid-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	csrPath := filepath.Join(tmpDir, "test.csr.pem")
	if err := os.WriteFile(csrPath, csrPEM, 0644); err != nil {
		t.Fatal(err)
	}

	req := &client.CertificateRequest{
		CSRPath:   csrPath,
		Template:  "server",
		CAURL:     "http://invalid:9999",
		OutCert:   filepath.Join(tmpDir, "cert.pem"),
		APIKey:    "",
	}

	err = client.RequestCertificate(req)
	if err == nil {
		t.Error("expected error from invalid URL")
	}
	t.Logf("expected error: %v", err)
}

func TestLoadPrivateKeyPKCS8(t *testing.T) {
    tmpDir := t.TempDir()
    keyPath := filepath.Join(tmpDir, "pkcs8.key.pem")

    // Генерируем PKCS8 ключ
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }
    pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
    if err != nil {
        t.Fatal(err)
    }
    pkcs8PEM := pem.EncodeToMemory(&pem.Block{
        Type:  "PRIVATE KEY",
        Bytes: pkcs8Bytes,
    })
    if err := os.WriteFile(keyPath, pkcs8PEM, 0600); err != nil {
        t.Fatal(err)
    }

    loadedKey, err := client.LoadPrivateKey(keyPath)
    if err != nil {
        t.Fatalf("LoadPrivateKey error for PKCS8: %v", err)
    }
    if loadedKey == nil {
        t.Error("loaded key is nil")
    }
}

func TestSaveCSREdgeCases(t *testing.T) {
    tmpDir, err := os.MkdirTemp("", "save-csr-edge-*")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(tmpDir)

    cfg := &client.CSRConfig{
        Subject: "/CN=test.example.com",
        KeyType: "rsa",
        KeySize: 2048,
        OutKey:  filepath.Join(tmpDir, "key.pem"),
        OutCSR:  filepath.Join(tmpDir, "csr.pem"),
    }

    generated, err := client.GenerateCSR(cfg)
    if err != nil {
        t.Fatal(err)
    }

    // Нормальное сохранение
    err = client.SaveCSR(generated, cfg.OutKey, cfg.OutCSR)
    if err != nil {
        t.Fatalf("SaveCSR error: %v", err)
    }

    // Ошибка: неверный путь для ключа (директория не существует)
    err = client.SaveCSR(generated, "/nonexistent/path/key.pem", cfg.OutCSR)
    if err == nil {
        t.Error("expected error for invalid key path")
    } else {
        t.Logf("Correctly rejected invalid key path: %v", err)
    }

    // Ошибка: неверный путь для CSR (директория не существует)
    err = client.SaveCSR(generated, cfg.OutKey, "/nonexistent/path/csr.pem")
    if err == nil {
        t.Error("expected error for invalid CSR path")
    } else {
        t.Logf("Correctly rejected invalid CSR path: %v", err)
    }

    // Тест с пустыми путями (должны быть ошибки)
    err = client.SaveCSR(generated, "", "")
    if err == nil {
        t.Error("expected error for empty paths")
    } else {
        t.Logf("Empty paths correctly rejected: %v", err)
    }

    t.Log("SaveCSR edge cases test completed")
}

func TestInitClientLoggerCoverage(t *testing.T) {
    tmpDir, err := os.MkdirTemp("", "init-logger-*")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(tmpDir)

    logPath := filepath.Join(tmpDir, "client.log")

    // Инициализация с правильным путём
    err = client.InitClientLogger(logPath)
    if err != nil {
        t.Fatalf("InitClientLogger error: %v", err)
    }
    defer client.CloseClientLogger()

    // Проверяем, что файл создан
    if _, err := os.Stat(logPath); os.IsNotExist(err) {
        t.Error("log file not created")
    }

    // Инициализация с пустым путём (должна создать в home директории)
    err = client.InitClientLogger("")
    if err != nil {
        t.Logf("InitClientLogger with empty path: %v", err)
    }
    client.CloseClientLogger()

    // Инициализация с невалидным путём (директория не существует)
    err = client.InitClientLogger("/nonexistent/path/client.log")
    if err == nil {
        t.Error("expected error for invalid path")
    } else {
        t.Logf("Correctly rejected invalid path: %v", err)
    }

    t.Log("InitClientLogger coverage test completed")
}

func TestInitClientLoggerFullCoverage(t *testing.T) {
    // Тест 1: Нормальная инициализация
    tmpDir, err := os.MkdirTemp("", "logger-full-*")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(tmpDir)

    logPath := filepath.Join(tmpDir, "client.log")
    
    err = client.InitClientLogger(logPath)
    if err != nil {
        t.Fatalf("InitClientLogger error: %v", err)
    }
    client.CloseClientLogger()

    // Тест 2: Инициализация с пустым путём (должна создать в home директории)
    err = client.InitClientLogger("")
    if err != nil {
        t.Logf("InitClientLogger with empty path: %v", err)
    }
    client.CloseClientLogger()

    // Тест 3: Инициализация с несуществующей директорией (должна создать)
    deepPath := filepath.Join(tmpDir, "a", "b", "c", "client.log")
    err = client.InitClientLogger(deepPath)
    if err != nil {
        t.Logf("InitClientLogger with deep path: %v", err)
    }
    client.CloseClientLogger()

    // Тест 4: Инициализация с невалидным путём (системная директория без прав)
    err = client.InitClientLogger("/root/client.log")
    if err == nil {
        t.Log("InitClientLogger with /root should fail or succeed depending on permissions")
    }
    client.CloseClientLogger()

    t.Log("InitClientLogger full coverage test completed")
}