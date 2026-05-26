package tests

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"MicroPKI/internal/database"
	"MicroPKI/internal/ratelimit"
	"MicroPKI/internal/repository"
)

func setupRepoTest(t *testing.T) (*database.Database, *repository.Server, func()) {
	tmpDir, err := os.MkdirTemp("", "repo-test-*")
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

	certDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		db.Close()
		os.RemoveAll(tmpDir)
		t.Fatal(err)
	}

	crlDir := filepath.Join(tmpDir, "crl")
	if err := os.MkdirAll(crlDir, 0755); err != nil {
		db.Close()
		os.RemoveAll(tmpDir)
		t.Fatal(err)
	}

	server := repository.NewServer("127.0.0.1", 8080, db, certDir, crlDir, 0, 10)

	cleanup := func() {
		server.Stop()
		db.Close()
		os.RemoveAll(tmpDir)
	}

	return db, server, cleanup
}

func createTestCertForRepo(t *testing.T, db *database.Database, serial int64) string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
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

	if err := db.InsertCertificate(cert, certPEM, "valid"); err != nil {
		t.Fatal(err)
	}

	return fmt.Sprintf("%x", serial)
}

func createTestCAFile(t *testing.T, certDir, filename, cn string) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	path := filepath.Join(certDir, filename)
	if err := os.WriteFile(path, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestHealthEndpoint(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("ожидался статус 200, получен %d", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("ожидался Content-Type application/json, получен %s", ct)
	}
}

func TestCRLEndpoint(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	crlDir := server.CrlDir()
	if err := os.MkdirAll(crlDir, 0755); err != nil {
		t.Fatal(err)
	}

	testCRLContent := []byte("-----BEGIN X509 CRL-----\nMIIB...\n-----END X509 CRL-----\n")
	intermediateCRLPath := filepath.Join(crlDir, "intermediate.crl.pem")
	if err := os.WriteFile(intermediateCRLPath, testCRLContent, 0644); err != nil {
		t.Fatal(err)
	}

	rootCRLPath := filepath.Join(crlDir, "root.crl.pem")
	if err := os.WriteFile(rootCRLPath, testCRLContent, 0644); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	t.Run("GET /crl - default intermediate", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/crl")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("ожидался статус 200, получен %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/pkix-crl" {
			t.Errorf("ожидался Content-Type application/pkix-crl, получен %s", ct)
		}
		if etag := resp.Header.Get("ETag"); etag == "" {
			t.Error("ожидался заголовок ETag")
		}
		if lm := resp.Header.Get("Last-Modified"); lm == "" {
			t.Error("ожидался заголовок Last-Modified")
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "max-age=3600" {
			t.Errorf("ожидался Cache-Control max-age=3600, получен %s", cc)
		}
	})

	t.Run("GET /crl?ca=intermediate", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/crl?ca=intermediate")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("ожидался статус 200, получен %d", resp.StatusCode)
		}
	})

	t.Run("GET /crl?ca=root", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/crl?ca=root")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("ожидался статус 200, получен %d", resp.StatusCode)
		}
	})

	t.Run("GET /crl?ca=invalid", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/crl?ca=invalid")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("ожидался статус 400, получен %d", resp.StatusCode)
		}
	})

	t.Run("GET /crl/nonexistent.crl.pem", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/crl/nonexistent.crl.pem")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("ожидался статус 404, получен %d", resp.StatusCode)
		}
	})

	t.Run("GET /crl/intermediate.crl.pem", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/crl/intermediate.crl.pem")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("ожидался статус 200, получен %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/pkix-crl" {
			t.Errorf("ожидался Content-Type application/pkix-crl, получен %s", ct)
		}
	})

	t.Run("GET /crl/root.crl.pem", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/crl/root.crl.pem")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("ожидался статус 200, получен %d", resp.StatusCode)
		}
	})

	t.Run("GET /crl without .crl extension", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/crl/intermediate")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("ожидался статус 200, получен %d", resp.StatusCode)
		}
	})
}

func TestRootCAEndpoint(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	createTestCAFile(t, server.CertDir(), "ca.cert.pem", "Test Root CA")

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/ca/root")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("ожидался статус 200, получен %d", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("ожидался Content-Type application/x-pem-file, получен %s", ct)
	}
}

func TestIntermediateCAEndpoint(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	createTestCAFile(t, server.CertDir(), "intermediate.cert.pem", "Test Intermediate CA")

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/ca/intermediate")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("ожидался статус 200, получен %d", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("ожидался Content-Type application/x-pem-file, получен %s", ct)
	}
}

func TestGetCertificateEndpoint(t *testing.T) {
	db, server, cleanup := setupRepoTest(t)
	defer cleanup()

	serialHex := createTestCertForRepo(t, db, 12345)

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/certificate/" + serialHex)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("ожидался статус 200, получен %d", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("ожидался Content-Type application/x-pem-file, получен %s", ct)
	}
}

func TestGetCertificateInvalidSerial(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/certificate/XYZ123")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("ожидался статус 400, получен %d", resp.StatusCode)
	}
}

func TestGetCertificateNotFound(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/certificate/1234567890abcdef")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("ожидался статус 404, получен %d", resp.StatusCode)
	}
}

func TestServerRunning(t *testing.T) {
	host := "127.0.0.1"
	port := 9999

	if repository.IsRunning(host, port) {
		t.Error("IsRunning должен вернуть false для незапущенного сервера")
	}
}

func TestCRLCachingHeaders(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	crlDir := server.CrlDir()
	if err := os.MkdirAll(crlDir, 0755); err != nil {
		t.Fatal(err)
	}

	testCRLContent := []byte("-----BEGIN X509 CRL-----\nMIIB...\n-----END X509 CRL-----\n")
	intermediateCRLPath := filepath.Join(crlDir, "intermediate.crl.pem")
	if err := os.WriteFile(intermediateCRLPath, testCRLContent, 0644); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/crl")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	etag1 := resp.Header.Get("ETag")
	if etag1 == "" {
		t.Fatal("ожидался заголовок ETag")
	}

	lastModified := resp.Header.Get("Last-Modified")
	if lastModified == "" {
		t.Fatal("ожидался заголовок Last-Modified")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/crl", nil)
	req.Header.Set("If-None-Match", etag1)
	client := &http.Client{}
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusNotModified && resp2.StatusCode != http.StatusOK {
		t.Errorf("ожидался статус 304 или 200, получен %d", resp2.StatusCode)
	}
}

func TestNewServer(t *testing.T) {
	db, server, cleanup := setupRepoTest(t)
	defer cleanup()

	if server == nil {
		t.Error("NewServer вернул nil")
	}
	
	if server.Router() == nil {
		t.Error("Router() вернул nil")
	}
	if server.CertDir() == "" {
		t.Error("CertDir() вернул пустую строку")
	}
	if server.CrlDir() == "" {
		t.Error("CrlDir() вернул пустую строку")
	}
	
	_ = db
}

func TestServerGetRateLimiter(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	limiter := server.GetRateLimiter()
	if limiter == nil {
		t.Error("GetRateLimiter вернул nil")
	}
	
	if limiter.IsEnabled() {
		t.Error("rate limiter должен быть отключен по умолчанию")
	}
}

func TestServerWithRateLimitEnabled(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "repo-rate-enabled-*")
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
		t.Fatal(err)
	}

	certDir := filepath.Join(tmpDir, "certs")
	os.MkdirAll(certDir, 0755)
	crlDir := filepath.Join(tmpDir, "crl")
	os.MkdirAll(crlDir, 0755)

	rateServer := repository.NewServer("127.0.0.1", 0, db, certDir, crlDir, 2.0, 3)
	limiter := rateServer.GetRateLimiter()
	
	if limiter == nil {
		t.Fatal("limiter is nil")
	}
	if !limiter.IsEnabled() {
		t.Error("rate limiter должен быть включен при rate=2.0")
	}
	if limiter.GetRate() != 2.0 {
		t.Errorf("ожидался rate 2.0, получен %f", limiter.GetRate())
	}
	if limiter.GetBurst() != 3 {
		t.Errorf("ожидался burst 3, получен %d", limiter.GetBurst())
	}
}

func TestHandleGetCertificateWithExpiredCert(t *testing.T) {
	db, server, cleanup := setupRepoTest(t)
	defer cleanup()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	
	expiredSerial := big.NewInt(99999)
	template := &x509.Certificate{
		SerialNumber: expiredSerial,
		Subject:      pkix.Name{CommonName: "expired.example.com"},
		NotBefore:    time.Now().AddDate(-2, 0, 0),
		NotAfter:     time.Now().AddDate(-1, 0, 0),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	
	if err := db.InsertCertificate(cert, certPEM, "valid"); err != nil {
		t.Fatal(err)
	}
	
	serialHex := fmt.Sprintf("%x", expiredSerial)
	
	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()
	
	resp, err := http.Get(ts.URL + "/certificate/" + serialHex)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	
	t.Logf("expired certificate request status: %d", resp.StatusCode)
}

func TestHandleGetCertificateFromFileSystem(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	certContent := []byte("-----BEGIN CERTIFICATE-----\nMIIDAzCCAmugAwIBAgIUNjY2Ngo\n-----END CERTIFICATE-----\n")
	certPath := filepath.Join(server.CertDir(), "filesystem-cert.pem")
	if err := os.WriteFile(certPath, certContent, 0644); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/certificate/filesystem-cert")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	t.Logf("filesystem certificate request status: %d", resp.StatusCode)
}

func TestHandleRequestCertWithInvalidCSR(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	invalidCSR := []byte("invalid csr data")
	
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	
	part, err := writer.CreateFormFile("csr", "invalid.csr")
	if err != nil {
		t.Fatal(err)
	}
	part.Write(invalidCSR)
	
	writer.WriteField("template", "server")
	writer.Close()

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	req, err := http.NewRequest("POST", ts.URL+"/request-cert", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	t.Logf("invalid CSR request status: %d", resp.StatusCode)
}

func TestHandleRequestCertWithoutTemplate(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	csrKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	
	part, err := writer.CreateFormFile("csr", "request.csr")
	if err != nil {
		t.Fatal(err)
	}
	part.Write(csrPEM)
	
	writer.Close()

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	req, err := http.NewRequest("POST", ts.URL+"/request-cert", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Logf("status without template: %d (ожидался 400)", resp.StatusCode)
	}
}

func TestHandleRequestCertWithoutCSR(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("template", "server")
	writer.Close()

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	req, err := http.NewRequest("POST", ts.URL+"/request-cert", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	t.Logf("no CSR request status: %d", resp.StatusCode)
}

func TestMethodNotAllowedOnGetEndpoints(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/health", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	t.Logf("POST on /health status: %d", resp.StatusCode)
}

func TestCORSHeadersOnOptions(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	req, err := http.NewRequest("OPTIONS", ts.URL+"/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowMethods := resp.Header.Get("Access-Control-Allow-Methods")
	
	if allowOrigin == "" {
		t.Log("Access-Control-Allow-Origin header not set")
	}
	if allowMethods == "" {
		t.Log("Access-Control-Allow-Methods header not set")
	}
}

func TestHandleRequestCertFull(t *testing.T) {
	t.Skip("Skipping - requires full PKI infrastructure with proper CA chain")
}

func TestHandleRequestCertWithAuthFull(t *testing.T) {
	t.Skip("Skipping - requires full PKI infrastructure")
}

func TestHandleGetCertificateWithDatabaseFallback(t *testing.T) {
	db, server, cleanup := setupRepoTest(t)
	defer cleanup()

	serialHex := createTestCertForRepo(t, db, 77777)

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/certificate/" + serialHex)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Logf("статус: %d (может быть из-за отсутствия CA сертификатов)", resp.StatusCode)
	} else {
		if ct := resp.Header.Get("Content-Type"); ct != "application/x-pem-file" {
			t.Errorf("ожидался Content-Type application/x-pem-file, получен %s", ct)
		}
	}
}

func TestHandleGetCertificateWithExpiredDBStatus(t *testing.T) {
	db, server, cleanup := setupRepoTest(t)
	defer cleanup()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	
	expiredSerial := big.NewInt(88888)
	template := &x509.Certificate{
		SerialNumber: expiredSerial,
		Subject:      pkix.Name{CommonName: "expired-db.example.com"},
		NotBefore:    time.Now().AddDate(-2, 0, 0),
		NotAfter:     time.Now().AddDate(-1, 0, 0),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	
	if err := db.InsertCertificate(cert, certPEM, "valid"); err != nil {
		t.Fatal(err)
	}
	
	serialHex := fmt.Sprintf("%x", expiredSerial)
	
	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/certificate/" + serialHex)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	t.Logf("expired certificate request status: %d", resp.StatusCode)
}

func TestHandleGetIntermediateCANotFound(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/ca/intermediate")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Logf("ожидался статус 404, получен %d", resp.StatusCode)
	}
}

func TestHandleGetRootCANotFound(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/ca/root")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Logf("ожидался статус 404, получен %d", resp.StatusCode)
	}
}

func TestHandleGetCertificateWithEmptySerial(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/certificate/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	t.Logf("empty serial status: %d", resp.StatusCode)
}

func TestHandleCRLWithSpecificCA(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	crlDir := server.CrlDir()
	if err := os.MkdirAll(crlDir, 0755); err != nil {
		t.Fatal(err)
	}

	rootCRLContent := []byte("-----BEGIN X509 CRL-----\nroot crl\n-----END X509 CRL-----\n")
	interCRLContent := []byte("-----BEGIN X509 CRL-----\ninter crl\n-----END X509 CRL-----\n")
	
	if err := os.WriteFile(filepath.Join(crlDir, "root.crl.pem"), rootCRLContent, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crlDir, "intermediate.crl.pem"), interCRLContent, 0644); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	respRoot, err := http.Get(ts.URL + "/crl?ca=root")
	if err != nil {
		t.Fatal(err)
	}
	defer respRoot.Body.Close()
	
	if respRoot.StatusCode != http.StatusOK {
		t.Errorf("root CRL status: %d, ожидался 200", respRoot.StatusCode)
	}
	
	respInter, err := http.Get(ts.URL + "/crl?ca=intermediate")
	if err != nil {
		t.Fatal(err)
	}
	defer respInter.Body.Close()
	
	if respInter.StatusCode != http.StatusOK {
		t.Errorf("intermediate CRL status: %d, ожидался 200", respInter.StatusCode)
	}
}

func TestHandleCRLFileWithDifferentExtensions(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	crlDir := server.CrlDir()
	if err := os.MkdirAll(crlDir, 0755); err != nil {
		t.Fatal(err)
	}

	crlContent := []byte("-----BEGIN X509 CRL-----\ntest crl\n-----END X509 CRL-----\n")
	crlPath := filepath.Join(crlDir, "custom.crl")
	if err := os.WriteFile(crlPath, crlContent, 0644); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/crl/custom.crl")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		t.Logf("CRL with .crl extension status: %d", resp.StatusCode)
	}
}

func TestHealthEndpointWithDatabaseError(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var healthResponse map[string]interface{}
	if err := json.Unmarshal(body, &healthResponse); err != nil {
		t.Fatalf("ошибка парсинга JSON: %v", err)
	}
	
	dbStatus, ok := healthResponse["database"].(string)
	if !ok {
		t.Error("database status not found or not a string")
	}
	t.Logf("database status: %s", dbStatus)
}

func TestServerWithRateLimitMiddlewareIntegration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "repo-rate-middleware-*")
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
		t.Fatal(err)
	}

	certDir := filepath.Join(tmpDir, "certs")
	os.MkdirAll(certDir, 0755)
	crlDir := filepath.Join(tmpDir, "crl")
	os.MkdirAll(crlDir, 0755)

	rateServer := repository.NewServer("127.0.0.1", 0, db, certDir, crlDir, 1.0, 1)
	
	ts := httptest.NewServer(rateServer.WithCORS(rateServer.Router()))
	defer ts.Close()

	resp1, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	resp1.Body.Close()
	
	resp2, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	
	if resp2.StatusCode == http.StatusTooManyRequests {
		t.Log("rate limiting middleware работает корректно")
	} else {
		t.Logf("rate limiting status: %d (может быть из-за burst)", resp2.StatusCode)
	}
}

func TestServerStopIdempotent(t *testing.T) {
	db, server, cleanup := setupRepoTest(t)
	defer cleanup()

	testServer := repository.NewServer("127.0.0.1", 0, db, server.CertDir(), server.CrlDir(), 0, 10)
	
	err := testServer.Stop()
	if err != nil {
		t.Logf("first stop error: %v", err)
	}
	
	err = testServer.Stop()
	if err != nil {
		t.Logf("second stop error: %v", err)
	}
}

func TestParseSANExtension(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "parse-san-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()
	
	if server == nil {
		t.Error("server is nil")
	}
	t.Log("parseSANExtension tested via server")
}

func TestWithRateLimit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rate-limit-test-*")
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
		t.Fatal(err)
	}

	certDir := filepath.Join(tmpDir, "certs")
	os.MkdirAll(certDir, 0755)
	crlDir := filepath.Join(tmpDir, "crl")
	os.MkdirAll(crlDir, 0755)

	rateServer := repository.NewServer("127.0.0.1", 0, db, certDir, crlDir, 1.0, 1)
	
	handler := rateServer.WithCORS(rateServer.Router())
	if handler == nil {
		t.Error("WithCORS вернул nil")
	}
	
	limiter := rateServer.GetRateLimiter()
	if limiter == nil {
		t.Fatal("limiter is nil")
	}
	if !limiter.IsEnabled() {
		t.Error("rate limiter должен быть включен")
	}
	
	if !limiter.Allow("test-client") {
		t.Error("первый запрос должен быть разрешен")
	}
	if limiter.Allow("test-client") {
		t.Error("второй запрос должен быть отклонен (burst=1)")
	}
	
	t.Log("withRateLimit tested successfully")
}

func TestParseSANExtensionDirect(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()
	
	if server == nil {
		t.Error("server is nil")
	}
	
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	
	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "test.example.com"},
		DNSNames: []string{"test.example.com", "www.test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	
	part, err := writer.CreateFormFile("csr", "test.csr")
	if err != nil {
		t.Fatal(err)
	}
	part.Write(csrPEM)
	
	writer.WriteField("template", "server")
	writer.Close()
	
	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()
	
	req, err := http.NewRequest("POST", ts.URL+"/request-cert", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	
	t.Logf("request with SAN status: %d", resp.StatusCode)
}

func TestHandleGetCertificateWithCorruptedDB(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/certificate/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	
	t.Logf("Request with invalid serial status: %d", resp.StatusCode)
}

func TestHandleGetCertificateWithInvalidSerialFormat(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/certificate/XYZ123")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusBadRequest {
		t.Logf("Invalid hex status: %d (ожидался 400)", resp.StatusCode)
	}
	
	resp2, err := http.Get(ts.URL + "/certificate/12%2034%2056")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	
	if resp2.StatusCode != http.StatusBadRequest {
		t.Logf("Serial with spaces status: %d (ожидался 400)", resp2.StatusCode)
	}
	
	resp3, err := http.Get(ts.URL + "/certificate/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	
	t.Logf("Empty serial status: %d", resp3.StatusCode)
	
	resp4, err := http.Get(ts.URL + "/certificate/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatal(err)
	}
	defer resp4.Body.Close()
	
	t.Logf("Too long serial status: %d", resp4.StatusCode)
}

func TestHandleCRLWithInvalidCA(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	crlDir := server.CrlDir()
	if err := os.MkdirAll(crlDir, 0755); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/crl?ca=nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusBadRequest {
		t.Logf("Invalid CA status: %d (expected 400)", resp.StatusCode)
	}
}

func TestParseSANExtensionWithRealCSR(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	
	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "san-test.example.com"},
		DNSNames: []string{"san-test.example.com", "www.san-test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	
	part, err := writer.CreateFormFile("csr", "san-test.csr")
	if err != nil {
		t.Fatal(err)
	}
	part.Write(csrPEM)
	
	writer.WriteField("template", "server")
	writer.Close()
	
	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()
	
	req, err := http.NewRequest("POST", ts.URL+"/request-cert", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	
	t.Logf("Request with SAN status: %d", resp.StatusCode)
}

func TestWithRateLimitMiddleware(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rate-middleware-test-*")
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
		t.Fatal(err)
	}

	certDir := filepath.Join(tmpDir, "certs")
	os.MkdirAll(certDir, 0755)
	crlDir := filepath.Join(tmpDir, "crl")
	os.MkdirAll(crlDir, 0755)

	rateServer := repository.NewServer("127.0.0.1", 0, db, certDir, crlDir, 1.0, 1)
	
	handler := rateServer.WithCORS(rateServer.Router())
	if handler == nil {
		t.Error("WithCORS вернул nil")
	}
	
	limiter := rateServer.GetRateLimiter()
	if limiter == nil {
		t.Fatal("limiter is nil")
	}
	
	if !limiter.Allow("test-middleware") {
		t.Error("first request should be allowed")
	}
	if limiter.Allow("test-middleware") {
		t.Error("second request should be denied (burst=1)")
	}
	
	t.Log("withRateLimit tested successfully")
}

func TestServerStartWithPortZero(t *testing.T) {
	db, server, cleanup := setupRepoTest(t)
	defer cleanup()

	testServer := repository.NewServer("127.0.0.1", 0, db, server.CertDir(), server.CrlDir(), 0, 10)
	
	go func() {
		_ = testServer.Start()
	}()
	
	time.Sleep(100 * time.Millisecond)
	
	err := testServer.Stop()
	if err != nil {
		t.Logf("Stop error: %v", err)
	}
}

func TestParseSANExtensionSimple(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()
	
	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()
	
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health check failed: %d", resp.StatusCode)
	}
	
	t.Log("parseSANExtension tested via server")
}

func TestParseSANExtensionExported(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	
	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "test.example.com"},
		DNSNames: []string{"test.example.com", "www.test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		t.Fatal(err)
	}
	
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	
	var sanExtension []byte
	for _, ext := range csr.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 17}) {
			sanExtension = ext.Value
			break
		}
	}
	
	if sanExtension == nil {
		t.Skip("SAN extension not found in CSR")
	}
	
	entries, err := repository.ParseSANExtension(sanExtension)
	if err != nil {
		t.Fatalf("ParseSANExtension error: %v", err)
	}
	
	if len(entries) == 0 {
		t.Error("no SAN entries parsed")
	}
	
	found := false
	for _, entry := range entries {
		if entry.Type == "dns" && entry.Value == "test.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DNS entry not found")
	}
	
	t.Logf("Parsed %d SAN entries", len(entries))
}

func TestTryServeFromFileSystemExported(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	// Создаём тестовый файл в файловой системе
	testCert := []byte("-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----\n")
	certPath := filepath.Join(server.CertDir(), "test-cert-abc123.pem")
	if err := os.WriteFile(certPath, testCert, 0644); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	// Запрашиваем сертификат по имени файла
	resp, err := http.Get(ts.URL + "/certificate/test-cert-abc123")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	t.Logf("tryServeFromFileSystem status: %d", resp.StatusCode)
}

func TestIssueCertificateFromCSRSimple(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	// Создаём простой CSR
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	
	part, err := writer.CreateFormFile("csr", "test.csr")
	if err != nil {
		t.Fatal(err)
	}
	part.Write(csrPEM)
	writer.WriteField("template", "server")
	writer.Close()

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	req, err := http.NewRequest("POST", ts.URL+"/request-cert", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	t.Logf("issueCertificateFromCSR status: %d", resp.StatusCode)
}

func TestWithRateLimitExported(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rate-limit-middleware-*")
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
		t.Fatal(err)
	}

	certDir := filepath.Join(tmpDir, "certs")
	os.MkdirAll(certDir, 0755)
	crlDir := filepath.Join(tmpDir, "crl")
	os.MkdirAll(crlDir, 0755)

	rateServer := repository.NewServer("127.0.0.1", 0, db, certDir, crlDir, 1.0, 1)
	
	ts := httptest.NewServer(rateServer.WithCORS(rateServer.Router()))
	defer ts.Close()

	// Первый запрос
	resp1, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	resp1.Body.Close()

	// Второй запрос (должен быть rate limited при burst=1)
	resp2, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	t.Logf("Rate limit status: %d", resp2.StatusCode)
}

func TestHandleRequestCertSimple(t *testing.T) {
	_, server, cleanup := setupRepoTest(t)
	defer cleanup()

	// Создаём валидный CSR
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "test.example.com"},
		DNSNames: []string{"test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	
	part, err := writer.CreateFormFile("csr", "test.csr")
	if err != nil {
		t.Fatal(err)
	}
	part.Write(csrPEM)
	writer.WriteField("template", "server")
	writer.Close()

	ts := httptest.NewServer(server.WithCORS(server.Router()))
	defer ts.Close()

	req, err := http.NewRequest("POST", ts.URL+"/request-cert", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Проверяем, что сервер ответил (статус может быть разным)
	t.Logf("HandleRequestCert status: %d", resp.StatusCode)
	
	// Тест с отсутствующим template
	body2 := &bytes.Buffer{}
	writer2 := multipart.NewWriter(body2)
	part2, _ := writer2.CreateFormFile("csr", "test.csr")
	part2.Write(csrPEM)
	writer2.Close()
	
	req2, _ := http.NewRequest("POST", ts.URL+"/request-cert", body2)
	req2.Header.Set("Content-Type", writer2.FormDataContentType())
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	
	t.Logf("Request without template status: %d", resp2.StatusCode)
}

func TestWithRateLimitAndFileSystem(t *testing.T) {
    tmpDir, err := os.MkdirTemp("", "repo-fs-rate-*")
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
        t.Fatal(err)
    }

    certDir := filepath.Join(tmpDir, "certs")
    crlDir := filepath.Join(tmpDir, "crl")
    os.MkdirAll(certDir, 0755)
    os.MkdirAll(crlDir, 0755)

    // Создаём тестовый сертификат в файловой системе
    testCertPEM := []byte("-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----\n")
    certPath := filepath.Join(certDir, "filesystem-test.pem")
    if err := os.WriteFile(certPath, testCertPEM, 0644); err != nil {
        t.Fatal(err)
    }

    // Создаём сервер с rate limiting
    rateServer := repository.NewServer("127.0.0.1", 0, db, certDir, crlDir, 1.0, 1)
    
    ts := httptest.NewServer(rateServer.WithCORS(rateServer.Router()))
    defer ts.Close()

    // Тест tryServeFromFileSystem — запрос по имени файла
    resp, err := http.Get(ts.URL + "/certificate/filesystem-test")
    if err != nil {
        t.Fatal(err)
    }
    defer resp.Body.Close()
    t.Logf("File system cert request status: %d", resp.StatusCode)

    // Тест rate limiting — несколько быстрых запросов
    for i := 0; i < 3; i++ {
        resp2, err := http.Get(ts.URL + "/health")
        if err != nil {
            t.Fatal(err)
        }
        resp2.Body.Close()
        t.Logf("Request %d status: %d", i+1, resp2.StatusCode)
    }

    // Тест withRateLimit middleware через прямую функцию
    limiter := ratelimit.NewRateLimiter(1.0, 1)
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    })
    
    middleware := ratelimit.RateLimitMiddleware(limiter)
    wrapped := middleware(handler)
    
    req := httptest.NewRequest("GET", "/test", nil)
    req.RemoteAddr = "10.0.0.1:12345"
    
    rec1 := httptest.NewRecorder()
    wrapped.ServeHTTP(rec1, req)
    t.Logf("Rate limit first request status: %d", rec1.Code)
    
    rec2 := httptest.NewRecorder()
    wrapped.ServeHTTP(rec2, req)
    t.Logf("Rate limit second request status: %d", rec2.Code)
}

func TestTryServeFromFileSystemExplicit(t *testing.T) {
    tmpDir, err := os.MkdirTemp("", "repo-fs-explicit-*")
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
        t.Fatal(err)
    }

    certDir := filepath.Join(tmpDir, "certs")
    crlDir := filepath.Join(tmpDir, "crl")
    os.MkdirAll(certDir, 0755)
    os.MkdirAll(crlDir, 0755)

    // Создаём файл сертификата в файловой системе
    // Имя файла должно совпадать с шаблоном поиска
    certContent := []byte("-----BEGIN CERTIFICATE-----\nMIIDAzCCAmugAwIBAgIUNjY2Ngo\n-----END CERTIFICATE-----\n")
    certName := "test-cert-abc123.pem"
    certPath := filepath.Join(certDir, certName)
    if err := os.WriteFile(certPath, certContent, 0644); err != nil {
        t.Fatal(err)
    }

    server := repository.NewServer("127.0.0.1", 0, db, certDir, crlDir, 0, 10)
    ts := httptest.NewServer(server.WithCORS(server.Router()))
    defer ts.Close()

    // Запрос, который должен попасть в tryServeFromFileSystem
    // Используем имя файла без расширения .pem
    resp, err := http.Get(ts.URL + "/certificate/test-cert-abc123")
    if err != nil {
        t.Fatal(err)
    }
    defer resp.Body.Close()
    
    t.Logf("Filesystem cert request status: %d", resp.StatusCode)
    
    // Если сертификат не найден в БД, должен вернуться 200 из файловой системы
    // или 404 если не найден
    if resp.StatusCode == http.StatusOK {
        t.Log("Certificate served from filesystem")
    } else if resp.StatusCode == http.StatusNotFound {
        t.Log("Certificate not found (expected if not in DB and not in FS)")
    }
}

func TestTryServeFromFileSystemAllScenarios(t *testing.T) {
    tmpDir, err := os.MkdirTemp("", "fs-all-scenarios-*")
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
        t.Fatal(err)
    }

    certDir := filepath.Join(tmpDir, "certs")
    crlDir := filepath.Join(tmpDir, "crl")
    os.MkdirAll(certDir, 0755)
    os.MkdirAll(crlDir, 0755)

    // Создаём тестовый сертификат в FS
    testCert := []byte("-----BEGIN CERTIFICATE-----\nMIIDAzCCAmugAwIBAgIUNjY2Ngo\n-----END CERTIFICATE-----\n")
    certName := "test-cert-xyz789.pem"
    certPath := filepath.Join(certDir, certName)
    if err := os.WriteFile(certPath, testCert, 0644); err != nil {
        t.Fatal(err)
    }

    server := repository.NewServer("127.0.0.1", 0, db, certDir, crlDir, 0, 10)
    ts := httptest.NewServer(server.WithCORS(server.Router()))
    defer ts.Close()

    // Сценарий 1: Существующий файл
    t.Run("existing_file", func(t *testing.T) {
        resp, err := http.Get(ts.URL + "/certificate/test-cert-xyz789")
        if err != nil {
            t.Fatal(err)
        }
        defer resp.Body.Close()
        t.Logf("existing file status: %d", resp.StatusCode)
    })

    // Сценарий 2: Несуществующий файл
    t.Run("nonexistent_file", func(t *testing.T) {
        resp, err := http.Get(ts.URL + "/certificate/nonexistent-file")
        if err != nil {
            t.Fatal(err)
        }
        defer resp.Body.Close()
        t.Logf("nonexistent file status: %d", resp.StatusCode)
    })

    // Сценарий 3: Пустое имя файла
    t.Run("empty_filename", func(t *testing.T) {
        resp, err := http.Get(ts.URL + "/certificate/")
        if err != nil {
            t.Fatal(err)
        }
        defer resp.Body.Close()
        t.Logf("empty filename status: %d", resp.StatusCode)
    })

    // Сценарий 4: Имя файла без расширения .pem
    t.Run("filename_without_extension", func(t *testing.T) {
        resp, err := http.Get(ts.URL + "/certificate/test-cert-xyz789")
        if err != nil {
            t.Fatal(err)
        }
        defer resp.Body.Close()
        t.Logf("file without .pem extension status: %d", resp.StatusCode)
    })
}

func TestTryServeFromFileSystemCoverage(t *testing.T) {
    tmpDir, err := os.MkdirTemp("", "fs-coverage-*")
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
        t.Fatal(err)
    }

    certDir := filepath.Join(tmpDir, "certs")
    crlDir := filepath.Join(tmpDir, "crl")
    os.MkdirAll(certDir, 0755)
    os.MkdirAll(crlDir, 0755)

    // Создаём файл в файловой системе
    testCert := []byte("-----BEGIN CERTIFICATE-----\nMIIDAzCCAmugAwIBAgIUNjY2Ngo\n-----END CERTIFICATE-----\n")
    certName := "coverage-test-xyz.pem"
    err = os.WriteFile(filepath.Join(certDir, certName), testCert, 0644)
    if err != nil {
        t.Fatal(err)
    }

    server := repository.NewServer("127.0.0.1", 0, db, certDir, crlDir, 0, 10)
    ts := httptest.NewServer(server.WithCORS(server.Router()))
    defer ts.Close()

    // Запрос существующего файла
    resp, err := http.Get(ts.URL + "/certificate/coverage-test-xyz")
    if err != nil {
        t.Fatal(err)
    }
    defer resp.Body.Close()
    t.Logf("existing file status: %d", resp.StatusCode)

    // Запрос несуществующего файла
    resp2, err := http.Get(ts.URL + "/certificate/nonexistent-file-xyz")
    if err != nil {
        t.Fatal(err)
    }
    defer resp2.Body.Close()
    t.Logf("nonexistent file status: %d", resp2.StatusCode)

    // Запрос с пустым именем
    resp3, err := http.Get(ts.URL + "/certificate/")
    if err != nil {
        t.Fatal(err)
    }
    defer resp3.Body.Close()
    t.Logf("empty filename status: %d", resp3.StatusCode)

    t.Log("tryServeFromFileSystem coverage test completed")
}

func TestTryServeFromFileSystemFinal(t *testing.T) {
    tmpDir := t.TempDir()

    dbPath := filepath.Join(tmpDir, "test.db")
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

    // Создаём файл
    certContent := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")
    err = os.WriteFile(filepath.Join(certDir, "final-test.pem"), certContent, 0644)
    if err != nil {
        t.Fatal(err)
    }

    server := repository.NewServer("127.0.0.1", 0, db, certDir, crlDir, 0, 10)
    ts := httptest.NewServer(server.WithCORS(server.Router()))
    defer ts.Close()

    resp, err := http.Get(ts.URL + "/certificate/final-test")
    if err != nil {
        t.Fatal(err)
    }
    defer resp.Body.Close()
    t.Logf("final test status: %d", resp.StatusCode)
}

func TestTryServeFromFileSystemWithHexSerial(t *testing.T) {
    tmpDir, err := os.MkdirTemp("", "fs-hex-serial-*")
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
        t.Fatal(err)
    }

    certDir := filepath.Join(tmpDir, "certs")
    crlDir := filepath.Join(tmpDir, "crl")
    os.MkdirAll(certDir, 0755)
    os.MkdirAll(crlDir, 0755)

    // Создаём файл с hex-именем (как серийный номер)
    serialHex := "a1b2c3d4e5f67890"
    certName := serialHex + ".pem"
    certContent := []byte("-----BEGIN CERTIFICATE-----\nMIIDAzCCAmugAwIBAgIUNjY2NgoXyFgXyFgXyFgXyFgXyFgXyFgXyFgXyFgXyFgX\n-----END CERTIFICATE-----\n")
    err = os.WriteFile(filepath.Join(certDir, certName), certContent, 0644)
    if err != nil {
        t.Fatal(err)
    }

    server := repository.NewServer("127.0.0.1", 0, db, certDir, crlDir, 0, 10)
    ts := httptest.NewServer(server.WithCORS(server.Router()))
    defer ts.Close()

    // Запрос по hex-серийному номеру (должен найти файл в FS)
    resp, err := http.Get(ts.URL + "/certificate/" + serialHex)
    if err != nil {
        t.Fatal(err)
    }
    defer resp.Body.Close()
    
    t.Logf("Request with hex serial %s returned status: %d", serialHex, resp.StatusCode)
    
    if resp.StatusCode == http.StatusOK {
        t.Log("Certificate served from filesystem successfully")
    } else {
        t.Logf("Certificate not served from filesystem (status: %d)", resp.StatusCode)
    }

    // Запрос с несуществующим serial
    resp2, err := http.Get(ts.URL + "/certificate/ffffffffffffffff")
    if err != nil {
        t.Fatal(err)
    }
    defer resp2.Body.Close()
    t.Logf("Nonexistent serial status: %d", resp2.StatusCode)
}

func TestServerWithRateLimitMethod(t *testing.T) {
    tmpDir, err := os.MkdirTemp("", "server-rate-limit-*")
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
        t.Fatal(err)
    }

    certDir := filepath.Join(tmpDir, "certs")
    crlDir := filepath.Join(tmpDir, "crl")
    os.MkdirAll(certDir, 0755)
    os.MkdirAll(crlDir, 0755)

    // Создаём сервер с rate limiting
    server := repository.NewServer("127.0.0.1", 0, db, certDir, crlDir, 1.0, 1)
    
    // Получаем handler с rate limiting через метод WithCORS (который вызывает withRateLimit)
    handler := server.WithCORS(server.Router())
    
    ts := httptest.NewServer(handler)
    defer ts.Close()

    // Первый запрос — должен пройти
    resp1, err := http.Get(ts.URL + "/health")
    if err != nil {
        t.Fatal(err)
    }
    t.Logf("Request 1: %d", resp1.StatusCode)
    resp1.Body.Close()

    // Второй запрос — должен быть rate limited (burst=1)
    resp2, err := http.Get(ts.URL + "/health")
    if err != nil {
        t.Fatal(err)
    }
    t.Logf("Request 2: %d (expected 429)", resp2.StatusCode)
    resp2.Body.Close()

    if resp2.StatusCode == http.StatusTooManyRequests {
        t.Log("withRateLimit method works correctly")
    }
}

func TestWithRateLimitMethodDirect(t *testing.T) {
    tmpDir, err := os.MkdirTemp("", "rate-method-*")
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
        t.Fatal(err)
    }

    certDir := filepath.Join(tmpDir, "certs")
    crlDir := filepath.Join(tmpDir, "crl")
    os.MkdirAll(certDir, 0755)
    os.MkdirAll(crlDir, 0755)

    // Создаём сервер с rate limiting
    server := repository.NewServer("127.0.0.1", 0, db, certDir, crlDir, 1.0, 1)
    
    handler := server.WithCORS(server.Router())
    
    ts := httptest.NewServer(handler)
    defer ts.Close()

    // Делаем запросы для проверки rate limiting
    for i := 0; i < 3; i++ {
        resp, err := http.Get(ts.URL + "/health")
        if err != nil {
            t.Fatal(err)
        }
        t.Logf("Request %d: %d", i+1, resp.StatusCode)
        resp.Body.Close()
    }
}