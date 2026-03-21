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

	"MicroPKI/internal/database"
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

	server := repository.NewServer("127.0.0.1", 8080, db, certDir, crlDir)

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
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
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
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
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
