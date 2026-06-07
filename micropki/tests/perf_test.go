package tests

import (
	"bytes"
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
	internalocsp "MicroPKI/internal/ocsp"
	x509ocsp "golang.org/x/crypto/ocsp"
)

func TestPerformance1000Certificates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "perf-test-*")
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

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Perf Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := db.InsertCertificate(caCert, caPEM, "valid"); err != nil {
		t.Fatal(err)
	}

	certCount := 1000
	startTime := time.Now()

	for i := 0; i < certCount; i++ {
		leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate key for cert %d: %v", i, err)
		}
		leafSerial := big.NewInt(int64(10000 + i))
		leafTemplate := &x509.Certificate{
			SerialNumber: leafSerial,
			Subject:      pkix.Name{CommonName: fmt.Sprintf("cert-%d.example.com", i)},
			Issuer:       caCert.Subject,
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(1, 0, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
		if err != nil {
			t.Fatalf("failed to create cert %d: %v", i, err)
		}
		leafCert, err := x509.ParseCertificate(leafDER)
		if err != nil {
			t.Fatalf("failed to parse cert %d: %v", i, err)
		}
		leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

		if err := db.InsertCertificate(leafCert, leafPEM, "valid"); err != nil {
			t.Fatalf("failed to insert cert %d: %v", i, err)
		}
	}

	elapsed := time.Since(startTime)
	certsPerSec := float64(certCount) / elapsed.Seconds()

	t.Logf("=== CERTIFICATE ISSUANCE PERFORMANCE TEST ===")
	t.Logf("Issued %d certificates in %v", certCount, elapsed)
	t.Logf("Issuance rate: %.2f certs/sec", certsPerSec)

	startValidate := time.Now()
	records, err := db.ListCertificates("", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	validateElapsed := time.Since(startValidate)

	t.Logf("Listed %d certificates in %v", len(records), validateElapsed)

	if len(records) < certCount {
		t.Errorf("expected at least %d certificates, got %d", certCount, len(records))
	}
}

func TestPerformance1000OCSPRequestsUnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OCSP performance test (unique certs) in short mode")
	}

	tmpDir, err := os.MkdirTemp("", "ocsp-perf-unique-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("failed to create DB: %v", err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "OCSP Perf CA (Unique)"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := db.InsertCertificate(caCert, caPEM, "valid"); err != nil {
		t.Fatalf("failed to insert CA cert: %v", err)
	}

	ocspKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate OCSP key: %v", err)
	}
	ocspTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "OCSP Responder"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	ocspDER, err := x509.CreateCertificate(rand.Reader, ocspTemplate, caCert, &ocspKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create OCSP cert: %v", err)
	}
	ocspPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ocspDER})
	ocspKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ocspKey)})

	ocspCertPath := filepath.Join(tmpDir, "ocsp.cert.pem")
	ocspKeyPath := filepath.Join(tmpDir, "ocsp.key.pem")
	caCertPath := filepath.Join(tmpDir, "ca.cert.pem")

	if err := os.WriteFile(ocspCertPath, ocspPEM, 0644); err != nil {
		t.Fatalf("failed to write OCSP cert: %v", err)
	}
	if err := os.WriteFile(ocspKeyPath, ocspKeyPEM, 0600); err != nil {
		t.Fatalf("failed to write OCSP key: %v", err)
	}
	if err := os.WriteFile(caCertPath, caPEM, 0644); err != nil {
		t.Fatalf("failed to write CA cert: %v", err)
	}

	responder, err := internalocsp.NewOCSPResponder(db, ocspCertPath, ocspKeyPath, caCertPath, 60, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("failed to create OCSP responder: %v", err)
	}
	defer responder.Close()

	handler := http.HandlerFunc(responder.HandleOCSPRequest)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	totalRequests := 1000
	leafRequests := make([][]byte, totalRequests)

	t.Logf("Generating %d unique certificates and OCSP requests...", totalRequests)
	genStart := time.Now()

	for i := 0; i < totalRequests; i++ {
		leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate leaf key %d: %v", i, err)
		}
		leafSerial := big.NewInt(int64(10000 + i))
		leafTemplate := &x509.Certificate{
			SerialNumber: leafSerial,
			Subject:      pkix.Name{CommonName: fmt.Sprintf("perf-unique-%d.example.com", i)},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(1, 0, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
		if err != nil {
			t.Fatalf("failed to create leaf cert %d: %v", i, err)
		}
		leafCert, err := x509.ParseCertificate(leafDER)
		if err != nil {
			t.Fatalf("failed to parse leaf cert %d: %v", i, err)
		}
		leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
		if err := db.InsertCertificate(leafCert, leafPEM, "valid"); err != nil {
			t.Fatalf("failed to insert leaf cert %d: %v", i, err)
		}

		ocspReq, err := x509ocsp.CreateRequest(leafCert, caCert, nil)
		if err != nil {
			t.Fatalf("failed to create OCSP request %d: %v", i, err)
		}
		leafRequests[i] = ocspReq
	}

	genElapsed := time.Since(genStart)
	t.Logf("Generated %d unique certificates in %v", totalRequests, genElapsed)

	results := make([]time.Duration, totalRequests)
	startTime := time.Now()

	client := &http.Client{Timeout: 5 * time.Second}

	for i := 0; i < totalRequests; i++ {
		reqData := leafRequests[i]

		httpReq, err := http.NewRequest("POST", ts.URL, bytes.NewReader(reqData))
		if err != nil {
			t.Fatalf("failed to create request %d: %v", i, err)
		}
		httpReq.Header.Set("Content-Type", "application/ocsp-request")

		reqStart := time.Now()
		resp, err := client.Do(httpReq)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		results[i] = time.Since(reqStart)
		resp.Body.Close()
	}

	elapsed := time.Since(startTime)

	reqPerSec := float64(totalRequests) / elapsed.Seconds()

	var totalLatency time.Duration
	minLatency := time.Duration(1<<63 - 1)
	maxLatency := time.Duration(0)

	for _, lat := range results {
		totalLatency += lat
		if lat < minLatency {
			minLatency = lat
		}
		if lat > maxLatency {
			maxLatency = lat
		}
	}
	avgLatency := totalLatency / time.Duration(totalRequests)

	t.Logf("=== OCSP PERFORMANCE TEST RESULTS (1000 UNIQUE certs, single worker) ===")
	t.Logf("Total requests: %d", totalRequests)
	t.Logf("Workers: 1")
	t.Logf("Unique certificates: %d", totalRequests)
	t.Logf("Certificate generation time: %v", genElapsed)
	t.Logf("Total time: %v", elapsed)
	t.Logf("Requests/sec: %.2f", reqPerSec)
	t.Logf("Latency - Min: %v, Avg: %v, Max: %v", minLatency, avgLatency, maxLatency)
}