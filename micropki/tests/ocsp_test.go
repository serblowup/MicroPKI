package tests

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"MicroPKI/internal/ca"
	"MicroPKI/internal/certs"
	"MicroPKI/internal/cryptoutil"
	"MicroPKI/internal/csr"
	"MicroPKI/internal/database"
	internalocsp "MicroPKI/internal/ocsp"
	"MicroPKI/internal/revocation"
	x509ocsp "golang.org/x/crypto/ocsp"
)

type ocspTestEnv struct {
	tmpDir            string
	db                *database.Database
	caCert            *x509.Certificate
	caKey             *rsa.PrivateKey
	responderCert     *x509.Certificate
	responderCertPath string
	responder         *internalocsp.OCSPResponder
	ts                *httptest.Server
	cleanup           func()
}

func setupOCSPTestEnv(t *testing.T) *ocspTestEnv {
	tmpDir, err := os.MkdirTemp("", "ocsp-test-*")
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

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	caPath := filepath.Join(tmpDir, "ca.cert.pem")
	if err := os.WriteFile(caPath, caCertPEM, 0644); err != nil {
		t.Fatal(err)
	}

	responderKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	responderTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "OCSP Responder"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}

	responderCertDER, err := x509.CreateCertificate(rand.Reader, responderTemplate, caCert, &responderKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	responderCert, err := x509.ParseCertificate(responderCertDER)
	if err != nil {
		t.Fatal(err)
	}

	responderCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: responderCertDER})
	responderCertPath := filepath.Join(tmpDir, "responder.cert.pem")
	if err := os.WriteFile(responderCertPath, responderCertPEM, 0644); err != nil {
		t.Fatal(err)
	}

	responderKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(responderKey)})
	responderKeyPath := filepath.Join(tmpDir, "responder.key.pem")
	if err := os.WriteFile(responderKeyPath, responderKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	responder, err := internalocsp.NewOCSPResponder(db, responderCertPath, responderKeyPath, caPath, 5, "127.0.0.1", 8081)
	if err != nil {
		t.Fatal(err)
	}

	handler := http.HandlerFunc(responder.HandleOCSPRequest)
	ts := httptest.NewServer(handler)

	cleanup := func() {
		ts.Close()
		db.Close()
		os.RemoveAll(tmpDir)
	}

	return &ocspTestEnv{
		tmpDir:            tmpDir,
		db:                db,
		caCert:            caCert,
		caKey:             caKey,
		responderCert:     responderCert,
		responderCertPath: responderCertPath,
		responder:         responder,
		ts:                ts,
		cleanup:           cleanup,
	}
}

func (env *ocspTestEnv) createTestCert(serial *big.Int, status string) *x509.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, env.caCert, &key.PublicKey, env.caKey)
	if err != nil {
		panic(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(err)
	}

	if err := env.db.InsertCertificate(cert, certPEM, status); err != nil {
		panic(err)
	}

	return cert
}

func (env *ocspTestEnv) createOCSPRequest(subjectCert *x509.Certificate, nonce bool) []byte {
	tmpFile, err := os.CreateTemp("", "ocsp-req-*.der")
	if err != nil {
		panic(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	issuerPath := filepath.Join(os.TempDir(), "issuer.pem")
	subjectPath := filepath.Join(os.TempDir(), "subject.pem")
	defer os.Remove(issuerPath)
	defer os.Remove(subjectPath)

	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: env.caCert.Raw})
	subjectPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subjectCert.Raw})

	if err := os.WriteFile(issuerPath, issuerPEM, 0644); err != nil {
		panic(err)
	}
	if err := os.WriteFile(subjectPath, subjectPEM, 0644); err != nil {
		panic(err)
	}

	cmd := exec.Command("openssl", "ocsp", "-issuer", issuerPath, "-cert", subjectPath, "-reqout", tmpFile.Name())
	if nonce {
		cmd.Args = append(cmd.Args, "-nonce")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		panic("ошибка создания OCSP запроса: " + err.Error() + "\n" + string(output))
	}

	reqData, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		panic(err)
	}

	return reqData
}

func (env *ocspTestEnv) sendOCSPRequest(reqData []byte) (*x509ocsp.Response, error) {
	resp, err := http.Post(env.ts.URL, "application/ocsp-request", bytes.NewReader(reqData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return x509ocsp.ParseResponse(respData, nil)
}

func TestOCSPSignerCert(t *testing.T) {
	env := setupOCSPTestEnv(t)
	defer env.cleanup()

	if env.responderCert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("сертификат OCSP-ответчика должен иметь KeyUsage digitalSignature")
	}

	hasOCSPSigning := false
	for _, eku := range env.responderCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			hasOCSPSigning = true
			break
		}
	}
	if !hasOCSPSigning {
		t.Error("сертификат OCSP-ответчика должен иметь ExtendedKeyUsage OCSPSigning")
	}

	if env.responderCert.IsCA {
		t.Error("сертификат OCSP-ответчика не должен быть CA")
	}
}

func TestOCSPGoodCertificate(t *testing.T) {
	env := setupOCSPTestEnv(t)
	defer env.cleanup()

	cert := env.createTestCert(big.NewInt(100), "valid")
	reqData := env.createOCSPRequest(cert, false)

	ocspResp, err := env.sendOCSPRequest(reqData)
	if err != nil {
		t.Fatal(err)
	}

	if ocspResp.Status != x509ocsp.Good {
		t.Errorf("ожидался статус good, получен %d", ocspResp.Status)
	}
}

func TestOCSPRevokedCertificate(t *testing.T) {
	env := setupOCSPTestEnv(t)
	defer env.cleanup()

	cert := env.createTestCert(big.NewInt(200), "revoked")
	reqData := env.createOCSPRequest(cert, false)

	ocspResp, err := env.sendOCSPRequest(reqData)
	if err != nil {
		t.Fatal(err)
	}

	if ocspResp.Status != x509ocsp.Revoked {
		t.Errorf("ожидался статус revoked, получен %d", ocspResp.Status)
	}
}

func TestOCSPUnknownCertificate(t *testing.T) {
	env := setupOCSPTestEnv(t)
	defer env.cleanup()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "unknown.example.com"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, env.caCert, &key.PublicKey, env.caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	reqData := env.createOCSPRequest(cert, false)

	ocspResp, err := env.sendOCSPRequest(reqData)
	if err != nil {
		t.Fatal(err)
	}

	if ocspResp.Status != x509ocsp.Unknown {
		t.Errorf("ожидался статус unknown, получен %d", ocspResp.Status)
	}
}

func TestOCSPNonce(t *testing.T) {
	env := setupOCSPTestEnv(t)
	defer env.cleanup()

	cert := env.createTestCert(big.NewInt(300), "valid")
	reqData := env.createOCSPRequest(cert, true)

	// Отправляем запрос с nonce и проверяем, что получаем good статус
	ocspResp, err := env.sendOCSPRequest(reqData)
	if err != nil {
		t.Fatal(err)
	}

	if ocspResp.Status != x509ocsp.Good {
		t.Errorf("ожидался статус good, получен %d", ocspResp.Status)
	}

	t.Log("OCSP request with nonce processed successfully")
}

func TestOCSPMalformedRequest(t *testing.T) {
	env := setupOCSPTestEnv(t)
	defer env.cleanup()

	tests := []struct {
		name        string
		body        []byte
		contentType string
		expectCode  int
	}{
		{"empty body", []byte{}, "application/ocsp-request", http.StatusOK},
		{"garbage data", []byte("garbage data"), "application/ocsp-request", http.StatusOK},
		{"wrong content type", []byte{0x30, 0x03, 0x0a, 0x01, 0x00}, "text/plain", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Post(env.ts.URL, tt.contentType, bytes.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectCode {
				t.Errorf("ожидался статус %d, получен %d", tt.expectCode, resp.StatusCode)
			}
		})
	}
}

func TestOCSPUnauthorizedIssuer(t *testing.T) {
	env := setupOCSPTestEnv(t)
	defer env.cleanup()

	otherCAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherCATemplate := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "Other CA"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	otherCACertDER, err := x509.CreateCertificate(rand.Reader, otherCATemplate, otherCATemplate, &otherCAKey.PublicKey, otherCAKey)
	if err != nil {
		t.Fatal(err)
	}
	otherCACert, err := x509.ParseCertificate(otherCACertDER)
	if err != nil {
		t.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(777),
		Subject:      pkix.Name{CommonName: "other.example.com"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, otherCACert, &key.PublicKey, otherCAKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	issuerPath := filepath.Join(os.TempDir(), "issuer.pem")
	subjectPath := filepath.Join(os.TempDir(), "subject.pem")
	defer os.Remove(issuerPath)
	defer os.Remove(subjectPath)

	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherCACert.Raw})
	subjectPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	os.WriteFile(issuerPath, issuerPEM, 0644)
	os.WriteFile(subjectPath, subjectPEM, 0644)

	tmpFile, _ := os.CreateTemp("", "ocsp-req-*.der")
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	cmd := exec.Command("openssl", "ocsp", "-issuer", issuerPath, "-cert", subjectPath, "-reqout", tmpFile.Name())
	cmd.CombinedOutput()

	reqData, _ := os.ReadFile(tmpFile.Name())

	ocspResp, err := env.sendOCSPRequest(reqData)
	if err == nil {
		if ocspResp.Status != x509ocsp.Unknown {
			t.Errorf("ожидался статус Unknown, получен %d", ocspResp.Status)
		}
	}
}

func TestOCSPResponderHTTP(t *testing.T) {
	env := setupOCSPTestEnv(t)
	defer env.cleanup()

	resp, err := http.Get(env.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("ожидался статус 405, получен %d", resp.StatusCode)
	}
}

func TestFullPKIWithOCSP(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-ocsp-full-*")
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

	rootPassFile := filepath.Join(tmpDir, "root.pass")
	os.WriteFile(rootPassFile, []byte("rootpass123\n"), 0600)

	rootCA, err := ca.NewRootCA("/CN=Test Root CA", "rsa", 4096, rootPassFile, tmpDir, 365, false, db)
	if err != nil {
		t.Fatal(err)
	}
	if err := rootCA.Initialize(); err != nil {
		t.Fatal(err)
	}

	interPassFile := filepath.Join(tmpDir, "inter.pass")
	os.WriteFile(interPassFile, []byte("interpass123\n"), 0600)

	rootKey, _ := cryptoutil.LoadEncryptedPrivateKey(filepath.Join(tmpDir, "private", "ca.key.pem"), []byte("rootpass123"))
	rootCertPEM, _ := os.ReadFile(filepath.Join(tmpDir, "certs", "ca.cert.pem"))
	block, _ := pem.Decode(rootCertPEM)
	rootCert, _ := x509.ParseCertificate(block.Bytes)

	interKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	cryptoutil.SaveEncryptedRSAPEM(filepath.Join(tmpDir, "private", "intermediate.key.pem"), interKey, []byte("interpass123"))

	csrPEM, _ := csr.GenerateIntermediateCSR("/CN=Test Intermediate CA", &interKey.PublicKey, interKey, 0)
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
		MaxPathLenZero:        true,
		SubjectKeyId:          ski,
		AuthorityKeyId:        rootCert.SubjectKeyId,
	}

	interCertDER, _ := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	interCert, _ := x509.ParseCertificate(interCertDER)
	interCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interCertDER})
	os.WriteFile(filepath.Join(tmpDir, "certs", "intermediate.cert.pem"), interCertPEM, 0644)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafSerial := big.NewInt(12345)
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "test.local"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.local"},
	}
	leafCertDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	leafCert, _ := x509.ParseCertificate(leafCertDER)
	leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertDER})
	db.InsertCertificate(leafCert, leafCertPEM, "valid")

	ocspDir := filepath.Join(tmpDir, "ocsp")
	os.MkdirAll(ocspDir, 0755)

	ocspKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ocspTemplate, _ := certs.GenerateOCSPResponderTemplate("CN=OCSP Responder", &ocspKey.PublicKey, 365, []string{"localhost"})
	ocspTemplate.Issuer = interCert.Subject
	ocspTemplate.AuthorityKeyId = interCert.SubjectKeyId

	ocspCertDER, _ := x509.CreateCertificate(rand.Reader, ocspTemplate, interCert, &ocspKey.PublicKey, interKey)
	ocspCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ocspCertDER})
	os.WriteFile(filepath.Join(ocspDir, "ocsp.cert.pem"), ocspCertPEM, 0644)

	ocspKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ocspKey)})
	os.WriteFile(filepath.Join(ocspDir, "ocsp.key.pem"), ocspKeyPEM, 0600)

	responder, err := internalocsp.NewOCSPResponder(
		db,
		filepath.Join(ocspDir, "ocsp.cert.pem"),
		filepath.Join(ocspDir, "ocsp.key.pem"),
		filepath.Join(tmpDir, "certs", "intermediate.cert.pem"),
		2,
		"127.0.0.1",
		18081,
	)
	if err != nil {
		t.Fatal(err)
	}

	handler := http.HandlerFunc(responder.HandleOCSPRequest)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	env := &ocspTestEnv{caCert: interCert, ts: ts}
	reqData := env.createOCSPRequest(leafCert, false)

	resp, _ := http.Post(ts.URL, "application/ocsp-request", bytes.NewReader(reqData))
	respData, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	ocspResp, _ := x509ocsp.ParseResponse(respData, nil)
	if ocspResp.Status != x509ocsp.Good {
		t.Errorf("ожидался статус Good, получен %d", ocspResp.Status)
	}

	serialHex := hex.EncodeToString(leafSerial.Bytes())
	revocation.RevokeCertificate(db, serialHex, 1, true)

	time.Sleep(3 * time.Second)

	resp2, _ := http.Post(ts.URL, "application/ocsp-request", bytes.NewReader(reqData))
	respData2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	ocspResp2, _ := x509ocsp.ParseResponse(respData2, nil)
	if ocspResp2.Status != x509ocsp.Revoked {
		t.Errorf("ожидался статус Revoked, получен %d", ocspResp2.Status)
	}
}