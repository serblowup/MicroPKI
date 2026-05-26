package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"MicroPKI/internal/crl"
	"MicroPKI/internal/database"
	internalocsp "MicroPKI/internal/ocsp"
	"MicroPKI/internal/revocation"
)

func setupRevocationTest(t *testing.T) (*database.Database, *x509.Certificate, *rsa.PrivateKey, func()) {
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

	// Создаем CA
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}

	return db, caCert, caKey, cleanup
}

func createLeafCert(t *testing.T, db *database.Database, caCert *x509.Certificate, caKey *rsa.PrivateKey, serial int64, status string) (*x509.Certificate, string) {
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafSerial := big.NewInt(serial)
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "test.example.com"},
		Issuer:       caCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	db.InsertCertificate(leafCert, leafPEM, status)

	serialHex := strings.ToLower(hex.EncodeToString(leafSerial.Bytes()))
	return leafCert, serialHex
}

func TestCRLChecker(t *testing.T) {
	db, caCert, caKey, cleanup := setupRevocationTest(t)
	defer cleanup()

	_, serialHex := createLeafCert(t, db, caCert, caKey, 12345, "valid")

	revocation.RevokeCertificate(db, serialHex, 1, true)

	revokedRecords, _ := db.GetRevokedCertificatesByIssuer(caCert.Subject.String())

	revokedCerts := make([]crl.RevokedCertInfo, 0)
	for _, r := range revokedRecords {
		serialBytes, _ := hex.DecodeString(r.SerialHex)
		serial := new(big.Int).SetBytes(serialBytes)

		revocationTime := time.Now()
		if r.RevocationDate.Valid {
			revocationTime = r.RevocationDate.Time
		}

		reasonCode := 0
		if r.RevocationReason.Valid {
			reasonCode, _ = revocation.ReasonCodeToInt(r.RevocationReason.String)
		}

		revokedCerts = append(revokedCerts, crl.RevokedCertInfo{
			SerialNumber:   serial,
			RevocationTime: revocationTime,
			ReasonCode:     reasonCode,
		})
	}

	crlPEM, err := crl.GenerateCRL(caCert, caKey, revokedCerts, 1, 7)
	if err != nil {
		t.Fatalf("ошибка генерации CRL: %v", err)
	}

	if len(crlPEM) == 0 {
		t.Error("CRL не сгенерирован")
	}

	t.Logf("CRL успешно сгенерирован, размер: %d байт", len(crlPEM))
}

func TestRevocationFallbackLogic(t *testing.T) {
	db, caCert, caKey, cleanup := setupRevocationTest(t)
	defer cleanup()

	leafCert, serialHex := createLeafCert(t, db, caCert, caKey, 67890, "valid")

	isRevoked, info, err := revocation.CheckRevoked(db, serialHex)
	if err != nil {
		t.Fatal(err)
	}
	if isRevoked {
		t.Error("сертификат не должен быть отозван")
	}
	t.Logf("статус до отзыва: revoked=%v", isRevoked)

	err = revocation.RevokeCertificate(db, serialHex, 1, true)
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
	if info.ReasonCode != 1 {
		t.Errorf("ожидался код причины 1, получен %d", info.ReasonCode)
	}
	t.Logf("статус после отзыва: revoked=%v, reason=%s", isRevoked, info.ReasonString)

	_ = leafCert
}

func TestRevocationReasonCodes(t *testing.T) {
	tests := []struct {
		reason   string
		expected int
	}{
		{"unspecified", 0},
		{"keyCompromise", 1},
		{"cACompromise", 2},
		{"affiliationChanged", 3},
		{"superseded", 4},
		{"cessationOfOperation", 5},
		{"certificateHold", 6},
		{"removeFromCRL", 8},
		{"privilegeWithdrawn", 9},
		{"aACompromise", 10},
	}

	for _, tt := range tests {
		code, err := revocation.ReasonCodeToInt(tt.reason)
		if err != nil {
			t.Errorf("ошибка для %s: %v", tt.reason, err)
		}
		if code != tt.expected {
			t.Errorf("для %s ожидался код %d, получен %d", tt.reason, tt.expected, code)
		}

		str := revocation.ReasonCodeToString(code)
		if str != tt.reason {
			t.Logf("обратное преобразование: %d -> %s", code, str)
		}
	}
}

func TestMultipleRevocations(t *testing.T) {
	db, caCert, caKey, cleanup := setupRevocationTest(t)
	defer cleanup()

	serials := []int64{1001, 1002, 1003}
	serialHexes := make([]string, 0, len(serials))

	for i, serial := range serials {
		_, serialHex := createLeafCert(t, db, caCert, caKey, serial, "valid")
		serialHexes = append(serialHexes, serialHex)

		reason := i + 1
		err := revocation.RevokeCertificate(db, serialHex, reason, true)
		if err != nil {
			t.Errorf("ошибка отзыва %d: %v", serial, err)
		}
	}

	for _, serialHex := range serialHexes {
		isRevoked, _, err := revocation.CheckRevoked(db, serialHex)
		if err != nil {
			t.Errorf("ошибка проверки %s: %v", serialHex, err)
		}
		if !isRevoked {
			t.Errorf("сертификат %s должен быть отозван", serialHex)
		}
	}

	revoked, err := db.GetRevokedCertificates()
	if err != nil {
		t.Fatal(err)
	}

	if len(revoked) != 3 {
		t.Errorf("ожидалось 3 отозванных, получено %d", len(revoked))
	}

	t.Logf("отозвано %d сертификатов", len(revoked))
}

func TestCRLNumberIncrement(t *testing.T) {
	db, caCert, caKey, cleanup := setupRevocationTest(t)
	defer cleanup()

	crlPEM1, _ := crl.GenerateCRL(caCert, caKey, []crl.RevokedCertInfo{}, 1, 7)
	block1, _ := pem.Decode(crlPEM1)
	crl1, _ := x509.ParseRevocationList(block1.Bytes)

	if crl1.Number.Int64() != 1 {
		t.Errorf("ожидался номер 1, получен %d", crl1.Number.Int64())
	}

	crlPEM2, _ := crl.GenerateCRL(caCert, caKey, []crl.RevokedCertInfo{}, 2, 7)
	block2, _ := pem.Decode(crlPEM2)
	crl2, _ := x509.ParseRevocationList(block2.Bytes)

	if crl2.Number.Int64() != 2 {
		t.Errorf("ожидался номер 2, получен %d", crl2.Number.Int64())
	}

	t.Logf("CRL номера корректно инкрементируются: %d -> %d", crl1.Number.Int64(), crl2.Number.Int64())

	_ = db
}

func TestCheckStatusWithOCSP(t *testing.T) {
	tmpDir := t.TempDir()
	db, caCert, caKey, cleanup := setupRevocationTest(t)
	defer cleanup()

	leafCert, serialHex := createLeafCert(t, db, caCert, caKey, 99999, "valid")

	ocspDir := filepath.Join(tmpDir, "ocsp")
	os.MkdirAll(ocspDir, 0755)

	ocspKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ocspTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "OCSP Responder"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	ocspDER, _ := x509.CreateCertificate(rand.Reader, ocspTemplate, caCert, &ocspKey.PublicKey, caKey)
	ocspPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ocspDER})
	ocspKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ocspKey)})

	ocspCertPath := filepath.Join(ocspDir, "ocsp.cert.pem")
	ocspKeyPath := filepath.Join(ocspDir, "ocsp.key.pem")
	os.WriteFile(ocspCertPath, ocspPEM, 0644)
	os.WriteFile(ocspKeyPath, ocspKeyPEM, 0600)

	caCertPath := filepath.Join(tmpDir, "ca.cert.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	os.WriteFile(caCertPath, caPEM, 0644)

	ocspResponder, err := internalocsp.NewOCSPResponder(
		db, ocspCertPath, ocspKeyPath, caCertPath, 60, "127.0.0.1", 0,
	)
	if err != nil {
		t.Fatalf("failed to create OCSP responder: %v", err)
	}

	handler := httptest.NewServer(http.HandlerFunc(ocspResponder.HandleOCSPRequest))
	ts := handler
	defer ts.Close()

	checker := revocation.NewRevocationChecker()
	opts := &revocation.RevocationCheckOptions{
		Cert:          leafCert,
		Issuer:        caCert,
		OCSPURL:       ts.URL,
		PreferOCSP:    true,
		FallbackToCRL: false,
	}

	result, err := checker.CheckStatus(opts)
	if err != nil {
		t.Logf("CheckStatus error: %v", err)
	}
	if result != nil {
		t.Logf("CheckStatus result: method=%s, status=%s", result.Method, result.Status)
	}

	_ = serialHex
}

func TestCheckStatusWithFallbackComplete(t *testing.T) {
    tmpDir, err := os.MkdirTemp("", "check-status-fallback-*")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(tmpDir)

    db, caCert, caKey, cleanup := setupRevocationTest(t)
    defer cleanup()

    // Создаём сертификат
    leafCert, serialHex := createLeafCert(t, db, caCert, caKey, 77777, "valid")

    checker := revocation.NewRevocationChecker()

    // Тест 1: PreferOCSP=true, недоступный OCSP, без fallback
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
            t.Logf("OCSP unavailable error: %v", err)
        }
        t.Logf("result: status=%s, method=%s", result.Status, result.Method)
    })

    // Тест 2: PreferOCSP=false, без CRL
    t.Run("no_OCSP_no_CRL", func(t *testing.T) {
        opts := &revocation.RevocationCheckOptions{
            Cert:          leafCert,
            Issuer:        caCert,
            PreferOCSP:    false,
            FallbackToCRL: false,
        }
        result, err := checker.CheckStatus(opts)
        if err != nil {
            t.Logf("no method error: %v", err)
        }
        t.Logf("result: status=%s", result.Status)
    })

    // Тест 3: С отзывом
    t.Run("revoked_certificate", func(t *testing.T) {
        err := revocation.RevokeCertificate(db, serialHex, 1, true)
        if err != nil {
            t.Fatalf("revoke error: %v", err)
        }

        opts := &revocation.RevocationCheckOptions{
            Cert:          leafCert,
            Issuer:        caCert,
            PreferOCSP:    false,
            FallbackToCRL: false,
        }
        result, err := checker.CheckStatus(opts)
        if err != nil {
            t.Logf("check revoked error: %v", err)
        }
        t.Logf("revoked result: status=%s", result.Status)
    })

    _ = serialHex
}

func TestCRLCheckerCoverage(t *testing.T) {
    db, caCert, caKey, cleanup := setupRevocationTest(t)
    defer cleanup()

    // Создаём сертификат
    leafCert, serialHex := createLeafCert(t, db, caCert, caKey, 77777, "valid")

    // Отзываем
    err := revocation.RevokeCertificate(db, serialHex, 1, true)
    if err != nil {
        t.Fatal(err)
    }

    // Получаем отозванные сертификаты
    revokedRecords, err := db.GetRevokedCertificatesByIssuer(caCert.Subject.String())
    if err != nil {
        t.Fatal(err)
    }

    // Генерируем CRL
    revokedCerts := make([]crl.RevokedCertInfo, 0)
    for _, r := range revokedRecords {
        serialBytes, _ := hex.DecodeString(r.SerialHex)
        serial := new(big.Int).SetBytes(serialBytes)
        revokedCerts = append(revokedCerts, crl.RevokedCertInfo{
            SerialNumber:   serial,
            RevocationTime: time.Now(),
            ReasonCode:     1,
        })
    }

    crlPEM, err := crl.GenerateCRL(caCert, caKey, revokedCerts, 1, 7)
    if err != nil {
        t.Fatal(err)
    }

    crlPath := filepath.Join(t.TempDir(), "test.crl.pem")
    err = os.WriteFile(crlPath, crlPEM, 0644)
    if err != nil {
        t.Fatal(err)
    }

    checker := revocation.NewCRLChecker()
    
    // Тест с валидным CRL
    result, err := checker.CheckCertificate(leafCert, caCert, crlPath)
    if err != nil {
        t.Logf("CRL check error: %v", err)
    }
    if result != nil {
        t.Logf("CRL result: status=%s", result.Status)
    }

    // Тест с несуществующим CRL
    _, err = checker.CheckCertificate(leafCert, caCert, "/nonexistent/path.crl")
    if err != nil {
        t.Logf("nonexistent CRL error: %v", err)
    }

    // Тест с неверным URL
    _, err = checker.CheckCertificate(leafCert, caCert, "http://localhost:9999/nonexistent.crl")
    if err != nil {
        t.Logf("invalid URL error: %v", err)
    }

    // Тест с валидным URL (опционально)
    mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write(crlPEM)
    }))
    defer mockServer.Close()

    result2, err := checker.CheckCertificate(leafCert, caCert, mockServer.URL)
    if err != nil {
        t.Logf("HTTP CRL error: %v", err)
    }
    if result2 != nil {
        t.Logf("HTTP CRL result: status=%s", result2.Status)
    }

    t.Log("CRLChecker coverage test completed")
}

func TestCheckStatusFinal(t *testing.T) {
    db, caCert, caKey, cleanup := setupRevocationTest(t)
    defer cleanup()

    leafCert, serialHex := createLeafCert(t, db, caCert, caKey, 99999, "valid")

    checker := revocation.NewRevocationChecker()

    // OCSP недоступен, без fallback
    opts1 := &revocation.RevocationCheckOptions{
        Cert:          leafCert,
        Issuer:        caCert,
        OCSPURL:       "http://localhost:9999/ocsp",
        PreferOCSP:    true,
        FallbackToCRL: false,
    }
    result1, _ := checker.CheckStatus(opts1)
    t.Logf("result1: status=%s", result1.Status)

    // Отзываем и проверяем через CRL
    revocation.RevokeCertificate(db, serialHex, 1, true)

    opts2 := &revocation.RevocationCheckOptions{
        Cert:          leafCert,
        Issuer:        caCert,
        PreferOCSP:    false,
        FallbackToCRL: true,
    }
    result2, _ := checker.CheckStatus(opts2)
    t.Logf("result2: status=%s", result2.Status)
}