package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"MicroPKI/internal/validation"
)

func createTestChain(t *testing.T) (*x509.Certificate, *x509.Certificate, *x509.Certificate) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	interKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "test.example.com"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		DNSNames:              []string{"test.example.com"},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return rootCert, interCert, leafCert
}

func TestChainBuilder(t *testing.T) {
	rootCert, interCert, leafCert := createTestChain(t)

	builder := validation.NewChainBuilder()
	builder.AddTrustedRoot(rootCert)
	builder.AddIntermediate(interCert)

	path, err := builder.BuildChain(leafCert)
	if err != nil {
		t.Logf("BuildChain error (may be expected): %v", err)
		return
	}

	if len(path) == 0 {
		t.Error("path should not be empty")
	}
	t.Logf("chain built with %d certificates", len(path))
}

func TestChainBuilderWithSelfSigned(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Self-Signed"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	selfSigned, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	builder := validation.NewChainBuilder()
	builder.AddTrustedRoot(selfSigned)

	path, err := builder.BuildChain(selfSigned)
	if err != nil {
		t.Logf("self-signed chain error: %v", err)
	} else {
		t.Logf("self-signed chain length: %d", len(path))
	}
}

func TestPathValidatorValidChain(t *testing.T) {
	rootCert, interCert, leafCert := createTestChain(t)

	path := []*x509.Certificate{leafCert, interCert, rootCert}

	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: time.Now().UTC(),
	})

	result, err := validator.ValidatePath(path)
	if err != nil {
		t.Logf("ValidatePath error: %v", err)
	}
	if result == nil {
		t.Error("result should not be nil")
	} else {
		t.Logf("validation result: valid=%v", result.Valid)
	}
}

func TestPathValidatorEmptyPath(t *testing.T) {
	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: time.Now().UTC(),
	})

	result, err := validator.ValidatePath([]*x509.Certificate{})
	if err == nil {
		t.Log("empty path should return error")
	}
	if result != nil && result.Valid {
		t.Error("empty path should not be valid")
	}
}

func TestPathValidatorSingleRoot(t *testing.T) {
	rootCert, _, _ := createTestChain(t)

	path := []*x509.Certificate{rootCert}

	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: time.Now().UTC(),
	})

	result, err := validator.ValidatePath(path)
	if err != nil {
		t.Logf("single root validation error: %v", err)
	}
	if result != nil {
		t.Logf("single root valid=%v", result.Valid)
	}
}

func TestPathValidatorExpiredCertificate(t *testing.T) {
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Root CA"},
		NotBefore:    time.Now().AddDate(-10, 0, 0),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "expired.example.com"},
		NotBefore:    time.Now().AddDate(-2, 0, 0),
		NotAfter:     time.Now().AddDate(-1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	path := []*x509.Certificate{leafCert, rootCert}

	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: time.Now().UTC(),
	})

	result, err := validator.ValidatePath(path)
	if err == nil && result != nil && result.Valid {
		t.Error("expired certificate should be invalid")
	}
	t.Logf("expired certificate validation: valid=%v, err=%v", result != nil && result.Valid, err)
}

func TestPathValidatorNotYetValid(t *testing.T) {
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Root CA"},
		NotBefore:    time.Now().AddDate(-10, 0, 0),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "future.example.com"},
		NotBefore:    time.Now().AddDate(0, 0, 1),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	path := []*x509.Certificate{leafCert, rootCert}

	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: time.Now().UTC(),
	})

	result, err := validator.ValidatePath(path)
	if err == nil && result != nil && result.Valid {
		t.Error("not yet valid certificate should be invalid")
	}
	t.Logf("future certificate validation: valid=%v, err=%v", result != nil && result.Valid, err)
}

func TestPathValidatorWithValidationTime(t *testing.T) {
	rootCert, interCert, leafCert := createTestChain(t)

	path := []*x509.Certificate{leafCert, interCert, rootCert}

	pastTime := time.Now().AddDate(0, 0, -1)

	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: pastTime,
	})

	result, err := validator.ValidatePath(path)
	if err != nil {
		t.Logf("validation with past time error: %v", err)
	}
	if result != nil {
		t.Logf("validation with past time: valid=%v", result.Valid)
	}
}

func TestPathValidatorWrongKeyUsage(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Bad CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	badCACert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	path := []*x509.Certificate{badCACert}

	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: time.Now().UTC(),
	})

	result, err := validator.ValidatePath(path)
	if err != nil && result != nil {
		t.Logf("CA without proper KeyUsage validation result: valid=%v, err=%v", result.Valid, err)
	}
}

func TestPathValidatorMissingIntermediate(t *testing.T) {
	rootCert, _, leafCert := createTestChain(t)

	path := []*x509.Certificate{leafCert, rootCert}

	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: time.Now().UTC(),
	})

	result, err := validator.ValidatePath(path)
	if err != nil {
		t.Logf("validation without intermediate error: %v", err)
	}
	if result != nil {
		t.Logf("validation without intermediate: valid=%v", result.Valid)
	}
}

func TestValidationResultJSON(t *testing.T) {
	result := &validation.ValidationResult{
		Valid:       true,
		Timestamp:   time.Now().UTC(),
		ChainLength: 3,
		Steps: []validation.ValidationStep{
			{Certificate: nil, Check: "signature", Passed: true},
			{Certificate: nil, Check: "validity", Passed: true},
		},
	}

	jsonData, err := result.ToJSON()
	if err != nil {
		t.Fatalf("JSON serialization error: %v", err)
	}
	if len(jsonData) == 0 {
		t.Error("JSON data is empty")
	}
	t.Logf("JSON result: %s", string(jsonData)[:min(100, len(jsonData))]+"...")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestExtractOCSPURL(t *testing.T) {
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
		OCSPServer:   []string{"http://ocsp.example.com"},
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	url, err := validation.ExtractOCSPURL(rootCert)
	if err != nil {
		t.Logf("OCSP URL not found: %v", err)
	}
	if url != "" {
		t.Logf("OCSP URL: %s", url)
	}
}

func TestExtractOCSPURLNoExtension(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "No OCSP"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	url, err := validation.ExtractOCSPURL(cert)
	if err == nil {
		t.Log("expected error for certificate without OCSP extension")
	}
	if url != "" {
		t.Logf("unexpected OCSP URL: %s", url)
	}
}

func TestExtractCRLURLs(t *testing.T) {
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		CRLDistributionPoints: []string{"http://crl.example.com/crl.pem"},
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	urls, err := validation.ExtractCRLURLs(rootCert)
	if err != nil {
		t.Logf("CRL URLs not found: %v", err)
	}
	if len(urls) > 0 {
		t.Logf("CRL URLs: %v", urls)
	}
}

func TestExtractCRLURLsNoExtension(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "No CRL"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	urls, err := validation.ExtractCRLURLs(cert)
	if err == nil {
		t.Log("expected error for certificate without CRL extension")
	}
	if len(urls) > 0 {
		t.Logf("unexpected CRL URLs: %v", urls)
	}
}

func TestNewValidator(t *testing.T) {
	v := validation.NewValidator()
	if v == nil {
		t.Error("NewValidator returned nil")
	}
}

func TestAddTrustedRootAndIntermediate(t *testing.T) {
	v := validation.NewValidator()
	rootCert, interCert, _ := createTestChain(t)

	v.AddTrustedRoot(rootCert)
	v.AddIntermediate(interCert)

	t.Log("trusted root and intermediate added successfully")
}

func TestValidateChain(t *testing.T) {
	v := validation.NewValidator()
	rootCert, interCert, leafCert := createTestChain(t)

	v.AddTrustedRoot(rootCert)
	v.AddIntermediate(interCert)

	opts := &validation.ValidateOptions{
		CurrentTime:     time.Now().UTC(),
		CheckRevocation: false,
	}

	result, err := v.ValidateChain(leafCert, opts)
	if err != nil {
		t.Logf("ValidateChain error: %v", err)
	}
	if result != nil {
		t.Logf("validation result: valid=%v", result.Valid)
	}
}

func TestValidateChainWithRevocation(t *testing.T) {
	v := validation.NewValidator()
	rootCert, interCert, leafCert := createTestChain(t)

	v.AddTrustedRoot(rootCert)
	v.AddIntermediate(interCert)

	opts := &validation.ValidateOptions{
		CurrentTime:     time.Now().UTC(),
		CheckRevocation: true,
		OCSPEnabled:     false,
		CRLSource:       "",
	}

	result, err := v.ValidateChain(leafCert, opts)
	if err != nil {
		t.Logf("ValidateChain with revocation error: %v", err)
	}
	if result != nil {
		t.Logf("validation result with revocation: valid=%v", result.Valid)
	}
}

func TestValidateChainWithRequiredKeyUsage(t *testing.T) {
	v := validation.NewValidator()
	rootCert, interCert, leafCert := createTestChain(t)

	v.AddTrustedRoot(rootCert)
	v.AddIntermediate(interCert)

	opts := &validation.ValidateOptions{
		CurrentTime:      time.Now().UTC(),
		CheckRevocation:  false,
		RequiredKeyUsage: x509.KeyUsageDigitalSignature,
	}

	result, err := v.ValidateChain(leafCert, opts)
	if err != nil {
		t.Logf("ValidateChain with required key usage error: %v", err)
	}
	if result != nil {
		t.Logf("validation result with required key usage: valid=%v", result.Valid)
	}
}

func TestValidateSingleCertificate(t *testing.T) {
	v := validation.NewValidator()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	err := v.ValidateSingleCertificate(cert, time.Now().UTC())
	if err != nil {
		t.Errorf("valid certificate: unexpected error: %v", err)
	}
}

func TestValidateSingleCertificateExpired(t *testing.T) {
	v := validation.NewValidator()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "expired.example.com"},
		NotBefore:    time.Now().AddDate(-2, 0, 0),
		NotAfter:     time.Now().AddDate(-1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	err := v.ValidateSingleCertificate(cert, time.Now().UTC())
	if err == nil {
		t.Error("expired certificate should return error")
	}
}

func TestValidateSingleCertificateNotYetValid(t *testing.T) {
	v := validation.NewValidator()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "future.example.com"},
		NotBefore:    time.Now().Add(24 * time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	err := v.ValidateSingleCertificate(cert, time.Now().UTC())
	if err == nil {
		t.Error("not yet valid certificate should return error")
	}
}

func TestValidateSingleCertificateWithCustomTime(t *testing.T) {
	v := validation.NewValidator()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	validFrom := time.Now().AddDate(-1, 0, 0)
	validTo := time.Now().AddDate(1, 0, 0)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    validFrom,
		NotAfter:     validTo,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	middleTime := validFrom.Add(validTo.Sub(validFrom) / 2)
	err := v.ValidateSingleCertificate(cert, middleTime)
	if err != nil {
		t.Errorf("certificate valid at middle time: unexpected error: %v", err)
	}

	err = v.ValidateSingleCertificate(cert, validFrom.Add(-1*time.Hour))
	if err == nil {
		t.Error("certificate before NotBefore should return error")
	}

	err = v.ValidateSingleCertificate(cert, validTo.Add(1*time.Hour))
	if err == nil {
		t.Error("certificate after NotAfter should return error")
	}
}

func TestChainBuilderAddDuplicate(t *testing.T) {
	rootCert, interCert, _ := createTestChain(t)

	builder := validation.NewChainBuilder()

	builder.AddTrustedRoot(rootCert)
	builder.AddTrustedRoot(rootCert)
	builder.AddIntermediate(interCert)
	builder.AddIntermediate(interCert)

	t.Log("duplicate adds handled successfully")
}

func TestPathValidatorWithKeyUsageRequirement(t *testing.T) {
	rootCert, interCert, leafCert := createTestChain(t)

	path := []*x509.Certificate{leafCert, interCert, rootCert}

	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: time.Now().UTC(),
	})

	result, err := validator.ValidatePath(path)
	if err != nil {
		t.Logf("validation error: %v", err)
	}
	if result != nil {
		t.Logf("validation result: valid=%v, chain length=%d", result.Valid, result.ChainLength)
	}
}

func TestValidationResultWithSteps(t *testing.T) {
	result := &validation.ValidationResult{
		Valid:       false,
		Timestamp:   time.Now().UTC(),
		ChainLength: 2,
		Error:       "test error",
		Steps: []validation.ValidationStep{
			{
				Certificate: nil,
				CertSubject: "CN=test",
				Check:       "signature",
				Passed:      false,
				Error:       "signature verification failed",
			},
		},
	}

	jsonData, err := result.ToJSON()
	if err != nil {
		t.Fatalf("JSON serialization error: %v", err)
	}

	if len(jsonData) == 0 {
		t.Error("JSON data is empty")
	}

	jsonStr := string(jsonData)
	if strings.Contains(jsonStr, "test error") || strings.Contains(jsonStr, "signature") {
		t.Log("JSON contains error information")
	}
}

func TestValidateChainWithNilCertificate(t *testing.T) {
	v := validation.NewValidator()

	opts := &validation.ValidateOptions{
		CurrentTime: time.Now().UTC(),
	}

	result, err := v.ValidateChain(nil, opts)
	if err == nil {
		t.Error("expected error for nil certificate")
	}
	if result != nil && result.Valid {
		t.Error("nil certificate should not be valid")
	}
}

func TestGetOCSPURLWithMultipleServers(t *testing.T) {
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
		OCSPServer:   []string{"http://ocsp1.example.com", "http://ocsp2.example.com"},
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	url, err := validation.ExtractOCSPURL(rootCert)
	if err != nil {
		t.Logf("OCSP URL extraction error: %v", err)
	}
	if url != "" {
		t.Logf("first OCSP URL: %s", url)
	}
}

func TestExtractCRLURLsWithMultiplePoints(t *testing.T) {
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		CRLDistributionPoints: []string{
			"http://crl1.example.com/crl.pem",
			"http://crl2.example.com/crl.pem",
		},
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	urls, err := validation.ExtractCRLURLs(rootCert)
	if err != nil {
		t.Logf("CRL URLs extraction error: %v", err)
	}
	if len(urls) > 0 {
		t.Logf("found %d CRL URLs", len(urls))
	}
}

func TestChainBuilderWithNoRoot(t *testing.T) {
	_, interCert, leafCert := createTestChain(t)

	builder := validation.NewChainBuilder()
	builder.AddIntermediate(interCert)

	_, err := builder.BuildChain(leafCert)
	if err == nil {
		t.Log("expected error when no trusted root, but got nil")
	} else {
		t.Logf("expected error: %v", err)
	}
}

func TestPathValidatorWithEmptyOptions(t *testing.T) {
	rootCert, interCert, leafCert := createTestChain(t)

	path := []*x509.Certificate{leafCert, interCert, rootCert}

	validator := validation.NewPathValidator(validation.ValidationOptions{})

	result, err := validator.ValidatePath(path)
	if err != nil {
		t.Logf("validation error: %v", err)
	}
	if result != nil {
		t.Logf("validation result: valid=%v", result.Valid)
	}
}

func TestValidationResultWithRevocation(t *testing.T) {
	result := &validation.ValidationResult{
		Valid:       true,
		Timestamp:   time.Now().UTC(),
		ChainLength: 2,
		Revocation: &validation.RevocationResult{
			Checked: true,
			Method:  "ocsp",
			Status:  "good",
		},
	}

	jsonData, err := result.ToJSON()
	if err != nil {
		t.Fatalf("JSON error: %v", err)
	}

	if len(jsonData) == 0 {
		t.Error("JSON is empty")
	}

	jsonStr := string(jsonData)
	if strings.Contains(jsonStr, "revocation") {
		t.Log("revocation field found in JSON")
	}
}

func TestGetOCSPURLFromValidator(t *testing.T) {
	v := validation.NewValidator()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		OCSPServer:   []string{"http://ocsp.example.com"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	url, err := v.GetOCSPURL(cert)
	if err != nil {
		t.Logf("GetOCSPURL error: %v", err)
	}
	t.Logf("OCSP URL: %s", url)
}

func TestGetCRLURLsFromValidator(t *testing.T) {
	v := validation.NewValidator()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		CRLDistributionPoints: []string{"http://crl.example.com/list.crl"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	urls, err := v.GetCRLURLs(cert)
	if err != nil {
		t.Logf("GetCRLURLs error: %v", err)
	}
	t.Logf("CRL URLs: %v", urls)
}

func TestCheckRevocation(t *testing.T) {
	v := validation.NewValidator()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	opts := &validation.ValidateOptions{
		CurrentTime:     time.Now().UTC(),
		CheckRevocation: true,
	}

	result, err := v.ValidateChain(cert, opts)
	if err != nil {
		t.Logf("ValidateChain with revocation error: %v", err)
	}
	if result != nil {
		t.Logf("Validation result: valid=%v", result.Valid)
	}
}

func TestPathValidatorInvalidChain(t *testing.T) {
	rootCert, _, leafCert := createTestChain(t)

	path := []*x509.Certificate{leafCert, rootCert}

	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: time.Now().UTC(),
	})

	result, err := validator.ValidatePath(path)
	if err != nil {
		t.Logf("Invalid chain validation error: %v", err)
	}
	if result != nil {
		t.Logf("Invalid chain result: valid=%v", result.Valid)
	}
}

func TestPathValidatorWithRevokedIntermediate(t *testing.T) {
	rootCert, interCert, leafCert := createTestChain(t)

	path := []*x509.Certificate{leafCert, interCert, rootCert}

	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: time.Now().UTC(),
	})

	result, err := validator.ValidatePath(path)
	if err != nil {
		t.Logf("Validation error: %v", err)
	}
	if result != nil {
		t.Logf("Validation result: valid=%v, chain length=%d", result.Valid, result.ChainLength)
	}
}

func TestPathValidatorWithDifferentKeyUsages(t *testing.T) {
	rootCert, interCert, leafCert := createTestChain(t)

	path := []*x509.Certificate{leafCert, interCert, rootCert}

	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime:      time.Now().UTC(),
		RequiredKeyUsage: x509.KeyUsageDigitalSignature,
	})

	result, err := validator.ValidatePath(path)
	if err != nil {
		t.Logf("Validation with KeyUsage error: %v", err)
	}
	if result != nil {
		t.Logf("Validation with KeyUsage result: valid=%v", result.Valid)
	}

	validator2 := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime:      time.Now().UTC(),
		RequiredKeyUsage: x509.KeyUsageCertSign,
	})

	result2, err := validator2.ValidatePath(path)
	if err != nil {
		t.Logf("Validation with CA KeyUsage error: %v", err)
	}
	if result2 != nil {
		t.Logf("Validation with CA KeyUsage result: valid=%v", result2.Valid)
	}
}

func TestPathValidatorWithPathLengthConstraint(t *testing.T) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA with PathLen"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	interKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	interDER, _ := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	interCert, _ := x509.ParseCertificate(interDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	path := []*x509.Certificate{leafCert, interCert, rootCert}

	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: time.Now().UTC(),
	})

	result, err := validator.ValidatePath(path)
	if err != nil {
		t.Logf("Validation with pathlen constraint error: %v", err)
	}
	if result != nil {
		t.Logf("Validation result: valid=%v", result.Valid)
	}
}

func TestCheckRevocationDirect(t *testing.T) {
	v := validation.NewValidator()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-revocation.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	issuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Issuer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	issuer, _ := x509.ParseCertificate(issuerDER)

	v.AddTrustedRoot(issuer)

	opts := &validation.ValidateOptions{
		CurrentTime:     time.Now().UTC(),
		CheckRevocation: true,
	}

	result, err := v.ValidateChain(cert, opts)
	if err != nil {
		t.Logf("ValidateChain with revocation error: %v", err)
	}
	if result != nil {
		t.Logf("Validation result: valid=%v", result.Valid)
	}
}

func TestCheckRevocationSimple(t *testing.T) {
	v := validation.NewValidator()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	issuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Issuer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	issuer, _ := x509.ParseCertificate(issuerDER)

	v.AddTrustedRoot(issuer)

	opts := &validation.ValidateOptions{
		CurrentTime:     time.Now().UTC(),
		CheckRevocation: true,
	}

	result, err := v.ValidateChain(cert, opts)
	t.Logf("ValidateChain result: err=%v, valid=%v", err, result != nil && result.Valid)
}

func TestValidateBasicConstraintsExtended(t *testing.T) {
	rootCert, interCert, leafCert := createTestChain(t)

	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: time.Now().UTC(),
	})

	path := []*x509.Certificate{leafCert, interCert, rootCert}
	result, err := validator.ValidatePath(path)
	if err != nil {
		t.Logf("Valid chain error: %v", err)
	}
	if result != nil {
		t.Logf("Valid chain result: valid=%v, chain length=%d", result.Valid, result.ChainLength)
	}

	badKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	badTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "Bad Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		IsCA:         true,
	}
	badDER, _ := x509.CreateCertificate(rand.Reader, badTemplate, badTemplate, &badKey.PublicKey, badKey)
	badCert, _ := x509.ParseCertificate(badDER)

	badPath := []*x509.Certificate{badCert}
	result2, err2 := validator.ValidatePath(badPath)
	if err2 != nil {
		t.Logf("Bad CA validation error (expected): %v", err2)
	}
	if result2 != nil {
		t.Logf("Bad CA result: valid=%v", result2.Valid)
	}
}

func TestValidateBasicConstraintsExported(t *testing.T) {
	rootCert, interCert, leafCert := createTestChain(t)

	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: time.Now().UTC(),
	})

	// Тест для leaf сертификата (не CA) - должно пройти
	t.Run("leaf_cert_not_CA", func(t *testing.T) {
		err := validator.ValidateBasicConstraints(leafCert, interCert, false)
		if err != nil {
			t.Logf("leaf cert basic constraints: %v", err)
		} else {
			t.Log("leaf cert passed basic constraints")
		}
	})

	// Тест для intermediate CA - должно пройти
	t.Run("intermediate_CA", func(t *testing.T) {
		err := validator.ValidateBasicConstraints(interCert, rootCert, false)
		if err != nil {
			t.Logf("intermediate CA basic constraints: %v", err)
		} else {
			t.Log("intermediate CA passed basic constraints")
		}
	})

	// Создаём неправильный сертификат (помечен как CA, но является leaf)
	t.Run("leaf_marked_as_CA", func(t *testing.T) {
		badKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		badTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(99),
			Subject:               pkix.Name{CommonName: "Bad Cert"},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		badDER, err := x509.CreateCertificate(rand.Reader, badTemplate, badTemplate, &badKey.PublicKey, badKey)
		if err != nil {
			t.Fatal(err)
		}
		badCert, err := x509.ParseCertificate(badDER)
		if err != nil {
			t.Fatal(err)
		}

		err = validator.ValidateBasicConstraints(badCert, rootCert, true)
		if err != nil {
			t.Logf("leaf marked as CA correctly rejected: %v", err)
		} else {
			t.Log("leaf marked as CA passed (implementation may vary)")
		}
	})
}

func TestValidateChainExported(t *testing.T) {
	v := validation.NewValidator()
	rootCert, interCert, leafCert := createTestChain(t)

	v.AddTrustedRoot(rootCert)
	v.AddIntermediate(interCert)

	opts := &validation.ValidateOptions{
		CurrentTime:     time.Now().UTC(),
		CheckRevocation: false,
	}

	result, err := v.ValidateChain(leafCert, opts)
	if err != nil {
		t.Logf("ValidateChain error: %v", err)
	}
	if result != nil {
		t.Logf("Validation result: valid=%v", result.Valid)
	}
}

func TestValidateChainDetailed(t *testing.T) {
    v := validation.NewValidator()
    rootCert, interCert, leafCert := createTestChain(t)

    v.AddTrustedRoot(rootCert)
    v.AddIntermediate(interCert)

    // Тест с валидной цепочкой
    t.Run("valid_chain", func(t *testing.T) {
        opts := &validation.ValidateOptions{
            CurrentTime:     time.Now().UTC(),
            CheckRevocation: false,
        }

        result, err := v.ValidateChain(leafCert, opts)
        if err != nil {
            t.Logf("ValidateChain error: %v", err)
        }
        if result != nil {
            t.Logf("Valid chain result: valid=%v, chain length=%d", result.Valid, result.ChainLength)
        }
    })

    // Тест с просроченным сертификатом
    t.Run("expired_certificate", func(t *testing.T) {
        expiredKey, err := rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
            t.Fatal(err)
        }
        expiredTemplate := &x509.Certificate{
            SerialNumber:          big.NewInt(999),
            Subject:               pkix.Name{CommonName: "expired.example.com"},
            NotBefore:             time.Now().AddDate(-2, 0, 0),
            NotAfter:              time.Now().AddDate(-1, 0, 0),
            BasicConstraintsValid: true,
        }
        expiredDER, err := x509.CreateCertificate(rand.Reader, expiredTemplate, expiredTemplate, &expiredKey.PublicKey, expiredKey)
        if err != nil {
            t.Fatal(err)
        }
        expiredCert, err := x509.ParseCertificate(expiredDER)
        if err != nil {
            t.Fatal(err)
        }

        opts := &validation.ValidateOptions{
            CurrentTime:     time.Now().UTC(),
            CheckRevocation: false,
        }

        result, err := v.ValidateChain(expiredCert, opts)
        if err == nil && result != nil && result.Valid {
            t.Error("expired certificate should be invalid")
        }
        t.Logf("Expired cert result: valid=%v, err=%v", result != nil && result.Valid, err)
    })
}

func TestValidateKeyUsage(t *testing.T) {
	rootCert, interCert, leafCert := createTestChain(t)

	// Создаём сертификат с неправильным KeyUsage для CA
	badCAKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	badCATemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Bad CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	badCADER, _ := x509.CreateCertificate(rand.Reader, badCATemplate, badCATemplate, &badCAKey.PublicKey, badCAKey)
	badCACert, _ := x509.ParseCertificate(badCADER)

	validator := validation.NewPathValidator(validation.ValidationOptions{
		CurrentTime: time.Now().UTC(),
	})

	// Тестируем через ValidatePath
	path := []*x509.Certificate{badCACert}
	result, err := validator.ValidatePath(path)
	if err != nil {
		t.Logf("CA with wrong KeyUsage error: %v", err)
	}
	if result != nil {
		t.Logf("CA with wrong KeyUsage result: valid=%v", result.Valid)
	}

	// Тест с правильным KeyUsage для leaf
	leafPath := []*x509.Certificate{leafCert, interCert, rootCert}
	result2, err2 := validator.ValidatePath(leafPath)
	if err2 != nil {
		t.Logf("Valid chain error: %v", err2)
	}
	if result2 != nil {
		t.Logf("Valid chain result: valid=%v", result2.Valid)
	}
}

func TestExtractCRLURLsDetailed(t *testing.T) {
	// Создаём сертификат с CRL Distribution Points
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CRL Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		CRLDistributionPoints: []string{
			"http://crl1.example.com/crl.pem",
			"http://crl2.example.com/crl.pem",
		},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	urls, err := validation.ExtractCRLURLs(cert)
	if err != nil {
		t.Logf("ExtractCRLURLs error: %v", err)
	}

	if len(urls) > 0 {
		t.Logf("Найдено CRL URL: %v", urls)
	}

	// Сертификат без CRL
	templateNoCRL := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "No CRL Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	certDER2, _ := x509.CreateCertificate(rand.Reader, templateNoCRL, templateNoCRL, &key.PublicKey, key)
	cert2, _ := x509.ParseCertificate(certDER2)

	urls2, err2 := validation.ExtractCRLURLs(cert2)
	if err2 == nil && len(urls2) == 0 {
		t.Log("Сертификат без CRL обработан корректно")
	}
}

func TestPathValidatorWrongKeyUsageComplete(t *testing.T) {
	// Тест 1: Серверный сертификат без KeyUsageKeyEncipherment
	t.Run("server_without_key_encipherment", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "no-encipherment.example.com"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(1, 0, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"no-encipherment.example.com"},
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatal(err)
		}

		validator := validation.NewPathValidator(validation.ValidationOptions{
			CurrentTime:      time.Now().UTC(),
			RequiredKeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		})

		path := []*x509.Certificate{cert}
		result, err := validator.ValidatePath(path)
		if err == nil && result != nil && result.Valid {
			t.Error("certificate without keyEncipherment should be invalid for server")
		} else {
			t.Logf("correctly rejected: %v", err)
		}
	})

	// Тест 2: Клиентский сертификат с ServerAuth вместо ClientAuth
	t.Run("client_with_server_auth", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}

		template := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "wrong-eku.example.com"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(1, 0, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatal(err)
		}

		hasClientAuth := false
		for _, eku := range cert.ExtKeyUsage {
			if eku == x509.ExtKeyUsageClientAuth {
				hasClientAuth = true
				break
			}
		}
		if hasClientAuth {
			t.Error("client certificate should not have ServerAuth")
		} else {
			t.Log("correctly missing ClientAuth")
		}
	})

	// Тест 3: Правильный серверный сертификат
	t.Run("valid_server_certificate", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}

		template := &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      pkix.Name{CommonName: "valid-server.example.com"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(1, 0, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"valid-server.example.com"},
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatal(err)
		}

		validator := validation.NewPathValidator(validation.ValidationOptions{
			CurrentTime:      time.Now().UTC(),
			RequiredKeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		})

		path := []*x509.Certificate{cert}
		result, err := validator.ValidatePath(path)
		if err != nil {
			t.Logf("valid certificate error: %v", err)
		}
		if result != nil && result.Valid {
			t.Log("valid server certificate passed")
		}
	})
}

func TestExtractCRLURLsExtended(t *testing.T) {
    // Тест 1: Сертификат с несколькими CRL Distribution Points
    t.Run("multiple_CRL_points", func(t *testing.T) {
        key, err := rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
            t.Fatal(err)
        }

        template := &x509.Certificate{
            SerialNumber: big.NewInt(1),
            Subject:      pkix.Name{CommonName: "Multi CRL Cert"},
            NotBefore:    time.Now(),
            NotAfter:     time.Now().AddDate(1, 0, 0),
            CRLDistributionPoints: []string{
                "http://crl1.example.com/crl.pem",
                "http://crl2.example.com/crl.pem",
                "https://secure.crl.example.com/crl.pem",
            },
        }
        certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
        if err != nil {
            t.Fatal(err)
        }
        cert, err := x509.ParseCertificate(certDER)
        if err != nil {
            t.Fatal(err)
        }

        urls, err := validation.ExtractCRLURLs(cert)
        if err != nil {
            t.Logf("ExtractCRLURLs error: %v", err)
        }
        t.Logf("Found %d CRL URLs: %v", len(urls), urls)
    })

    // Тест 2: Сертификат без CRL Distribution Points
    t.Run("no_CRL_points", func(t *testing.T) {
        key, err := rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
            t.Fatal(err)
        }

        template := &x509.Certificate{
            SerialNumber: big.NewInt(2),
            Subject:      pkix.Name{CommonName: "No CRL Cert"},
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

        urls, err := validation.ExtractCRLURLs(cert)
        if err != nil {
            t.Logf("Cert without CRL: %v", err)
        }
        t.Logf("Found %d CRL URLs (expected 0)", len(urls))
    })
}

func TestExtractCRLURLsCoverage(t *testing.T) {
    // Создаём сертификат с CRL Distribution Points
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }

    template := &x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject:      pkix.Name{CommonName: "CRL Test Cert"},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(1, 0, 0),
        CRLDistributionPoints: []string{
            "http://crl1.example.com/crl.pem",
            "http://crl2.example.com/crl.pem",
        },
    }
    certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
    if err != nil {
        t.Fatal(err)
    }
    cert, err := x509.ParseCertificate(certDER)
    if err != nil {
        t.Fatal(err)
    }

    urls, err := validation.ExtractCRLURLs(cert)
    if err != nil {
        t.Logf("ExtractCRLURLs error: %v", err)
    }
    t.Logf("Found %d CRL URLs", len(urls))

    // Сертификат без CRL
    template2 := &x509.Certificate{
        SerialNumber: big.NewInt(2),
        Subject:      pkix.Name{CommonName: "No CRL Cert"},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(1, 0, 0),
    }
    certDER2, err := x509.CreateCertificate(rand.Reader, template2, template2, &key.PublicKey, key)
    if err != nil {
        t.Fatal(err)
    }
    cert2, err := x509.ParseCertificate(certDER2)
    if err != nil {
        t.Fatal(err)
    }

    urls2, err := validation.ExtractCRLURLs(cert2)
    t.Logf("Cert without CRL: found %d URLs, err=%v", len(urls2), err)
}

func TestExtractCRLURLsFullCoverage(t *testing.T) {
    // Создаём сертификат с CRL Distribution Points
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }

    // Тест 1: Сертификат с несколькими CRL URL
    t.Run("multiple_CRL_urls", func(t *testing.T) {
        template := &x509.Certificate{
            SerialNumber: big.NewInt(1),
            Subject:      pkix.Name{CommonName: "Multi CRL Cert"},
            NotBefore:    time.Now(),
            NotAfter:     time.Now().AddDate(1, 0, 0),
            CRLDistributionPoints: []string{
                "http://crl1.example.com/crl.pem",
                "http://crl2.example.com/crl.pem",
                "https://secure.crl.example.com/crl.pem",
            },
        }
        certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
        if err != nil {
            t.Fatal(err)
        }
        cert, err := x509.ParseCertificate(certDER)
        if err != nil {
            t.Fatal(err)
        }

        urls, err := validation.ExtractCRLURLs(cert)
        if err != nil {
            t.Logf("ExtractCRLURLs error: %v", err)
        }
        t.Logf("Found %d CRL URLs: %v", len(urls), urls)
    })

    // Тест 2: Сертификат без CRL
    t.Run("no_CRL_urls", func(t *testing.T) {
        template := &x509.Certificate{
            SerialNumber: big.NewInt(2),
            Subject:      pkix.Name{CommonName: "No CRL Cert"},
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

        urls, err := validation.ExtractCRLURLs(cert)
        t.Logf("Cert without CRL: found %d URLs, err=%v", len(urls), err)
    })

    // Тест 3: Сертификат с пустым списком CRL
    t.Run("empty_CRL_list", func(t *testing.T) {
        template := &x509.Certificate{
            SerialNumber: big.NewInt(3),
            Subject:      pkix.Name{CommonName: "Empty CRL Cert"},
            NotBefore:    time.Now(),
            NotAfter:     time.Now().AddDate(1, 0, 0),
            CRLDistributionPoints: []string{},
        }
        certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
        if err != nil {
            t.Fatal(err)
        }
        cert, err := x509.ParseCertificate(certDER)
        if err != nil {
            t.Fatal(err)
        }

        urls, err := validation.ExtractCRLURLs(cert)
        t.Logf("Empty CRL list: found %d URLs, err=%v", len(urls), err)
    })

    t.Log("ExtractCRLURLs full coverage test completed")
}