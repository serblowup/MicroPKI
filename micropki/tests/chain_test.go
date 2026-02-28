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

	"MicroPKI/internal/chain"
)

func createTestCertificate(t *testing.T, isCA bool, parent *x509.Certificate, parentKey interface{}) (*x509.Certificate, interface{}, []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	serialNumber := big.NewInt(1)
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "Test Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	var issuer *x509.Certificate
	var signingKey interface{}
	if parent == nil {
		issuer = template
		signingKey = key
	} else {
		issuer = parent
		signingKey = parentKey
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, signingKey)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return cert, key, certPEM
}

func TestLoadCertificate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "chain-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	_, _, certPEM := createTestCertificate(t, true, nil, nil)

	certPath := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}

	cert, err := chain.LoadCertificate(certPath)
	if err != nil {
		t.Fatal(err)
	}

	if cert == nil {
		t.Error("сертификат не загружен")
	}
}

func TestVerifyChain(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "chain-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	rootCert, rootKey, rootPEM := createTestCertificate(t, true, nil, nil)
	interCert, interKey, interPEM := createTestCertificate(t, true, rootCert, rootKey)
	leafCert, _, leafPEM := createTestCertificate(t, false, interCert, interKey)

	rootPath := filepath.Join(tmpDir, "root.pem")
	interPath := filepath.Join(tmpDir, "inter.pem")
	leafPath := filepath.Join(tmpDir, "leaf.pem")

	if err := os.WriteFile(rootPath, rootPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(interPath, interPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leafPath, leafPEM, 0644); err != nil {
		t.Fatal(err)
	}

	err = chain.VerifyChain(leafPath, interPath, rootPath)
	if err != nil {
		t.Errorf("ошибка проверки цепочки: %v", err)
	}

	err = chain.VerifyWithOpenSSLCompatibility(leafPath, interPath, rootPath)
	if err != nil {
		t.Errorf("ошибка проверки совместимости: %v", err)
	}

	_, _, _ = rootCert, interCert, leafCert
}

func TestVerifyChainInvalid(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "chain-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	rootCert, rootKey, rootPEM := createTestCertificate(t, true, nil, nil)
	
	interCert, interKey, interPEM := createTestCertificate(t, true, rootCert, rootKey)
	
	leafCert, _, leafPEM := createTestCertificate(t, false, interCert, interKey)

	rootPath := filepath.Join(tmpDir, "root.pem")
	interPath := filepath.Join(tmpDir, "inter.pem")
	leafPath := filepath.Join(tmpDir, "leaf.pem")

	if err := os.WriteFile(rootPath, rootPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(interPath, interPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leafPath, leafPEM, 0644); err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(leafPath, []byte("invalid data"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = chain.VerifyChain(leafPath, interPath, rootPath)
	if err == nil {
		t.Error("ожидалась ошибка при неверных данных сертификата")
	}

	_, _, _ = rootCert, interCert, leafCert
	_ = rootKey
}