package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"MicroPKI/internal/csr"
)

func TestGenerateIntermediateCSR(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "csr-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	subject := "/CN=Test Intermediate CA/O=Test"
	csrPEM, err := csr.GenerateIntermediateCSR(subject, &key.PublicKey, key, 0)
	if err != nil {
		t.Fatal(err)
	}

	csrPath := filepath.Join(tmpDir, "test.csr.pem")
	if err := csr.SaveCSR(csrPath, csrPEM); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(csrPath); err != nil {
		t.Errorf("файл CSR не создан: %v", err)
	}

	parsedCSR, err := csr.ParseCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}

	if parsedCSR.Subject.CommonName != "Test Intermediate CA" {
		t.Errorf("ожидался CN=Test Intermediate CA, получен %s", parsedCSR.Subject.CommonName)
	}
}

func TestParseCSRInvalid(t *testing.T) {
	invalidPEM := []byte("invalid pem data")
	_, err := csr.ParseCSR(invalidPEM)
	if err == nil {
		t.Error("ожидалась ошибка для неверного PEM")
	}

	wrongTypePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("test"),
	})
	_, err = csr.ParseCSR(wrongTypePEM)
	if err == nil {
		t.Error("ожидалась ошибка для неверного типа блока")
	}
}

func TestCreateIntermediateCSRExtensions(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	extensions, err := csr.CreateIntermediateCSRExtensions(&key.PublicKey, 1)
	if err != nil {
		t.Fatal(err)
	}

	if len(extensions) == 0 {
		t.Error("расширения не созданы")
	}
}