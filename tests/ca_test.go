package tests

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"MicroPKI/internal/ca"
	"MicroPKI/internal/certs"
	"MicroPKI/internal/cryptoutil"
)

func TestRootCAInitialization(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	passFile := filepath.Join(tmpDir, "test.pass")
	if err := os.WriteFile(passFile, []byte("testpass123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootCA, err := ca.NewRootCA(
		"/CN=Test Root CA",
		"rsa",
		4096,
		passFile,
		tmpDir,
		365,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := rootCA.Initialize(); err != nil {
		t.Fatal(err)
	}

	checkFileExists(t, filepath.Join(tmpDir, "private", "ca.key.pem"))
	checkFileExists(t, filepath.Join(tmpDir, "certs", "ca.cert.pem"))
	checkFileExists(t, filepath.Join(tmpDir, "policy.txt"))

	info, err := os.Stat(filepath.Join(tmpDir, "private", "ca.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("Неправильные права на ключ: ожидалось 0600, получено %o", info.Mode().Perm())
	}
}

func TestECCRootCAInitialization(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	passFile := filepath.Join(tmpDir, "test.pass")
	if err := os.WriteFile(passFile, []byte("testpass123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootCA, err := ca.NewRootCA(
		"CN=ECC Test Root CA,O=Test",
		"ecc",
		384,
		passFile,
		tmpDir,
		365,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := rootCA.Initialize(); err != nil {
		t.Fatal(err)
	}

	checkFileExists(t, filepath.Join(tmpDir, "private", "ca.key.pem"))
	checkFileExists(t, filepath.Join(tmpDir, "certs", "ca.cert.pem"))
}

func TestKeyCertMatching(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	privateDir := filepath.Join(tmpDir, "private")
	if err := os.MkdirAll(privateDir, 0700); err != nil {
		t.Fatal(err)
	}

	passFile := filepath.Join(tmpDir, "test.pass")
	passphrase := []byte("testpass123")
	if err := os.WriteFile(passFile, passphrase, 0600); err != nil {
		t.Fatal(err)
	}

	rootCA, err := ca.NewRootCA(
		"/CN=Test Root CA",
		"rsa",
		4096,
		passFile,
		tmpDir,
		365,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := rootCA.Initialize(); err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(tmpDir, "private", "ca.key.pem")
	loadedKey, err := cryptoutil.LoadEncryptedPrivateKey(keyPath, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := loadedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("Загруженный ключ не является RSA ключом")
	}
}

func TestNegativeCases(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	passFile := filepath.Join(tmpDir, "test.pass")
	if err := os.WriteFile(passFile, []byte("testpass123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		subject     string
		keyType     string
		keySize     int
		passFile    string
		validity    int
		expectError bool
	}{
		{
			name:        "Пустой subject",
			subject:     "",
			keyType:     "rsa",
			keySize:     4096,
			passFile:    passFile,
			validity:    365,
			expectError: true,
		},
		{
			name:        "Неправильный тип ключа",
			subject:     "/CN=Test",
			keyType:     "dsa",
			keySize:     4096,
			passFile:    passFile,
			validity:    365,
			expectError: true,
		},
		{
			name:        "Неправильный размер RSA ключа",
			subject:     "/CN=Test",
			keyType:     "rsa",
			keySize:     2048,
			passFile:    passFile,
			validity:    365,
			expectError: true,
		},
		{
			name:        "Неправильный размер ECC ключа",
			subject:     "/CN=Test",
			keyType:     "ecc",
			keySize:     256,
			passFile:    passFile,
			validity:    365,
			expectError: true,
		},
		{
			name:        "Несуществующий файл пароля",
			subject:     "/CN=Test",
			keyType:     "rsa",
			keySize:     4096,
			passFile:    "/nonexistent/pass.txt",
			validity:    365,
			expectError: true,
		},
		{
			name:        "Отрицательный срок действия",
			subject:     "/CN=Test",
			keyType:     "rsa",
			keySize:     4096,
			passFile:    passFile,
			validity:    -1,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootCA, err := ca.NewRootCA(
				tt.subject,
				tt.keyType,
				tt.keySize,
				tt.passFile,
				tmpDir,
				tt.validity,
				false,
			)
			if err != nil {
				if !tt.expectError {
					t.Errorf("Неожиданная ошибка при создании: %v", err)
				}
				return
			}

			err = rootCA.Initialize()
			if tt.expectError && err == nil {
				t.Error("Ожидалась ошибка, но ее не было")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Неожиданная ошибка: %v", err)
			}
		})
	}
}

func TestDNParsing(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/CN=Test CA", "Test CA"},
		{"CN=Test CA,O=Org", "Test CA"},
		{"/CN=Test/OU=Unit", "Test"},
	}

	for _, tt := range tests {
		name, err := certs.ParseDN(tt.input)
		if err != nil {
			t.Errorf("Ошибка парсинга %s: %v", tt.input, err)
			continue
		}
		if name.CommonName != tt.expected {
			t.Errorf("Для %s ожидалось CN=%s, получено %s", tt.input, tt.expected, name.CommonName)
		}
	}
}

func TestGenerateSerialNumber(t *testing.T) {
	serial1, err := certs.GenerateSerialNumber()
	if err != nil {
		t.Fatal(err)
	}

	serial2, err := certs.GenerateSerialNumber()
	if err != nil {
		t.Fatal(err)
	}

	if serial1.Cmp(serial2) == 0 {
		t.Error("Сгенерированы одинаковые серийные номера")
	}

	if serial1.Sign() <= 0 {
		t.Error("Серийный номер должен быть положительным")
	}
}

func TestCertificateVerification(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	passFile := filepath.Join(tmpDir, "test.pass")
	if err := os.WriteFile(passFile, []byte("testpass123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootCA, err := ca.NewRootCA(
		"/CN=Test Root CA",
		"rsa",
		4096,
		passFile,
		tmpDir,
		365,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := rootCA.Initialize(); err != nil {
		t.Fatal(err)
	}

	certPEM, err := os.ReadFile(filepath.Join(tmpDir, "certs", "ca.cert.pem"))
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("Не удалось декодировать PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if !cert.IsCA {
		t.Error("Сертификат не является CA")
	}

	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("Отсутствует KeyUsage CertSign")
	}

	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("Отсутствует KeyUsage CRLSign")
	}
}

func checkFileExists(t *testing.T, path string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("Файл не существует: %s", path)
	}
}
