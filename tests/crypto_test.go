package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	"MicroPKI/internal/cryptoutil"
)

func TestHashSHA1(t *testing.T) {
	data := []byte("hello world")
	hash := cryptoutil.HashSHA1(data)
	if len(hash) != 20 {
		t.Errorf("Ожидалась длина 20, получено %d", len(hash))
	}
	expected := [20]byte{0x2a, 0xae, 0x6c, 0x35, 0xc9, 0x4f, 0xcf, 0xb4, 0x15, 0xdb, 0xe9, 0x5f, 0x40, 0x8b, 0x9c, 0xe9, 0x1e, 0xe8, 0x46, 0xed}
	if hash != expected {
		t.Errorf("SHA-1 хеш не совпадает")
	}
}

func TestGenerateRSAKey(t *testing.T) {
	key, err := cryptoutil.GenerateRSAKey(4096)
	if err != nil {
		t.Fatal(err)
	}
	if key.N.BitLen() != 4096 {
		t.Errorf("Ожидался ключ 4096 бит, получено %d", key.N.BitLen())
	}

	_, err = cryptoutil.GenerateRSAKey(2048)
	if err == nil {
		t.Error("Ожидалась ошибка при размере ключа 2048")
	}
}

func TestGenerateECCP384Key(t *testing.T) {
	key, err := cryptoutil.GenerateECCP384Key()
	if err != nil {
		t.Fatal(err)
	}
	if key.Curve != elliptic.P384() {
		t.Error("Ключ не на кривой P-384")
	}
}

func TestEncryptedKeyRSA(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "test.key")
	passphrase := []byte("testpass123")

	key, err := cryptoutil.GenerateRSAKey(4096)
	if err != nil {
		t.Fatal(err)
	}

	if err := cryptoutil.SaveEncryptedRSAPEM(keyPath, key, passphrase); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("Неправильные права: ожидалось 0600, получено %o", info.Mode().Perm())
	}

	loadedKey, err := cryptoutil.LoadEncryptedPrivateKey(keyPath, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	loadedRSA, ok := loadedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("Загруженный ключ не является RSA")
	}

	if key.N.Cmp(loadedRSA.N) != 0 {
		t.Error("Загруженный ключ не совпадает с исходным")
	}
}

func TestEncryptedKeyECC(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "test.key")
	passphrase := []byte("testpass123")

	key, err := cryptoutil.GenerateECCP384Key()
	if err != nil {
		t.Fatal(err)
	}

	if err := cryptoutil.SaveEncryptedECCPEM(keyPath, key, passphrase); err != nil {
		t.Fatal(err)
	}

	loadedKey, err := cryptoutil.LoadEncryptedPrivateKey(keyPath, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	loadedECC, ok := loadedKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("Загруженный ключ не является ECC")
	}

	if loadedECC.Curve != elliptic.P384() {
		t.Error("Загруженный ключ не на кривой P-384")
	}
}

func TestWrongPassphrase(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "test.key")
	correctPass := []byte("correctpass")
	wrongPass := []byte("wrongpass")

	key, err := cryptoutil.GenerateRSAKey(4096)
	if err != nil {
		t.Fatal(err)
	}

	if err := cryptoutil.SaveEncryptedRSAPEM(keyPath, key, correctPass); err != nil {
		t.Fatal(err)
	}

	_, err = cryptoutil.LoadEncryptedPrivateKey(keyPath, wrongPass)
	if err == nil {
		t.Error("Ожидалась ошибка при неправильном пароле, но ее не было")
	}
}