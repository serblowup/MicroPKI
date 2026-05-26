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
		t.Errorf("ожидалась длина 20, получено %d", len(hash))
	}
	expected := [20]byte{0x2a, 0xae, 0x6c, 0x35, 0xc9, 0x4f, 0xcf, 0xb4, 0x15, 0xdb, 0xe9, 0x5f, 0x40, 0x8b, 0x9c, 0xe9, 0x1e, 0xe8, 0x46, 0xed}
	if hash != expected {
		t.Errorf("SHA-1 хеш не совпадает")
	}
}

func TestHashSHA256(t *testing.T) {
	data := []byte("hello world")
	hash := cryptoutil.HashSHA256(data)
	if len(hash) != 32 {
		t.Errorf("ожидалась длина 32, получено %d", len(hash))
	}
}

func TestGenerateRSAKey(t *testing.T) {
	key, err := cryptoutil.GenerateRSAKey(4096)
	if err != nil {
		t.Fatal(err)
	}
	if key.N.BitLen() != 4096 {
		t.Errorf("ожидался ключ 4096 бит, получено %d", key.N.BitLen())
	}

	_, err = cryptoutil.GenerateRSAKey(2048)
	if err == nil {
		t.Error("ожидалась ошибка при размере ключа 2048")
	}
}

func TestGenerateECCP384Key(t *testing.T) {
	key, err := cryptoutil.GenerateECCP384Key()
	if err != nil {
		t.Fatal(err)
	}
	if key.Curve != elliptic.P384() {
		t.Error("ключ не на кривой P-384")
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
		t.Errorf("неправильные права: ожидалось 0600, получено %o", info.Mode().Perm())
	}

	loadedKey, err := cryptoutil.LoadEncryptedPrivateKey(keyPath, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	loadedRSA, ok := loadedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("загруженный ключ не является RSA")
	}

	if key.N.Cmp(loadedRSA.N) != 0 {
		t.Error("загруженный ключ не совпадает с исходным")
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
		t.Fatal("загруженный ключ не является ECC")
	}

	if loadedECC.Curve != elliptic.P384() {
		t.Error("загруженный ключ не на кривой P-384")
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
		t.Error("ожидалась ошибка при неправильном пароле, но ее не было")
	}
}

func TestGenerateECCP256Key(t *testing.T) {
	key, err := cryptoutil.GenerateECCP256Key()
	if err != nil {
		t.Fatalf("GenerateECCP256Key ошибка: %v", err)
	}
	if key == nil {
		t.Error("ключ nil")
	}
	if key.Curve != elliptic.P256() {
		t.Error("ключ не на кривой P-256")
	}
	t.Log("ECC P-256 ключ успешно сгенерирован")
}

func TestGenerateEndEntityRSAKey(t *testing.T) {
	key, err := cryptoutil.GenerateEndEntityRSAKey()
	if err != nil {
		t.Fatalf("GenerateEndEntityRSAKey ошибка: %v", err)
	}
	if key == nil {
		t.Error("ключ nil")
	}
	if key.N.BitLen() != 2048 {
		t.Errorf("ожидался ключ 2048 бит, получен %d", key.N.BitLen())
	}
	t.Log("End-entity RSA ключ успешно сгенерирован")
}

func TestGenerateEndEntityECCKey(t *testing.T) {
	key, err := cryptoutil.GenerateEndEntityECCKey()
	if err != nil {
		t.Fatalf("GenerateEndEntityECCKey ошибка: %v", err)
	}
	if key == nil {
		t.Error("ключ nil")
	}
	if key.Curve != elliptic.P256() {
		t.Error("ключ не на кривой P-256")
	}
	t.Log("End-entity ECC ключ успешно сгенерирован")
}

func TestLoadEncryptedPrivateKeyFromPEM(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-pem-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "test.key")
	passphrase := []byte("testpass456")

	key, err := cryptoutil.GenerateRSAKey(4096)
	if err != nil {
		t.Fatal(err)
	}

	if err := cryptoutil.SaveEncryptedRSAPEM(keyPath, key, passphrase); err != nil {
		t.Fatal(err)
	}

	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	loadedKey, err := cryptoutil.LoadEncryptedPrivateKeyFromPEM(pemBytes, passphrase)
	if err != nil {
		t.Fatalf("LoadEncryptedPrivateKeyFromPEM ошибка: %v", err)
	}
	if loadedKey == nil {
		t.Error("загруженный ключ nil")
	}

	// Тест с неверным паролем
	_, err = cryptoutil.LoadEncryptedPrivateKeyFromPEM(pemBytes, []byte("wrongpass"))
	if err == nil {
		t.Error("ожидалась ошибка при неверном пароле")
	}
}

func TestSavePEMBlock(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crypto-save-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "test-save.key")
	passphrase := []byte("savepass")

	key, err := cryptoutil.GenerateRSAKey(4096)
	if err != nil {
		t.Fatal(err)
	}

	err = cryptoutil.SaveEncryptedRSAPEM(keyPath, key, passphrase)
	if err != nil {
		t.Fatalf("SaveEncryptedRSAPEM ошибка: %v", err)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("файл не создан")
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("неправильные права: ожидалось 0600, получено %o", info.Mode().Perm())
	}
}