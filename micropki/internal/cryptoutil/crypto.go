package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func HashSHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func HashSHA1(data []byte) [20]byte {
	return sha1.Sum(data)
}

func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	if bits != 4096 {
		return nil, fmt.Errorf("для RSA размер ключа должен быть 4096 бит, получено: %d", bits)
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

func GenerateECCP384Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

func GenerateEndEntityRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func SaveEncryptedRSAPEM(path string, key *rsa.PrivateKey, passphrase []byte) error {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)

	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", keyBytes, passphrase, x509.PEMCipherAES256)
	if err != nil {
		return fmt.Errorf("ошибка шифрования rsa ключа: %w", err)
	}

	return savePEMBlock(path, block)
}

func SaveEncryptedECCPEM(path string, key *ecdsa.PrivateKey, passphrase []byte) error {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("ошибка маршалинга ecc ключа: %w", err)
	}

	block, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", keyBytes, passphrase, x509.PEMCipherAES256)
	if err != nil {
		return fmt.Errorf("ошибка шифрования ecc ключа: %w", err)
	}

	return savePEMBlock(path, block)
}

func savePEMBlock(path string, block *pem.Block) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("ошибка создания файла ключа: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("ошибка записи pem: %w", err)
	}
	return nil
}

func LoadEncryptedPrivateKey(path string, passphrase []byte) (crypto.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения файла ключа: %w", err)
	}

	return LoadEncryptedPrivateKeyFromPEM(pemBytes, passphrase)
}

func LoadEncryptedPrivateKeyFromPEM(pemBytes []byte, passphrase []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("ошибка декодирования pem")
	}

	if !x509.IsEncryptedPEMBlock(block) {
		return nil, fmt.Errorf("ключ не зашифрован")
	}

	decrypted, err := x509.DecryptPEMBlock(block, passphrase)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки ключа (неверный пароль?): %w", err)
	}

	if key, err := x509.ParsePKCS1PrivateKey(decrypted); err == nil {
		return key, nil
	}

	if key, err := x509.ParseECPrivateKey(decrypted); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(decrypted); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("неизвестный формат закрытого ключа")
}