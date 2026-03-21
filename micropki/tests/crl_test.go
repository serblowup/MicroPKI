package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"MicroPKI/internal/crl"
)

func TestGenerateCRL(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4, 5},
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	revocationTime := time.Now().UTC()
	revokedCerts := []crl.RevokedCertInfo{
		{
			SerialNumber:   big.NewInt(100),
			RevocationTime: revocationTime,
			ReasonCode:     1,
		},
		{
			SerialNumber:   big.NewInt(200),
			RevocationTime: revocationTime,
			ReasonCode:     4,
		},
	}

	crlPEM, err := crl.GenerateCRL(caCert, caKey, revokedCerts, 1, 7)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("не удалось декодировать CRL PEM")
	}
	if block.Type != "X509 CRL" {
		t.Errorf("ожидался тип X509 CRL, получен %s", block.Type)
	}

	crlList, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if crlList.Number.Int64() != 1 {
		t.Errorf("ожидался номер CRL 1, получен %d", crlList.Number.Int64())
	}

	if len(crlList.RevokedCertificates) != 2 {
		t.Errorf("ожидалось 2 отозванных сертификата, получено %d", len(crlList.RevokedCertificates))
	}
}

func TestGenerateCRLWithNoRevokedCerts(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4, 5},
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	crlPEM, err := crl.GenerateCRL(caCert, caKey, []crl.RevokedCertInfo{}, 5, 14)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("не удалось декодировать CRL PEM")
	}
	crlList, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if crlList.Number.Int64() != 5 {
		t.Errorf("ожидался номер CRL 5, получен %d", crlList.Number.Int64())
	}

	if len(crlList.RevokedCertificates) != 0 {
		t.Errorf("ожидалось 0 отозванных сертификатов, получено %d", len(crlList.RevokedCertificates))
	}

	expectedNextUpdate := crlList.ThisUpdate.AddDate(0, 0, 14)
	if crlList.NextUpdate.Sub(expectedNextUpdate).Abs() > time.Second {
		t.Errorf("NextUpdate не соответствует ожидаемому: ожидалось %v, получено %v", expectedNextUpdate, crlList.NextUpdate)
	}
}

func TestGenerateCRLWithReasonCodes(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4, 5},
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	revocationTime := time.Now().UTC()
	revokedCerts := []crl.RevokedCertInfo{
		{SerialNumber: big.NewInt(1), RevocationTime: revocationTime, ReasonCode: 1},
		{SerialNumber: big.NewInt(2), RevocationTime: revocationTime, ReasonCode: 2},
		{SerialNumber: big.NewInt(3), RevocationTime: revocationTime, ReasonCode: 4},
		{SerialNumber: big.NewInt(4), RevocationTime: revocationTime, ReasonCode: 8},
	}

	crlPEM, err := crl.GenerateCRL(caCert, caKey, revokedCerts, 1, 7)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("не удалось декодировать CRL PEM")
	}
	crlList, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(crlList.RevokedCertificates) != 4 {
		t.Fatalf("ожидалось 4 записи, получено %d", len(crlList.RevokedCertificates))
	}
}
