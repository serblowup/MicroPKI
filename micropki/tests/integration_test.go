package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"MicroPKI/internal/ca"
	"MicroPKI/internal/certs"
	"MicroPKI/internal/chain"
	"MicroPKI/internal/cryptoutil"
	"MicroPKI/internal/csr"
	"MicroPKI/internal/san"
	"MicroPKI/internal/templates"
)

func TestFullPKIChain(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-integration-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	rootPassFile := filepath.Join(tmpDir, "root.pass")
	if err := os.WriteFile(rootPassFile, []byte("rootpass123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootCA, err := ca.NewRootCA(
		"/CN=Test Root CA",
		"rsa",
		4096,
		rootPassFile,
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

	interPassFile := filepath.Join(tmpDir, "inter.pass")
	if err := os.WriteFile(interPassFile, []byte("interpass123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootKey, err := cryptoutil.LoadEncryptedPrivateKey(
		filepath.Join(tmpDir, "private", "ca.key.pem"),
		[]byte("rootpass123"),
	)
	if err != nil {
		t.Fatal(err)
	}

	rootCertPEM, err := os.ReadFile(filepath.Join(tmpDir, "certs", "ca.cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(rootCertPEM)
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	interKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	if err := cryptoutil.SaveEncryptedRSAPEM(
		filepath.Join(tmpDir, "private", "intermediate.key.pem"),
		interKey,
		[]byte("interpass123"),
	); err != nil {
		t.Fatal(err)
	}

	csrPEM, err := csr.GenerateIntermediateCSR(
		"/CN=Test Intermediate CA",
		&interKey.PublicKey,
		interKey,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	csrObj, err := csr.ParseCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, err := certs.GenerateSerialNumber()
	if err != nil {
		t.Fatal(err)
	}

	ski, err := certs.CalculateSKI(&interKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csrObj.Subject,
		Issuer:       rootCert.Subject,
		NotBefore:    rootCert.NotBefore,
		NotAfter:     rootCert.NotAfter,

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,

		SubjectKeyId:   ski,
		AuthorityKeyId: rootCert.SubjectKeyId,
	}

	interCertDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	interCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: interCertDER,
	})

	if err := os.WriteFile(filepath.Join(tmpDir, "certs", "intermediate.cert.pem"), interCertPEM, 0644); err != nil {
		t.Fatal(err)
	}

	interCA, err := ca.NewIntermediateCA(
		filepath.Join(tmpDir, "certs", "intermediate.cert.pem"),
		filepath.Join(tmpDir, "private", "intermediate.key.pem"),
		interPassFile,
	)
	if err != nil {
		t.Fatal(err)
	}

	interCert, interSigner, err := interCA.Load()
	if err != nil {
		t.Fatal(err)
	}

	sans := []san.SANEntry{
		{Type: "dns", Value: "example.com"},
		{Type: "ip", Value: "192.168.1.1"},
	}

	leafTemplate, err := templates.BuildCertificateTemplate(
		templates.ServerTemplate,
		"/CN=example.com",
		&interKey.PublicKey,
		sans,
		30,
		false,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate.Issuer = interCert.Subject
	leafTemplate.AuthorityKeyId = interCert.SubjectKeyId

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &interKey.PublicKey, interSigner)
	if err != nil {
		t.Fatal(err)
	}

	leafCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCertDER,
	})

	leafPath := filepath.Join(tmpDir, "certs", "leaf.cert.pem")
	if err := os.WriteFile(leafPath, leafCertPEM, 0644); err != nil {
		t.Fatal(err)
	}

	if err := chain.VerifyChain(
		leafPath,
		filepath.Join(tmpDir, "certs", "intermediate.cert.pem"),
		filepath.Join(tmpDir, "certs", "ca.cert.pem"),
	); err != nil {
		t.Errorf("ошибка проверки цепочки: %v", err)
	}
}

func TestNegativeScenarios(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-negative-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	rootPassFile := filepath.Join(tmpDir, "root.pass")
	if err := os.WriteFile(rootPassFile, []byte("rootpass123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootCA, err := ca.NewRootCA(
		"/CN=Test Root CA",
		"rsa",
		4096,
		rootPassFile,
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

	interPassFile := filepath.Join(tmpDir, "inter.pass")
	if err := os.WriteFile(interPassFile, []byte("interpass123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootKey, err := cryptoutil.LoadEncryptedPrivateKey(
		filepath.Join(tmpDir, "private", "ca.key.pem"),
		[]byte("rootpass123"),
	)
	if err != nil {
		t.Fatal(err)
	}

	rootCertPEM, err := os.ReadFile(filepath.Join(tmpDir, "certs", "ca.cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(rootCertPEM)
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	interKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("server_cert_without_san", func(t *testing.T) {
		sans := []san.SANEntry{}

		_, err := templates.BuildCertificateTemplate(
			templates.ServerTemplate,
			"/CN=example.com",
			&interKey.PublicKey,
			sans,
			30,
			false,
			0,
		)

		if err == nil {
			t.Error("ожидалась ошибка при создании серверного сертификата без SAN")
		}
	})

	t.Run("unsupported_san_type", func(t *testing.T) {
		sans := []san.SANEntry{
			{Type: "email", Value: "test@example.com"},
		}

		err := templates.ValidateSANsForTemplate(
			&templates.CertTemplate{
				Type:             templates.ServerTemplate,
				AllowedSANTypes:  []string{"dns", "ip"},
			},
			sans,
		)

		if err == nil {
			t.Error("ожидалась ошибка при использовании неподдерживаемого типа SAN")
		}
	})

	t.Run("wrong_passphrase", func(t *testing.T) {
		if err := cryptoutil.SaveEncryptedRSAPEM(
			filepath.Join(tmpDir, "private", "intermediate.key.pem"),
			interKey,
			[]byte("interpass123"),
		); err != nil {
			t.Fatal(err)
		}

		_, err := cryptoutil.LoadEncryptedPrivateKey(
			filepath.Join(tmpDir, "private", "intermediate.key.pem"),
			[]byte("wrongpass"),
		)

		if err == nil {
			t.Error("ожидалась ошибка при неверном пароле")
		}
	})

	t.Run("csr_with_ca_true", func(t *testing.T) {
	badKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, _ := certs.GenerateSerialNumber()
	ski, _ := certs.CalculateSKI(&badKey.PublicKey)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "Bad CSR"},
		Issuer:       rootCert.Subject,
		NotBefore:    rootCert.NotBefore,
		NotAfter:     rootCert.NotAfter,

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,

		SubjectKeyId:   ski,
		AuthorityKeyId: rootCert.SubjectKeyId,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, &badKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("неожиданная ошибка при создании сертификата: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	if !cert.IsCA {
		t.Error("сертификат должен быть CA")
	}

	err = cert.CheckSignatureFrom(rootCert)
	if err != nil {
		t.Error("подпись должна быть валидной")
	}
    })
}