package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"MicroPKI/internal/ca"
	"MicroPKI/internal/certs"
	"MicroPKI/internal/chain"
	"MicroPKI/internal/crl"
	"MicroPKI/internal/cryptoutil"
	"MicroPKI/internal/csr"
	"MicroPKI/internal/database"
	"MicroPKI/internal/revocation"
	"MicroPKI/internal/san"
	"MicroPKI/internal/templates"
)

func setupTestDBForIntegration(t *testing.T) (*database.Database, func()) {
	tmpDir, err := os.MkdirTemp("", "integration-test-*")
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

	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}

	return db, cleanup
}

func TestFullPKIChain(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-integration-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, cleanupDB := setupTestDBForIntegration(t)
	defer cleanupDB()

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
		db,
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
		db,
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

	db, cleanupDB := setupTestDBForIntegration(t)
	defer cleanupDB()

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
		db,
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

func TestRevocationLifecycle(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pki-revocation-lifecycle-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, cleanupDB := setupTestDBForIntegration(t)
	defer cleanupDB()

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
		db,
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

	interTemplate := &x509.Certificate{
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

	interCertDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	interCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: interCertDER,
	})

	interCertPath := filepath.Join(tmpDir, "certs", "intermediate.cert.pem")
	if err := os.WriteFile(interCertPath, interCertPEM, 0644); err != nil {
		t.Fatal(err)
	}

	interCert, err := x509.ParseCertificate(interCertDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	leafSerial := big.NewInt(999)
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		Issuer:       interCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"leaf.example.com"},
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}

	leafCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCertDER,
	})

	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.InsertCertificate(leafCert, leafCertPEM, "valid"); err != nil {
		t.Fatal(err)
	}

	allCerts, err := db.ListCertificates("", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	
	var leafSerialHex string
	for _, cert := range allCerts {
		if cert.Subject == leafCert.Subject.String() {
			leafSerialHex = cert.SerialHex
			break
		}
	}
	
	if leafSerialHex == "" {
		t.Fatal("не удалось найти серийный номер сертификата")
	}
	t.Logf("Найден серийный номер: %s", leafSerialHex)

	record, err := db.GetCertificateBySerial(leafSerialHex)
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatalf("сертификат с серийным номером %s не найден", leafSerialHex)
	}
	if record.Status != "valid" {
		t.Errorf("ожидался статус valid, получен %s", record.Status)
	}

	err = revocation.RevokeCertificate(db, leafSerialHex, 1, true)
	if err != nil {
		t.Fatal(err)
	}

	record, err = db.GetCertificateBySerial(leafSerialHex)
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatal("сертификат не найден после отзыва")
	}
	if record.Status != "revoked" {
		t.Errorf("ожидался статус revoked, получен %s", record.Status)
	}
	if !record.RevocationReason.Valid || record.RevocationReason.String != "keyCompromise" {
		t.Errorf("ожидалась причина keyCompromise, получена %v", record.RevocationReason)
	}

	revokedRecords, err := db.GetRevokedCertificatesByIssuer(interCert.Subject.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(revokedRecords) != 1 {
		t.Errorf("ожидался 1 отозванный сертификат, получено %d", len(revokedRecords))
	}

	revokedCerts := make([]crl.RevokedCertInfo, 0, len(revokedRecords))
	for _, r := range revokedRecords {
		serialBytes, err := hex.DecodeString(r.SerialHex)
		if err != nil {
			t.Fatalf("ошибка декодирования серийного номера %s: %v", r.SerialHex, err)
		}
		serial := new(big.Int).SetBytes(serialBytes)
		reasonCode, _ := revocation.ReasonCodeToInt(r.RevocationReason.String)

		revocationTime := time.Now().UTC()
		if r.RevocationDate.Valid {
			revocationTime = r.RevocationDate.Time
		}

		revokedCerts = append(revokedCerts, crl.RevokedCertInfo{
			SerialNumber:   serial,
			RevocationTime: revocationTime,
			ReasonCode:     reasonCode,
		})
	}

	crlPEM, err := crl.GenerateCRL(interCert, interKey, revokedCerts, 1, 7)
	if err != nil {
		t.Fatal(err)
	}

	crlDir := filepath.Join(tmpDir, "crl")
	if err := os.MkdirAll(crlDir, 0755); err != nil {
		t.Fatal(err)
	}
	crlPath := filepath.Join(crlDir, "intermediate.crl.pem")
	if err := os.WriteFile(crlPath, crlPEM, 0644); err != nil {
		t.Fatal(err)
	}

	crlBlock, _ := pem.Decode(crlPEM)
	if crlBlock == nil {
		t.Fatal("не удалось декодировать CRL PEM")
	}
	crlList, err := x509.ParseRevocationList(crlBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, rc := range crlList.RevokedCertificates {
		if rc.SerialNumber.Cmp(leafCert.SerialNumber) == 0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("CRL не содержит отозванный сертификат")
	}
}
