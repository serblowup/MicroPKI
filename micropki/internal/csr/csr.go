package csr

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"

	"MicroPKI/internal/certs"
)

func GenerateIntermediateCSR(subjectDN string, pubKey crypto.PublicKey, privKey crypto.PrivateKey, pathlen int) ([]byte, error) {
	name, err := certs.ParseDN(subjectDN)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга subject: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject: *name,
	}

	extensions, err := CreateIntermediateCSRExtensions(pubKey, pathlen)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания расширений CSR: %w", err)
	}
	template.ExtraExtensions = extensions

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, nil
}

func CreateIntermediateCSRExtensions(pubKey crypto.PublicKey, pathlen int) ([]pkix.Extension, error) {
	ski, err := certs.CalculateSKI(pubKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка вычисления SKI: %w", err)
	}

	extensions := []pkix.Extension{
		{
			Id:       []int{2, 5, 29, 14},
			Critical: false,
			Value:    ski,
		},
	}

	basicConstraints := []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, byte(pathlen)}
	if pathlen < 0 {
		basicConstraints = []byte{0x30, 0x03, 0x01, 0x01, 0xff}
	}

	extensions = append(extensions, pkix.Extension{
		Id:       []int{2, 5, 29, 19},
		Critical: true,
		Value:    basicConstraints,
	})

	return extensions, nil
}

func ParseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM")
	}

	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("неверный тип блока: %s", block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("неверная подпись CSR: %w", err)
	}

	return csr, nil
}

func SaveCSR(path string, csrPEM []byte) error {
	if err := os.WriteFile(path, csrPEM, 0644); err != nil {
		return fmt.Errorf("ошибка сохранения CSR: %w", err)
	}
	return nil
}