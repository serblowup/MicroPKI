package revocation

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type CRLChecker struct {
	client *http.Client
}

func NewCRLChecker() *CRLChecker {
	return &CRLChecker{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

type CRLResult struct {
	Status       string // "good", "revoked", "error"
	RevokedAt    time.Time
	ReasonCode   int
	ReasonString string
	Fresh        bool
	Error        error
}

// CheckCertificate проверяет сертификат по CRL
func (cc *CRLChecker) CheckCertificate(cert *x509.Certificate, issuer *x509.Certificate, crlSource string) (*CRLResult, error) {
	var crlData []byte
	var err error

	// Загружаем CRL из файла или URL
	if isURL(crlSource) {
		crlData, err = cc.downloadCRL(crlSource)
	} else {
		crlData, err = os.ReadFile(crlSource)
	}
	if err != nil {
		return &CRLResult{Status: "error", Error: err}, err
	}

	// Парсим CRL
	block, _ := pem.Decode(crlData)
	if block == nil {
		return &CRLResult{Status: "error", Error: fmt.Errorf("не удалось декодировать PEM")}, nil
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return &CRLResult{Status: "error", Error: fmt.Errorf("ошибка парсинга CRL: %w", err)}, err
	}

	// Проверяем подпись CRL
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return &CRLResult{Status: "error", Error: fmt.Errorf("неверная подпись CRL: %w", err)}, err
	}

	// Проверяем свежесть CRL
	fresh := time.Now().UTC().Before(crl.NextUpdate)

	// Ищем сертификат в списке отозванных
	for _, rc := range crl.RevokedCertificates {
		if rc.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			reason := "unspecified"
			reasonCode := 0

			// Извлекаем reason code из расширений
			for _, ext := range rc.Extensions {
				// OID для Reason Code = 2.5.29.21
				if ext.Id.Equal([]int{2, 5, 29, 21}) {
					var code asn1.Enumerated
					rest, err := asn1.Unmarshal(ext.Value, &code)
					if err == nil && len(rest) == 0 {
						reasonCode = int(code)
						reason = ReasonCodeToString(reasonCode)
					}
					break
				}
			}

			return &CRLResult{
				Status:       "revoked",
				RevokedAt:    rc.RevocationTime,
				ReasonCode:   reasonCode,
				ReasonString: reason,
				Fresh:        fresh,
			}, nil
		}
	}

	// Сертификат не найден в CRL
	return &CRLResult{
		Status: "good",
		Fresh:  fresh,
	}, nil
}

func (cc *CRLChecker) downloadCRL(url string) ([]byte, error) {
	resp, err := cc.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("ошибка загрузки CRL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ошибка HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func isURL(s string) bool {
	return len(s) > 7 && (s[:7] == "http://" || s[:8] == "https://")
}
