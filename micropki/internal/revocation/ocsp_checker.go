package revocation

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

type OCSPChecker struct {
	client *http.Client
}

func NewOCSPChecker() *OCSPChecker {
	return &OCSPChecker{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

type OCSPResult struct {
	Status       string
	RevokedAt    time.Time
	ReasonCode   int
	ReasonString string
	Error        error
}

// CheckCertificate проверяет сертификат через OCSP
func (oc *OCSPChecker) CheckCertificate(cert, issuer *x509.Certificate, ocspURL string) (*OCSPResult, error) {
	// Создаем OCSP запрос
	opts := &ocsp.RequestOptions{
		Hash: crypto.SHA1,
	}
	ocspReq, err := ocsp.CreateRequest(cert, issuer, opts)
	if err != nil {
		return &OCSPResult{Status: "error", Error: err}, err
	}

	// Отправляем запрос
	httpReq, err := http.NewRequest("POST", ocspURL, bytes.NewReader(ocspReq))
	if err != nil {
		return &OCSPResult{Status: "error", Error: err}, err
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")

	resp, err := oc.client.Do(httpReq)
	if err != nil {
		return &OCSPResult{Status: "error", Error: fmt.Errorf("ошибка OCSP запроса: %w", err)}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &OCSPResult{Status: "error", Error: fmt.Errorf("ошибка HTTP %d", resp.StatusCode)}, nil
	}

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return &OCSPResult{Status: "error", Error: err}, err
	}

	// Парсим ответ
	ocspResp, err := ocsp.ParseResponse(respData, issuer)
	if err != nil {
		return &OCSPResult{Status: "error", Error: fmt.Errorf("ошибка парсинга OCSP ответа: %w", err)}, err
	}

	// Преобразуем статус
	result := &OCSPResult{}
	switch ocspResp.Status {
	case ocsp.Good:
		result.Status = "good"
	case ocsp.Revoked:
		result.Status = "revoked"
		result.RevokedAt = ocspResp.RevokedAt
		result.ReasonCode = ocspResp.RevocationReason
		result.ReasonString = ReasonCodeToString(ocspResp.RevocationReason)
	case ocsp.Unknown:
		result.Status = "unknown"
	}

	return result, nil
}