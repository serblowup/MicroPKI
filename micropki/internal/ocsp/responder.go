package ocsp

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"MicroPKI/internal/database"
	"MicroPKI/internal/logger"
	"MicroPKI/internal/ratelimit"
	"golang.org/x/crypto/ocsp"
)

type OCSPResponder struct {
	db            *database.Database
	issuerManager *IssuerManager
	signerCert    *OCSPResponderCert
	caCert        *x509.Certificate
	cache         *ResponseCache
	cacheTTL      time.Duration
	host          string
	port          int
	rateLimiter   *ratelimit.RateLimiter
}

func NewOCSPResponder(
	db *database.Database,
	responderCertPath, responderKeyPath, caCertPath string,
	cacheTTLSeconds int,
	host string,
	port int,
) (*OCSPResponder, error) {
	signerCert, err := LoadOCSPResponderCert(responderCertPath, responderKeyPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка загрузки сертификата OCSP-ответчика: %w", err)
	}

	caPEM, err := loadPEMFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка загрузки CA сертификата: %w", err)
	}

	caCert, err := x509.ParseCertificate(caPEM)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга CA сертификата: %w", err)
	}

	issuerManager := NewIssuerManager()
	if _, err := issuerManager.LoadIssuer(caCertPath); err != nil {
		return nil, fmt.Errorf("ошибка загрузки эмитента: %w", err)
	}

	var cache *ResponseCache
	if cacheTTLSeconds > 0 {
		cache = NewResponseCache(time.Duration(cacheTTLSeconds) * time.Second)
	}

	return &OCSPResponder{
		db:            db,
		issuerManager: issuerManager,
		signerCert:    signerCert,
		caCert:        caCert,
		cache:         cache,
		cacheTTL:      time.Duration(cacheTTLSeconds) * time.Second,
		host:          host,
		port:          port,
		rateLimiter:   ratelimit.NewRateLimiter(0, 10), // по умолчанию отключен
	}, nil
}

// SetRateLimit устанавливает ограничение частоты запросов
func (r *OCSPResponder) SetRateLimit(rate float64, burst int) {
	r.rateLimiter = ratelimit.NewRateLimiter(rate, burst)
	if rate > 0 {
		logger.Info("[OCSP] включено ограничение частоты: rate=%.1f/s, burst=%d", rate, burst)
	}
}

func (r *OCSPResponder) HandleOCSPRequest(w http.ResponseWriter, req *http.Request) {
	startTime := time.Now()

	// Rate limiting
	if r.rateLimiter.IsEnabled() {
		clientIP := req.RemoteAddr
		if !r.rateLimiter.Allow(clientIP) {
			retryAfter := r.rateLimiter.GetRetryAfter()
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			w.Header().Set("Content-Type", "application/ocsp-response")
			w.WriteHeader(http.StatusTooManyRequests)
			logger.Warn("[OCSP] превышен лимит частоты для %s", clientIP)
			return
		}
	}

	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if req.Header.Get("Content-Type") != "application/ocsp-request" {
		logger.Warn("[OCSP] неверный Content-Type: %s", req.Header.Get("Content-Type"))
		http.Error(w, "Expected Content-Type: application/ocsp-request", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		logger.Error("[OCSP] ошибка чтения тела запроса: %v", err)
		r.sendErrorResponse(w, NewInternalError("ошибка чтения запроса"))
		return
	}

	if len(body) == 0 {
		logger.Error("[OCSP] пустое тело запроса")
		r.sendErrorResponse(w, NewMalformedRequestError("пустое тело запроса"))
		return
	}

	ocspReq, err := ocsp.ParseRequest(body)
	if err != nil {
		logger.Error("[OCSP] ошибка парсинга запроса: %v", err)
		r.sendErrorResponse(w, NewMalformedRequestError(err.Error()))
		return
	}

	clientIP := req.RemoteAddr
	serialHex := hex.EncodeToString(ocspReq.SerialNumber.Bytes())

	logger.Info("[OCSP] запрос: client=%s, serial=%s", clientIP, serialHex)
	logger.Info("[OCSP]   issuerNameHash=%x", ocspReq.IssuerNameHash)
	logger.Info("[OCSP]   issuerKeyHash=%x", ocspReq.IssuerKeyHash)

	issuer := r.issuerManager.FindByHashes(ocspReq.IssuerNameHash, ocspReq.IssuerKeyHash)
	if issuer == nil {
		logger.Warn("[OCSP] неизвестный эмитент для запроса - возвращаем unknown")

		// Возвращаем ответ со статусом unknown
		template := ocsp.Response{
			Status:       ocsp.Unknown,
			SerialNumber: ocspReq.SerialNumber,
			ThisUpdate:   time.Now().UTC(),
			NextUpdate:   time.Now().UTC().Add(r.cacheTTL),
		}

		// Используем загруженный CA сертификат как issuer для ответа unknown
		respBytes, err := ocsp.CreateResponse(r.caCert, r.signerCert.Certificate, template, r.signerCert.PrivateKey)
		if err != nil {
			logger.Error("[OCSP] ошибка создания ответа unknown: %v", err)
			r.sendErrorResponse(w, NewInternalError("ошибка создания ответа"))
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		w.Write(respBytes)

		processingTime := time.Since(startTime)
		logger.Info("[OCSP] ответ: client=%s, serial=%s, status=unknown, time=%v",
			clientIP, serialHex, processingTime)

		// Аудит
		logger.LogAuditEvent("ocsp_request", "success",
			fmt.Sprintf("OCSP request processed: unknown issuer, serial=%s", serialHex),
			map[string]interface{}{
				"client_ip":       clientIP,
				"serial":          serialHex,
				"status":          "unknown",
				"processing_time": processingTime.Milliseconds(),
				"issuer_found":    false,
			})
		return
	}

	status, revocationTime, revocationReason, err := r.getCertStatus(serialHex)
	if err != nil {
		logger.Error("[OCSP] ошибка получения статуса: %v", err)
		r.sendErrorResponse(w, NewInternalError("ошибка получения статуса"))
		return
	}

	var certStatus int
	switch status {
	case StatusGood:
		certStatus = ocsp.Good
	case StatusRevoked:
		certStatus = ocsp.Revoked
	default:
		certStatus = ocsp.Unknown
	}

	template := ocsp.Response{
		Status:           certStatus,
		SerialNumber:     ocspReq.SerialNumber,
		ThisUpdate:       time.Now().UTC(),
		NextUpdate:       time.Now().UTC().Add(r.cacheTTL),
		RevokedAt:        revocationTime,
		RevocationReason: revocationReason,
	}

	respBytes, err := ocsp.CreateResponse(issuer.Certificate, r.signerCert.Certificate, template, r.signerCert.PrivateKey)
	if err != nil {
		logger.Error("[OCSP] ошибка создания ответа: %v", err)
		r.sendErrorResponse(w, NewInternalError("ошибка создания ответа"))
		return
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)

	processingTime := time.Since(startTime)
	logger.Info("[OCSP] ответ: client=%s, serial=%s, status=%s, time=%v",
		clientIP, serialHex, status.String(), processingTime)

	// Аудит
	logger.LogAuditEvent("ocsp_request", "success",
		fmt.Sprintf("OCSP request processed: status=%s, serial=%s", status.String(), serialHex),
		map[string]interface{}{
			"client_ip":       clientIP,
			"serial":          serialHex,
			"status":          status.String(),
			"processing_time": processingTime.Milliseconds(),
			"issuer_found":    true,
		})
}

func (r *OCSPResponder) getCertStatus(serialHex string) (CertStatus, time.Time, int, error) {
	if r.cache != nil {
		if cached, found := r.cache.Get(serialHex); found {
			return cached.CertStatus, cached.RevocationTime, cached.RevocationReason, nil
		}
	}

	record, err := r.db.GetCertificateBySerial(serialHex)
	if err != nil {
		return StatusUnknown, time.Time{}, 0, fmt.Errorf("ошибка запроса БД: %w", err)
	}

	var status CertStatus
	var revocationTime time.Time
	var reasonCode int

	if record == nil {
		status = StatusUnknown
	} else {
		switch record.Status {
		case "valid":
			status = StatusGood
		case "revoked":
			status = StatusRevoked
			if record.RevocationDate.Valid {
				revocationTime = record.RevocationDate.Time
			}
			if record.RevocationReason.Valid {
				reasonCode = reasonStringToCode(record.RevocationReason.String)
			}
		default:
			status = StatusUnknown
		}
	}

	if r.cache != nil && status != StatusUnknown {
		resp := &OCSPResponse{
			CertStatus:       status,
			RevocationTime:   revocationTime,
			RevocationReason: reasonCode,
			ProducedAt:       time.Now().UTC(),
			ThisUpdate:       time.Now().UTC(),
			NextUpdate:       time.Now().UTC().Add(r.cacheTTL),
		}
		r.cache.Set(serialHex, resp)
	}

	return status, revocationTime, reasonCode, nil
}

func (r *OCSPResponder) sendErrorResponse(w http.ResponseWriter, err *OCSPError) {
	logger.Error("[OCSP] ошибка: %v", err)

	var status int
	switch err.Code {
	case MalformedRequest:
		status = 1
	case InternalError:
		status = 2
	case TryLater:
		status = 3
	case Unauthorized:
		status = 6
	default:
		status = 2
	}

	// Простой OCSP ответ с ошибкой
	respBytes := []byte{
		0x30, 0x03,
		0x0a, 0x01, byte(status),
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)

	// Аудит ошибки
	logger.LogAuditError("ocsp_error", err.Error(),
		map[string]interface{}{
			"error_code":    err.Code,
			"error_message": err.Message,
		})
}

func loadPEMFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM")
	}

	return block.Bytes, nil
}

func reasonStringToCode(reason string) int {
	reasons := map[string]int{
		"unspecified":          0,
		"keyCompromise":        1,
		"cACompromise":         2,
		"affiliationChanged":   3,
		"superseded":           4,
		"cessationOfOperation": 5,
		"certificateHold":      6,
		"removeFromCRL":        8,
		"privilegeWithdrawn":   9,
		"aACompromise":         10,
	}
	if code, ok := reasons[reason]; ok {
		return code
	}
	return 0
}

// GetRateLimiter возвращает rate limiter для внешней настройки
func (r *OCSPResponder) GetRateLimiter() *ratelimit.RateLimiter {
	return r.rateLimiter
}

// Close останавливает OCSP responder и освобождает ресурсы
func (r *OCSPResponder) Close() error {
	if r.cache != nil {
		r.cache.Close()
	}
	if r.rateLimiter != nil {
		r.rateLimiter.Close()
	}
	return nil
}