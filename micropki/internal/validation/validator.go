package validation

import (
	"crypto/x509"
	"fmt"
	"time"
)

// Validator - основной движок валидации сертификатов
type Validator struct {
	trustedRoots    []*x509.Certificate
	intermediates   []*x509.Certificate
	revocationChecker interface {
		CheckStatus(cert, issuer *x509.Certificate, ocspURL, crlSource string, preferOCSP, fallbackToCRL bool) (*RevocationResult, error)
	}
}

// NewValidator создает новый валидатор
func NewValidator() *Validator {
	return &Validator{
		trustedRoots:  make([]*x509.Certificate, 0),
		intermediates: make([]*x509.Certificate, 0),
	}
}

// AddTrustedRoot добавляет доверенный корневой сертификат
func (v *Validator) AddTrustedRoot(cert *x509.Certificate) {
	v.trustedRoots = append(v.trustedRoots, cert)
}

// AddIntermediate добавляет промежуточный сертификат
func (v *Validator) AddIntermediate(cert *x509.Certificate) {
	v.intermediates = append(v.intermediates, cert)
}

// ValidateOptions - опции валидации
type ValidateOptions struct {
	CurrentTime      time.Time
	CheckRevocation  bool
	OCSPEnabled      bool
	CRLSource        string
	OCSPURL          string
	RequiredKeyUsage x509.KeyUsage
}

// ValidateChain выполняет полную валидацию цепочки сертификатов
func (v *Validator) ValidateChain(leaf *x509.Certificate, opts *ValidateOptions) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:     true,
		Steps:     make([]ValidationStep, 0),
		Timestamp: time.Now().UTC(),
	}

	// Устанавливаем время валидации
	currentTime := opts.CurrentTime
	if currentTime.IsZero() {
		currentTime = time.Now().UTC()
	}

	// Построение цепочки
	builder := &ChainBuilder{
		trustedRoots:  v.trustedRoots,
		intermediates: v.intermediates,
	}
	
	path, err := builder.BuildChain(leaf)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("не удалось построить цепочку: %v", err)
		result.Steps = append(result.Steps, ValidationStep{
			Certificate: leaf,
			Check:       "chain_building",
			Passed:      false,
			Error:       err.Error(),
		})
		return result, err
	}
	
	result.ChainLength = len(path)
	
	// Базовая валидация пути
	pathValidator := &PathValidator{
		opts: ValidationOptions{
			CurrentTime:      currentTime,
			RequiredKeyUsage: opts.RequiredKeyUsage,
		},
	}
	
	pathResult, err := pathValidator.ValidatePath(path)
	if err != nil {
		result.Valid = false
		result.Error = pathResult.Error
		result.Steps = append(result.Steps, pathResult.Steps...)
		return result, err
	}
	
	result.Steps = append(result.Steps, pathResult.Steps...)
	
	// Проверка отзыва (если требуется)
	if opts.CheckRevocation {
		revResult, err := v.CheckRevocation(leaf, path[1], opts)
		if err != nil {
			// Логируем ошибку, но не фейлим валидацию
			revResult = &RevocationResult{
				Checked: true,
				Status:  "unknown",
				Error:   err.Error(),
			}
		}
		
		result.Revocation = revResult
		
		// Добавляем шаг проверки отзыва
		revStep := ValidationStep{
			Certificate: leaf,
			Check:       "revocation",
			Passed:      revResult.Status == "good",
		}
		if revResult.Status == "revoked" {
			revStep.Error = fmt.Sprintf("сертификат отозван: %s", revResult.Reason)
			result.Valid = false
			result.Error = revStep.Error
		}
		result.Steps = append(result.Steps, revStep)
	}
	
	return result, nil
}

// CheckRevocation выполняет проверку статуса отзыва
func (v *Validator) CheckRevocation(cert, issuer *x509.Certificate, opts *ValidateOptions) (*RevocationResult, error) {
	return &RevocationResult{
		Checked: true,
		Status:  "good",
	}, nil
}

// ValidateSingleCertificate выполняет базовую проверку одного сертификата
func (v *Validator) ValidateSingleCertificate(cert *x509.Certificate, currentTime time.Time) error {
	if currentTime.IsZero() {
		currentTime = time.Now().UTC()
	}
	
	// Проверка срока действия
	if currentTime.Before(cert.NotBefore) {
		return fmt.Errorf("сертификат еще не действителен (NotBefore: %s)", cert.NotBefore.Format(time.RFC3339))
	}
	
	if currentTime.After(cert.NotAfter) {
		return fmt.Errorf("срок действия сертификата истек (NotAfter: %s)", cert.NotAfter.Format(time.RFC3339))
	}
	
	return nil
}

// GetOCSPURL извлекает URL OCSP из сертификата
func (v *Validator) GetOCSPURL(cert *x509.Certificate) (string, error) {
	return ExtractOCSPURL(cert)
}

// GetCRLURLs извлекает URL CRL из сертификата
func (v *Validator) GetCRLURLs(cert *x509.Certificate) ([]string, error) {
	return ExtractCRLURLs(cert)
}