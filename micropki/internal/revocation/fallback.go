package revocation

import (
	"crypto/x509"

	"MicroPKI/internal/validation"
)

type RevocationChecker struct {
	ocspChecker *OCSPChecker
	crlChecker  *CRLChecker
}

func NewRevocationChecker() *RevocationChecker {
	return &RevocationChecker{
		ocspChecker: NewOCSPChecker(),
		crlChecker:  NewCRLChecker(),
	}
}

type RevocationCheckOptions struct {
	Cert          *x509.Certificate
	Issuer        *x509.Certificate
	OCSPURL       string
	CRLSource     string
	PreferOCSP    bool
	FallbackToCRL bool
}

// CheckStatus выполняет проверку статуса с fallback логикой
func (rc *RevocationChecker) CheckStatus(opts *RevocationCheckOptions) (*validation.RevocationResult, error) {
	result := &validation.RevocationResult{
		Checked: true,
	}

	// Определяем OCSP URL
	ocspURL := opts.OCSPURL
	if ocspURL == "" && opts.PreferOCSP {
		var err error
		ocspURL, err = validation.ExtractOCSPURL(opts.Cert)
		if err != nil {
			// OCSP URL не найден, переходим к CRL
			opts.PreferOCSP = false
		}
	}

	// Пробуем OCSP
	if opts.PreferOCSP && ocspURL != "" {
		ocspResult, err := rc.ocspChecker.CheckCertificate(opts.Cert, opts.Issuer, ocspURL)
		if err == nil && ocspResult.Status != "error" && ocspResult.Status != "unknown" {
			result.Method = "ocsp"
			result.Status = ocspResult.Status
			result.RevokedAt = ocspResult.RevokedAt
			result.Reason = ocspResult.ReasonString

			if ocspResult.Status == "good" || ocspResult.Status == "revoked" {
				return result, nil
			}
		}

		// OCSP не дал определенного результата
		if !opts.FallbackToCRL {
			result.Status = "unknown"
			result.Error = "OCSP не дал определенного результата"
			return result, nil
		}
	}

	// Fallback на CRL
	if opts.FallbackToCRL {
		crlSource := opts.CRLSource
		if crlSource == "" {
			urls, err := validation.ExtractCRLURLs(opts.Cert)
			if err == nil && len(urls) > 0 {
				crlSource = urls[0]
			}
		}

		if crlSource != "" {
			crlResult, err := rc.crlChecker.CheckCertificate(opts.Cert, opts.Issuer, crlSource)
			if err == nil && crlResult.Status != "error" {
				result.Method = "crl"
				result.Status = crlResult.Status
				result.RevokedAt = crlResult.RevokedAt
				result.Reason = crlResult.ReasonString

				if !crlResult.Fresh {
					result.Error = "CRL устарел"
				}

				return result, nil
			}
		}
	}

	// Оба метода не дали результата
	result.Status = "unknown"
	result.Error = "не удалось проверить статус отзыва"
	return result, nil
}