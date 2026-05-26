package validation

import (
    "crypto/x509"
    "fmt"
    "time"
)

type ValidationOptions struct {
    CurrentTime  time.Time
    CheckRevocation bool
    RequiredKeyUsage x509.KeyUsage
    RequiredExtKeyUsage []x509.ExtKeyUsage
}

type PathValidator struct {
    opts ValidationOptions
}

func NewPathValidator(opts ValidationOptions) *PathValidator {
    if opts.CurrentTime.IsZero() {
        opts.CurrentTime = time.Now().UTC()
    }
    return &PathValidator{opts: opts}
}

// ValidatePath выполняет базовые проверки согласно RFC 5280
func (pv *PathValidator) ValidatePath(path []*x509.Certificate) (*ValidationResult, error) {
    result := &ValidationResult{
        Valid: true,
        Steps: make([]ValidationStep, 0),
    }
    
    if len(path) == 0 {
        result.Valid = false
        result.Error = "пустой путь сертификации"
        return result, fmt.Errorf(result.Error)
    }
    
    leaf := path[0]
    root := path[len(path)-1]
    
    if !root.IsCA {
        result.Valid = false
        result.Error = "корневой сертификат не является CA"
        result.Steps = append(result.Steps, ValidationStep{
            Certificate: leaf,
            Check:       "root_is_ca",
            Passed:      false,
            Error:       result.Error,
        })
        return result, fmt.Errorf(result.Error)
    }
    
    // Проверяем каждый сертификат в цепочке
    for i := 0; i < len(path)-1; i++ {
        cert := path[i]
        issuer := path[i+1]
        
        // Проверка подписи
        if err := cert.CheckSignatureFrom(issuer); err != nil {
            result.Valid = false
            result.Error = fmt.Sprintf("неверная подпись сертификата %v", cert.Subject)
            result.Steps = append(result.Steps, ValidationStep{
                Certificate: cert,
                Check:       "signature",
                Passed:      false,
                Error:       err.Error(),
            })
            return result, fmt.Errorf(result.Error)
        }
        result.Steps = append(result.Steps, ValidationStep{
            Certificate: cert,
            Check:       "signature",
            Passed:      true,
        })
        
        // Проверка срока действия
        if pv.opts.CurrentTime.Before(cert.NotBefore) {
            result.Valid = false
            result.Error = fmt.Sprintf("сертификат %v еще не действителен", cert.Subject)
            result.Steps = append(result.Steps, ValidationStep{
                Certificate: cert,
                Check:       "validity",
                Passed:      false,
                Error:       result.Error,
            })
            return result, fmt.Errorf(result.Error)
        }
        if pv.opts.CurrentTime.After(cert.NotAfter) {
            result.Valid = false
            result.Error = fmt.Sprintf("срок действия сертификата %v истек", cert.Subject)
            result.Steps = append(result.Steps, ValidationStep{
                Certificate: cert,
                Check:       "validity",
                Passed:      false,
                Error:       result.Error,
            })
            return result, fmt.Errorf(result.Error)
        }
        result.Steps = append(result.Steps, ValidationStep{
            Certificate: cert,
            Check:       "validity",
            Passed:      true,
        })
        
        // Проверка Basic Constraints
        if err := pv.ValidateBasicConstraints(cert, issuer, i == len(path)-2); err != nil {
            result.Valid = false
            result.Error = err.Error()
            result.Steps = append(result.Steps, ValidationStep{
                Certificate: cert,
                Check:       "basic_constraints",
                Passed:      false,
                Error:       err.Error(),
            })
            return result, err
        }
        result.Steps = append(result.Steps, ValidationStep{
            Certificate: cert,
            Check:       "basic_constraints",
            Passed:      true,
        })
        
        // Проверка Key Usage
        if err := pv.validateKeyUsage(cert, issuer); err != nil {
            result.Valid = false
            result.Error = err.Error()
            result.Steps = append(result.Steps, ValidationStep{
                Certificate: cert,
                Check:       "key_usage",
                Passed:      false,
                Error:       err.Error(),
            })
            return result, err
        }
        result.Steps = append(result.Steps, ValidationStep{
            Certificate: cert,
            Check:       "key_usage",
            Passed:      true,
        })
    }
    
    return result, nil
}

// ValidateBasicConstraints проверяет Basic Constraints
func (pv *PathValidator) ValidateBasicConstraints(cert, issuer *x509.Certificate, isLastCA bool) error {
	// Для конечного сертификата
	if !isLastCA && cert.IsCA {
		return fmt.Errorf("конечный сертификат не должен быть CA")
	}
	
	// Для промежуточных CA
	if cert.IsCA && !isLastCA {
		// Проверяем pathLenConstraint
		if cert.MaxPathLenZero && !isLastCA {
			return fmt.Errorf("pathLenConstraint=0, но сертификат используется для выпуска других сертификатов")
		}
	}
	
	return nil
}

func (pv *PathValidator) validateKeyUsage(cert, issuer *x509.Certificate) error {
    // Для CA сертификатов проверяем keyCertSign
    if cert.IsCA {
        if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
            return fmt.Errorf("CA сертификат должен иметь keyCertSign")
        }
    }
    
    // Для конечных сертификатов проверяем требуемые KeyUsage
    if !cert.IsCA && pv.opts.RequiredKeyUsage != 0 {
        if cert.KeyUsage&pv.opts.RequiredKeyUsage != pv.opts.RequiredKeyUsage {
            return fmt.Errorf("отсутствуют требуемые KeyUsage: 0x%x", pv.opts.RequiredKeyUsage)
        }
    }
    
    return nil
}