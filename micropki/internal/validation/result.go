package validation

import (
    "crypto/x509"
    "encoding/json"
    "time"
)

type ValidationStep struct {
    Certificate *x509.Certificate `json:"-"`
    CertSubject string            `json:"certificate"`
    Check       string            `json:"check"`
    Passed      bool              `json:"passed"`
    Error       string            `json:"error,omitempty"`
}

type ValidationResult struct {
    Valid       bool              `json:"valid"`
    Error       string            `json:"error,omitempty"`
    Steps       []ValidationStep  `json:"steps"`
    Timestamp   time.Time         `json:"timestamp"`
    ChainLength int               `json:"chain_length"`
    Revocation  *RevocationResult `json:"revocation,omitempty"`
}

func (vr *ValidationResult) ToJSON() ([]byte, error) {
    result := struct {
        Valid       bool              `json:"valid"`
        Error       string            `json:"error,omitempty"`
        Steps       []ValidationStep  `json:"steps"`
        Timestamp   time.Time         `json:"timestamp"`
        ChainLength int               `json:"chain_length"`
        Revocation  *RevocationResult `json:"revocation,omitempty"`
    }{
        Valid:       vr.Valid,
        Error:       vr.Error,
        Timestamp:   vr.Timestamp,
        ChainLength: vr.ChainLength,
        Revocation:  vr.Revocation,
        Steps:       make([]ValidationStep, len(vr.Steps)),
    }
    
    for i, step := range vr.Steps {
        result.Steps[i] = step
        if step.Certificate != nil {
            result.Steps[i].CertSubject = step.Certificate.Subject.String()
        }
    }
    
    return json.MarshalIndent(result, "", "  ")
}

type RevocationResult struct {
    Checked      bool      `json:"checked"`
    Method       string    `json:"method,omitempty"`
    Status       string    `json:"status"`
    RevokedAt    time.Time `json:"revoked_at,omitempty"`
    Reason       string    `json:"reason,omitempty"`
    Error        string    `json:"error,omitempty"`
}