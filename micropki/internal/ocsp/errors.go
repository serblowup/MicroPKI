package ocsp

import (
	"encoding/asn1"
	"fmt"
)

type OCSPErrorCode int

const (
	MalformedRequest OCSPErrorCode = 1
	InternalError    OCSPErrorCode = 2
	TryLater         OCSPErrorCode = 3
	SigRequired      OCSPErrorCode = 5
	Unauthorized     OCSPErrorCode = 6
)

type OCSPError struct {
	Code    OCSPErrorCode
	Message string
}

func (e *OCSPError) Error() string {
	return fmt.Sprintf("OCSP error %d: %s", e.Code, e.Message)
}

func NewMalformedRequestError(msg string) *OCSPError {
	return &OCSPError{
		Code:    MalformedRequest,
		Message: msg,
	}
}

func NewInternalError(msg string) *OCSPError {
	return &OCSPError{
		Code:    InternalError,
		Message: msg,
	}
}

func NewTryLaterError(msg string) *OCSPError {
	return &OCSPError{
		Code:    TryLater,
		Message: msg,
	}
}

func NewUnauthorizedError(msg string) *OCSPError {
	return &OCSPError{
		Code:    Unauthorized,
		Message: msg,
	}
}

func BuildErrorResponse(code OCSPErrorCode) ([]byte, error) {
	// OCSPResponse ::= SEQUENCE {
	//    responseStatus         OCSPResponseStatus,
	//    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
	//
	// OCSPResponseStatus ::= ENUMERATED {
	//    successful            (0),
	//    malformedRequest      (1),
	//    internalError         (2),
	//    tryLater              (3),
	//    sigRequired           (5),
	//    unauthorized          (6) }

	status := asn1.Enumerated(code)
	responseData, err := asn1.Marshal(status)
	if err != nil {
		return nil, err
	}
	return responseData, nil
}
