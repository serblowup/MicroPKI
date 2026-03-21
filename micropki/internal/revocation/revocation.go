package revocation

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"MicroPKI/internal/database"
	"MicroPKI/internal/logger"
)

type RevokedCertInfo struct {
	SerialNumber   *big.Int
	RevocationTime time.Time
	ReasonCode     int
	ReasonString   string
}

func ReasonCodeToInt(reason string) (int, error) {
	reasonMap := map[string]int{
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

	code, ok := reasonMap[reason]
	if !ok {
		return -1, fmt.Errorf("неподдерживаемый код причины отзыва: %s", reason)
	}
	return code, nil
}

func ReasonCodeToString(code int) string {
	reasonMap := map[int]string{
		0:  "unspecified",
		1:  "keyCompromise",
		2:  "cACompromise",
		3:  "affiliationChanged",
		4:  "superseded",
		5:  "cessationOfOperation",
		6:  "certificateHold",
		8:  "removeFromCRL",
		9:  "privilegeWithdrawn",
		10: "aACompromise",
	}

	if str, ok := reasonMap[code]; ok {
		return str
	}
	return "unknown"
}

func RevokeCertificate(db *database.Database, serialHex string, reasonCode int, force bool) error {
	record, err := db.GetCertificateBySerial(serialHex)
	if err != nil {
		return fmt.Errorf("ошибка поиска сертификата: %w", err)
	}
	if record == nil {
		return fmt.Errorf("сертификат с серийным номером %s не найден", serialHex)
	}

	if record.Status == "revoked" {
		logger.Warn("сертификат %s уже отозван", serialHex)
		return nil
	}

	reasonStr := ReasonCodeToString(reasonCode)

	if !force {
		logger.Info("отзыв сертификата %s (subject=%s) с причиной %s", serialHex, record.Subject, reasonStr)
	}

	err = db.UpdateCertificateStatus(serialHex, "revoked", reasonStr)
	if err != nil {
		return fmt.Errorf("ошибка обновления статуса: %w", err)
	}

	logger.Info("сертификат %s успешно отозван, причина: %s", serialHex, reasonStr)

	auditData := map[string]interface{}{
		"action":        "certificate_revoked",
		"serial_number": serialHex,
		"subject":       record.Subject,
		"reason":        reasonStr,
		"reason_code":   reasonCode,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	}
	logger.AuditJSON("certificate_revoked", auditData)

	return nil
}

func GetRevokedCertificatesByIssuer(db *database.Database, issuerSubject string) ([]RevokedCertInfo, error) {
	records, err := db.GetRevokedCertificatesByIssuer(issuerSubject)
	if err != nil {
		return nil, fmt.Errorf("ошибка получения отозванных сертификатов: %w", err)
	}

	var result []RevokedCertInfo
	for _, r := range records {
		serialBytes, err := hex.DecodeString(r.SerialHex)
		if err != nil {
			logger.Warn("не удалось декодировать серийный номер %s: %v", r.SerialHex, err)
			continue
		}
		serial := new(big.Int).SetBytes(serialBytes)

		reasonCode := 0
		if r.RevocationReason.Valid {
			reasonCode, _ = ReasonCodeToInt(r.RevocationReason.String)
		}

		revocationTime := time.Now().UTC()
		if r.RevocationDate.Valid {
			revocationTime = r.RevocationDate.Time
		}

		result = append(result, RevokedCertInfo{
			SerialNumber:   serial,
			RevocationTime: revocationTime,
			ReasonCode:     reasonCode,
			ReasonString:   r.RevocationReason.String,
		})
	}

	return result, nil
}

func CheckRevoked(db *database.Database, serialHex string) (bool, *RevokedCertInfo, error) {
	record, err := db.GetCertificateBySerial(serialHex)
	if err != nil {
		return false, nil, fmt.Errorf("ошибка поиска сертификата: %w", err)
	}
	if record == nil {
		return false, nil, fmt.Errorf("сертификат с серийным номером %s не найден", serialHex)
	}

	if record.Status != "revoked" {
		return false, nil, nil
	}

	serialBytes, err := hex.DecodeString(record.SerialHex)
	if err != nil {
		return false, nil, fmt.Errorf("ошибка декодирования серийного номера: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)

	reasonCode := 0
	if record.RevocationReason.Valid {
		reasonCode, _ = ReasonCodeToInt(record.RevocationReason.String)
	}

	revocationTime := time.Now().UTC()
	if record.RevocationDate.Valid {
		revocationTime = record.RevocationDate.Time
	}

	info := &RevokedCertInfo{
		SerialNumber:   serial,
		RevocationTime: revocationTime,
		ReasonCode:     reasonCode,
		ReasonString:   record.RevocationReason.String,
	}

	return true, info, nil
}
