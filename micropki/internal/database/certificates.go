package database

import (
	"crypto/x509"
	"crypto/ecdsa"
	"crypto/rsa"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"MicroPKI/internal/logger"
)

type CertificateRecord struct {
	ID               int64
	SerialHex        string
	Subject          string
	Issuer           string
	NotBefore        time.Time
	NotAfter         time.Time
	CertPEM          string
	Status           string
	RevocationReason sql.NullString
	RevocationDate   sql.NullTime
	CreatedAt        time.Time
	CommonName       string
	KeyType          string
	KeySize          int
}

func (d *Database) InsertCertificate(cert *x509.Certificate, certPEM []byte, status string) error {
	logger.Info("вставка сертификата в БД: serial=%x, subject=%s", cert.SerialNumber, cert.Subject.CommonName)

	commonName := cert.Subject.CommonName
	if commonName == "" && len(cert.Subject.Names) > 0 {
		for _, name := range cert.Subject.Names {
			if name.Type.String() == "2.5.4.3" {
				if cn, ok := name.Value.(string); ok {
					commonName = cn
					break
				}
			}
		}
	}

	keyType, keySize := getKeyInfo(cert.PublicKey)

	tx, err := d.BeginTx()
	if err != nil {
		return fmt.Errorf("ошибка начала транзакции: %w", err)
	}
	defer tx.Rollback()

	query := `
	INSERT INTO certificates (
		serial_hex, subject, issuer, not_before, not_after, cert_pem, 
		status, created_at, common_name, key_type, key_size
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = tx.Exec(query,
		hex.EncodeToString(cert.SerialNumber.Bytes()),
		cert.Subject.String(),
		cert.Issuer.String(),
		cert.NotBefore.UTC().Format(time.RFC3339),
		cert.NotAfter.UTC().Format(time.RFC3339),
		string(certPEM),
		status,
		time.Now().UTC().Format(time.RFC3339),
		commonName,
		keyType,
		keySize,
	)

	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			logger.Error("попытка вставить дубликат серийного номера: %x", cert.SerialNumber)
			return fmt.Errorf("сертификат с серийным номером %x уже существует", cert.SerialNumber)
		}
		logger.Error("ошибка вставки сертификата: %v", err)
		return fmt.Errorf("ошибка вставки сертификата: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ошибка коммита транзакции: %w", err)
	}

	auditData := map[string]interface{}{
		"action":        "certificate_inserted",
		"serial_number": hex.EncodeToString(cert.SerialNumber.Bytes()),
		"subject":       cert.Subject.String(),
		"common_name":   commonName,
		"issuer":        cert.Issuer.String(),
		"status":        status,
		"not_before":    cert.NotBefore.UTC().Format(time.RFC3339),
		"not_after":     cert.NotAfter.UTC().Format(time.RFC3339),
		"key_type":      keyType,
		"key_size":      keySize,
	}
	logger.AuditJSON("certificate_inserted", auditData)

	logger.Info("сертификат успешно вставлен: serial=%x", cert.SerialNumber)
	return nil
}

func (d *Database) InsertCertificateTx(tx *sql.Tx, cert *x509.Certificate, certPEM []byte, status string) error {
    if tx == nil {
        return fmt.Errorf("tx не может быть nil")
    }
    
    logger.Info("вставка сертификата в БД (транзакция): serial=%x, subject=%s", cert.SerialNumber, cert.Subject.CommonName)

    commonName := cert.Subject.CommonName
    if commonName == "" && len(cert.Subject.Names) > 0 {
        for _, name := range cert.Subject.Names {
            if name.Type.String() == "2.5.4.3" {
                if cn, ok := name.Value.(string); ok {
                    commonName = cn
                    break
                }
            }
        }
    }

    keyType, keySize := getKeyInfo(cert.PublicKey)

    query := `
    INSERT INTO certificates (
        serial_hex, subject, issuer, not_before, not_after, cert_pem, 
        status, created_at, common_name, key_type, key_size
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `

    _, err := tx.Exec(query,
        hex.EncodeToString(cert.SerialNumber.Bytes()),
        cert.Subject.String(),
        cert.Issuer.String(),
        cert.NotBefore.UTC().Format(time.RFC3339),
        cert.NotAfter.UTC().Format(time.RFC3339),
        string(certPEM),
        status,
        time.Now().UTC().Format(time.RFC3339),
        commonName,
        keyType,
        keySize,
    )

    if err != nil {
        if strings.Contains(err.Error(), "UNIQUE constraint failed") {
            logger.Error("попытка вставить дубликат серийного номера: %x", cert.SerialNumber)
            return fmt.Errorf("сертификат с серийным номером %x уже существует", cert.SerialNumber)
        }
        logger.Error("ошибка вставки сертификата: %v", err)
        return fmt.Errorf("ошибка вставки сертификата: %w", err)
    }

    logger.Info("сертификат успешно вставлен (транзакция): serial=%x", cert.SerialNumber)
    return nil
}

func (d *Database) GetCertificateBySerial(serialHex string) (*CertificateRecord, error) {
	logger.Info("поиск сертификата по серийному номеру: %s", serialHex)

	query := `
	SELECT id, serial_hex, subject, issuer, not_before, not_after, cert_pem,
		   status, revocation_reason, revocation_date, created_at, common_name
	FROM certificates 
	WHERE serial_hex = ?
	`

	row := d.DB.QueryRow(query, serialHex)

	var record CertificateRecord
	var notBeforeStr, notAfterStr, createdAtStr string
	var revocationDateStr sql.NullString

	err := row.Scan(
		&record.ID,
		&record.SerialHex,
		&record.Subject,
		&record.Issuer,
		&notBeforeStr,
		&notAfterStr,
		&record.CertPEM,
		&record.Status,
		&record.RevocationReason,
		&revocationDateStr,
		&createdAtStr,
		&record.CommonName,
	)

	if err == sql.ErrNoRows {
		logger.Info("сертификат с серийным номером %s не найден", serialHex)
		return nil, nil
	}
	if err != nil {
		logger.Error("ошибка запроса сертификата: %v", err)
		return nil, fmt.Errorf("ошибка запроса сертификата: %w", err)
	}

	record.NotBefore, _ = time.Parse(time.RFC3339, notBeforeStr)
	record.NotAfter, _ = time.Parse(time.RFC3339, notAfterStr)
	record.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)

	if revocationDateStr.Valid {
		var t time.Time
		t, _ = time.Parse(time.RFC3339, revocationDateStr.String)
		record.RevocationDate = sql.NullTime{Time: t, Valid: true}
	}

	logger.Info("сертификат найден: subject=%s", record.Subject)
	return &record, nil
}

func (d *Database) ListCertificates(status string, issuer string, daysUntilExpiry int) ([]*CertificateRecord, error) {
	logger.Info("получение списка сертификатов: status=%s, issuer=%s", status, issuer)

	query := `
	SELECT id, serial_hex, subject, issuer, not_before, not_after, cert_pem,
		   status, revocation_reason, revocation_date, created_at, common_name
	FROM certificates
	WHERE 1=1
	`
	args := []interface{}{}

	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}

	if issuer != "" {
		query += " AND issuer LIKE ?"
		args = append(args, "%"+issuer+"%")
	}

	if daysUntilExpiry > 0 {
		query += " AND datetime(not_after) <= datetime('now', '+' || ? || ' days')"
		args = append(args, daysUntilExpiry)
	}

	query += " ORDER BY not_before DESC"

	rows, err := d.DB.Query(query, args...)
	if err != nil {
		logger.Error("ошибка запроса списка сертификатов: %v", err)
		return nil, fmt.Errorf("ошибка запроса списка сертификатов: %w", err)
	}
	defer rows.Close()

	var records []*CertificateRecord
	for rows.Next() {
		var record CertificateRecord
		var notBeforeStr, notAfterStr, createdAtStr string
		var revocationDateStr sql.NullString

		err := rows.Scan(
			&record.ID,
			&record.SerialHex,
			&record.Subject,
			&record.Issuer,
			&notBeforeStr,
			&notAfterStr,
			&record.CertPEM,
			&record.Status,
			&record.RevocationReason,
			&revocationDateStr,
			&createdAtStr,
			&record.CommonName,
		)
		if err != nil {
			logger.Error("ошибка сканирования записи: %v", err)
			continue
		}

		record.NotBefore, _ = time.Parse(time.RFC3339, notBeforeStr)
		record.NotAfter, _ = time.Parse(time.RFC3339, notAfterStr)
		record.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)

		if revocationDateStr.Valid {
			var t time.Time
			t, _ = time.Parse(time.RFC3339, revocationDateStr.String)
			record.RevocationDate = sql.NullTime{Time: t, Valid: true}
		}

		records = append(records, &record)
	}

	logger.Info("найдено %d сертификатов", len(records))
	return records, nil
}

func (d *Database) UpdateCertificateStatus(serialHex string, status string, reason string) error {
	logger.Info("обновление статуса сертификата: serial=%s, status=%s", serialHex, status)

	query := `
	UPDATE certificates 
	SET status = ?, 
		revocation_reason = ?,
		revocation_date = CASE WHEN ? = 'revoked' THEN datetime('now') ELSE NULL END
	WHERE serial_hex = ?
	`

	result, err := d.DB.Exec(query, status, reason, status, serialHex)
	if err != nil {
		logger.Error("ошибка обновления статуса: %v", err)
		return fmt.Errorf("ошибка обновления статуса: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		logger.Warn("сертификат с серийным номером %s не найден", serialHex)
		return fmt.Errorf("сертификат с серийным номером %s не найден", serialHex)
	}

	auditData := map[string]interface{}{
		"action":         "certificate_status_updated",
		"serial_number":  serialHex,
		"new_status":     status,
		"reason":         reason,
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
	}
	logger.AuditJSON("status_updated", auditData)

	logger.Info("статус сертификата обновлен")
	return nil
}

func (d *Database) GetRevokedCertificates() ([]*CertificateRecord, error) {
	logger.Info("получение списка отозванных сертификатов")

	query := `
	SELECT id, serial_hex, subject, issuer, not_before, not_after, cert_pem,
		   status, revocation_reason, revocation_date, created_at, common_name
	FROM certificates
	WHERE status = 'revoked'
	ORDER BY revocation_date DESC
	`

	rows, err := d.DB.Query(query)
	if err != nil {
		logger.Error("ошибка запроса отозванных сертификатов: %v", err)
		return nil, fmt.Errorf("ошибка запроса отозванных сертификатов: %w", err)
	}
	defer rows.Close()

	var records []*CertificateRecord
	for rows.Next() {
		var record CertificateRecord
		var notBeforeStr, notAfterStr, createdAtStr string
		var revocationDateStr sql.NullString

		err := rows.Scan(
			&record.ID,
			&record.SerialHex,
			&record.Subject,
			&record.Issuer,
			&notBeforeStr,
			&notAfterStr,
			&record.CertPEM,
			&record.Status,
			&record.RevocationReason,
			&revocationDateStr,
			&createdAtStr,
			&record.CommonName,
		)
		if err != nil {
			logger.Error("ошибка сканирования записи: %v", err)
			continue
		}

		record.NotBefore, _ = time.Parse(time.RFC3339, notBeforeStr)
		record.NotAfter, _ = time.Parse(time.RFC3339, notAfterStr)
		record.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)

		if revocationDateStr.Valid {
			var t time.Time
			t, _ = time.Parse(time.RFC3339, revocationDateStr.String)
			record.RevocationDate = sql.NullTime{Time: t, Valid: true}
		}

		records = append(records, &record)
	}

	logger.Info("найдено %d отозванных сертификатов", len(records))
	return records, nil
}

func ParseCertFromPEM(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func getKeyInfo(pubKey interface{}) (string, int) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return "rsa", key.N.BitLen()
	case *ecdsa.PublicKey:
		return "ecc", key.Curve.Params().BitSize
	default:
		return "unknown", 0
	}
}
