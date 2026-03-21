package crl

import (
	"database/sql"
	"fmt"
	"time"

	"MicroPKI/internal/database"
	"MicroPKI/internal/logger"
)

type CRLMetadata struct {
	ID            int64
	CASubject     string
	CRLNumber     int64
	LastGenerated time.Time
	NextUpdate    time.Time
	CRLPath       string
}

func GetNextCRLNumber(db *database.Database, caSubject string) (int64, error) {
	var number int64
	var lastGenerated sql.NullString

	query := `SELECT crl_number, last_generated FROM crl_metadata WHERE ca_subject = ?`
	err := db.DB.QueryRow(query, caSubject).Scan(&number, &lastGenerated)

	if err == sql.ErrNoRows {
		return 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("ошибка получения номера CRL: %w", err)
	}

	return number + 1, nil
}

func UpdateCRLMetadata(db *database.Database, caSubject string, crlNumber int64, nextUpdate time.Time, crlPath string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	nextUpdateStr := nextUpdate.UTC().Format(time.RFC3339)

	var count int
	err := db.DB.QueryRow("SELECT COUNT(*) FROM crl_metadata WHERE ca_subject = ?", caSubject).Scan(&count)
	if err != nil {
		return fmt.Errorf("ошибка проверки существования записи: %w", err)
	}

	if count == 0 {
		query := `INSERT INTO crl_metadata (ca_subject, crl_number, last_generated, next_update, crl_path)
				  VALUES (?, ?, ?, ?, ?)`
		_, err = db.DB.Exec(query, caSubject, crlNumber, now, nextUpdateStr, crlPath)
	} else {
		query := `UPDATE crl_metadata 
				  SET crl_number = ?, last_generated = ?, next_update = ?, crl_path = ?
				  WHERE ca_subject = ?`
		_, err = db.DB.Exec(query, crlNumber, now, nextUpdateStr, crlPath, caSubject)
	}

	if err != nil {
		return fmt.Errorf("ошибка обновления метаданных CRL: %w", err)
	}

	logger.Info("метаданные CRL обновлены: ca=%s, number=%d", caSubject, crlNumber)
	return nil
}

func GetCRLMetadata(db *database.Database, caSubject string) (*CRLMetadata, error) {
	var metadata CRLMetadata
	var lastGeneratedStr, nextUpdateStr string

	query := `SELECT id, ca_subject, crl_number, last_generated, next_update, crl_path
			  FROM crl_metadata WHERE ca_subject = ?`
	err := db.DB.QueryRow(query, caSubject).Scan(
		&metadata.ID,
		&metadata.CASubject,
		&metadata.CRLNumber,
		&lastGeneratedStr,
		&nextUpdateStr,
		&metadata.CRLPath,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ошибка получения метаданных CRL: %w", err)
	}

	metadata.LastGenerated, _ = time.Parse(time.RFC3339, lastGeneratedStr)
	metadata.NextUpdate, _ = time.Parse(time.RFC3339, nextUpdateStr)

	return &metadata, nil
}
