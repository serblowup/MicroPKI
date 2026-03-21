package database

import (
	"fmt"
	"time"

	"MicroPKI/internal/logger"
)

func GetSchema() string {
	return `
-- Таблица сертификатов
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_hex TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('valid', 'revoked', 'expired')),
    revocation_reason TEXT,
    revocation_date TEXT,
    created_at TEXT NOT NULL,
    
    -- Дополнительные поля для удобства поиска
    common_name TEXT,
    key_type TEXT,
    key_size INTEGER,
    
    -- Временные метки для аудита
    updated_at TEXT
);

-- Индексы для ускорения поиска
CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates(serial_hex);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_certificates_issuer ON certificates(issuer);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_certificates_common_name ON certificates(common_name);

-- Таблица для отслеживания миграций
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL
);

-- Таблица для аудита изменений
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    serial_hex TEXT,
    details TEXT,
    FOREIGN KEY (serial_hex) REFERENCES certificates(serial_hex) ON DELETE SET NULL
);

-- Вставляем запись о версии схемы, если её нет
INSERT OR IGNORE INTO schema_migrations (version, applied_at, description) 
VALUES (1, datetime('now'), 'Initial schema for Sprint 3');

-- Таблица для отслеживания счетчиков серийных номеров
CREATE TABLE IF NOT EXISTS serial_counters (
    counter_name TEXT PRIMARY KEY,
    counter_value INTEGER NOT NULL,
    last_updated TEXT NOT NULL
);

-- Инициализируем счетчик для серийных номеров, если его нет
INSERT OR IGNORE INTO serial_counters (counter_name, counter_value, last_updated) 
VALUES ('serial_counter', 0, datetime('now'));

-- Таблица метаданных CRL
CREATE TABLE IF NOT EXISTS crl_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_subject TEXT NOT NULL,
    crl_number INTEGER NOT NULL,
    last_generated TEXT NOT NULL,
    next_update TEXT NOT NULL,
    crl_path TEXT NOT NULL
);

-- Индекс для crl_metadata
CREATE INDEX IF NOT EXISTS idx_crl_metadata_ca_subject ON crl_metadata(ca_subject);

-- Триггер для автоматического обновления updated_at
CREATE TRIGGER IF NOT EXISTS update_certificates_timestamp 
AFTER UPDATE ON certificates
BEGIN
    UPDATE certificates SET updated_at = datetime('now') WHERE id = NEW.id;
END;

-- Триггер для аудита вставки
CREATE TRIGGER IF NOT EXISTS audit_certificates_insert 
AFTER INSERT ON certificates
BEGIN
    INSERT INTO audit_log (timestamp, action, serial_hex, details)
    VALUES (datetime('now'), 'INSERT', NEW.serial_hex, json_object('subject', NEW.subject, 'issuer', NEW.issuer));
END;

-- Триггер для аудита обновления статуса
CREATE TRIGGER IF NOT EXISTS audit_certificates_status_update 
AFTER UPDATE OF status ON certificates
BEGIN
    INSERT INTO audit_log (timestamp, action, serial_hex, details)
    VALUES (datetime('now'), 'STATUS_UPDATE', NEW.serial_hex, json_object('old_status', OLD.status, 'new_status', NEW.status));
END;
`
}

func GetMigrations() map[int]string {
	return map[int]string{
		1: GetSchema(),
		2: `-- Миграция для добавления индекса по дате отзыва
CREATE INDEX IF NOT EXISTS idx_certificates_revocation_date ON certificates(revocation_date) WHERE status = 'revoked';`,
		3: `-- Миграция для добавления поля для хранения цепочки сертификатов
ALTER TABLE certificates ADD COLUMN chain_pem TEXT;`,
		4: `-- Миграция для создания таблицы метаданных CRL
CREATE TABLE IF NOT EXISTS crl_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_subject TEXT NOT NULL,
    crl_number INTEGER NOT NULL,
    last_generated TEXT NOT NULL,
    next_update TEXT NOT NULL,
    crl_path TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_crl_metadata_ca_subject ON crl_metadata(ca_subject);`,
	}
}

func (d *Database) ApplyMigrations() error {
	logger.Info("применение миграций БД")
	
	var currentVersion int
	err := d.DB.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("ошибка получения текущей версии: %w", err)
	}
	
	migrations := GetMigrations()
	
	for version := currentVersion + 1; version <= len(migrations); version++ {
		migration, ok := migrations[version]
		if !ok {
			continue
		}
		
		logger.Info("применение миграции версии %d", version)
		
		tx, err := d.BeginTx()
		if err != nil {
			return fmt.Errorf("ошибка начала транзакции для миграции %d: %w", version, err)
		}
		
		if _, err := tx.Exec(migration); err != nil {
			tx.Rollback()
			return fmt.Errorf("ошибка применения миграции %d: %w", version, err)
		}
		
		_, err = tx.Exec(
			"INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, datetime('now'), ?)",
			version, fmt.Sprintf("Migration to version %d", version),
		)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("ошибка записи миграции %d: %w", version, err)
		}
		
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("ошибка коммита миграции %d: %w", version, err)
		}
		
		logger.Info("миграция версии %d успешно применена", version)
		
		auditData := map[string]interface{}{
			"action":    "migration_applied",
			"version":   version,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		logger.AuditJSON("migration_applied", auditData)
	}
	
	return nil
}
