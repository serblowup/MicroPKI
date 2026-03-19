package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
	"MicroPKI/internal/logger"
)

type Database struct {
	DB *sql.DB
	Path string
}

func NewDatabase(dbPath string) (*Database, error) {
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return nil, fmt.Errorf("ошибка создания директории для БД: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=ON&_journal_mode=WAL&_synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("ошибка открытия БД: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ошибка подключения к БД: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	logger.Info("подключение к БД установлено: %s", dbPath)

	return &Database{
		DB:   db,
		Path: dbPath,
	}, nil
}

func (d *Database) Close() error {
	if d.DB != nil {
		return d.DB.Close()
	}
	return nil
}

func (d *Database) InitSchema() error {
	logger.Info("инициализация схемы БД")

	schema := GetSchema()
	_, err := d.DB.Exec(schema)
	if err != nil {
		logger.Error("ошибка создания схемы: %v", err)
		return fmt.Errorf("ошибка создания схемы: %w", err)
	}

	if err := d.ApplyMigrations(); err != nil {
		return fmt.Errorf("ошибка применения миграций: %w", err)
	}

	var count int
	err = d.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='certificates'").Scan(&count)
	if err != nil {
		return fmt.Errorf("ошибка проверки создания таблиц: %w", err)
	}

	if count == 0 {
		return fmt.Errorf("таблицы не были созданы")
	}

	logger.Info("схема БД успешно инициализирована")
	return nil
}

func (d *Database) IsInitialized() (bool, error) {
	var count int
	err := d.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='certificates'").Scan(&count)
	if err != nil {
		return false, fmt.Errorf("ошибка проверки инициализации: %w", err)
	}
	return count > 0, nil
}

func (d *Database) BeginTx() (*sql.Tx, error) {
	tx, err := d.DB.Begin()
	if err != nil {
		return nil, fmt.Errorf("ошибка начала транзакции: %w", err)
	}
	logger.Info("транзакция БД начата")
	return tx, nil
}

func (d *Database) BeginTxWithLevel(opts *sql.TxOptions) (*sql.Tx, error) {
	tx, err := d.DB.BeginTx(context.Background(), opts)
	if err != nil {
		return nil, fmt.Errorf("ошибка начала транзакции: %w", err)
	}
	logger.Info("транзакция БД начата с уровнем изоляции: %v", opts)
	return tx, nil
}