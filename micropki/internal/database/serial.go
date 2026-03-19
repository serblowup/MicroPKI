package database

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"MicroPKI/internal/logger"
)

type SerialGenerator struct {
	db *Database
}

func NewSerialGenerator(db *Database) *SerialGenerator {
	return &SerialGenerator{
		db: db,
	}
}

func (sg *SerialGenerator) GenerateSerialNumber() (*big.Int, error) {
	logger.Info("генерация серийного номера")

	epoch := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	timestamp := uint32(time.Now().Unix() - epoch.Unix())

	randomBytes := make([]byte, 4)
	_, err := rand.Read(randomBytes)
	if err != nil {
		logger.Error("ошибка генерации случайных байт: %v", err)
		return nil, fmt.Errorf("ошибка генерации случайных байт: %w", err)
	}
	randomPart := binary.BigEndian.Uint32(randomBytes)

	serialUint64 := (uint64(timestamp) << 32) | uint64(randomPart)

	serial := new(big.Int).SetUint64(serialUint64)

	logger.Info("сгенерирован серийный номер: %x (%d)", serial, serialUint64)
	return serial, nil
}

func (sg *SerialGenerator) GenerateSerialNumberWithCounter() (*big.Int, error) {
	logger.Info("генерация серийного номера с использованием счетчика")

	tx, err := sg.db.BeginTx()
	if err != nil {
		return nil, fmt.Errorf("ошибка начала транзакции: %w", err)
	}
	defer tx.Rollback()

	var counter int64
	var lastUpdated string
	err = tx.QueryRow(
		"SELECT counter_value, last_updated FROM serial_counters WHERE counter_name = 'serial_counter' FOR UPDATE",
	).Scan(&counter, &lastUpdated)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения счетчика: %w", err)
	}

	counter++

	_, err = tx.Exec(
		"UPDATE serial_counters SET counter_value = ?, last_updated = datetime('now') WHERE counter_name = 'serial_counter'",
		counter,
	)
	if err != nil {
		return nil, fmt.Errorf("ошибка обновления счетчика: %w", err)
	}

	randomBytes := make([]byte, 4)
	_, err = rand.Read(randomBytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации случайных байт: %w", err)
	}
	randomPart := binary.BigEndian.Uint32(randomBytes)

	serialUint64 := (uint64(counter) << 32) | uint64(randomPart)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("ошибка коммита транзакции: %w", err)
	}

	serial := new(big.Int).SetUint64(serialUint64)
	logger.Info("сгенерирован серийный номер (со счетчиком): %x (счетчик=%d)", serial, counter)
	return serial, nil
}

func (sg *SerialGenerator) ValidateSerialNumber(serial *big.Int) (bool, error) {
	serialHex := fmt.Sprintf("%x", serial)

	var count int
	err := sg.db.DB.QueryRow(
		"SELECT count(*) FROM certificates WHERE serial_hex = ?",
		serialHex,
	).Scan(&count)

	if err != nil {
		return false, fmt.Errorf("ошибка проверки уникальности: %w", err)
	}

	return count == 0, nil
}
