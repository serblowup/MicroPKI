# Отчет о выполнении требований Спринта 5

## 1. Структура проекта и гигиена репозитория

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **STR-16** | Добавлены модули для OCSP | **internal/ocsp/**: `responder.go`, `signer.go`, `issuer.go`, `errors.go`, `cache.go`, `types.go` |
| **STR-17** | README обновлен с OCSP инструкциями | **README.md**: добавлены разделы "OCSP-ответчик", "Проверка статуса через OpenSSL OCSP", "Защита от повторного воспроизведения (Replay Protection)", полные примеры команд |
| **STR-18** | Структура директорий расширена для OCSP | **cmd/micropki/main.go**: команда `ca issue-ocsp-cert` создает `ocsp/` поддиректорию. В `runOCSPServe()` логи могут писаться в `ocsp/` |

## 2. Командный интерфейс (CLI)

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **CLI-22** | `ca issue-ocsp-cert` - выпуск сертификата OCSP-ответчика | **cmd/micropki/main.go**: функция `runCAIssueOCSPCert()` (строки 1356-1512). Проверяет размер ключа, генерирует шаблон с `ExtKeyUsageOCSPSigning`, `KeyUsageDigitalSignature`, `IsCA=false`. Сохраняет незашифрованный ключ с предупреждением |
| **CLI-23** | `ocsp serve` - запуск OCSP-ответчика | **cmd/micropki/main.go**: функция `runOCSPServe()` (строки 1514-1577). Принимает все обязательные флаги, запускает HTTP сервер с graceful shutdown |
| **CLI-24** | Флаг `--enable-ocsp` для репозитория (опционально) | Требование Could. Реализован отдельный сервер `ocsp serve`, что обеспечивает лучшую модульность |

## 3. Ядро OCSP (Парсинг, Генерация, Статус)

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **OCSP-1** | Парсинг OCSP запросов | **internal/ocsp/responder.go**: `HandleOCSPRequest()` использует `ocsp.ParseRequest` из `golang.org/x/crypto/ocsp`. Проверяет Content-Type, извлекает `CertID` и nonce |
| **OCSP-2** | Генерация OCSP ответов | **internal/ocsp/responder.go**: создает `ocsp.Response` с полями `Status`, `SerialNumber`, `ThisUpdate`, `NextUpdate`, `RevokedAt`, `RevocationReason`. Подписывается через `ocsp.CreateResponse` |
| **OCSP-3** | Определение статуса сертификата | **internal/ocsp/responder.go**: `getCertStatus()` запрашивает БД. `valid` → `StatusGood`, `revoked` → `StatusRevoked` (с датой и причиной), отсутствует → `StatusUnknown` |
| **OCSP-4** | Обработка Nonce | Библиотека `golang.org/x/crypto/ocsp` автоматически копирует nonce из запроса в ответ. Явная реализация не требуется |
| **OCSP-5** | Кодирование ответа | Библиотека `golang.org/x/crypto/ocsp` формирует DER-структуру. Устанавливается `Content-Type: application/ocsp-response` |
| **OCSP-6** | Ответы с ошибками | **internal/ocsp/errors.go**: `BuildErrorResponse()` и **internal/ocsp/responder.go**: `sendErrorResponse()` генерируют корректные OCSP ошибки |
| **OCSP-7** | Кэширование ответов (опционально) | **internal/ocsp/cache.go**: `ResponseCache` с TTL и фоновой очисткой. Интегрирован в `getCertStatus()`. Требование Could выполнено |
| **OCSP-8** | Логирование запросов | **internal/ocsp/responder.go**: каждый запрос логируется с IP, серийным номером, статусом и временем обработки. Ошибки логируются отдельно |

## 4. Сертификат подписанта OCSP

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **OSC-1** | Профиль сертификата OCSP-ответчика | **internal/certs/certificate.go**: `GenerateOCSPResponderTemplate()` (строки 190-218) создает шаблон с `IsCA=false`, `KeyUsageDigitalSignature`, `ExtKeyUsageOCSPSigning` |
| **OSC-2** | Размер ключа (RSA ≥ 2048, ECC ≥ 256) | **cmd/micropki/main.go**: `runCAIssueOCSPCert()` валидирует `keySize` |
| **OSC-3** | Хранение ключа без шифрования | **cmd/micropki/main.go**: `runCAIssueOCSPCert()` сохраняет ключ в PEM без шифрования с правами `0600` и выводит предупреждение `"ВНИМАНИЕ: Закрытый ключ OCSP-ответчика сохранен незашифрованным"` |

## 5. Интеграция с базой данных

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **DB-8** | Идентификация эмитента по хешам | **internal/ocsp/issuer.go**: `IssuerManager` загружает CA сертификат, вычисляет SHA-1 хеши имени и ключа. `FindByHashes()` ищет эмитента по хешам из запроса |
| **DB-9** | Эффективные запросы | Используется существующий индекс `idx_certificates_serial`. `GetCertificateBySerial()` выполняется быстро |

## 6. Логирование и аудит

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **LOG-12** | Логирование OCSP запросов | **internal/ocsp/responder.go**: `HandleOCSPRequest()` логирует `[OCSP] запрос` и `[OCSP] ответ` с деталями |
| **LOG-13** | Аудиторский след | **internal/ocsp/responder.go**: `logger.AuditJSON("ocsp_request", ...)` записывает решение в JSON формате для аудита |

## 7. Тестирование

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **TEST-28** | Тест профиля сертификата OCSP | **tests/ocsp_test.go**: `TestOCSPSignerCert()` проверяет KeyUsage, ExtKeyUsage, IsCA |
| **TEST-29** | Тест good сертификата | **tests/ocsp_test.go**: `TestOCSPGoodCertificate()` |
| **TEST-30** | Тест revoked сертификата | **tests/ocsp_test.go**: `TestOCSPRevokedCertificate()` |
| **TEST-31** | Тест unknown сертификата | **tests/ocsp_test.go**: `TestOCSPUnknownCertificate()` |
| **TEST-32** | Тест nonce | **tests/ocsp_test.go**: `TestOCSPNonce()` |
| **TEST-33** | Верификация подписи ответа | **tests/ocsp_test.go**: проверяется через `x509ocsp.ParseResponse()` с валидацией подписи |
| **TEST-34** | Негативный тест (Malformed) | **tests/ocsp_test.go**: `TestOCSPMalformedRequest()` |
| **TEST-35** | Негативный тест (Unauthorized) | **tests/ocsp_test.go**: `TestOCSPUnauthorizedIssuer()` |
| **TEST-37** | Интеграционный тест полного цикла | **tests/ocsp_test.go**: `TestFullPKIWithOCSP()` - выпуск → good → отзыв → revoked |

## 8. Ключевые изменения в `main.go` для 5 спринта

| Команда | Строки | Назначение |
|---------|--------|------------|
| `ca issue-ocsp-cert` | 1356-1512 | Выпуск сертификата OCSP-ответчика |
| `ocsp serve` | 1514-1577 | Запуск OCSP-ответчика |
| Флаг `--subject` (OCSP) | - | Subject для OCSP-сертификата |
| Флаг `--san` (OCSP) | - | SAN для OCSP-сертификата |
| Флаг `--host`/`--port` (OCSP) | - | Настройки сервера OCSP |
| Флаг `--responder-cert` | - | Путь к сертификату ответчика |
| Флаг `--responder-key` | - | Путь к ключу ответчика |
| Флаг `--cache-ttl` | - | TTL кэша в секундах |

## 9. Сводная таблица по новым файлам

| Файл | Какие требования реализованы |
|------|---------------------------|
| `internal/ocsp/responder.go` | OCSP-1, OCSP-2, OCSP-3, OCSP-5, OCSP-6, OCSP-8, LOG-12, LOG-13 |
| `internal/ocsp/signer.go` | OSC-1 |
| `internal/ocsp/issuer.go` | DB-8 |
| `internal/ocsp/errors.go` | OCSP-6 |
| `internal/ocsp/cache.go` | OCSP-7 |
| `internal/ocsp/types.go` | Вспомогательные типы |
| `tests/ocsp_test.go` | TEST-28, TEST-29, TEST-30, TEST-31, TEST-32, TEST-34, TEST-35, TEST-37 |

## 10. Сводная таблица по измененным файлам

| Файл | Изменения | Реализованные требования |
|------|-----------|-------------------------|
| `cmd/micropki/main.go` | Добавлены команды `ca issue-ocsp-cert`, `ocsp serve`, флаги | CLI-22, CLI-23, OSC-2, OSC-3 |
| `internal/certs/certificate.go` | Добавлена `GenerateOCSPResponderTemplate()` | OSC-1 |
| `README.md` | Добавлены разделы по OCSP | STR-17 |
| `Makefile` | Добавлены цели `issue-ocsp-cert`, `ocsp-serve`, `test-ocsp` | STR-17 |
| `go.mod` | Добавлена зависимость `golang.org/x/crypto` | - |

## 11. Структура проекта после 5 спринта

```text
MicroPKI/
├── docs
│   └── sprints
│       ├── 1 sprint.md # Отчёт по первому спринту
│       ├── 2 sprint.md # Отчёт по второму спринту
│       ├── 3 sprint.md # Отчёт по третьему спринту
│       ├── 4 sprint.md # Отчёт по четвёртому спринту
│       └── 5 sprint.md # Отчёт по пятому спринту
├── .gitignore
├── micropki
│   ├── cmd
│   │   └── micropki
│   │       └── main.go
│   ├── go.mod
│   ├── go.sum
│   ├── internal
│   │   ├── ca # Логика работы с УЦ
│   │   │   └── ca.go
│   │   ├── certs # Создание сертификатов
│   │   │   └── certificate.go
│   │   ├── chain # Проверка цепочек
│   │   │   └── chain.go
│   │   ├── crl # Генерация и управление CRL файлами
│   │   │   ├── crl.go
│   │   │   └── manager.go
│   │   ├── cryptoutil # Криптографические утилиты
│   │   │   └── crypto.go
│   │   ├── csr # Генерация и обработка CSR
│   │   │   └── csr.go
│   │   ├── database # Работа с БД
│   │   │   ├── certificates.go
│   │   │   ├── db.go
│   │   │   ├── schema.go
│   │   │   └── serial.go
│   │   ├── logger # Логи
│   │   │   └── logger.go
│   │   ├── ocsp # OCSP-ответчик
│   │   │   ├── cache.go
│   │   │   ├── errors.go
│   │   │   ├── issuer.go
│   │   │   ├── responder.go
│   │   │   ├── signer.go
│   │   │   └── types.go
│   │   ├── repository # HTTP репозиторий
│   │   │   ├── handlers.go
│   │   │   ├── middleware.go
│   │   │   └── server.go
│   │   ├── revocation # Управление отзывами сертификатов
│   │   │   └── revocation.go
│   │   ├── san # Парсинг и валидация SAN
│   │   │   └── san.go
│   │   └── templates # Шаблоны сертификатов
│   │       └── templates.go
│   ├── Makefile
│   ├── scripts # Скрипты
│   │   ├── test-revocation-with-openssl.sh
│   │   ├── test.sh
│   │   └── verify-chain.sh
│   └── tests # Тесты
│       ├── ca_test.go
│       ├── chain_test.go
│       ├── crl_test.go
│       ├── crypto_test.go
│       ├── csr_test.go
│       ├── database_test.go
│       ├── integration_test.go
│       ├── ocsp_test.go
│       ├── repository_test.go
│       ├── revocation_test.go
│       ├── san_test.go
│       └── templates_test.go
└── README.md
```
