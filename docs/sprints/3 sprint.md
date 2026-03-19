# **Отчет о выполнении требований Спринта 3**

## 1. Структура проекта и репозиторий

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **STR-9** | Добавлены модули для БД и HTTP сервера | **internal/database/**: `db.go`, `schema.go`, `certificates.go`, `serial.go`<br>**internal/repository/**: `server.go`, `handlers.go`, `middleware.go` |
| **STR-10** | README обновлен с инструкциями | **Makefile**: цель `examples` (строки 174-236) показывает все команды<br>**README.md**: содержит полные инструкции |
| **STR-11** | Конфигурационный файл (опциональное требование) | Опциональное требование не реализовано, проект полностью управляется через флаги CLI, что соответствует спецификации |
| **STR-12** | .gitignore для БД | **.gitignore**: добавлены `*.db`, `/pki/*.db`, `*.db-journal`, `*.db-wal`, `*.db-shm` |

## 2. Команды CLI

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **CLI-12** | `db init` - инициализация БД | **cmd/micropki/main.go**: функция `runDBInit()` строки 963-1007 |
| **CLI-13** | `ca list-certs` с фильтрами | **cmd/micropki/main.go**: функция `runCAListCerts()` строки 1009-1032 |
| **CLI-14** | `ca show-cert <serial>` | **cmd/micropki/main.go**: функция `runCAShowCert()` строки 1034-1058 |
| **CLI-15** | `repo serve` - HTTP сервер | **cmd/micropki/main.go**: функция `runRepoServe()` строки 1060-1085 |
| **CLI-16** | `repo status` - проверка сервера | **cmd/micropki/main.go**: функция `runRepoStatus()` строки 1087-1100 |
| **CLI-17** | Автовставка в issuance команды | **cmd/micropki/main.go**: строки 548-579 (issue-intermediate) и 797-834 (issue-cert) |

## 3. Ядро PKI с БД

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **PKI-13** | Уникальные серийные номера | **internal/database/serial.go**: `GenerateSerialNumber()` - 64-битный составной номер (timestamp<<32 \| random) |
| **PKI-14** | Автовставка при issuance | **internal/database/certificates.go**: `InsertCertificateTx()` строки 124-176 |
| **PKI-15** | Схема БД | **internal/database/schema.go**: `GetSchema()` - полная таблица certificates с индексами |
| **PKI-16** | Миграции БД | **internal/database/schema.go**: `ApplyMigrations()` и `GetMigrations()` |
| **PKI-17** | Атомарность ошибок | **cmd/micropki/main.go**: транзакции с rollback и удалением временных файлов (строки 548-579, 797-834) |

## 4. Хранение и репозиторий (CRUD)

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **DB-1** | Получение по серийному номеру | **internal/database/certificates.go**: `GetCertificateBySerial()` строки 178-229 |
| **DB-2** | Список с фильтрами | **internal/database/certificates.go**: `ListCertificates()` строки 231-302 |
| **DB-3** | Обновление статуса | **internal/database/certificates.go**: `UpdateCertificateStatus()` строки 304-338 |
| **DB-4** | Запрос для CRL | **internal/database/certificates.go**: `GetRevokedCertificates()` строки 340-381 |

## 5. HTTP Репозиторий

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **REPO-1** | HTTP сервер | **internal/repository/server.go**: `Server` структура и `Start()` метод |
| **REPO-2** | GET /certificate/{serial} | **internal/repository/handlers.go**: `handleGetCertificate()` строки 16-60 |
| **REPO-3** | GET /ca/root и /ca/intermediate | **internal/repository/handlers.go**: `handleGetRootCA()` (62-67), `handleGetIntermediateCA()` (69-84) |
| **REPO-4** | GET /crl placeholder | **internal/repository/handlers.go**: `handleCRL()` строки 86-93 (возвращает 501) |
| **REPO-5** | Fallback на файловую систему | **internal/repository/handlers.go**: `tryServeFromFileSystem()` строки 117-141 |
| **REPO-6** | Логирование запросов | **internal/repository/middleware.go**: `withLogging()` строки 16-34 |
| **REPO-7** | CORS заголовки | **internal/repository/middleware.go**: `withCORS()` строки 36-49 |
| **REPO-8** | Обработка ошибок | **internal/repository/handlers.go**: 400 для неверного hex, 404 для не найденного |

## 6. Логирование и аудит

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **LOG-6** | Новые события CLI | **cmd/micropki/main.go**: `logger.Info()` и `logger.AuditJSON()` во всех командах |
| **LOG-7** | HTTP лог с префиксом | **internal/repository/middleware.go**: префикс `[HTTP]` в логах |
| **LOG-8** | JSON логи аудита | **internal/logger/logger.go**: `AuditJSON()` строки 115-133 |

## 7. Тестирование

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **TEST-13** | Вставка 5 сертификатов | **tests/database_test.go**: `TestInsertAndGetCertificate()` |
| **TEST-14** | CLI retrieval | **tests/database_test.go**: `TestListCertificates()` |
| **TEST-15** | API fetch | **tests/repository_test.go**: `TestGetCertificateEndpoint()` |
| **TEST-16** | CA fetch | **tests/repository_test.go**: `TestRootCAEndpoint()`, `TestIntermediateCAEndpoint()` |
| **TEST-17** | Стресс-тест 100 сертификатов | **tests/database_test.go**: `TestSerialUniquenessStress()` |
| **TEST-18** | Дубликат серийного | **tests/database_test.go**: `TestDuplicateSerial()` |
| **TEST-19** | Неверный формат serial | **tests/repository_test.go**: `TestGetCertificateInvalidSerial()` |
| **TEST-20** | Интеграционный тест | **tests/integration_test.go**: `TestFullPKIChain()` |

## 8. Ключевые изменения в `main.go` для 3 спринта

| Команда | Строки | Назначение |
|---------|--------|------------|
| `db init` | 963-1007 | Инициализация БД |
| `ca list-certs` | 1009-1032 | Список сертификатов |
| `ca show-cert` | 1034-1058 | Показать сертификат |
| `repo serve` | 1060-1085 | Запуск HTTP сервера |
| `repo status` | 1087-1100 | Проверка статуса |
| Флаг `--db-path` | везде | Путь к БД |
| Флаг `--host`/`--port` | 1060-1085 | Настройки сервера |

## Сводная таблица по новым файлам

| Файл | Какие требования реализованы |
|------|---------------------------|
| `internal/database/db.go` | DB-1, DB-2, DB-3, DB-4, PKI-15, PKI-16 |
| `internal/database/schema.go` | PKI-15, PKI-16 |
| `internal/database/certificates.go` | DB-1, DB-2, DB-3, DB-4, PKI-14 |
| `internal/database/serial.go` | PKI-13 |
| `internal/repository/server.go` | REPO-1 |
| `internal/repository/handlers.go` | REPO-2, REPO-3, REPO-4, REPO-5, REPO-8 |
| `internal/repository/middleware.go` | REPO-6, REPO-7 |
| `tests/database_test.go` | TEST-13, TEST-14, TEST-17, TEST-18 |
| `tests/repository_test.go` | TEST-15, TEST-16, TEST-19 |
| `tests/integration_test.go` | TEST-20 |

## Структура проекта после 3 спринта

```text
MicroPKI/
├── docs
│   └── sprints
│       ├── 1 sprint.md # Отчёт по первому спринту
│       ├── 2 sprint.md # Отчёт по второму спринту
│       └── 3 sprint.md # Отчёт по третьему спринту
├── .gitignore
├── micropki
│   ├── cmd
│   │   └── micropki
│   │       └── main.go
│   ├── go.mod
│   ├── go.sum
│   ├── internal
│   │   ├── ca # Логика работы с УЦ
│   │   │   └── ca.go
│   │   ├── certs # Создание сертификатов
│   │   │   └── certificate.go
│   │   ├── chain # Проверка цепочек
│   │   │   └── chain.go
│   │   ├── cryptoutil # Криптографические утилиты
│   │   │   └── crypto.go
│   │   ├── csr # Генерация и обработка CSR
│   │   │   └── csr.go
│   │   ├── database # Работа с БД
│   │   │   ├── certificates.go
│   │   │   ├── db.go
│   │   │   ├── schema.go
│   │   │   └── serial.go
│   │   ├── logger # Логи
│   │   │   └── logger.go
│   │   ├── repository # HTTP репозиторий
│   │   │   ├── handlers.go
│   │   │   ├── middleware.go
│   │   │   └── server.go
│   │   ├── san # Парсинг и валидация SAN
│   │   │   └── san.go
│   │   └── templates # Шаблоны сертификатов
│   │       └── templates.go
│   ├── Makefile
│   ├── scripts # Скрипты
│   │   ├── test.sh
│   │   └── verify-chain.sh
│   └── tests # Тесты
│       ├── ca_test.go
│       ├── chain_test.go
│       ├── crypto_test.go
│       ├── csr_test.go
│       ├── database_test.go
│       ├── integration_test.go
│       ├── repository_test.go
│       ├── san_test.go
│       └── templates_test.go
└── README.md
```
