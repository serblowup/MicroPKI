# Отчет о выполнении требований Спринта 4

## 1. Структура проекта и репозиторий

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **STR-13** | Добавлены модули для CRL и отзыва | **internal/crl/**: `crl.go`, `manager.go`<br>**internal/revocation/**: `revocation.go` |
| **STR-14** | README обновлен с инструкциями | **README.md**: добавлены разделы с командами `revoke`, `gen-crl`, `check-revoked`, примерами `curl` для CRL, проверкой через OpenSSL |
| **STR-15** | Структура директорий расширена для CRL | **cmd/micropki/main.go**: функция `runCAGenCRL` (строки 609-722) создает директорию `crl/` и сохраняет файлы `<ca>.crl.pem` |

## 2. Команды CLI

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **CLI-18** | `ca revoke` с поддержкой причин | **cmd/micropki/main.go**: функция `runCARevoke()` строки 466-544<br>**internal/revocation/revocation.go**: `ReasonCodeToInt()` (строки 19-38) и `RevokeCertificate()` (строки 40-76) |
| **CLI-19** | `ca gen-crl` с параметрами | **cmd/micropki/main.go**: функция `runCAGenCRL()` строки 546-722 |
| **CLI-20** | `ca check-revoked` проверка статуса | **cmd/micropki/main.go**: функция `runCACheckRevoked()` строки 724-759<br>**internal/revocation/revocation.go**: `CheckRevoked()` (строки 114-143) |
| **CLI-21** | Существующие команды не изменены | Команды `ca issue-cert` и `ca issue-intermediate` остались без изменений |

## 3. Ядро PKI с CRL

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **CRL-1** | CRLv2 формат с полями | **internal/crl/crl.go**: `GenerateCRL()` строки 17-83 - использует `x509.CreateRevocationList` с заполнением Number, ThisUpdate, NextUpdate, Issuer, AuthorityKeyId |
| **CRL-2** | Расширения CRL (AKI, CRL Number, Reason Code) | **internal/crl/crl.go**: `GenerateCRL()` - AKI из сертификата (строка 62), Number (строка 65), Reason Code как расширение (строки 35-46) |
| **CRL-3** | Интеграция с БД при отзыве | **internal/revocation/revocation.go**: `RevokeCertificate()` (строки 40-76) обновляет статус, дату и причину<br>**internal/database/certificates.go**: `UpdateCertificateStatus()` (строки 304-338) |
| **CRL-4** | Подпись CRL ключом УЦ | **internal/crl/crl.go**: `GenerateCRL()` строка 74 - `x509.CreateRevocationList` подписывает CRL |
| **CRL-5** | Хранение CRL в поддиректории | **cmd/micropki/main.go**: строка 681 - `crlDir := filepath.Join(filepath.Dir(dbPath), "crl")`<br>Сохранение в `<out-dir>/crl/<ca>.crl.pem` |
| **CRL-6** | Сохранение номера CRL | **internal/crl/manager.go**: `GetNextCRLNumber()` (строки 23-40) и `UpdateCRLMetadata()` (строки 42-69) используют таблицу `crl_metadata` |
| **CRL-7** | Поддержка всех кодов причин | **internal/revocation/revocation.go**: `ReasonCodeToInt()` (строки 19-38) и `ReasonCodeToString()` (строки 40-57) поддерживают все 10 кодов RFC 5280 |
| **CRL-8** | Delta-CRL не требуется | Не реализовано, что соответствует требованию |

## 4. Распространение CRL (HTTP репозиторий)

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **REPO-9** | GET /crl с параметром ca | **internal/repository/handlers.go**: `handleCRL()` строки 86-115 - обрабатывает `?ca=root|intermediate`, возвращает `Content-Type: application/pkix-crl` |
| **REPO-10** | GET /crl/{filename} альтернативный путь | **internal/repository/handlers.go**: `handleCRLFile()` строки 117-139 - обслуживает `/crl/root.crl.pem` и `/crl/intermediate.crl.pem` |
| **REPO-11** | Заголовки кэширования | **internal/repository/handlers.go**: `serveCRLFile()` строки 141-169 - добавляет `Last-Modified`, `ETag`, `Cache-Control: max-age=3600` |
| **REPO-12** | Логирование CRL запросов | **internal/repository/middleware.go**: `withLogging()` строки 16-34 - логирует все HTTP запросы, включая CRL |

## 5. База данных и обновления схемы

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **DB-5** | Использование существующих полей | **internal/database/certificates.go**: поля `status`, `revocation_reason`, `revocation_date` обновляются через `UpdateCertificateStatus()` (строки 304-338) |
| **DB-6** | Новая таблица crl_metadata | **internal/database/schema.go**: `GetSchema()` (строки 87-94) создает таблицу `crl_metadata` с полями `ca_subject`, `crl_number`, `last_generated`, `next_update`, `crl_path` |
| **DB-7** | Миграции для существующих БД | **internal/database/schema.go**: `GetMigrations()` (строки 110-133) включает миграцию версии 4 для создания `crl_metadata`<br>`ApplyMigrations()` (строки 135-185) применяет миграции при запуске |

## 6. Логирование и аудит

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **LOG-9** | Логи событий отзыва | **internal/revocation/revocation.go**: `RevokeCertificate()` - логирование успеха (строка 67), предупреждение для уже отозванных (строка 55)<br>**cmd/micropki/main.go**: `runCARevoke()` - логирование ошибок |
| **LOG-10** | Логи генерации CRL | **cmd/micropki/main.go**: `runCAGenCRL()` - логирование начала (строка 553), успешного завершения (строка 708), ошибок |
| **LOG-11** | JSON логи аудита | **internal/logger/logger.go**: `AuditJSON()` (строки 115-133) - используется для записи отзывов (строка 74 в revocation.go) и генерации CRL (строка 714 в main.go) |

## 7. Тестирование

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **TEST-21** | Жизненный цикл отзыва | **tests/integration_test.go**: `TestRevocationLifecycle()` строки 441-653 - полный цикл: выпуск → проверка → отзыв → проверка БД → генерация CRL → проверка содержимого |
| **TEST-22** | Проверка подписи CRL через OpenSSL | **scripts/test-revocation-with-openssl.sh**: использует `openssl crl -CAfile` для проверки подписи<br>**Makefile**: цель `make scripts` |
| **TEST-23** | Увеличение номера CRL | **tests/integration_test.go**: `TestRevocationLifecycle()` проверяет генерацию CRL с номером 1<br>**internal/crl/manager.go**: `GetNextCRLNumber()` реализует инкремент |
| **TEST-24** | Отзыв несуществующего сертификата | **tests/revocation_test.go**: `TestRevokeNonExistentCertificate()` строки 208-214 |
| **TEST-25** | Отзыв уже отозванного сертификата | **tests/revocation_test.go**: `TestRevokeAlreadyRevokedCertificate()` строки 162-206 |
| **TEST-26** | Распространение CRL через HTTP | **tests/repository_test.go**: `TestCRLEndpoint()` строки 117-234 - проверяет все эндпоинты CRL |
| **TEST-27** | Интероперабельность с OpenSSL s_client | **scripts/test-revocation-with-openssl.sh**: запускает HTTPS сервер и проверяет отказ при подключении с отозванным сертификатом (строки 80-100) |

## Ключевые изменения в `main.go` для 4 спринта

| Команда | Строки | Назначение |
|---------|--------|------------|
| `ca revoke` | 466-544 | Отзыв сертификата по серийному номеру |
| `ca gen-crl` | 546-722 | Генерация CRL для указанного УЦ |
| `ca check-revoked` | 724-759 | Проверка статуса отзыва сертификата |
| Флаг `--reason` | 472 | Код причины отзыва |
| Флаг `--crl` | 473 | Путь к CRL файлу для обновления |
| Флаг `--ca` | 512 | Имя УЦ (root/intermediate) |
| Флаг `--next-update` | 513 | Дней до следующего обновления CRL |

## Сводная таблица по новым файлам

| Файл | Какие требования реализованы |
|------|---------------------------|
| `internal/crl/crl.go` | CRL-1, CRL-2, CRL-4, CRL-5, CRL-7 |
| `internal/crl/manager.go` | CRL-6, DB-6 |
| `internal/revocation/revocation.go` | CLI-18, CLI-20, CRL-3, CRL-7, LOG-9, TEST-24, TEST-25 |
| `tests/crl_test.go` | TEST-21, TEST-22, TEST-23 |
| `tests/revocation_test.go` | TEST-24, TEST-25 |
| `scripts/test-revocation-with-openssl.sh` | TEST-22, TEST-27 |

## Сводная таблица по измененным файлам

| Файл | Изменения | Реализованные требования |
|------|-----------|-------------------------|
| `cmd/micropki/main.go` | Добавлены команды revoke, gen-crl, check-revoked, флаги | CLI-18, CLI-19, CLI-20, STR-13, STR-15, LOG-9, LOG-10 |
| `internal/database/schema.go` | Добавлена таблица crl_metadata, миграция версии 4 | DB-6, DB-7 |
| `internal/database/certificates.go` | Добавлен метод GetRevokedCertificatesByIssuer | DB-5, CRL-3 |
| `internal/repository/handlers.go` | Добавлены handleCRL, handleCRLFile, serveCRLFile | REPO-9, REPO-10, REPO-11 |
| `internal/repository/middleware.go` | Логирование всех запросов | REPO-12 |
| `internal/logger/logger.go` | Метод AuditJSON уже существовал | LOG-11 |
| `README.md` | Добавлены инструкции по отзыву и CRL | STR-14 |
| `Makefile` | Добавлены цели revoke, gen-crl, check-revoked, test-revocation | STR-14, TEST-27 |

## Структура проекта после 4 спринта


```text
MicroPKI/
├── docs
│   └── sprints
│       ├── 1 sprint.md # Отчёт по первому спринту
│       ├── 2 sprint.md # Отчёт по второму спринту
│       ├── 3 sprint.md # Отчёт по третьему спринту
│       └── 4 sprint.md # Отчёт по четвёртому спринту
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
│       ├── repository_test.go
│       ├── revocation_test.go
│       ├── san_test.go
│       └── templates_test.go
└── README.md
```
