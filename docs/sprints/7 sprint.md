# Отчет о выполнении требований Спринта 7

## 1. Структура проекта и гигиена репозитория

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **STR-22** | Добавлены модули для аудита и безопасности | **internal/audit/**: `anomaly.go`, `audit.go`, `chain.go`, `query.go`, `verify.go`<br>**internal/policy/**: `policy.go`<br>**internal/ratelimit/**: `ratelimit.go`<br>**internal/transparency/**: `transparency.go`<br>**internal/compromise/**: `compromise.go` |
| **STR-23** | README обновлен с описанием аудит-системы | **README.md**: разделы "Аудит-система", "Certificate Transparency", "Ограничение частоты запросов", описание `audit query`, `audit verify`, `audit ct-verify`, `audit detect-anomalies`, `ca compromise` |
| **STR-24** | Конфигурационный файл (Should) | **micropki.yaml**: конфигурация политик (размеры ключей, сроки действия, SAN, path length)<br>**cmd/micropki/main.go**: флаг `--config`, функция `loadConfig()`<br>**internal/policy/policy.go**: `LoadPolicyFromFile()`, структуры `PolicyConfig`, `PolicySettings` |
| **STR-25** | Логирование security-sensitive операций | **cmd/micropki/main.go**: вызовы `logger.LogAuditEvent()` и `logger.LogAuditError()` во всех командах<br>**internal/ca/ca.go**: `logger.LogAuditError()` при нарушениях политик |

## 2. Парсер командной строки (CLI)

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **CLI-31** | `audit query` с фильтрами | **cmd/micropki/main.go**: `runAuditQuery()` — поддержка `--from`, `--to`, `--level`, `--operation`, `--serial`, `--format` (table/json/csv), `--verify`<br>**internal/audit/query.go**: `QueryLog()`, `FormatEntries()` |
| **CLI-32** | `audit verify` проверка целостности | **cmd/micropki/main.go**: `runAuditVerify()` — флаги `--log-file`, `--chain-file`<br>**internal/audit/verify.go**: `VerifyLogFile()`, `IsTampered()`<br>**internal/audit/chain.go**: `VerifyHashChain()` |
| **CLI-33** | `ca compromise` симуляция компрометации | **cmd/micropki/main.go**: `runCACompromise()` — флаги `--cert`, `--reason`, `--force`<br>**internal/compromise/compromise.go**: `SimulateKeyCompromise()`, `IsKeyCompromised()` |
| **CLI-34** | Rate limiting для repo/ocsp serve (Should) | **cmd/micropki/main.go**: флаги `--rate-limit`, `--rate-burst`<br>**internal/ratelimit/ratelimit.go**: `RateLimiter`, `TokenBucket`, `RateLimitMiddleware()`<br>**internal/repository/server.go**: интеграция rate limiter<br>**internal/ocsp/responder.go**: `SetRateLimit()` |
| **CLI-35** | Policy enforcement в issue-cert/issue-intermediate | **cmd/micropki/main.go**: вызовы `pol.ValidateKeySize()`, `pol.ValidateValidityPeriod()`, `pol.ValidateSANs()`, `pol.ValidatePathLength()` |

## 3. Ядро PKI (Policy Enforcement)

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **POL-3** | Key Size Enforcement | **internal/policy/policy.go**: `ValidateKeySize()` — RSA Root ≥ 4096, Intermediate ≥ 3072, End-entity ≥ 2048; ECC Root/Int ≥ P-384, End-entity ≥ P-256<br>**cmd/micropki/main.go**: проверки в `runCAInit()`, `runCAIssueIntermediate()`, `runCAIssueCert()` |
| **POL-4** | Validity Period Enforcement | **internal/policy/policy.go**: `ValidateValidityPeriod()` — Root ≤ 3650, Intermediate ≤ 1825, End-entity ≤ 365 |
| **POL-5** | SAN Validation & Restrictions | **internal/policy/policy.go**: `ValidateSANs()` — wildcard запрещены, server: DNS/IP, client: DNS/email, code_signing: DNS/URI<br>**internal/policy/policy.go**: `IsWildcard()` |
| **POL-6** | Algorithm & Hash Enforcement | **internal/policy/policy.go**: `ValidateAlgorithm()`, `ValidateSignatureAlgorithm()` — SHA-1 запрещён |
| **POL-7** | Path Length Constraint | **internal/policy/policy.go**: `ValidatePathLength()` — Intermediate pathLen ≤ 0 |
| **POL-8** | Configuration Overrides (Could) | **internal/policy/policy.go**: `LoadPolicyFromFile()`<br>**micropki.yaml**: пример конфигурации<br>**cmd/micropki/main.go**: `loadConfig()`, `getPolicy()` |

## 4. Аудит-система и целостность логов

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **AUD-1** | Structured JSON Logging (NDJSON) | **internal/audit/audit.go**: `AuditEntry`, `AuditLogger`, поля timestamp, level, operation, status, message, metadata, integrity |
| **AUD-2** | Hash Chain Integrity | **internal/audit/audit.go**: `writeEntry()` — вычисление `prev_hash` и `hash`<br>**internal/audit/chain.go**: `VerifyHashChain()`, `HashEntry()`, `ReadAllHashes()`<br>Файл `chain.dat` для хранения хешей |
| **AUD-3** | Audit Log Verification | **internal/audit/verify.go**: `VerifyLogFile()` — проверка количества записей, хеш-цепочки, совпадения с chain.dat<br>**internal/audit/chain.go**: `VerificationReport`, `TamperDetail` |
| **AUD-4** | Mandatory Audit Events | **cmd/micropki/main.go**: AUDIT-записи для CA init, issuance, revocation, CRL gen, policy violations, compromise, OCSP start/stop<br>**internal/compromise/compromise.go**: `logger.LogAuditEvent("key_compromise_simulated", ...)` |
| **AUD-5** | Audit Log Rotation (Could) | **internal/audit/audit.go**: `Rotate()` — ротация с переименованием audit.log и chain.dat, создание нового лога |
| **AUD-6** | Tamper Evidence (Should) | **internal/audit/verify.go**: `IsAuditLogTampered()`, `SetTampered()`, `ResetTampered()`<br>**internal/ca/ca.go**: `CheckAuditIntegrityBeforeOperation()` — готова к использованию |

## 5. Средства контроля безопасности

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **CTL-1** | Rate Limiting (Should) | **internal/ratelimit/ratelimit.go**: `RateLimiter` с token bucket, `RateLimitMiddleware()`<br>**internal/repository/server.go**: интеграция в HTTP сервер |
| **CTL-2** | CT Simulation | **internal/transparency/transparency.go**: `CTLogger`, `AppendCertificate()`, `QueryBySerial()`, `QueryByFingerprint()`<br>**cmd/micropki/main.go**: `runAuditCtVerify()` |
| **CTL-3** | Key Compromise Simulation | **internal/compromise/compromise.go**: `SimulateKeyCompromise()` — отзыв, compromised_keys, AUDIT запись<br>**cmd/micropki/main.go**: `runCACompromise()` |
| **CTL-4** | Compromised Key Blocking (Should) | **internal/compromise/compromise.go**: `IsKeyCompromised()`<br>**cmd/micropki/main.go**: проверка перед issue-cert |
| **CTL-5** | Intrusion Detection (Could) | **internal/audit/anomaly.go**: `DetectAnomalies()` — высокая частота событий, отзывов, компрометации<br>**cmd/micropki/main.go**: `runAuditDetectAnomalies()` |

## 6. Расширения базы данных

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **DB-10** | Таблица compromised_keys (Should) | **internal/database/schema.go**: миграция версии 5 — создание таблицы `compromised_keys` |
| **DB-11** | Аудит-лог в БД (N/A) | Не требуется |
| **DB-12** | Миграция для compromised_keys (Should) | **internal/database/schema.go**: `GetMigrations()` версия 5, `ApplyMigrations()` |

## 7. Логирование и аудит (улучшения)

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **LOG-17** | Audit Logger | **internal/audit/audit.go**: `AuditLogger` — отдельный от application logger, NDJSON + hash chain |
| **LOG-18** | Sensitive Data Reduction | **internal/logger/logger.go**: пароли скрываются, приватные ключи не логируются |
| **LOG-19** | Log Initialisation | **internal/audit/audit.go**: `NewAuditLogger()` — создаёт audit.log с первой записью (prev_hash = "0"*64) |

## 8. Тестирование

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **TEST-51** | Policy Violation — Weak Key | **tests/policy_test.go**: `TestKeySizePolicy` — RSA-1024, ECC P-256 для Root |
| **TEST-52** | Policy Violation — Excessive Validity | **tests/policy_test.go**: `TestValidityPolicy` — 3651 дней для Root, 366 для End-entity |
| **TEST-53** | Policy Violation — Wildcard SAN | **tests/policy_test.go**: `TestWildcardPolicy` — `*.example.com` отклонён |
| **TEST-54** | Policy Violation — Forbidden SAN | **tests/policy_test.go**: `TestSANTypePolicy` — email для code_signing, email для server |
| **TEST-55** | Tamper Detection | **tests/audit_test.go**: `TestAuditLogTamperDetection` — изменение status в JSON |
| **TEST-56** | Chain Continuity (Should) | **tests/audit_test.go**: `TestAuditLogMissingEntry` — удаление записи B |
| **TEST-57** | Compromise & Blocking (Should) | **tests/compromise_test.go**: `TestCompromiseSimulation`, `TestCompromisedKeyBlocking`, `TestCompromisedKeyList` |
| **TEST-58** | Rate Limiting (Should) | **tests/ratelimit_test.go**: `TestTokenBucketAllow`, `TestRateLimiterPerClient`, `TestRateLimitMiddleware` |
| **TEST-59** | CT Log Test | **tests/transparency_test.go**: `TestCTLogAppendAndQuery`, `TestCTLogMultipleCertificates`, `TestCTLogQueryByFingerprint` |
| **TEST-60** | Integration Test (Should) | **tests/audit_integration_test.go**: `TestFullSecurityHardeningIntegration` — 16 подтестов: политики, выдача, CT, компрометация, блокировка, аудит, tamper, rate limiting, аномалии |

## Ключевые изменения в `main.go` для 7 спринта

| Команда | Строки | Назначение |
|---------|--------|------------|
| `audit query` | runAuditQuery | Запрос и фильтрация аудит-лога |
| `audit verify` | runAuditVerify | Проверка целостности аудит-лога |
| `audit ct-verify` | runAuditCtVerify | Проверка CT лога |
| `audit detect-anomalies` | runAuditDetectAnomalies | Обнаружение аномалий |
| `ca compromise` | runCACompromise | Симуляция компрометации ключа |
| Флаг `--config` | PersistentFlags | Загрузка конфигурации политик |
| Флаг `--rate-limit` | repoServeCmd, ocspServeCmd | Ограничение частоты запросов |
| Флаг `--rate-burst` | repoServeCmd, ocspServeCmd | Максимальный burst |

## Сводная таблица по новым файлам

| Файл | Какие требования реализованы |
|------|---------------------------|
| `internal/audit/audit.go` | AUD-1, AUD-2, AUD-5, LOG-17, LOG-19 |
| `internal/audit/chain.go` | AUD-2, AUD-3 |
| `internal/audit/verify.go` | AUD-3, AUD-6, TEST-55, TEST-56 |
| `internal/audit/query.go` | CLI-31 |
| `internal/audit/anomaly.go` | CTL-5 |
| `internal/policy/policy.go` | POL-3, POL-4, POL-5, POL-6, POL-7, POL-8 |
| `internal/ratelimit/ratelimit.go` | CLI-34, CTL-1, TEST-58 |
| `internal/transparency/transparency.go` | CTL-2, TEST-59 |
| `internal/compromise/compromise.go` | CLI-33, CTL-3, CTL-4, TEST-57 |
| `tests/audit_test.go` | TEST-55, TEST-56 |
| `tests/policy_test.go` | TEST-51, TEST-52, TEST-53, TEST-54 |
| `tests/compromise_test.go` | TEST-57 |
| `tests/ratelimit_test.go` | TEST-58 |
| `tests/transparency_test.go` | TEST-59 |
| `tests/audit_integration_test.go` | TEST-60 |
| `micropki.yaml` | POL-8 |

## Сводная таблица по измененным файлам

| Файл | Изменения | Реализованные требования |
|------|-----------|-------------------------|
| `cmd/micropki/main.go` | Добавлены команды audit, compromise, флаги --config, --rate-limit, --rate-burst, policy enforcement | CLI-31, CLI-32, CLI-33, CLI-34, CLI-35, POL-3..7, STR-25 |
| `internal/ca/ca.go` | `CheckAuditIntegrityBeforeOperation()`, логирование policy violations | AUD-6, STR-25 |
| `internal/database/schema.go` | Миграция версии 5 (compromised_keys) | DB-10, DB-12 |
| `internal/repository/server.go` | Интеграция rate limiter | CLI-34, CTL-1 |
| `internal/ocsp/responder.go` | `SetRateLimit()` | CLI-34 |
| `internal/logger/logger.go` | `InitAudit()` | LOG-19 |
| `README.md` | Добавлены разделы аудита, CT, rate limiting, компрометации | STR-23 |
| `Makefile` | Цели `test-audit`, `audit-query`, `audit-verify`, `audit-ct-verify`, `compromise` | STR-23 |
| `.gitignore` | Добавлен `/micropki.yaml` | STR-24 |

## Структура проекта после 7 спринта

```text
MicroPKI/
├── docs
│   └── sprints
│       ├── 1 sprint.md
│       ├── 2 sprint.md
│       ├── 3 sprint.md
│       ├── 4 sprint.md
│       ├── 5 sprint.md
│       ├── 6 sprint.md
│       └── 7 sprint.md
├── .gitignore
├── micropki.yaml
├── micropki
│   ├── cmd
│   │   └── micropki
│   │       └── main.go
│   ├── go.mod
│   ├── go.sum
│   ├── internal
│   │   ├── audit
│   │   │   ├── anomaly.go
│   │   │   ├── audit.go
│   │   │   ├── chain.go
│   │   │   ├── query.go
│   │   │   └── verify.go
│   │   ├── ca
│   │   │   └── ca.go
│   │   ├── certs
│   │   │   └── certificate.go
│   │   ├── chain
│   │   │   └── chain.go
│   │   ├── client
│   │   │   ├── client.go
│   │   │   ├── csrgen.go
│   │   │   ├── logging.go
│   │   │   └── request.go
│   │   ├── compromise
│   │   │   └── compromise.go
│   │   ├── crl
│   │   │   ├── crl.go
│   │   │   └── manager.go
│   │   ├── cryptoutil
│   │   │   └── crypto.go
│   │   ├── csr
│   │   │   └── csr.go
│   │   ├── database
│   │   │   ├── certificates.go
│   │   │   ├── db.go
│   │   │   ├── schema.go
│   │   │   └── serial.go
│   │   ├── logger
│   │   │   └── logger.go
│   │   ├── ocsp
│   │   │   ├── cache.go
│   │   │   ├── errors.go
│   │   │   ├── issuer.go
│   │   │   ├── responder.go
│   │   │   ├── signer.go
│   │   │   └── types.go
│   │   ├── policy
│   │   │   └── policy.go
│   │   ├── ratelimit
│   │   │   └── ratelimit.go
│   │   ├── repository
│   │   │   ├── handlers.go
│   │   │   ├── middleware.go
│   │   │   └── server.go
│   │   ├── revocation
│   │   │   ├── crl_checker.go
│   │   │   ├── fallback.go
│   │   │   ├── ocsp_checker.go
│   │   │   └── revocation.go
│   │   ├── san
│   │   │   └── san.go
│   │   ├── templates
│   │   │   └── templates.go
│   │   ├── transparency
│   │   │   └── transparency.go
│   │   └── validation
│   │       ├── chain_builder.go
│   │       ├── extensions.go
│   │       ├── path_validator.go
│   │       ├── result.go
│   │       └── validator.go
│   ├── Makefile
│   ├── scripts
│   │   ├── test-revocation-with-openssl.sh
│   │   ├── test.sh
│   │   └── verify-chain.sh
│   └── tests
│       ├── audit_integration_test.go
│       ├── audit_test.go
│       ├── ca_test.go
│       ├── chain_test.go
│       ├── client_test.go
│       ├── compromise_test.go
│       ├── crl_test.go
│       ├── crypto_test.go
│       ├── csr_test.go
│       ├── database_test.go
│       ├── e2e_test.go
│       ├── integration_test.go
│       ├── ocsp_test.go
│       ├── policy_test.go
│       ├── ratelimit_test.go
│       ├── repository_test.go
│       ├── revocation_integration_test.go
│       ├── revocation_test.go
│       ├── san_test.go
│       ├── templates_test.go
│       ├── transparency_test.go
│       └── validation_test.go
└── README.md
```

## Итоги спринта

| Категория | Всего | Выполнено |
|-----------|-------|-----------|
| **MUST** | 26 | 26 |
| **SHOULD** | 13 | 13 |
| **COULD** | 4 | 4 |
| **N/A** | 1 | — |

Все обязательные требования выполнены.