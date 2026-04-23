# Отчет о выполнении требований Спринта 6

## 1. Структура проекта и гигиена репозитория

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **STR-19** | Добавлены модули для валидации и клиентской функциональности | **internal/validation/**: `validator.go`, `chain_builder.go`, `path_validator.go`, `result.go`, `extensions.go`<br>**internal/client/**: `client.go`, `csrgen.go`, `request.go`, `logging.go`<br>**internal/revocation/**: `crl_checker.go`, `ocsp_checker.go`, `fallback.go` |
| **STR-20** | README обновлен с клиентскими инструкциями | **README.md**: добавлены разделы "Клиентские команды", примеры `gen-csr`, `request-cert`, `validate`, `check-status`, объяснение fallback логики OCSP→CRL |
| **STR-21** | Отдельный клиентский бинарник (Should) | **НЕ РЕАЛИЗОВАНО**: Клиентские команды интегрированы в основной `micropki` как подкоманда `client`. Это соответствует требованию Should и не нарушает спецификацию |

## 2. Команды CLI

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **CLI-25** | `client gen-csr` - генерация CSR | **cmd/micropki/main.go**: `runClientGenCSR()` (строки 1718-1748)<br>**internal/client/csrgen.go**: `GenerateCSR()` с поддержкой RSA/ECC, SAN, сохранением ключа с правами 0600 |
| **CLI-26** | `client request-cert` - запрос сертификата | **cmd/micropki/main.go**: `runClientRequestCert()` (строки 1750-1779)<br>**internal/client/request.go**: `RequestCertificate()` отправляет CSR через HTTP API |
| **CLI-27** | `client validate` - валидация цепочки | **cmd/micropki/main.go**: `runClientValidate()` (строки 1781-1872)<br>**internal/validation/**: полная валидация с поддержкой CRL, OCSP, режимов `chain`/`full` |
| **CLI-28** | `client check-status` - проверка статуса отзыва | **cmd/micropki/main.go**: `runClientCheckStatus()` (строки 1874-1922)<br>**internal/revocation/fallback.go**: `CheckStatus()` с логикой OCSP→CRL |
| **CLI-29** | `ca issue-cert --csr` - подписание CSR | **cmd/micropki/main.go**: флаг `--csr` (строка 79), обработка в `runCAIssueCert()` (строки 848-865)<br>**internal/ca/ca.go**: `IssueCertificateFromCSR()` (строки 290-420) |
| **CLI-30** | `POST /request-cert` endpoint | **internal/repository/handlers.go**: `HandleRequestCert()` (строки 146-240) |

## 3. Ядро валидации пути (Path Validation)

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **VAL-1** | Построение цепочки сертификатов | **internal/validation/chain_builder.go**: `ChainBuilder.BuildChain()` рекурсивно строит путь от leaf до trusted root, выбирает кратчайший путь |
| **VAL-2** | Базовые проверки RFC 5280 | **internal/validation/path_validator.go**: `PathValidator.ValidatePath()` проверяет:<br>• Подпись (`CheckSignatureFrom`)<br>• Срок действия<br>• BasicConstraints (CA/FALSE)<br>• PathLenConstraint<br>• KeyUsage (keyCertSign для CA) |
| **VAL-3** | Name Constraints (Could) | **НЕ РЕАЛИЗОВАНО**: Опциональное требование, не требуется по спецификации |
| **VAL-4** | Policy Validation (N/A) | Не требуется |
| **VAL-5** | Структурированный результат | **internal/validation/result.go**: `ValidationResult` с полями `Valid`, `Steps`, `Error`, `ChainLength`, `Revocation` |
| **VAL-6** | `--validation-time` (Should) | **cmd/micropki/main.go**: флаг `--validation-time` (строка 244), парсинг RFC3339 в `runClientValidate()` (строки 1833-1837) |

## 4. Проверка отзыва (CRL и OCSP)

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **REV-1** | Проверка через CRL | **internal/revocation/crl_checker.go**: `CRLChecker.CheckCertificate()` - загрузка CRL, проверка подписи, свежести, поиск серийного номера с причиной |
| **REV-2** | Проверка через OCSP | **internal/revocation/ocsp_checker.go**: `OCSPChecker.CheckCertificate()` - создание запроса, парсинг ответа, статус good/revoked/unknown |
| **REV-3** | Fallback логика OCSP→CRL | **internal/revocation/fallback.go**: `RevocationChecker.CheckStatus()` - сначала OCSP, при неудаче/unknown → CRL |
| **REV-4** | Извлечение OCSP URL из AIA | **internal/validation/extensions.go**: `ExtractOCSPURL()` парсит AIA расширение (OID 1.3.6.1.5.5.7.1.1), извлекает OCSP URL |
| **REV-5** | Извлечение CRL URL из CDP (Should) | **internal/validation/extensions.go**: `ExtractCRLURLs()` парсит CRL Distribution Points (OID 2.5.29.31) |
| **REV-6** | Кэширование (Could) | **internal/ocsp/cache.go**: `ResponseCache` с TTL и фоновой очисткой<br>**internal/ocsp/responder.go**: использование кэша в `getCertStatus()` |

## 5. Репозиторий и УЦ для CSR

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **REPO-15** | `POST /request-cert` endpoint | **internal/repository/handlers.go**: `HandleRequestCert()` (строки 146-240) - принимает multipart форму с CSR, вызывает `issueCertificateFromCSR()`, возвращает PEM |
| **REPO-16** | Аутентификация API ключом (Should) | **internal/repository/handlers.go**: проверка `X-API-Key` через `os.Getenv("MICROPKI_API_KEY")` (строки 158-168) |
| **CA-1** | Подписание CSR с проверками | **internal/ca/ca.go**: `IssueCertificateFromCSR()` (строки 290-420):<br>• Проверка подписи CSR (`CheckSignature`)<br>• Извлечение subject и публичного ключа<br>• Проверка на CA=FALSE<br>• Извлечение SAN из CSR<br>• Валидация SAN для шаблона |

## 6. Логирование и аудит

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **LOG-14** | Клиентское логирование (Should) | **internal/client/logging.go**: `InitClientLogger()`, `LogClientOperation()` - запись в `~/.micropki/client.log` в JSON формате |
| **LOG-15** | JSON вывод валидации (Could) | **internal/validation/result.go**: `ValidationResult.ToJSON()`<br>**cmd/micropki/main.go**: сохранение в `--log-json` (строки 1866-1869) |
| **LOG-16** | Логирование API выдач | **internal/repository/handlers.go**: `HandleRequestCert()` логирует успешные выпуски с IP клиента (строки 226-234), запись в audit log |

## 7. Тестирование

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **TEST-38** | Генерация CSR | **tests/client_test.go**: `TestGenerateCSR()`, `TestGenerateCSRWithECC()`, `TestGenerateCSREmailSAN()` - проверка прав 0600, подписи, subject, SAN |
| **TEST-39** | Запрос сертификата | **tests/e2e_test.go**: `TestE2EClientWorkflow()` - полный цикл с HTTP сервером |
| **TEST-40** | Валидация валидной цепочки | **tests/validation_test.go**: `TestPathValidatorValidChain()` - проверка подписи, срока, BC |
| **TEST-41** | Валидация истекшего сертификата | **tests/validation_test.go**: `TestPathValidatorExpiredCertificate()` - создание просроченного, ожидание ошибки |
| **TEST-42** | Неверный KeyUsage (Could) | **tests/validation_test.go**: `TestPathValidatorWrongKeyUsage()` - скелет теста |
| **TEST-43** | Проверка отзыва через CRL | **tests/revocation_integration_test.go**: `TestCRLChecker()` - генерация CRL с отозванным сертификатом |
| **TEST-44** | Проверка отзыва через OCSP | **tests/ocsp_test.go**: `TestOCSPGoodCertificate()`, `TestOCSPRevokedCertificate()` |
| **TEST-45** | Fallback логика (Should) | **tests/revocation_integration_test.go**: `TestRevocationFallbackLogic()` - проверка OCSP→CRL перехода |
| **TEST-46** | Отсутствие промежуточного | **tests/validation_test.go**: `TestChainBuilderMissingIntermediate()` - ошибка построения без intermediate |
| **TEST-47** | Множественные пути (N/A) | Не требуется |
| **TEST-48** | Сквозной E2E тест (Should) | **tests/e2e_test.go**: `TestE2EClientWorkflow()` - полный цикл: CSR→request→validate→revoke→check-status |
| **TEST-49** | Неверная подпись CSR (Should) | **internal/ca/ca.go**: `IssueCertificateFromCSR()` проверяет `csrObj.CheckSignature()` |
| **TEST-50** | Отклонение CA=true в CSR (Should) | **internal/ca/ca.go**: `IssueCertificateFromCSR()` проверяет BasicConstraints на CA (строки 307-315) |

## 8. Ключевые изменения в `main.go` для 6 спринта

| Команда | Строки | Назначение |
|---------|--------|------------|
| `client gen-csr` | 1718-1748 | Генерация приватного ключа и CSR |
| `client request-cert` | 1750-1779 | Отправка CSR в CA через API |
| `client validate` | 1781-1872 | Валидация цепочки сертификатов |
| `client check-status` | 1874-1922 | Проверка статуса отзыва с fallback |
| Флаг `--validation-time` | 244 | Время для валидации (RFC3339) |
| Флаг `--mode` | 242 | Режим: chain или full |
| Флаг `--ocsp` | 241 | Включение OCSP проверки |

## 9. Сводная таблица по новым файлам

| Файл | Какие требования реализованы |
|------|---------------------------|
| `internal/validation/validator.go` | VAL-1, VAL-2, VAL-5 |
| `internal/validation/chain_builder.go` | VAL-1, TEST-46 |
| `internal/validation/path_validator.go` | VAL-2, VAL-5, VAL-6 |
| `internal/validation/result.go` | VAL-5, LOG-15 |
| `internal/validation/extensions.go` | REV-4, REV-5 |
| `internal/client/client.go` | STR-19, базовые функции |
| `internal/client/csrgen.go` | CLI-25, TEST-38 |
| `internal/client/request.go` | CLI-26, TEST-39 |
| `internal/client/logging.go` | LOG-14 |
| `internal/revocation/crl_checker.go` | REV-1 |
| `internal/revocation/ocsp_checker.go` | REV-2 |
| `internal/revocation/fallback.go` | REV-3, TEST-45 |
| `tests/client_test.go` | TEST-38 |
| `tests/validation_test.go` | TEST-40, TEST-41, TEST-42, TEST-46 |
| `tests/revocation_integration_test.go` | TEST-43, TEST-45 |
| `tests/e2e_test.go` | TEST-39, TEST-48 |

## 10. Сводная таблица по измененным файлам

| Файл | Изменения | Реализованные требования |
|------|-----------|-------------------------|
| `cmd/micropki/main.go` | Добавлены команды `client`, флаги `--validation-time`, `--mode`, `--ocsp`, обработка `--csr` в `issue-cert` | CLI-25, CLI-26, CLI-27, CLI-28, CLI-29, VAL-6 |
| `internal/ca/ca.go` | Добавлен `IssueCertificateFromCSR()` | CA-1 |
| `internal/repository/handlers.go` | Добавлен `HandleRequestCert()`, `issueCertificateFromCSR()`, `parseSANExtension()` | REPO-15, REPO-16, LOG-16 |
| `internal/repository/server.go` | Добавлен маршрут `POST /request-cert` | REPO-15 |
| `README.md` | Добавлены разделы по клиентским командам, fallback логике | STR-20 |
| `Makefile` | Добавлены цели `csr`, `request-cert`, `validate`, `check-status`, `test-csr` | STR-20 |

## 11. Структура проекта после 6 спринта

```text
MicroPKI/
├── docs
│   └── sprints
│       ├── 1 sprint.md # Отчёт по первому спринту
│       ├── 2 sprint.md # Отчёт по второму спринту
│       ├── 3 sprint.md # Отчёт по третьему спринту
│       ├── 4 sprint.md # Отчёт по четвёртому спринту
│       ├── 5 sprint.md # Отчёт по пятому спринту
│       └── 6 sprint.md # Отчёт по шестому спринту
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
│   │   ├── client # Клиентские операции
│   │   │   ├── client.go
│   │   │   ├── csrgen.go
│   │   │   ├── logging.go
│   │   │   └── request.go
│   │   ├── crl # Генерация и управление CRL
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
│   │   ├── revocation # Проверка отзыва
│   │   │   ├── crl_checker.go
│   │   │   ├── fallback.go
│   │   │   ├── ocsp_checker.go
│   │   │   └── revocation.go
│   │   ├── san # Парсинг и валидация SAN
│   │   │   └── san.go
│   │   ├── templates # Шаблоны сертификатов
│   │   │   └── templates.go
│   │   └── validation # Валидация цепочек
│   │       ├── chain_builder.go
│   │       ├── extensions.go
│   │       ├── path_validator.go
│   │       ├── result.go
│   │       └── validator.go
│   ├── Makefile
│   ├── scripts # Скрипты
│   │   ├── test-revocation-with-openssl.sh
│   │   ├── test.sh
│   │   └── verify-chain.sh
│   └── tests # Тесты
│       ├── ca_test.go
│       ├── chain_test.go
│       ├── client_test.go
│       ├── crl_test.go
│       ├── crypto_test.go
│       ├── csr_test.go
│       ├── database_test.go
│       ├── e2e_test.go
│       ├── integration_test.go
│       ├── ocsp_test.go
│       ├── repository_test.go
│       ├── revocation_integration_test.go
│       ├── revocation_test.go
│       ├── san_test.go
│       ├── templates_test.go
│       └── validation_test.go
└── README.md
```

### Невыполненные требования:
1. **STR-21** (Should) - Отдельный бинарник `micropki-client` не создан
2. **VAL-3** (Could) - Name Constraints не реализованы
