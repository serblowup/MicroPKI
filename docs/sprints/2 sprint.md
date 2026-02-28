# Отчет о выполнении требований Спринта 2

## 1. Промежуточный удостоверяющий центр (Intermediate CA)

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **INT-1** | Создание промежуточного УЦ, подписанного корневым | **cmd/micropki/main.go**: функция `runCAIssueIntermediate()` строки 197-390 реализует полный процесс создания промежуточного УЦ |
| **INT-2** | Генерация CSR для промежуточного УЦ | **internal/csr/csr.go**: функция `GenerateIntermediateCSR()` строки 17-41 генерирует CSR с правильными расширениями |
| **INT-3** | Расширения для промежуточного УЦ | **internal/csr/csr.go**: функция `CreateIntermediateCSRExtensions()` строки 44-66 добавляет BasicConstraints и SKI |
| **INT-4** | Подписание промежуточного УЦ корневым | **cmd/micropki/main.go**: строки 334-351 создают и подписывают сертификат промежуточного УЦ |
| **INT-5** | Сохранение CSR | **cmd/micropki/main.go**: строки 311-317 сохраняют CSR в `csrs/intermediate.csr.pem` |
| **INT-6** | Ограничение длины пути (pathlen) | **cmd/micropki/main.go**: флаг `--pathlen` строка 61 передается в шаблон сертификата (строки 345-346) |

## 2. Выпуск конечных сертификатов

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **CERT-1** | Выпуск сертификата от промежуточного УЦ | **cmd/micropki/main.go**: функция `runCAIssueCert()` строки 392-565 реализует выпуск конечных сертификатов |
| **CERT-2** | Шаблоны сертификатов | **internal/templates/templates.go**: структура `CertTemplate` строки 21-29 и функция `GetTemplate()` строки 31-65 |
| **CERT-3** | Server template | **internal/templates/templates.go**: строки 34-43 определяют шаблон server (KeyUsage, ExtKeyUsage, разрешенные SAN) |
| **CERT-4** | Client template | **internal/templates/templates.go**: строки 44-51 определяют шаблон client |
| **CERT-5** | Code signing template | **internal/templates/templates.go**: строки 52-60 определяют шаблон code_signing |
| **CERT-6** | Построение шаблона сертификата | **internal/templates/templates.go**: функция `BuildCertificateTemplate()` строки 106-172 создает готовый шаблон X.509 |
| **CERT-7** | Валидация SAN для шаблонов | **internal/templates/templates.go**: функция `ValidateSANsForTemplate()` строки 68-103 проверяет соответствие SAN типу шаблона |

## 3. Subject Alternative Names (SAN)

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **SAN-1** | Парсинг SAN строк | **internal/san/san.go**: функция `ParseSANString()` строки 15-28 разбирает строки вида `type:value` |
| **SAN-2** | Поддержка DNS SAN | **internal/san/san.go**: поддерживается тип "dns" (строки 23, 40) |
| **SAN-3** | Поддержка IP SAN | **internal/san/san.go**: поддерживается тип "ip" с валидацией через `net.ParseIP()` (строки 44-46) |
| **SAN-4** | Поддержка Email SAN | **internal/san/san.go**: поддерживается тип "email" с проверкой наличия "@" (строки 47-49) |
| **SAN-5** | Поддержка URI SAN | **internal/san/san.go**: поддерживается тип "uri" с парсингом через `url.Parse()` (строки 50-52) |
| **SAN-6** | Валидация SAN записей | **internal/san/san.go**: функция `ValidateSANEntry()` строки 38-60 проверяет корректность каждого типа SAN |
| **SAN-7** | Добавление SAN в сертификат | **internal/templates/templates.go**: строки 149-169 добавляют DNS, IP, email и URI в соответствующие поля сертификата |

## 4. Подписание внешних CSR

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **CSR-1** | Парсинг внешнего CSR | **internal/csr/csr.go**: функция `ParseCSR()` строки 69-90 декодирует и проверяет подпись CSR |
| **CSR-2** | Проверка подписи CSR | **internal/csr/csr.go**: строка 86 вызывает `csr.CheckSignature()` для валидации |
| **CSR-3** | Подписание внешнего CSR | **cmd/micropki/main.go**: строки 468-491 обрабатывают случай с `--csr`, извлекая публичный ключ и subject из CSR |
| **CSR-4** | Флаг `--csr` в CLI | **cmd/micropki/main.go**: строка 79 определяет флаг `--csr` для команды `issue-cert` |

## 5. Проверка цепочки сертификатов

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **CHAIN-1** | Загрузка сертификатов | **internal/chain/chain.go**: функция `LoadCertificate()` строки 14-35 загружает PEM сертификаты |
| **CHAIN-2** | Проверка сроков действия | **internal/chain/chain.go**: строки 53-67 проверяют NotBefore/NotAfter для всех сертификатов в цепочке |
| **CHAIN-3** | Проверка подписей | **internal/chain/chain.go**: строки 69-76 проверяют подписи leaf→intermediate и intermediate→root |
| **CHAIN-4** | Проверка BasicConstraints | **internal/chain/chain.go**: строки 78-86 проверяют, что root и intermediate являются CA, а leaf - нет |
| **CHAIN-5** | Проверка KeyUsage | **internal/chain/chain.go**: строки 88-93 проверяют наличие KeyUsageCertSign у CA сертификатов |
| **CHAIN-6** | Команда `ca verify` | **cmd/micropki/main.go**: строки 567-594 реализуют команду verify с вызовом `chain.VerifyChain()` |
| **CHAIN-7** | Совместимость с OpenSSL | **internal/chain/chain.go**: функция `VerifyWithOpenSSLCompatibility()` строки 96-122 использует `x509.Verify()` для проверки |

## 6. Тестирование компонентов 2 спринта

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **TEST-INT-1** | Тест создания промежуточного УЦ | **tests/ca_test.go**: функция `TestIntermediateCA()` строки 114-262 тестирует полный процесс создания intermediate |
| **TEST-INT-2** | Тест CSR | **tests/csr_test.go**: функции `TestGenerateIntermediateCSR()`, `TestParseCSRInvalid()`, `TestCreateIntermediateCSRExtensions()` |
| **TEST-INT-3** | Тест SAN | **tests/san_test.go**: все функции тестируют парсинг и валидацию SAN |
| **TEST-INT-4** | Тест шаблонов | **tests/templates_test.go**: функции `TestGetTemplate()`, `TestValidateSANsForTemplate()`, `TestBuildCertificateTemplate()` |
| **TEST-INT-5** | Тест цепочки сертификатов | **tests/chain_test.go**: функции `TestVerifyChain()` и `TestVerifyChainInvalid()` |
| **TEST-INT-6** | Интеграционный тест | **tests/integration_test.go**: `TestFullPKIChain()` проверяет полный цикл Root→Intermediate→Leaf |
| **TEST-INT-7** | Негативные сценарии | **tests/integration_test.go**: `TestNegativeScenarios()` проверяет ошибки валидации |

## 7. Скрипты и утилиты

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **SCRIPT-1** | Скрипт проверки цепочки | **scripts/verify-chain.sh**: полный скрипт для проверки цепочки через OpenSSL |
| **SCRIPT-2** | Автоматическая генерация тестовых сертификатов | **scripts/verify-chain.sh**: строки 12-45 генерируют временные тестовые сертификаты, если аргументы не переданы |
| **SCRIPT-3** | Проверка через OpenSSL | **scripts/verify-chain.sh**: строки 72-101 используют `openssl verify` для проверки подписей |
| **SCRIPT-4** | Makefile цель для скриптов | **Makefile**: цель `scripts` запускает все скрипты в директории `scripts/` |

## Ключевые изменения в `main.go` для 2 спринта

| Команда | Строки | Назначение |
|---------|--------|------------|
| `ca issue-intermediate` | 197-390 | Создание промежуточного УЦ |
| `ca issue-cert` | 392-565 | Выпуск конечных сертификатов |
| `ca verify` | 567-594 | Проверка цепочки сертификатов |
| Флаг `--pathlen` | 61 | Ограничение длины пути для intermediate |
| Флаг `--template` | 76 | Выбор шаблона (server/client/code_signing) |
| Флаг `--san` | 77 | Добавление альтернативных имен |
| Флаг `--csr` | 79 | Подписание внешнего CSR |

## Сводная таблица по новым файлам

| Файл | Какие требования реализованы |
|------|---------------------------|
| `internal/san/san.go` | SAN-1, SAN-2, SAN-3, SAN-4, SAN-5, SAN-6, SAN-7 |
| `internal/templates/templates.go` | CERT-2, CERT-3, CERT-4, CERT-5, CERT-6, CERT-7 |
| `internal/csr/csr.go` | INT-2, INT-3, CSR-1, CSR-2 |
| `internal/chain/chain.go` | CHAIN-1, CHAIN-2, CHAIN-3, CHAIN-4, CHAIN-5, CHAIN-7 |
| `tests/san_test.go` | TEST-INT-3 |
| `tests/templates_test.go` | TEST-INT-4 |
| `tests/csr_test.go` | TEST-INT-2 |
| `tests/chain_test.go` | TEST-INT-5 |
| `tests/integration_test.go` | TEST-INT-6, TEST-INT-7 |
| `scripts/verify-chain.sh` | SCRIPT-1, SCRIPT-2, SCRIPT-3 |

## Cтруктура проекта после 2 спринта

```text
MicroPKI/
├── docs # Отчёты
│   └── sprints
│       ├── 1 sprint.md # Отчёт по первому спринту
│       └── 2 sprint.md # Отчёт по второму спринту
├── .gitignore
└── micropki
    ├── cmd
    │   └── micropki
    │       └── main.go
    ├── go.mod
    ├── go.sum
    ├── internal
    │   ├── ca # Логика работы с УЦ
    │   │   └── ca.go
    │   ├── certs # Создание сертификатов
    │   │   └── certificate.go
    │   ├── chain # Проверка цепочек
    │   │   └── chain.go
    │   ├── cryptoutil # Криптографические утилиты
    │   │   └── crypto.go
    │   ├── csr # Генерация и обработка CSR
    │   │   └── csr.go
    │   ├── logger # Логи
    │   │   └── logger.go
    │   ├── san # Парсинг и валидация SAN
    │   │   └── san.go
    │   └── templates # Шаблоны сертификатов
    │       └── templates.go
    ├── Makefile
    ├── README.md
    ├── scripts # Скрипты
    │   ├── test.sh
    │   └── verify-chain.sh
    └── tests # Тесты
        ├── ca_test.go
        ├── chain_test.go
        ├── crypto_test.go
        ├── csr_test.go
        ├── integration_test.go
        ├── san_test.go
        └── templates_test.go
```
