## 1. Структура проекта и гигиена репозитория

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **STR-1** | Git-репозиторий, .gitignore | **Корень проекта**: `.gitignore` содержит все необходимые исключения (бинарники, ключи, логи, pki/) |
| **STR-2** | README.md с инструкциями | **Корень проекта**: `README.md` содержит название, описание, инструкции по сборке и использованию, зависимости |
| **STR-3** | Файл управления зависимостями | **Корень проекта**: `go.mod` и `go.sum` с зависимостью `github.com/spf13/cobra` |
| **STR-4** | Логическая организация кода | **Вся структура**: `cmd/` (точка входа), `internal/` (внутренние пакеты), `tests/` (тесты) |
| **STR-5** | Скрипт для запуска тестов | **Makefile**: цель `test`; **scripts/test.sh**: отдельный скрипт |

## 2. Парсер командной строки (CLI)

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **CLI-1** | Вызов как `micropki` | **cmd/micropki/main.go**: сборка создает бинарник `micropki` |
| **CLI-2** | Подкоманда `ca init` | **cmd/micropki/main.go**: строки 18-25 - определение команды `ca` и подкоманды `init` |
| **CLI-3** | Аргументы команды | **cmd/micropki/main.go**: строки 34-45 - определение всех флагов (`--subject`, `--key-type`, и т.д.) |
| **CLI-4** | Валидация аргументов | **cmd/micropki/main.go**: функция `validateCAInitParams()` строки 126-168 |
| **CLI-5** | Безопасная обработка пароля | **cmd/micropki/main.go**: чтение пароля (строка 151-157) + **internal/ca/ca.go**: очистка пароля из памяти (строки 108-112) |
| **CLI-6** | Проверка перезаписи (--force) | **cmd/micropki/main.go**: функция `checkExistingFiles()` строки 170-188 и проверка `--force` в строке 91 |

## 3. Базовая реализация PKI

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **PKI-1** | Генерация ключей RSA/ECC | **internal/cryptoutil/crypto.go**: `GenerateRSAKey()` (строка 32-39), `GenerateECCP384Key()` (строка 42-44) |
| **PKI-2** | Самоподписанный сертификат X.509 | **internal/certs/certificate.go**: функция `GenerateRootCATemplate()` строки 84-122 создает шаблон со всеми требуемыми полями |
| **PKI-3** | Расширения X.509v3 | **internal/certs/certificate.go**: строки 111-121 - BasicConstraints (CA=TRUE), KeyUsage (keyCertSign, cRLSign), SKI/AKI |
| **PKI-4** | Кодировка PEM | **internal/certs/certificate.go**: функция `CreateCertificatePEM()` строки 127-138 кодирует сертификат в PEM |
| **PKI-5** | Сохранение сертификата | **internal/ca/ca.go**: функция `saveCertificate()` строки 234-240 сохраняет в `certs/ca.cert.pem` |

## 4. Безопасное хранение ключей

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **KEY-1** | Шифрование ключа AES-256 | **internal/cryptoutil/crypto.go**: `SaveEncryptedRSAPEM()` (строка 48-57) и `SaveEncryptedECCPEM()` (строка 60-71) используют `x509.EncryptPEMBlock` с AES-256 |
| **KEY-2** | Сохранение ключа | **internal/ca/ca.go**: функция `generateKeys()` строки 174-197 сохраняет ключ в `private/ca.key.pem` |
| **KEY-3** | Права доступа 0600/0700 | **internal/cryptoutil/crypto.go**: функция `savePEMBlock()` строка 75-84 создает файл с правами 0600; **internal/ca/ca.go**: строка 160-168 создает `private` с правами 0700 |
| **KEY-4** | Структура каталогов | **internal/ca/ca.go**: функция `createDirectories()` строки 158-171 создает `private/` и `certs/` |

## 5. Политика и журналирование

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **POL-1** | policy.txt | **internal/ca/ca.go**: функция `createPolicyFile()` строки 243-267 генерирует файл со всеми требуемыми полями |
| **LOG-1** | Инфраструктура логирования | **internal/logger/logger.go**: функция `Init()` строки 19-33 инициализирует логгер в файл или stderr |
| **LOG-2** | Обязательные события | **internal/ca/ca.go**: многочисленные вызовы `logger.Info()` на всех ключевых этапах (генерация ключей, создание сертификата, сохранение файлов) |
| **LOG-3** | Сокрытие паролей | **internal/logger/logger.go**: функция `containsPassphrase()` строки 76-92 и `formatMessage()` строки 49-72 автоматически скрывают парольные фразы из логов |

## 6. Тестирование и проверка

| ID | Требование | Где реализовано |
|-----|------------|-----------------|
| **TEST-1** | Самосогласованность сертификата | **internal/ca/ca.go**: функция `Verify()` строки 141-153 проверяет сертификат; **Makefile**: цель `verify` для проверки через OpenSSL |
| **TEST-2** | Соответствие ключа и сертификата | **internal/ca/ca.go**: функция `verifyKeyPair()` строки 270-300 создает тестовую подпись и проверяет её |
| **TEST-3** | Загрузка зашифрованного ключа | **internal/cryptoutil/crypto.go**: функция `LoadEncryptedPrivateKey()` строки 87-120; **tests/crypto_test.go**: тесты `TestEncryptedKeyRSA` и `TestEncryptedKeyECC` |
| **TEST-4** | Негативные сценарии | **tests/ca_test.go**: функция `TestNegativeCases()` строки 167-235 тестирует все граничные случаи |
| **TEST-5** | Автоматизированные тесты | **tests/ca_test.go** и **tests/crypto_test.go**: содержат модульные тесты для всех компонентов |
| **TEST-6** | Совместимость с OpenSSL | **Makefile**: цель `verify` использует OpenSSL для проверки сертификата; **README.md**: инструкции по проверке через OpenSSL |

## 7. Технический стек

| Компонент | Реализация в коде |
|-----------|-------------------|
| **Язык Go 1.21+** | **go.mod**: `go 1.25` |
| **Криптобиблиотека** | Стандартные пакеты: `crypto/rsa`, `crypto/ecdsa`, `crypto/x509`, `crypto/rand`, `encoding/pem` |
| **CLI-фреймворк** | `github.com/spf13/cobra` в **go.mod** и используется в **cmd/micropki/main.go** |
| **Логирование** | Стандартный `log` пакет, обернутый в **internal/logger/logger.go** |
| **Хранение ключей** | Зашифрованные PEM-блоки через `x509.EncryptPEMBlock` |

## Сводная таблица по файлам

| Файл | Какие требования реализованы |
|------|---------------------------|
| `cmd/micropki/main.go` | CLI-1, CLI-2, CLI-3, CLI-4, CLI-5, CLI-6 |
| `internal/ca/ca.go` | PKI-5, KEY-2, KEY-4, POL-1, LOG-2, TEST-1, TEST-2 |
| `internal/certs/certificate.go` | PKI-2, PKI-3, PKI-4 |
| `internal/cryptoutil/crypto.go` | PKI-1, KEY-1, KEY-3, TEST-3 |
| `internal/logger/logger.go` | LOG-1, LOG-3 |
| `tests/ca_test.go` | TEST-4, TEST-5 |
| `tests/crypto_test.go` | TEST-3, TEST-5 |
| `Makefile` | STR-5, TEST-1, TEST-6 |
| `README.md` | STR-2 |
| `.gitignore` | STR-1 |
| `go.mod` / `go.sum` | STR-3 |

## Структура проекта после 1 спринта

```
MicroPKI/
├── cmd
│   └── micropki
│       └── main.go
├── .gitignore
├── go.mod
├── go.sum
├── internal
│   ├── ca
│   │   └── ca.go
│   ├── certs
│   │   └── certificate.go
│   ├── cryptoutil
│   │   └── crypto.go
│   └── logger
│       └── logger.go
├── Makefile
├── README.md
├── scripts
│   └── test.sh
└── tests
    ├── ca_test.go
    └── crypto_test.go
 ```
 
