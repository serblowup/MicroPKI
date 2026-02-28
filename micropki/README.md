# MicroPKI

Минимальная реализация инфраструктуры открытых ключей (PKI) в рамках курса криптографии.

## Возможности

- Создание самоподписанного корневого УЦ (RSA 4096 или ECC P-384)
- Создание промежуточного УЦ, подписанного корневым
- Выпуск сертификатов по шаблонам: server, client, code_signing
- Поддержка Subject Alternative Name (SAN) - DNS, IP, email, URI
- Подписание внешних CSR
- Проверка цепочки сертификатов
- Безопасное хранение ключей с шифрованием (AES-256)
- Генерация X.509 сертификатов с правильными расширениями
- Документирование политики сертификации

## Требования

- Go 1.21 или выше (разработка на go 1.25.7)
- Make (для сборки)
- OpenSSL (для проверки сертификатов)

## Зависимости

- github.com/spf13/cobra (CLI фреймворк)
- Стандартные криптографические пакеты Go

## Установка

```bash
# Клонирование репозитория
git clone https://github.com/serblowup/MicroPKI.git
cd MicroPKI/micropki

# Установка зависимостей
go mod tidy

# Очистка
make clean

# Сборка проекта
make build

# Запуск всех тестов
make test

# Запуск всех скриптов
make scripts
```

После сборки бинарный файл будет доступен в `./bin/micropki`.

---

## Команды

### 1. Управление удостоверяющими центрами (`ca`)

#### `ca init` - инициализация корневого УЦ

```bash
# Создание корневого УЦ (RSA 4096)
./bin/micropki ca init \
    --subject "/CN=Test Root CA" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./root.pass \
    --out-dir ./pki \
    --validity-days 3650 \
    --log-file ./ca-init.log
```

| Параметр | Описание | Значение по умолчанию |
|----------|----------|----------------------|
| `--subject` | Distinguished Name (обязательно) | - |
| `--key-type` | Тип ключа: `rsa` или `ecc` | `rsa` |
| `--key-size` | Размер ключа в битах | `4096` (RSA), `384` (ECC) |
| `--passphrase-file` | Файл с парольной фразой (обязательно) | - |
| `--out-dir` | Выходная директория | `./pki` |
| `--validity-days` | Срок действия в днях | `3650` (10 лет) |
| `--log-file` | Файл для логов | stderr |
| `--force` | Принудительная перезапись | `false` |

#### `ca issue-intermediate` - создание промежуточного УЦ

```bash
# Создание промежуточного УЦ, подписанного корневым
./bin/micropki ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file ./root.pass \
    --subject "/CN=Test Intermediate CA" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./inter.pass \
    --out-dir ./pki \
    --validity-days 1825 \
    --pathlen 0
```

| Параметр | Описание | Значение по умолчанию |
|----------|----------|----------------------|
| `--root-cert` | Путь к сертификату корневого УЦ | - |
| `--root-key` | Путь к зашифрованному ключу корневого УЦ | - |
| `--root-pass-file` | Файл с паролем корневого УЦ | - |
| `--subject` | Отличительное имя для промежуточного УЦ | - |
| `--key-type` | Тип ключа: `rsa` или `ecc` | `rsa` |
| `--key-size` | Размер ключа в битах | `4096` |
| `--passphrase-file` | Парольная фраза для ключа промежуточного УЦ | - |
| `--out-dir` | Выходная директория | `./pki` |
| `--validity-days` | Срок действия в днях | `1825` (5 лет) |
| `--pathlen` | Ограничение длины пути | `0` |
| `--log-file` | Файл для логов | stderr |
| `--force` | Принудительная перезапись | `false` |

#### `ca issue-cert` - выпуск конечного сертификата

```bash
# Серверный сертификат с SAN
./bin/micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./inter.pass \
    --template server \
    --subject "/CN=example.com" \
    --san dns:example.com \
    --san dns:www.example.com \
    --san ip:192.168.1.10 \
    --out-dir ./pki/certs \
    --validity-days 365

# Клиентский сертификат
./bin/micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./inter.pass \
    --template client \
    --subject "/CN=Alice Smith/emailAddress=alice@example.com" \
    --san email:alice@example.com \
    --out-dir ./pki/certs \
    --validity-days 365

# Сертификат для подписи кода
./bin/micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./inter.pass \
    --template code_signing \
    --subject "/CN=MicroPKI Code Signer" \
    --out-dir ./pki/certs \
    --validity-days 365

# Подписание внешнего CSR
./bin/micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./inter.pass \
    --template server \
    --subject "/CN=external.com" \
    --san dns:external.com \
    --csr ./external.csr \
    --out-dir ./pki/certs \
    --validity-days 30
```

| Параметр | Описание | Значение по умолчанию |
|----------|----------|----------------------|
| `--ca-cert` | Сертификат промежуточного УЦ | - |
| `--ca-key` | Зашифрованный ключ промежуточного УЦ | - |
| `--ca-pass-file` | Парольная фраза для ключа УЦ | - |
| `--template` | Шаблон: `server`, `client`, `code_signing` | - |
| `--subject` | Отличительное имя для сертификата | - |
| `--san` | Альтернативные имена субъекта | `[]` |
| `--csr` | Подписать внешний CSR (опционально) | - |
| `--out-dir` | Выходная директория | `./pki/certs` |
| `--validity-days` | Срок действия в днях | `365` |
| `--log-file` | Файл для логов | stderr |
| `--force` | Принудительная перезапись | `false` |

**Поддерживаемые типы SAN:**
- `dns:example.com` - DNS имя
- `ip:192.168.1.1` - IP адрес
- `email:user@example.com` - Email адрес
- `uri:https://example.com` - URI

**Валидация шаблонов:**
- `server`: требует DNS или IP, не принимает email
- `client`: принимает DNS, IP, email
- `code_signing`: принимает DNS, URI, не принимает IP

#### `ca verify` - проверка цепочки сертификатов

```bash
./bin/micropki ca verify \
    --root ./pki/certs/ca.cert.pem \
    --intermediate ./pki/certs/intermediate.cert.pem \
    --leaf ./pki/certs/example.com.cert.pem
```

---

## Структура выходной директории

```
./pki/
├── private/
│   ├── ca.key.pem               # зашифрованный ключ корневого УЦ (0600)
│   └── intermediate.key.pem     # зашифрованный ключ промежуточного УЦ (0600)
├── certs/
│   ├── ca.cert.pem              # сертификат корневого УЦ
│   ├── intermediate.cert.pem    # сертификат промежуточного УЦ
│   ├── example.com.cert.pem     # конечные сертификаты
│   └── example.com.key.pem      # незашифрованные ключи (0600) с предупреждением
├── csrs/
│   └── intermediate.csr.pem     # CSR промежуточного УЦ
└── policy.txt                    # документ политики сертификации
```

---

## Пример `policy.txt` после создания промежуточного УЦ

```
[CERTIFICATE POLICY DOCUMENT]
CA Name: /CN=Test Root CA
Certificate Serial Number: 3524fda9282a3dcfe9a033965b2f93cdc897069d
Validity Period: 
  Not Before: 2026-02-28T13:56:24Z
  Not After:  2036-02-26T13:56:24Z
Key Algorithm: rsa-4096
Purpose: Root CA for MicroPKI demonstration
Policy Version: 1.0
Creation Date: 2026-02-28T16:56:24+03:00
Generated by: MicroPKI

[INTERMEDIATE CA INFORMATION]
Subject: /CN=Test Intermediate CA
Serial Number: 77826282edd30710c0c58f49d113e66c9d1065a
Validity Period:
  Not Before: 2026-02-28T13:56:41Z
  Not After:  2031-02-27T13:56:41Z
Key Algorithm: rsa-4096
Path Length Constraint: 0
Issuer: CN=Test Root CA
```

---

## Проверка совместимости с OpenSSL

```bash
# Просмотр сертификата
openssl x509 -in pki/certs/example.com.cert.pem -text -noout

# Проверка цепочки
openssl verify -CAfile pki/certs/ca.cert.pem \
    -untrusted pki/certs/intermediate.cert.pem \
    pki/certs/example.com.cert.pem

# Проверка соответствия ключа и сертификата
openssl x509 -in pki/certs/example.com.cert.pem -noout -modulus
openssl rsa -in pki/certs/example.com.key.pem -noout -modulus
```

---

## Скрипты

```bash
# Запуск всех скриптов 
make scripts
```

---

## Логирование

Все операции детально логируются с аудитом выдачи сертификатов:

```
2026-02-28T13:58:23.765Z [INFO] сертификат успешно выпущен: серийный номер cefae944..., шаблон server, subject /CN=example.com
2026-02-28T13:58:23.765Z [INFO] audit: issued certificate serial=123... subject=/CN=example.com template=server timestamp=2026-02-28T13:58:23Z
2026-02-28T13:59:21.507Z [ERROR] ошибка валидации SAN для шаблона: тип SAN 'email' не разрешен для шаблона server
```

---

## Тестирование

```bash
# Все тесты
make test

# Короткие тесты (без интеграционных)
make test-short

# Интеграционные тесты
make test-integration
```

Тесты проверяют:
- Генерацию RSA и ECC ключей
- Создание корневого и промежуточного УЦ
- Выпуск сертификатов по шаблонам
- Валидацию SAN
- Подписание внешних CSR
- Проверку цепочек сертификатов
- Негативные сценарии (неверные параметры, неподдерживаемые SAN, неверные пароли)

---

## Безопасность

1. **Ключи корневого и промежуточного УЦ**: зашифрованы AES-256, права доступа 0600
2. **Ключи конечных субъектов**: сохраняются незашифрованными с правами 0600 (с предупреждением)
3. **Парольная фраза**: никогда не попадает в логи (автоматически скрывается)
4. **Временные данные**: очищаются из памяти после использования
5. **OpenSSL совместимость**: все сертификаты работают с OpenSSL

---

## Структура проекта

```text
MicroPKI/
├── docs
│   └── sprints
│       ├── 1 sprint.md
│       └── 2 sprint.md
├── .gitignore
└── micropki
    ├── cmd
    │   └── micropki
    │       └── main.go
    ├── go.mod
    ├── go.sum
    ├── internal
    │   ├── ca
    │   │   └── ca.go
    │   ├── certs
    │   │   └── certificate.go
    │   ├── chain
    │   │   └── chain.go
    │   ├── cryptoutil
    │   │   └── crypto.go
    │   ├── csr
    │   │   └── csr.go
    │   ├── logger
    │   │   └── logger.go
    │   ├── san
    │   │   └── san.go
    │   └── templates
    │       └── templates.go
    ├── Makefile
    ├── README.md
    ├── scripts
    │   ├── test.sh
    │   └── verify-chain.sh
    └── tests
        ├── ca_test.go
        ├── chain_test.go
        ├── crypto_test.go
        ├── csr_test.go
        ├── integration_test.go
        ├── san_test.go
        └── templates_test.go
```
