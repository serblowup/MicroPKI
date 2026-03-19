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
- SQLite БД для хранения всех выпущенных сертификатов
- Уникальные серийные номера (64-битные: timestamp + random)
- Автоматическое сохранение сертификатов в БД при выпуске
- Просмотр сертификатов в табличном, JSON и CSV форматах
- HTTP репозиторий для получения сертификатов по API

## Требования

- Go 1.21 или выше (разработка на go 1.25.7)
- Make (для сборки)
- OpenSSL (для проверки сертификатов)
- SQLite 3.x (встроенная через go-sqlite3)

## Зависимости

- github.com/spf13/cobra (CLI фреймворк)
- github.com/mattn/go-sqlite3 (драйвер SQLite)
- Стандартные криптографические пакеты Go

## Установка

```bash
# Клонирование репозитория
git clone https://github.com/serblowup/MicroPKI.git
cd MicroPKI/micropki

# Установка зависимостей
go mod tidy

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

### 1. Работа с базой данных (`db`)

#### `db init` - инициализация базы данных

```bash
# Инициализация новой БД
./bin/micropki db init --db-path ./pki/micropki.db

# Принудительная перезапись существующей БД
./bin/micropki db init --db-path ./pki/micropki.db --force
```

| Параметр | Описание | Значение по умолчанию |
|----------|----------|----------------------|
| `--db-path` | Путь к SQLite базе данных | `./pki/micropki.db` |
| `--force` | Принудительная перезапись | `false` |
| `--log-file` | Файл для логов | stderr |

### 2. Управление удостоверяющими центрами (`ca`)

#### `ca init` - инициализация корневого УЦ

```bash
# Создание корневого УЦ (RSA 4096) с сохранением в БД
./bin/micropki ca init \
    --subject "/CN=Test Root CA" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./root.pass \
    --out-dir ./pki \
    --db-path ./pki/micropki.db \
    --validity-days 3650
```

| Параметр | Описание | Значение по умолчанию |
|----------|----------|----------------------|
| `--subject` | Distinguished Name (обязательно) | - |
| `--key-type` | Тип ключа: `rsa` или `ecc` | `rsa` |
| `--key-size` | Размер ключа в битах | `4096` (RSA), `384` (ECC) |
| `--passphrase-file` | Файл с парольной фразой (обязательно) | - |
| `--out-dir` | Выходная директория | `./pki` |
| `--db-path` | Путь к SQLite базе данных | `./pki/micropki.db` |
| `--validity-days` | Срок действия в днях | `3650` (10 лет) |
| `--log-file` | Файл для логов | stderr |
| `--force` | Принудительная перезапись | `false` |

#### `ca issue-intermediate` - создание промежуточного УЦ

```bash
# Создание промежуточного УЦ с сохранением в БД
./bin/micropki ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file ./root.pass \
    --subject "/CN=Test Intermediate CA" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./inter.pass \
    --out-dir ./pki \
    --db-path ./pki/micropki.db \
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
| `--db-path` | Путь к SQLite базе данных | `./pki/micropki.db` |
| `--validity-days` | Срок действия в днях | `1825` (5 лет) |
| `--pathlen` | Ограничение длины пути | `0` |
| `--log-file` | Файл для логов | stderr |
| `--force` | Принудительная перезапись | `false` |

#### `ca issue-cert` - выпуск конечного сертификата

```bash
# Серверный сертификат с SAN (автосохранение в БД)
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
    --db-path ./pki/micropki.db \
    --validity-days 365

# Клиентский сертификат
./bin/micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./inter.pass \
    --template client \
    --subject "/CN=Alice Smith" \
    --san email:alice@example.com \
    --out-dir ./pki/certs \
    --db-path ./pki/micropki.db \
    --validity-days 365

# Сертификат для подписи кода
./bin/micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./inter.pass \
    --template code_signing \
    --subject "/CN=MicroPKI Code Signer" \
    --out-dir ./pki/certs \
    --db-path ./pki/micropki.db \
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
    --db-path ./pki/micropki.db \
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
| `--db-path` | Путь к SQLite базе данных | `./pki/micropki.db` |
| `--validity-days` | Срок действия в днях | `365` |
| `--log-file` | Файл для логов | stderr |
| `--force` | Принудительная перезапись | `false` |

#### `ca list-certs` - просмотр сертификатов в БД 

```bash
# Табличный вывод (вывод по умолчанию)
./bin/micropki ca list-certs --db-path ./pki/micropki.db --format table

# JSON формат
./bin/micropki ca list-certs --db-path ./pki/micropki.db --format json

# CSV формат
./bin/micropki ca list-certs --db-path ./pki/micropki.db --format csv

# Фильтр по статусу
./bin/micropki ca list-certs --db-path ./pki/micropki.db --status valid
```

| Параметр | Описание | Значение по умолчанию |
|----------|----------|----------------------|
| `--db-path` | Путь к SQLite базе данных | `./pki/micropki.db` |
| `--status` | Фильтр по статусу (valid, revoked, expired) | все |
| `--format` | Формат вывода: `table`, `json`, `csv` | `table` |
| `--log-file` | Файл для логов | stderr |

#### `ca show-cert` - просмотр конкретного сертификата

```bash
# Показать сертификат по серийному номеру
./bin/micropki ca show-cert 0baee839362091a1 --db-path ./pki/micropki.db

# Сохранить в файл
./bin/micropki ca show-cert 0baee839362091a1 --db-path ./pki/micropki.db > cert.pem
```

| Параметр | Описание | Значение по умолчанию |
|----------|----------|----------------------|
| `serial` | Серийный номер в hex формате (обязательно) | - |
| `--db-path` | Путь к SQLite базе данных | `./pki/micropki.db` |
| `--log-file` | Файл для логов | stderr |

#### `ca verify` - проверка цепочки сертификатов

```bash
./bin/micropki ca verify \
    --root ./pki/certs/ca.cert.pem \
    --intermediate ./pki/certs/intermediate.cert.pem \
    --leaf ./pki/certs/example.com.cert.pem
```

### 3. HTTP репозиторий (`repo`) 

#### `repo serve` - запуск HTTP сервера

```bash
# Запуск на локальном интерфейсе
./bin/micropki repo serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db

# Запуск на всех интерфейсах
./bin/micropki repo serve --host 0.0.0.0 --port 8443 --db-path ./pki/micropki.db
```

| Параметр | Описание | Значение по умолчанию |
|----------|----------|----------------------|
| `--host` | Адрес для привязки сервера | `127.0.0.1` |
| `--port` | TCP порт | `8080` |
| `--db-path` | Путь к SQLite базе данных | `./pki/micropki.db` |
| `--cert-dir` | Директория с PEM сертификатами | `./pki/certs` |
| `--log-file` | Файл для логов | stderr |

#### `repo status` - проверка статуса сервера

```bash
./bin/micropki repo status --host 127.0.0.1 --port 8080
```

| Параметр | Описание | Значение по умолчанию |
|----------|----------|----------------------|
| `--host` | Адрес сервера | `127.0.0.1` |
| `--port` | TCP порт | `8080` |
| `--log-file` | Файл для логов | stderr |

### 4. API эндпоинты HTTP сервера

#### `GET /health` - проверка работоспособности

```bash
curl http://127.0.0.1:8080/health
```
Вывод:
```json
{
  "status": "ok",
  "timestamp": "2026-03-18T15:58:27Z",
  "database": "ok",
  "cert_dir": "./pki/certs"
}
```

#### `GET /ca/root` - получение корневого сертификата

```bash
curl http://127.0.0.1:8080/ca/root -o root.pem
openssl x509 -in root.pem -text -noout
```

#### `GET /ca/intermediate` - получение промежуточного сертификата

```bash
curl http://127.0.0.1:8080/ca/intermediate -o inter.pem
openssl x509 -in inter.pem -text -noout
```

#### `GET /certificate/{serial}` - получение сертификата по серийному номеру

```bash
# Получение сертификата
curl http://127.0.0.1:8080/certificate/0baee839362091a1 -o cert.pem

# Проверка
openssl x509 -in cert.pem -text -noout | head -5
```

#### `GET /crl` - получение CRL 

```bash
curl -v http://127.0.0.1:8080/crl
```
---

## Поддерживаемые типы SAN

- `dns:example.com` - DNS имя
- `ip:192.168.1.1` - IP адрес
- `email:user@example.com` - Email адрес
- `uri:https://example.com` - URI

**Валидация шаблонов:**
- `server`: требует DNS или IP, не принимает email
- `client`: принимает DNS, IP, email
- `code_signing`: принимает DNS, URI, не принимает IP

---

## Структура выходной директории

```
./pki/
├── micropki.db                  # SQLite база данных
├── private/
│   ├── ca.key.pem               # зашифрованный ключ корневого УЦ (0600)
│   └── intermediate.key.pem     # зашифрованный ключ промежуточного УЦ (0600)
├── certs/
│   ├── ca.cert.pem              # сертификат корневого УЦ
│   ├── intermediate.cert.pem    # сертификат промежуточного УЦ
│   ├── example.com.cert.pem     # конечные сертификаты
│   └── example.com.key.pem      # незашифрованные ключи (0600)
├── csrs/
│   └── intermediate.csr.pem     # CSR промежуточного УЦ
└── policy.txt                   # документ политики сертификации
```

---

## Примеры работы с БД

```bash
# Инициализация БД
./bin/micropki db init --db-path ./pki/micropki.db

# Создание корневого УЦ
./bin/micropki ca init --subject "/CN=Test Root CA" --passphrase-file ./root.pass --db-path ./pki/micropki.db

# Просмотр всех сертификатов
./bin/micropki ca list-certs --db-path ./pki/micropki.db --format table

# Просмотр в JSON
./bin/micropki ca list-certs --db-path ./pki/micropki.db --format json | jq '.[] | {serial: .serial_hex, subject: .subject}'
```

---

## Пример `policy.txt` после создания промежуточного УЦ

```
[CERTIFICATE POLICY DOCUMENT]
CA Name: /CN=Test Root CA
Certificate Serial Number: 0baee839362091a1
Validity Period: 
  Not Before: 2026-03-18T15:48:09Z
  Not After:  2027-03-18T15:48:09Z
Key Algorithm: rsa-4096
Purpose: Root CA for MicroPKI demonstration
Policy Version: 1.0
Creation Date: 2026-03-18T18:48:09+03:00
Generated by: MicroPKI

[INTERMEDIATE CA INFORMATION]
Subject: /CN=Test Intermediate CA
Serial Number: 0baee875c66b2ca1
Validity Period:
  Not Before: 2026-03-18T15:49:09Z
  Not After:  2027-03-18T15:49:09Z
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

## Логирование

Все операции детально логируются. В Спринте 3 добавлено логирование HTTP запросов:

```
2026-03-18T15:58:27.747Z [INFO] [HTTP] GET /health - 200 OK [28.252µs] client=127.0.0.1:45722
2026-03-18T15:58:38.101Z [INFO] [HTTP] GET /ca/root - 200 OK [205.787µs] client=127.0.0.1:50916
2026-03-18T15:59:05.934Z [WARN] неверный формат серийного номера: XYZ123
2026-03-18T15:59:05.934Z [INFO] [HTTP] GET /certificate/XYZ123 - 400 Bad Request [71.26µs] client=127.0.0.1:60806
2026-03-18T15:59:18.056Z [INFO] [HTTP] GET /crl - 501 Not Implemented [72.763µs] client=127.0.0.1:37614
2026-03-18T15:59:50.991Z [INFO] [HTTP] GET /certificate/0000000000000000 - 404 Not Found [773.709µs] client=127.0.0.1:45602
```

---

## Скрипты

```bash
# Запуск всех скриптов 
make scripts
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

# Тесты базы данных
make test-db

# Тесты репозитория
make test-repo
```

Тесты проверяют:
- Генерацию RSA и ECC ключей
- Создание корневого и промежуточного УЦ
- Выпуск сертификатов по шаблонам
- Валидацию SAN
- Подписание внешних CSR
- Проверку цепочек сертификатов
- Негативные сценарии
- Работу с базой данных
- HTTP эндпоинты

---

## Безопасность

1. **Ключи корневого и промежуточного УЦ**: зашифрованы AES-256, права доступа 0600
2. **Ключи конечных субъектов**: сохраняются незашифрованными с правами 0600 (с предупреждением)
3. **Парольная фраза**: никогда не попадает в логи (автоматически скрывается)
4. **Временные данные**: очищаются из памяти после использования
5. **База данных**: SQLite с правами 0644, чувствительные данные не хранятся
6. **OpenSSL совместимость**: все сертификаты работают с OpenSSL

---

## Структура проекта

```text
MicroPKI/
├── docs
│   └── sprints
│       ├── 1 sprint.md
│       ├── 2 sprint.md
│       └── 3 sprint.md
├── .gitignore
├── micropki
│   ├── cmd
│   │   └── micropki
│   │       └── main.go
│   ├── go.mod
│   ├── go.sum
│   ├── internal
│   │   ├── ca
│   │   │   └── ca.go
│   │   ├── certs
│   │   │   └── certificate.go
│   │   ├── chain
│   │   │   └── chain.go
│   │   ├── cryptoutil
│   │   │   └── crypto.go
│   │   ├── csr
│   │   │   └── csr.go
│   │   ├── database
│   │   │   ├── certificates.go
│   │   │   ├── db.go
│   │   │   ├── schema.go
│   │   │   └── serial.go
│   │   ├── logger
│   │   │   └── logger.go
│   │   ├── repository
│   │   │   ├── handlers.go
│   │   │   ├── middleware.go
│   │   │   └── server.go
│   │   ├── san
│   │   │   └── san.go
│   │   └── templates
│   │       └── templates.go
│   ├── Makefile
│   ├── scripts
│   │   ├── test.sh
│   │   └── verify-chain.sh
│   └── tests
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
