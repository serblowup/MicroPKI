# MicroPKI

Минимальная реализация инфраструктуры открытых ключей (PKI) в рамках курса криптографии.

## Возможности

- Создание самоподписанного корневого УЦ (RSA 4096 или ECC P-384)
- Создание промежуточного УЦ, подписанного корневым
- Выпуск сертификатов по шаблонам: server, client, code_signing
- Поддержка Subject Alternative Name (SAN) - DNS, IP, email, URI
- Подписание внешних CSR
- Проверка цепочки сертификатов
- Отзыв сертификатов с поддержкой всех причин RFC 5280
- Генерация и распространение списков отзыва (CRL)
- Безопасное хранение ключей с шифрованием (AES-256)
- Генерация X.509 сертификатов с правильными расширениями
- Документирование политики сертификации
- SQLite БД для хранения всех выпущенных сертификатов
- Уникальные серийные номера (64-битные: timestamp + random)
- Автоматическое сохранение сертификатов в БД при выпуске
- Просмотр сертификатов в табличном, JSON и CSV форматах
- HTTP репозиторий для получения сертификатов и CRL по API

## Требования

- Go 1.21 или выше (разработка на go 1.25.7)
- Make (для сборки)
- OpenSSL (для проверки сертификатов и CRL)
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

#### `ca revoke` - отзыв сертификата

```bash
# Отзыв сертификата по серийному номеру
./bin/micropki ca revoke 0baee839362091a1 --reason keyCompromise

# Отзыв с подтверждением (без --force)
./bin/micropki ca revoke 0baee839362091a1 --reason superseded

# Принудительный отзыв без подтверждения
./bin/micropki ca revoke 0baee839362091a1 --reason keyCompromise --force
```

| Параметр | Описание | Значение по умолчанию |
|----------|----------|----------------------|
| `serial` | Серийный номер в hex формате (обязательно) | - |
| `--reason` | Причина отзыва: unspecified, keyCompromise, cACompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCRL, privilegeWithdrawn, aACompromise | `unspecified` |
| `--crl` | Путь к CRL файлу для обновления | автоматически |
| `--force` | Пропустить подтверждение | `false` |
| `--db-path` | Путь к SQLite базе данных | `./pki/micropki.db` |

#### `ca gen-crl` - генерация списка отозванных сертификатов (CRL)

```bash
# Генерация CRL для промежуточного УЦ
./bin/micropki ca gen-crl --ca intermediate --next-update 14

# Генерация CRL для корневого УЦ с пользовательским путем
./bin/micropki ca gen-crl --ca root --next-update 7 --out-file ./backup/root.crl.pem

# Генерация CRL с указанием сертификата и ключа
./bin/micropki ca gen-crl --ca custom \
    --ca-cert ./pki/certs/custom.cert.pem \
    --ca-key ./pki/private/custom.key.pem \
    --ca-pass-file ./custom.pass \
    --next-update 30
```

| Параметр | Описание | Значение по умолчанию |
|----------|----------|----------------------|
| `--ca` | УЦ: root, intermediate или путь к сертификату | - |
| `--next-update` | Дней до следующего обновления CRL | `7` |
| `--out-file` | Выходной файл CRL | `<out-dir>/crl/<ca>.crl.pem` |
| `--ca-cert` | Путь к сертификату УЦ (опционально) | - |
| `--ca-key` | Путь к ключу УЦ (опционально) | - |
| `--ca-pass-file` | Файл с паролем УЦ (опционально) | - |
| `--db-path` | Путь к SQLite базе данных | `./pki/micropki.db` |

#### `ca check-revoked` - проверка статуса отзыва

```bash
# Проверка статуса сертификата
./bin/micropki ca check-revoked 0baee839362091a1
```

| Параметр | Описание | Значение по умолчанию |
|----------|----------|----------------------|
| `serial` | Серийный номер в hex формате (обязательно) | - |
| `--db-path` | Путь к SQLite базе данных | `./pki/micropki.db` |

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
  "timestamp": "2026-03-21T15:58:27Z",
  "database": "ok",
  "cert_dir": "./pki/certs",
  "crl_dir": "./pki/crl"
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

#### `GET /crl` - получение списка отозванных сертификатов

```bash
# Получение CRL по умолчанию (промежуточный УЦ)
curl -v http://127.0.0.1:8080/crl -o intermediate.crl.pem

# Получение CRL корневого УЦ
curl "http://127.0.0.1:8080/crl?ca=root" -o root.crl.pem

# Получение CRL по имени файла
curl http://127.0.0.1:8080/crl/intermediate.crl.pem -o crl.pem

# Проверка CRL с помощью OpenSSL
openssl crl -inform PEM -in intermediate.crl.pem -text -noout
openssl crl -inform PEM -in intermediate.crl.pem -CAfile intermediate.cert.pem -noout
```

**Заголовки ответа:**
- `Content-Type: application/pkix-crl`
- `Last-Modified`: время последнего изменения файла
- `Cache-Control: max-age=3600`
- `ETag`: хеш содержимого файла

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
├── crl/                         # CRL файлы
│   ├── root.crl.pem             # CRL корневого УЦ
│   └── intermediate.crl.pem     # CRL промежуточного УЦ
└── policy.txt                   # документ политики сертификации
```

---

## Примеры работы с отзывом сертификатов

```bash
# 1. Выпустить сертификат
./bin/micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./inter.pass \
    --template server \
    --subject "/CN=test.example.com" \
    --san dns:test.example.com

# 2. Посмотреть серийный номер
./bin/micropki ca list-certs --format table

# 3. Отозвать сертификат
./bin/micropki ca revoke 0baee839362091a1 --reason keyCompromise

# 4. Сгенерировать CRL
./bin/micropki ca gen-crl --ca intermediate --next-update 14

# 5. Проверить статус
./bin/micropki ca check-revoked 0baee839362091a1

# 6. Получить CRL через HTTP
curl http://127.0.0.1:8080/crl -o crl.pem

# 7. Проверить CRL через OpenSSL
openssl crl -in crl.pem -text -noout | grep -A5 "Revoked Certificates"
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

# Проверка CRL
openssl crl -inform PEM -in pki/crl/intermediate.crl.pem -text -noout
openssl crl -inform PEM -in pki/crl/intermediate.crl.pem -CAfile pki/certs/intermediate.cert.pem -noout

# Проверка соответствия ключа и сертификата
openssl x509 -in pki/certs/example.com.cert.pem -noout -modulus
openssl rsa -in pki/certs/example.com.key.pem -noout -modulus
```

## Логирование

Все операции детально логируются:

```
2026-03-21T15:44:54.074Z [INFO] корневой УЦ успешно создан в директории: test-debug
2026-03-21T15:46:56.024Z [INFO] сертификат 0bb2dc0fae29114a успешно отозван, причина: keyCompromise
2026-03-21T15:48:01.875Z [INFO] CRL успешно сгенерирован: test-debug/crl/intermediate.crl.pem, номер=1, отозванных сертификатов=2
2026-03-21T15:50:07.227Z [INFO] [HTTP] GET /crl - 200 OK [146.089µs] client=127.0.0.1:35966
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

# Тесты CRL
make test-crl

# Тесты отзыва
make test-revocation
```

Тесты проверяют:
- Генерацию RSA и ECC ключей
- Создание корневого и промежуточного УЦ
- Выпуск сертификатов по шаблонам
- Валидацию SAN
- Подписание внешних CSR
- Проверку цепочек сертификатов
- Отзыв сертификатов с различными причинами
- Генерацию и проверку CRL
- HTTP эндпоинты для CRL
- Негативные сценарии
- Работу с базой данных

---

## Безопасность

1. **Ключи корневого и промежуточного УЦ**: зашифрованы AES-256, права доступа 0600
2. **Ключи конечных субъектов**: сохраняются незашифрованными с правами 0600 (с предупреждением)
3. **Парольная фраза**: никогда не попадает в логи (автоматически скрывается)
4. **Временные данные**: очищаются из памяти после использования
5. **База данных**: SQLite с правами 0644, чувствительные данные не хранятся
6. **OpenSSL совместимость**: все сертификаты и CRL работают с OpenSSL

---

## Структура проекта

```text
MicroPKI/
├── docs
│   └── sprints
│       ├── 1 sprint.md
│       ├── 2 sprint.md
│       ├── 3 sprint.md
│       └── 4 sprint.md
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
│   │   ├── crl
│   │   │   ├── crl.go
│   │   │   └── manager.go
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
│   │   ├── revocation
│   │   │   └── revocation.go
│   │   ├── san
│   │   │   └── san.go
│   │   └── templates
│   │       └── templates.go
│   ├── Makefile
│   ├── scripts
│   │   ├── test-revocation-with-openssl.sh
│   │   ├── test.sh
│   │   └── verify-chain.sh
│   └── tests
│       ├── ca_test.go
│       ├── chain_test.go
│       ├── crl_test.go
│       ├── crypto_test.go
│       ├── csr_test.go
│       ├── database_test.go
│       ├── integration_test.go
│       ├── repository_test.go
│       ├── revocation_test.go
│       ├── san_test.go
│       └── templates_test.go
└── README.md
```
