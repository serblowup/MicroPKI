# Руководство пользователя MicroPKI

## Введение

MicroPKI — это минимальная реализация инфраструктуры открытых ключей (PKI), предназначенная для образовательных целей. Система позволяет создавать удостоверяющие центры, выпускать сертификаты, проверять их статус и управлять отзывом.

## Установка

### Требования

- Go 1.21 или выше
- Make
- OpenSSL (для проверки сертификатов)
- SQLite3 (встроенная через go-sqlite3)

### Сборка из исходников

```bash
git clone https://github.com/serblowup/MicroPKI.git
cd MicroPKI/micropki
go mod tidy
make build
```

Бинарный файл будет доступен по пути `./bin/micropki`.

## Быстрый старт

### 1. Инициализация базы данных

```bash
./bin/micropki db init --db-path ./pki/micropki.db
```

### 2. Создание корневого УЦ

```bash
echo "mysecret" > root.pass
./bin/micropki ca init \
    --subject "/CN=My Root CA" \
    --passphrase-file ./root.pass \
    --out-dir ./pki
```

> **Примечание:** Корневой сертификат сохраняется **только в файловой системе** (`certs/ca.cert.pem`) и не дублируется в БД.

### 3. Создание промежуточного УЦ

```bash
echo "intersecret" > inter.pass
./bin/micropki ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file ./root.pass \
    --subject "/CN=My Intermediate CA" \
    --passphrase-file ./inter.pass \
    --out-dir ./pki
```

> **Примечание:** Сертификат промежуточного УЦ сохраняется **и в файловой системе, и в БД**.

### 4. Выпуск сертификата

```bash
./bin/micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./inter.pass \
    --template server \
    --subject "/CN=example.com" \
    --san dns:example.com \
    --out-dir ./pki/certs
```

> **Примечание:** Конечные сертификаты сохраняются **и в файловой системе, и в БД**.

## Основные операции

### Управление сертификатами

#### Просмотр всех сертификатов

```bash
./bin/micropki ca list-certs --db-path ./pki/micropki.db
```

> **Примечание:** Команда показывает только сертификаты, сохранённые в БД
> (промежуточные УЦ и конечные). Корневой сертификат в этот список не включается,
> так как он хранится только в файловой системе.

#### Просмотр конкретного сертификата

```bash
./bin/micropki ca show-cert <серийный_номер> --db-path ./pki/micropki.db
```

#### Отзыв сертификата

```bash
./bin/micropki ca revoke <серийный_номер> --reason keyCompromise
```

Поддерживаемые причины отзыва:

| Причина | Код |
|---------|-----|
| unspecified | 0 |
| keyCompromise | 1 |
| cACompromise | 2 |
| affiliationChanged | 3 |
| superseded | 4 |
| cessationOfOperation | 5 |
| certificateHold | 6 |
| removeFromCRL | 8 |
| privilegeWithdrawn | 9 |
| aACompromise | 10 |

#### Генерация CRL

```bash
./bin/micropki ca gen-crl --ca intermediate --next-update 14
```

Параметр `--next-update` указывает количество дней до следующего обновления CRL.

### Клиентские операции

#### Генерация CSR

```bash
./bin/micropki client gen-csr \
    --subject "/CN=myapp.example.com" \
    --key-type rsa \
    --key-size 2048 \
    --san dns:myapp.example.com \
    --san ip:192.168.1.100 \
    --out-key ./myapp.key.pem \
    --out-csr ./myapp.csr.pem
```

**Поддерживаемые типы SAN:**
- `dns:example.com` — DNS имя
- `ip:192.168.1.1` — IP адрес
- `email:user@example.com` — Email адрес
- `uri:https://example.com` — URI

#### Запрос сертификата через API

```bash
./bin/micropki client request-cert \
    --csr ./myapp.csr.pem \
    --template server \
    --ca-url http://localhost:8080 \
    --out-cert ./myapp.cert.pem
```

#### Проверка цепочки сертификатов

```bash
./bin/micropki client validate \
    --cert ./myapp.cert.pem \
    --untrusted ./pki/certs/intermediate.cert.pem \
    --trusted ./pki/certs/ca.cert.pem
```

Режимы валидации:
- `chain` — только проверка цепочки (подписи, сроки, key usage)
- `full` — полная проверка с отзывом (CRL/OCSP)

#### Проверка статуса отзыва

```bash
./bin/micropki client check-status \
    --cert ./myapp.cert.pem \
    --ca-cert ./pki/certs/intermediate.cert.pem
```

Логика проверки: сначала OCSP (если доступен), при ошибке — fallback на CRL.

### Аудит и безопасность

#### Просмотр аудит-лога

```bash
./bin/micropki audit query
```

Фильтрация:

```bash
# По времени
./bin/micropki audit query --from "2026-01-01T00:00:00Z" --to "2026-12-31T23:59:59Z"

# По операции
./bin/micropki audit query --operation issue

# По серийному номеру
./bin/micropki audit query --serial abc123

# JSON формат
./bin/micropki audit query --format json
```

#### Проверка целостности аудит-лога

```bash
./bin/micropki audit verify
```

При нарушении целостности команда завершится с кодом ошибки 1.

#### Поиск аномалий

```bash
./bin/micropki audit detect-anomalies --threshold 50
```

Обнаруживаемые аномалии:
- Высокая частота событий (превышение порога в час)
- Подозрительно высокая частота отзывов (>30%)
- События компрометации ключей
- Высокая частота ошибок

#### Проверка CT лога

```bash
./bin/micropki audit ct-verify --serial <серийный_номер>
```

#### Симуляция компрометации ключа

```bash
./bin/micropki ca compromise --cert ./myapp.cert.pem --reason keyCompromise
```

При компрометации происходит:
1. Немедленный отзыв сертификата
2. Добавление публичного ключа в чёрный список
3. Запись в аудит-лог с высоким уровнем важности

### Запуск серверов

#### HTTP репозиторий

```bash
./bin/micropki repo serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db
```

**С rate limiting:**

```bash
./bin/micropki repo serve --rate-limit 5 --rate-burst 10
```

#### OCSP-ответчик

```bash
./bin/micropki ocsp serve \
    --responder-cert ./pki/ocsp/ocsp.cert.pem \
    --responder-key ./pki/ocsp/ocsp.key.pem \
    --ca-cert ./pki/certs/intermediate.cert.pem
```

## Шаблоны сертификатов

| Шаблон | Назначение | Разрешённые SAN | Key Usage | Extended Key Usage |
|--------|-----------|-----------------|-----------|-------------------|
| `server` | TLS сервер | DNS, IP | digitalSignature, keyEncipherment | serverAuth |
| `client` | Аутентификация клиента | DNS, IP, email | digitalSignature | clientAuth |
| `code_signing` | Подпись кода | DNS, URI | digitalSignature | codeSigning |

## Политики безопасности

### Размеры ключей

| Тип сертификата | RSA | ECC |
|----------------|-----|-----|
| Корневой УЦ | ≥ 4096 бит | ≥ P-384 |
| Промежуточный УЦ | ≥ 3072 бит | ≥ P-384 |
| Конечный сертификат | ≥ 2048 бит | ≥ P-256 |

### Сроки действия

| Тип сертификата | Максимальный срок |
|----------------|------------------|
| Корневой УЦ | 3650 дней (10 лет) |
| Промежуточный УЦ | 1825 дней (5 лет) |
| Конечный сертификат | 365 дней (1 год) |

### Ограничения SAN

- Wildcard (`*.example.com`) запрещены по умолчанию
- Server: только DNS и IP
- Client: DNS, IP, email
- Code Signing: DNS, URI (email и IP запрещены)

### Алгоритмы подписи

- SHA-1 запрещён
- Разрешены: SHA-256, SHA-384, SHA-512 с RSA или ECDSA

## Структура выходной директории

```
./pki/
├── micropki.db                  # SQLite база данных (intermediate и leaf сертификаты)
├── audit/                       # Аудит-система
│   ├── audit.log               # Аудит-лог (NDJSON)
│   ├── chain.dat               # Хеш-цепочка
│   └── ct.log                  # CT лог
├── private/
│   ├── ca.key.pem              # зашифрованный ключ корневого УЦ (0600)
│   └── intermediate.key.pem    # зашифрованный ключ промежуточного УЦ (0600)
├── certs/
│   ├── ca.cert.pem             # сертификат корневого УЦ (только в ФС)
│   ├── intermediate.cert.pem   # сертификат промежуточного УЦ
│   ├── example.com.cert.pem    # конечные сертификаты
│   └── example.com.key.pem     # незашифрованные ключи (0600)
├── csrs/
│   └── intermediate.csr.pem    # CSR промежуточного УЦ
├── crl/                         # CRL файлы
│   ├── root.crl.pem            # CRL корневого УЦ
│   └── intermediate.crl.pem    # CRL промежуточного УЦ
├── ocsp/                        # OCSP файлы
│   ├── ocsp.cert.pem           # сертификат OCSP-ответчика
│   └── ocsp.key.pem            # незашифрованный ключ OCSP-ответчика (0600)
└── policy.txt                   # документ политики сертификации
```

## Демонстрация работы

MicroPKI включает полностью автоматизированный демонстрационный скрипт:

```bash
./demo/demo.sh
```

Скрипт выполняет 15 шагов, демонстрируя все основные возможности системы. Подробное описание см. в [DEMO.md](../demo/DEMO.md).

## Лицензия

MIT License. Подробнее см. файл [LICENSE](../LICENSE).