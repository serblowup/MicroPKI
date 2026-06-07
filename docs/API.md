# API Reference MicroPKI

## Базовый URL

```
http://localhost:8080
```

Порт можно изменить при запуске сервера с помощью флага `--port`.

## Аутентификация

Если при запуске сервера установлена переменная окружения `MICROPKI_API_KEY`, то все запросы к эндпоинту `POST /request-cert` должны содержать заголовок:

```
X-API-Key: <ключ>
```

## Эндпоинты

### Проверка работоспособности

**`GET /health`**

Проверяет, что сервер работает и база данных доступна.

**Пример запроса:**

```bash
curl http://localhost:8080/health
```

**Пример ответа:**

```json
{
  "status": "ok",
  "timestamp": "2026-05-25T15:40:11Z",
  "database": "ok",
  "cert_dir": "./pki/certs",
  "crl_dir": "pki/crl"
}
```

**Коды ответа:**

| Код | Описание |
|-----|----------|
| 200 | Успешно |

---

### Получение корневого сертификата

**`GET /ca/root`**

Возвращает сертификат корневого УЦ в формате PEM.

> **Примечание:** Корневой сертификат хранится **только в файловой системе** и не дублируется в БД. Этот эндпоинт читает файл `certs/ca.cert.pem` напрямую.

**Пример запроса:**

```bash
curl http://localhost:8080/ca/root -o root.cert.pem
```

**Коды ответа:**

| Код | Описание |
|-----|----------|
| 200 | Успешно, сертификат возвращён |
| 404 | Сертификат не найден |

**Заголовки ответа:**

| Заголовок | Значение |
|-----------|----------|
| Content-Type | application/x-pem-file |
| Content-Disposition | inline; filename="root-ca.pem" |

---

### Получение промежуточного сертификата

**`GET /ca/intermediate`**

Возвращает сертификат промежуточного УЦ в формате PEM.

**Пример запроса:**

```bash
curl http://localhost:8080/ca/intermediate -o intermediate.cert.pem
```

**Коды ответа:**

| Код | Описание |
|-----|----------|
| 200 | Успешно, сертификат возвращён |
| 404 | Сертификат не найден |

**Заголовки ответа:**

| Заголовок | Значение |
|-----------|----------|
| Content-Type | application/x-pem-file |
| Content-Disposition | inline; filename="intermediate-ca.pem" |

---

### Получение сертификата по серийному номеру

**`GET /certificate/{serial}`**

Возвращает сертификат в формате PEM по его серийному номеру (в hex-формате).

> **Важно:** Этот эндпоинт ищет сертификаты **только в SQLite базе данных**.
> Корневой сертификат (который не сохраняется в БД) через этот эндпоинт недоступен.
> Для получения корневого сертификата используйте `GET /ca/root`.

**Параметры пути:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `serial` | string | Серийный номер в hex-формате (например, `0baee839362091a1`) |

**Пример запроса:**

```bash
curl http://localhost:8080/certificate/0baee839362091a1 -o cert.pem
```

**Коды ответа:**

| Код | Описание |
|-----|----------|
| 200 | Успешно, сертификат возвращён |
| 400 | Неверный формат серийного номера |
| 404 | Сертификат не найден |

**Заголовки ответа:**

| Заголовок | Значение |
|-----------|----------|
| Content-Type | application/x-pem-file |
| Content-Disposition | inline; filename="cert-<serial>.pem" |

---

### Запрос сертификата из CSR

**`POST /request-cert`**

Отправляет CSR в УЦ и получает подписанный сертификат.

**Параметры формы (multipart/form-data):**

| Параметр | Тип | Обязательный | Описание |
|----------|-----|--------------|----------|
| `csr` | file | Да | Файл CSR в формате PEM |
| `template` | string | Да | Шаблон сертификата: `server`, `client`, `code_signing` |

**Заголовки (опционально):**

| Заголовок | Описание |
|-----------|----------|
| `X-API-Key` | API ключ для аутентификации (если настроен) |

**Пример запроса:**

```bash
curl -X POST http://localhost:8080/request-cert \
    -F "csr=@request.csr.pem" \
    -F "template=server" \
    -o certificate.pem
```

**С API ключом:**

```bash
curl -X POST http://localhost:8080/request-cert \
    -H "X-API-Key: changeme" \
    -F "csr=@request.csr.pem" \
    -F "template=server" \
    -o certificate.pem
```

**Пример ответа при ошибке:**

```json
{
  "success": false,
  "message": "нарушение политики размера ключа: размер RSA ключа для конечного сертификата должен быть не менее 2048 бит, получено: 1024"
}
```

**Коды ответа:**

| Код | Описание |
|-----|----------|
| 201 | Успешно, сертификат создан и возвращён |
| 400 | Ошибка в запросе (неверный CSR, отсутствует template, нарушение политик) |
| 401 | Неверный API ключ |
| 500 | Внутренняя ошибка сервера |

**Проверяемые политики безопасности:**

- Размер ключа (RSA ≥ 2048, ECC ≥ 256)
- Срок действия (не более 365 дней)
- Типы SAN для выбранного шаблона
- Отсутствие wildcard в DNS именах (по умолчанию)
- Ключ не должен быть скомпрометирован

---

### Получение списка отозванных сертификатов (CRL)

**`GET /crl`**

Возвращает CRL (Certificate Revocation List) в формате PEM.

**Параметры запроса:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `ca` | string | УЦ: `root` или `intermediate`. По умолчанию `intermediate` |

**Пример запроса:**

```bash
# Получение CRL промежуточного УЦ (по умолчанию)
curl http://localhost:8080/crl -o intermediate.crl.pem

# Получение CRL корневого УЦ
curl "http://localhost:8080/crl?ca=root" -o root.crl.pem
```

**Заголовки ответа:**

| Заголовок | Значение |
|-----------|----------|
| Content-Type | application/pkix-crl |
| Cache-Control | max-age=3600 |
| ETag | `<хеш_файла>` |
| Last-Modified | `<дата_последнего_изменения>` |
| Content-Disposition | inline; filename="<ca>.crl.pem" |

**Коды ответа:**

| Код | Описание |
|-----|----------|
| 200 | Успешно, CRL возвращён |
| 400 | Неверный параметр `ca` (допустимо только `root` или `intermediate`) |
| 404 | CRL не найден |

---

### Получение CRL по имени файла

**`GET /crl/{filename}`**

Возвращает CRL файл по имени. Расширение `.pem` можно не указывать — оно будет добавлено автоматически.

**Параметры пути:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `filename` | string | Имя файла CRL (например, `intermediate.crl.pem` или `intermediate.crl`) |

**Пример запроса:**

```bash
# С указанием расширения
curl http://localhost:8080/crl/intermediate.crl.pem -o intermediate.crl.pem

# Без указания расширения
curl http://localhost:8080/crl/intermediate.crl -o intermediate.crl.pem
```

**Коды ответа:**

| Код | Описание |
|-----|----------|
| 200 | Успешно, CRL возвращён |
| 404 | Файл не найден |

---

## Форматы данных

### Формат CSR (PEM)

```
-----BEGIN CERTIFICATE REQUEST-----
MIIC5TCCAc0CAQAwGjEYMBYGA1UEAwwPdGVzdC5leGFtcGxlLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBALvBvK6YtMkZ... (обрезано)
-----END CERTIFICATE REQUEST-----
```

### Формат сертификата (PEM)

```
-----BEGIN CERTIFICATE-----
MIIDAzCCAmugAwIBAgIUNjY2NgoXyFgXyFgXyFgXyFgXyFgXyFgXyFgXyFgXyFgX
... (обрезано)
-----END CERTIFICATE-----
```

### Формат CRL (PEM)

```
-----BEGIN X509 CRL-----
MIIBpTCBkKCBjDCBiTANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxUZXN0IENB
... (обрезано)
-----END X509 CRL-----
```

---

## Ограничения

### Rate Limiting

При включённом ограничении частоты запросов (флаги `--rate-limit` и `--rate-burst`) сервер возвращает HTTP 429 при превышении лимита:

**Пример ответа при превышении лимита:**

```json
{
  "error": "rate_limit_exceeded",
  "message": "Превышен лимит запросов. Попробуйте через 1 секунд",
  "retry_after": 1
}
```

**Заголовки:**

| Заголовок | Значение |
|-----------|----------|
| Retry-After | количество секунд до следующей попытки |

### Максимальный размер запроса

- Максимальный размер CSR: 10 MB

### Поддерживаемые форматы ключей

- RSA (1024-8192 бит, но политики требуют ≥2048)
- ECDSA (P-256, P-384, P-521, но политики ограничивают)

---

## Пример полного цикла с использованием API

### 1. Генерация CSR (клиент)

```bash
./bin/micropki client gen-csr \
    --subject "/CN=api.example.com" \
    --key-type rsa \
    --key-size 2048 \
    --san dns:api.example.com \
    --out-key ./api.key.pem \
    --out-csr ./api.csr.pem
```

### 2. Запуск сервера с API ключом

```bash
export MICROPKI_API_KEY="secret-key"
./bin/micropki repo serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db
```

### 3. Запрос сертификата

```bash
curl -X POST http://localhost:8080/request-cert \
    -H "X-API-Key: secret-key" \
    -F "csr=@api.csr.pem" \
    -F "template=server" \
    -o api.cert.pem
```

### 4. Проверка сертификата

```bash
./bin/micropki client validate \
    --cert api.cert.pem \
    --untrusted ./pki/certs/intermediate.cert.pem \
    --trusted ./pki/certs/ca.cert.pem
```

### 5. Получение CRL

```bash
curl http://localhost:8080/crl -o intermediate.crl.pem
```

### 6. Проверка статуса с CRL

```bash
./bin/micropki client check-status \
    --cert api.cert.pem \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --crl intermediate.crl.pem
```

---

## Коды ошибок HTTP

| Код | Описание |
|-----|----------|
| 200 | Успешно (GET запросы) |
| 201 | Успешно создано (POST /request-cert) |
| 400 | Неверный запрос (неверные параметры, отсутствуют обязательные поля) |
| 401 | Не авторизован (неверный API ключ) |
| 404 | Ресурс не найден |
| 405 | Метод не разрешён (например, POST на GET эндпоинт) |
| 429 | Слишком много запросов (превышен rate limit) |
| 500 | Внутренняя ошибка сервера |

---

## Безопасность

- Корневой сертификат хранится **только в файловой системе** и не дублируется в БД
- Ключи OCSP-ответчика и конечных субъектов хранятся **незашифрованными**
- Сервер не использует TLS — рекомендуется запускать за reverse proxy (nginx, Caddy)
- Rate limiting не защищает от распределённых атак (DDoS)

---

## См. также

- [Руководство пользователя](USERGUIDE.md)
- [README](../README.md)
- [Демонстрация работы](../demo/DEMO.md)