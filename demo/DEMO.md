# Пошаговое руководство по демонстрации MicroPKI

## Обзор

MicroPKI включает полностью автоматизированный демонстрационный скрипт (`demo/demo.sh`), который показывает все основные возможности системы PKI. Скрипт запускается во временной директории, собирает проект, выполняет все операции PKI и очищает за собой.

## Требования

- Установленный Go 1.21+
- Утилита Make
- OpenSSL (для демонстрации TLS и подписи кода)
- curl (для тестирования HTTP API)
- Интернет-соединение (для загрузки Go-модулей)

## Запуск демонстрации

```bash
# Из корневой директории проекта
./demo/demo.sh
```

Скрипт выполнит:
1. Сборку бинарного файла MicroPKI
2. Создание временной директории для всех операций
3. Выполнение 15 шагов демонстрации
4. Вывод результатов с цветным оформлением
5. Остановку всех серверов и предложение очистки

## Описание шагов демонстрации

### Шаг 0: Сборка MicroPKI
Выполняет `make build` в директории `micropki/` для компиляции бинарного файла.

### Шаги 1-3: Настройка инфраструктуры PKI
- **Шаг 1**: Создание базы данных SQLite
- **Шаг 2**: Генерация корневого УЦ (RSA 4096, срок действия 10 лет)
- **Шаг 3**: Создание промежуточного УЦ, подписанного корневым (RSA 4096, срок действия 5 лет)

### Шаги 4-7: Выпуск сертификатов
- **Шаг 4**: Серверный сертификат для TLS (CN=localhost, SAN: localhost, 127.0.0.1)
- **Шаг 5**: Сертификат для подписи кода (CN=MicroPKI Code Signer)
- **Шаг 6**: Клиентский сертификат (CN=Demo Client, email SAN)
- **Шаг 7**: Сертификат OCSP-ответчика (с расширением OCSPSigning)

### Шаги 8-9: Запуск сервисов
- **Шаг 8**: HTTP сервер репозитория на порту 18080
- **Шаг 9**: OCSP-ответчик на порту 18081

### Шаги 10-11: Демонстрация TLS и OCSP Stapling
- Запуск HTTPS сервера OpenSSL на порту 8443 с поддержкой OCSP Stapling (`-status`)
- Четыре теста:
  - Подключение с доверенным корневым сертификатом (должно успешно)
  - Подключение без доверенного CA (должно провалиться — проверка безопасности)
  - Верификация цепочки сертификатов (должна пройти)
  - Проверка OCSP Stapling (должна показать, что stapling активен)

### Шаг 12: Демонстрация подписи кода
- Создание тестового bash-скрипта
- Подпись с использованием SHA-256 и закрытого ключа
- Верификация подписи с использованием сертификата
- Изменение файла и проверка, что подпись отклоняется

### Шаг 13: Отзыв сертификата
- Отзыв сертификата сервера (причина: keyCompromise)
- Генерация нового CRL (Списка отзыва сертификатов)
- Обновление статуса в базе данных

### Шаг 14: Проверка целостности аудит-лога
- Чтение аудит-лога
- Верификация SHA-256 хеш-цепочки
- Подтверждение отсутствия подделки

### Шаг 15: Очистка артефактов сборки
- Выполнение `make clean` для удаления артефактов сборки
- Остановка всех запущенных серверов
- Предложение удалить временную директорию демонстрации

## Ожидаемый вывод

Успешная демонстрация покажет:

```
MicroPKI Demo - Sprint 8

Project root: /home/user/MicroPKI

[0/15] Building MicroPKI...
...

[11/15] TLS Demonstration - Testing HTTPS Connection...
  Test 1: Connection with trusted Root CA...
    TLS connection successful with trusted Root CA
  Test 2: Connection without trusted Root CA...
    TLS connection correctly rejected without trusted CA
  Test 3: Certificate chain verification with openssl verify...
    Certificate chain verified successfully

TLS Test Results:
  All TLS tests passed!

[12/15] Code Signing Demonstration...
  Code signature verified successfully
  Tampered file correctly rejected by signature verification

[13/15] Certificate Revocation Demonstration...
Certificate revoked successfully
CRL generated successfully

[14/15] Audit Log Integrity Check...
Audit log intact

[15/15] Cleaning up build artifacts...

Demo completed successfully!

Demo Summary:
  - PKI Hierarchy: Root CA → Intermediate CA
  - TLS Server: https://localhost:8443
  - Code Signing: test_script.sh signed and verified
  - Revocation: Certificate revoked, CRL generated
  - Audit Log: Integrity verified
  - Build artifacts cleaned
```

## Устранение неполадок

### Порт уже используется

Если порты 18080, 18081 или 8443 уже заняты:

```bash
# Проверка, что использует порт
lsof -i :18080
lsof -i :18081
lsof -i :8443

# Завершение процесса при необходимости
kill -9 <PID>
```

### OpenSSL не найден

Установите OpenSSL:

```bash
# Ubuntu/Debian
sudo apt install openssl

# CentOS/RHEL
sudo yum install openssl

# Arch Linux
sudo pacman -S openssl
```

### Ошибка сборки

Убедитесь, что Go-модули настроены правильно:

```bash
cd micropki
go mod tidy
go mod verify
make build
```

### Ошибка TLS подключения

Убедитесь, что брандмауэр не блокирует локальные подключения:

```bash
# Проверка базовой connectivity
curl -k https://localhost:8443
```

## Ручное тестирование

После демонстрации вы можете выполнять отдельные команды вручную:

```bash
# Список всех сертификатов
./micropki/bin/micropki ca list-certs --db-path ./pki/micropki.db

# Запрос аудит-лога
./micropki/bin/micropki audit query

# Просмотр содержимого CRL
openssl crl -in ./pki/crl/intermediate.crl.pem -text -noout
```

## Замечания по безопасности

- В демонстрации используются простые пароли (`rootpass123`, `interpass123`) для упрощения
- Закрытые ключи конечных субъектов хранятся **незашифрованными** (выводится предупреждение)
- Закрытые ключи УЦ хранятся **зашифрованными** с использованием AES-256
- Временная директория создаётся с помощью `mktemp -d` для изоляции
- Все серверы завершаются после демонстрации

## Файлы, создаваемые во время демонстрации

| Файл | Описание |
|------|----------|
| `pki/micropki.db` | База данных SQLite со всеми сертификатами |
| `pki/audit/audit.log` | Аудит-лог в формате NDJSON |
| `pki/audit/chain.dat` | SHA-256 хеш-цепочка |
| `pki/audit/ct.log` | Лог симуляции Certificate Transparency |
| `pki/certs/ca.cert.pem` | Сертификат корневого УЦ |
| `pki/certs/intermediate.cert.pem` | Сертификат промежуточного УЦ |
| `pki/certs/localhost.cert.pem` | Серверный сертификат для TLS |
| `pki/certs/localhost.key.pem` | Закрытый ключ сервера (незашифрованный) |
| `pki/certs/MicroPKI\ Code\ Signer.*` | Сертификат и ключ для подписи кода |
| `pki/ocsp/ocsp.cert.pem` | Сертификат OCSP-ответчика |
| `pki/ocsp/ocsp.key.pem` | Закрытый ключ OCSP-ответчика |
| `pki/crl/intermediate.crl.pem` | CRL файл |

## Очистка

Демонстрация запрашивает подтверждение перед удалением временной директории:

```
Clean up demo directory? (y/N)
```

- Введите `y` → удалить все сгенерированные файлы
- Введите `n` → сохранить файлы  (путь будет показан)

Вы можете удалить вручную позже:

```bash
rm -rf /tmp/tmp.*
```