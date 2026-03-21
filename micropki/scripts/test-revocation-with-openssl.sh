#!/bin/bash

echo "Тест отзыва сертификата с проверкой CRL через OpenSSL"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MICROPKI="$PROJECT_ROOT/bin/micropki"

if [ ! -f "$MICROPKI" ]; then
    echo "Ошибка: Бинарный файл не найден. Запустите make build!!!"
    exit 1
fi

TEST_DIR=$(mktemp -d)
cd "$TEST_DIR" || exit 1

echo "rootpass" > root.pass
echo "interpass" > inter.pass

echo "1. Инициализация PKI..."
"$MICROPKI" db init --db-path ./pki/micropki.db --force > /dev/null 2>&1

"$MICROPKI" ca init \
    --subject "/CN=Test Root CA" \
    --passphrase-file ./root.pass \
    --out-dir ./pki \
    --db-path ./pki/micropki.db \
    --force > /dev/null 2>&1

"$MICROPKI" ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file ./root.pass \
    --subject "/CN=Test Intermediate CA" \
    --passphrase-file ./inter.pass \
    --out-dir ./pki \
    --db-path ./pki/micropki.db \
    --force > /dev/null 2>&1

echo "2. Выпуск тестового сертификата..."
"$MICROPKI" ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./inter.pass \
    --template server \
    --subject "/CN=test.local" \
    --san dns:test.local \
    --out-dir ./pki/certs \
    --db-path ./pki/micropki.db > /dev/null 2>&1

echo "3. Получение серийного номера из БД..."
SERIAL=$(sqlite3 ./pki/micropki.db "SELECT serial_hex FROM certificates WHERE subject='CN=test.local';")
echo "Серийный номер: $SERIAL"

if [ -z "$SERIAL" ]; then
    echo "ОШИБКА: Не удалось получить серийный номер"
    cd "$PROJECT_ROOT"
    rm -rf "$TEST_DIR"
    exit 1
fi

cat ./pki/certs/intermediate.cert.pem ./pki/certs/ca.cert.pem > ./chain.pem

echo "4. Проверка сертификата до отзыва..."
openssl verify -CAfile ./chain.pem ./pki/certs/test.local.cert.pem
if [ $? -eq 0 ]; then
    echo "Oк: Сертификат действителен!"
else
    echo "Ошибка: Проверка сертификата не пройдена!!!"
fi

echo "5. Отзыв сертификата..."
"$MICROPKI" ca revoke "$SERIAL" --reason keyCompromise --force --db-path ./pki/micropki.db

echo "6. Генерация CRL..."
"$MICROPKI" ca gen-crl \
    --ca intermediate \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./inter.pass \
    --db-path ./pki/micropki.db

echo "7. Проверка сертификата с CRL (ожидается отказ)..."
openssl verify -CAfile ./chain.pem -CRLfile ./pki/crl/intermediate.crl.pem -crl_check ./pki/certs/test.local.cert.pem 2>&1
if [ $? -ne 0 ]; then
    echo "Oк: Сертификат отклонен (отозван)!"
else
    echo "Ошибка: Сертификат принят (должен быть отозван)!!!"
fi

echo "8. Выпуск валидного сертификата для сравнения..."
"$MICROPKI" ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./inter.pass \
    --template server \
    --subject "/CN=valid.local" \
    --san dns:valid.local \
    --out-dir ./pki/certs \
    --db-path ./pki/micropki.db > /dev/null 2>&1

VALID_SERIAL=$(sqlite3 ./pki/micropki.db "SELECT serial_hex FROM certificates WHERE subject='CN=valid.local';")
echo "Серийный номер валидного сертификата: $VALID_SERIAL"

echo "9. Проверка валидного сертификата с CRL..."
openssl verify -CAfile ./chain.pem -CRLfile ./pki/crl/intermediate.crl.pem -crl_check ./pki/certs/valid.local.cert.pem
if [ $? -eq 0 ]; then
    echo "Oк: Валидный сертификат принят!"
else
    echo "Ошибка: Валидный сертификат отклонен!!!"
fi

echo "10. Тестирование HTTPS сервера с отозванным сертификатом..."
openssl s_server -accept 8444 -cert ./pki/certs/test.local.cert.pem -key ./pki/certs/test.local.key.pem -www > /dev/null 2>&1 &
SERVER_PID=$!
sleep 2

echo "11. Подключение к серверу с отозванным сертификатом..."
echo "Q" | openssl s_client -connect localhost:8444 -CAfile ./chain.pem -CRLfile ./pki/crl/intermediate.crl.pem -crl_check 2>&1 | grep "Verify return code"

kill $SERVER_PID 2>/dev/null

echo "Тест завершен!"

cd "$PROJECT_ROOT"
rm -rf "$TEST_DIR"
