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

DB_PATH="$TEST_DIR/pki/micropki.db"
OUT_DIR="$TEST_DIR/pki"

echo "rootpass" > "$TEST_DIR/root.pass"
echo "interpass" > "$TEST_DIR/inter.pass"

echo "1. Инициализация PKI..."
"$MICROPKI" db init --db-path "$DB_PATH" --force > /dev/null 2>&1

"$MICROPKI" ca init \
    --subject "/CN=Test Root CA" \
    --key-size 4096 \
    --passphrase-file "$TEST_DIR/root.pass" \
    --out-dir "$OUT_DIR" \
    --db-path "$DB_PATH" \
    --force > /dev/null 2>&1

"$MICROPKI" ca issue-intermediate \
    --root-cert "$OUT_DIR/certs/ca.cert.pem" \
    --root-key "$OUT_DIR/private/ca.key.pem" \
    --root-pass-file "$TEST_DIR/root.pass" \
    --subject "/CN=Test Intermediate CA" \
    --key-size 4096 \
    --passphrase-file "$TEST_DIR/inter.pass" \
    --out-dir "$OUT_DIR" \
    --db-path "$DB_PATH" \
    --force > /dev/null 2>&1

echo "2. Выпуск тестового сертификата..."
"$MICROPKI" ca issue-cert \
    --ca-cert "$OUT_DIR/certs/intermediate.cert.pem" \
    --ca-key "$OUT_DIR/private/intermediate.key.pem" \
    --ca-pass-file "$TEST_DIR/inter.pass" \
    --template server \
    --subject "/CN=test.local" \
    --san dns:test.local \
    --out-dir "$OUT_DIR/certs" \
    --db-path "$DB_PATH" > /dev/null 2>&1

echo "3. Получение серийного номера из БД..."
SERIAL=$(sqlite3 "$DB_PATH" "SELECT serial_hex FROM certificates WHERE subject='CN=test.local';")
echo "Серийный номер: $SERIAL"

if [ -z "$SERIAL" ]; then
    echo "ОШИБКА: Не удалось получить серийный номер"
    cd "$PROJECT_ROOT"
    rm -rf "$TEST_DIR"
    exit 1
fi

cat "$OUT_DIR/certs/intermediate.cert.pem" "$OUT_DIR/certs/ca.cert.pem" > "$TEST_DIR/chain.pem"

echo "4. Проверка сертификата до отзыва..."
openssl verify -CAfile "$TEST_DIR/chain.pem" "$OUT_DIR/certs/test.local.cert.pem"
if [ $? -eq 0 ]; then
    echo "Oк: Сертификат действителен!"
else
    echo "Ошибка: Проверка сертификата не пройдена!!!"
fi

echo "5. Отзыв сертификата..."
"$MICROPKI" ca revoke "$SERIAL" --reason keyCompromise --force --db-path "$DB_PATH"

echo "6. Генерация CRL..."
"$MICROPKI" ca gen-crl \
    --ca intermediate \
    --ca-cert "$OUT_DIR/certs/intermediate.cert.pem" \
    --ca-key "$OUT_DIR/private/intermediate.key.pem" \
    --ca-pass-file "$TEST_DIR/inter.pass" \
    --db-path "$DB_PATH"

echo "7. Проверка сертификата с CRL (ожидается отказ)..."
openssl verify -CAfile "$TEST_DIR/chain.pem" -CRLfile "$OUT_DIR/crl/intermediate.crl.pem" -crl_check "$OUT_DIR/certs/test.local.cert.pem" 2>&1
if [ $? -ne 0 ]; then
    echo "Oк: Сертификат отклонен (отозван)!"
else
    echo "Ошибка: Сертификат принят (должен быть отозван)!!!"
fi

echo "8. Выпуск валидного сертификата для сравнения..."
"$MICROPKI" ca issue-cert \
    --ca-cert "$OUT_DIR/certs/intermediate.cert.pem" \
    --ca-key "$OUT_DIR/private/intermediate.key.pem" \
    --ca-pass-file "$TEST_DIR/inter.pass" \
    --template server \
    --subject "/CN=valid.local" \
    --san dns:valid.local \
    --out-dir "$OUT_DIR/certs" \
    --db-path "$DB_PATH" > /dev/null 2>&1

VALID_SERIAL=$(sqlite3 "$DB_PATH" "SELECT serial_hex FROM certificates WHERE subject='CN=valid.local';")
echo "Серийный номер валидного сертификата: $VALID_SERIAL"

echo "9. Проверка валидного сертификата с CRL..."
openssl verify -CAfile "$TEST_DIR/chain.pem" -CRLfile "$OUT_DIR/crl/intermediate.crl.pem" -crl_check "$OUT_DIR/certs/valid.local.cert.pem"
if [ $? -eq 0 ]; then
    echo "Oк: Валидный сертификат принят!"
else
    echo "Ошибка: Валидный сертификат отклонен!!!"
fi

cd "$PROJECT_ROOT"
rm -rf "$TEST_DIR"

echo "Тест завершен!"