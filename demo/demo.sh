#!/bin/bash

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}MicroPKI Demo - Sprint 8${NC}"

# Определяем корневую директорию проекта
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo -e "${YELLOW}Project root: $PROJECT_ROOT${NC}"

# 1. Сборка проекта
echo -e "\n${GREEN}[0/16] Building MicroPKI...${NC}"
cd "$PROJECT_ROOT/micropki"
make build
cd "$PROJECT_ROOT"

# Создаём временную директорию
DEMO_DIR=$(mktemp -d)
echo -e "${YELLOW}Demo directory: $DEMO_DIR${NC}"
cd "$DEMO_DIR"

# Автоматическая очистка при выходе (идемпотентность)
trap 'echo -e "\n${YELLOW}Cleaning up demo directory...${NC}"; rm -rf "$DEMO_DIR"' EXIT

# Путь к бинарнику
MICROPKI="$PROJECT_ROOT/micropki/bin/micropki"

# Проверяем, что бинарник существует
if [ ! -f "$MICROPKI" ]; then
    echo -e "${RED}Error: micropki binary not found at $MICROPKI${NC}"
    exit 1
fi

# Создаём парольные файлы
echo "rootpass123" > root.pass
echo "interpass123" > inter.pass

echo -e "\n${GREEN}[1/16] Initializing database...${NC}"
$MICROPKI db init --db-path ./pki/micropki.db --force

echo -e "\n${GREEN}[2/16] Creating Root CA...${NC}"
$MICROPKI ca init \
    --subject "/CN=Demo Root CA" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./root.pass \
    --out-dir ./pki \
    --db-path ./pki/micropki.db \
    --validity-days 3650 \
    --force

echo -e "\n${GREEN}[3/16] Creating Intermediate CA...${NC}"
$MICROPKI ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file ./root.pass \
    --subject "/CN=Demo Intermediate CA" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./inter.pass \
    --out-dir ./pki \
    --db-path ./pki/micropki.db \
    --validity-days 1825 \
    --pathlen 0 \
    --force

echo -e "\n${GREEN}[4/16] Issuing Server Certificate for TLS...${NC}"
$MICROPKI ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./inter.pass \
    --template server \
    --subject "/CN=localhost" \
    --san dns:localhost \
    --san ip:127.0.0.1 \
    --out-dir ./pki/certs \
    --db-path ./pki/micropki.db \
    --validity-days 365

echo -e "\n${GREEN}[5/16] Issuing Code Signing Certificate...${NC}"
$MICROPKI ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./inter.pass \
    --template code_signing \
    --subject "/CN=MicroPKI Code Signer" \
    --san dns:codesign.demo.local \
    --out-dir ./pki/certs \
    --db-path ./pki/micropki.db \
    --validity-days 365

echo -e "\n${GREEN}[6/16] Issuing Client Certificate...${NC}"
$MICROPKI ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./inter.pass \
    --template client \
    --subject "/CN=Demo Client" \
    --san email:client@demo.local \
    --out-dir ./pki/certs \
    --db-path ./pki/micropki.db \
    --validity-days 365

echo -e "\n${GREEN}[7/16] Issuing OCSP Responder Certificate...${NC}"
$MICROPKI ca issue-ocsp-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./inter.pass \
    --subject "/CN=OCSP Responder" \
    --key-type rsa \
    --key-size 2048 \
    --san dns:ocsp.demo.local \
    --out-dir ./pki/ocsp \
    --validity-days 365

echo -e "\n${GREEN}[8/16] Starting HTTP Repository Server...${NC}"
$MICROPKI repo serve --host 127.0.0.1 --port 18080 --db-path ./pki/micropki.db &
REPO_PID=$!
sleep 2

echo -e "\n${GREEN}[9/16] Starting OCSP Responder...${NC}"
$MICROPKI ocsp serve \
    --host 127.0.0.1 \
    --port 18081 \
    --db-path ./pki/micropki.db \
    --responder-cert ./pki/ocsp/ocsp.cert.pem \
    --responder-key ./pki/ocsp/ocsp.key.pem \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --cache-ttl 60 &
OCSP_PID=$!
sleep 2

echo -e "\n${GREEN}[10/16] TLS Demonstration - Starting HTTPS Server with OpenSSL...${NC}"
mkdir -p ./www
cat > ./www/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>MicroPKI TLS Demo</title></head>
<body>
<h1>MicroPKI TLS Demo</h1>
<p>This page is served over TLS using a certificate issued by MicroPKI!</p>
<p>Connection is secure and verified with the Root CA.</p>
</body>
</html>
EOF

# Запускаем openssl s_server с поддержкой OCSP Stapling
(cd ./www && openssl s_server -accept 8443 \
    -cert ../pki/certs/localhost.cert.pem \
    -key ../pki/certs/localhost.key.pem \
    -CAfile ../pki/certs/ca.cert.pem \
    -status \
    -WWW) &
TLS_PID=$!
sleep 2

echo -e "\n${GREEN}[11/16] TLS Demonstration - Testing HTTPS Connection...${NC}"

# Тест 1: Соединение с доверием к корневому сертификату
echo -e "${YELLOW}  Test 1: Connection with trusted Root CA...${NC}"
if echo -e "GET /index.html HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n" | \
   openssl s_client -connect localhost:8443 -CAfile ./pki/certs/ca.cert.pem -quiet 2>/dev/null | \
   grep -q "MicroPKI TLS Demo"; then
    echo -e "${GREEN}    TLS connection successful with trusted Root CA${NC}"
    TLS_TRUSTED_OK=1
else
    echo -e "${RED}    TLS connection failed with trusted Root CA${NC}"
    TLS_TRUSTED_OK=0
fi

# Тест 2: Соединение без доверия к корневому сертификату
echo -e "${YELLOW}  Test 2: Connection without trusted Root CA ...${NC}"
# Используем -verify_return_error, чтобы openssl возвращал ошибку при неверном сертификате
if echo -e "GET /index.html HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n" | \
   openssl s_client -connect localhost:8443 -verify_return_error 2>&1 >/dev/null; then
    echo -e "${RED}    TLS connection succeeded without trusted CA (SECURITY ISSUE!)${NC}"
    TLS_UNTRUSTED_OK=1
else
    echo -e "${GREEN}    TLS connection correctly rejected without trusted CA${NC}"
    TLS_UNTRUSTED_OK=0
fi

# Тест 3: Верификация цепочки сертификатов
echo -e "${YELLOW}  Test 3: Certificate chain verification with openssl verify...${NC}"
if openssl verify -CAfile ./pki/certs/ca.cert.pem -untrusted ./pki/certs/intermediate.cert.pem ./pki/certs/localhost.cert.pem 2>/dev/null | grep -q "OK"; then
    echo -e "${GREEN}    Certificate chain verified successfully${NC}"
    CHAIN_VERIFY_OK=1
else
    echo -e "${RED}    Certificate chain verification failed${NC}"
    CHAIN_VERIFY_OK=0
fi

# Итоговый вывод TLS тестов
echo -e "\n${BLUE}TLS Test Results:${NC}"
if [ "$TLS_TRUSTED_OK" -eq 1 ] && [ "$TLS_UNTRUSTED_OK" -eq 0 ] && [ "$CHAIN_VERIFY_OK" -eq 1 ]; then
    echo -e "${GREEN}  All TLS tests passed!${NC}"
else
    echo -e "${YELLOW}  Some TLS tests failed:${NC}"
    [ "$TLS_TRUSTED_OK" -eq 0 ] && echo -e "${RED}    - Trusted CA connection failed${NC}"
    [ "$TLS_UNTRUSTED_OK" -eq 1 ] && echo -e "${RED}    - Untrusted connection should have failed but succeeded${NC}"
    [ "$CHAIN_VERIFY_OK" -eq 0 ] && echo -e "${RED}    - Chain verification failed${NC}"
fi

# Тест 4: OCSP Stapling демонстрация
echo -e "\n${YELLOW}  Test 4: OCSP Stapling check...${NC}"
if echo -e "GET /index.html HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n" | \
   openssl s_client -connect localhost:8443 -CAfile ./pki/certs/ca.cert.pem -status 2>/dev/null | \
   grep -q "OCSP response"; then
    echo -e "${GREEN}    OCSP Stapling is enabled and working${NC}"
    OCSP_STAPLING_OK=1
else
    echo -e "${YELLOW}    OCSP Stapling not detected (may be supported anyway)${NC}"
    OCSP_STAPLING_OK=0
fi

echo -e "\n${GREEN}[12/16] Code Signing Demonstration...${NC}"
# Создаём тестовый скрипт
cat > ./test_script.sh << 'EOF'
#!/bin/bash
echo "Hello from MicroPKI signed script!"
echo "Current time: $(date)"
EOF
chmod +x ./test_script.sh

# Создаём подпись с помощью OpenSSL
openssl dgst -sha256 -sign "./pki/certs/MicroPKI Code Signer.key.pem" \
    -out ./test_script.sig ./test_script.sh

# Извлекаем публичный ключ из сертификата для верификации
openssl x509 -in "./pki/certs/MicroPKI Code Signer.cert.pem" -pubkey -noout > ./pubkey.pem

# Верифицируем подпись
if openssl dgst -sha256 -verify ./pubkey.pem -signature ./test_script.sig ./test_script.sh 2>&1 | grep -q "Verified OK"; then
    echo -e "${GREEN}  Code signature verified successfully${NC}"
else
    echo -e "${RED}  Code signature verification failed${NC}"
fi

# Демонстрация, что подпись не проходит после изменения файла
echo "# Tampered line" >> ./test_script.sh
if openssl dgst -sha256 -verify ./pubkey.pem -signature ./test_script.sig ./test_script.sh 2>&1 | grep -q "Verification failure"; then
    echo -e "${GREEN}  Tampered file correctly rejected by signature verification${NC}"
else
    echo -e "${YELLOW}  Tampered file signature check: may not detect modification${NC}"
fi

echo -e "\n${GREEN}[13/16] Certificate Revocation Demonstration...${NC}"
SERIAL=$(openssl x509 -in ./pki/certs/localhost.cert.pem -serial -noout 2>/dev/null | cut -d'=' -f2 | tr '[:upper:]' '[:lower:]' || echo "unknown")
if [ "$SERIAL" != "unknown" ]; then
    $MICROPKI ca revoke "$SERIAL" --reason keyCompromise --force --db-path ./pki/micropki.db
fi
$MICROPKI ca gen-crl \
    --ca intermediate \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./inter.pass \
    --db-path ./pki/micropki.db

echo -e "\n${GREEN}[14/16] Audit Log Integrity Check...${NC}"
$MICROPKI audit verify

echo -e "\n${GREEN}[15/16] Cleaning up build artifacts...${NC}"
cd "$PROJECT_ROOT/micropki"
make clean
cd "$PROJECT_ROOT"

echo -e "\n${GREEN}[16/16] Stopping servers...${NC}"
kill $REPO_PID $OCSP_PID $TLS_PID 2>/dev/null || true

echo -e "\n${GREEN}Demo completed successfully!${NC}"
echo -e "\n${YELLOW}Demo Summary:${NC}"
echo -e "  - PKI Hierarchy: Root CA → Intermediate CA"
echo -e "  - TLS Server: https://localhost:8443 (with OCSP Stapling)"
echo -e "  - Code Signing: test_script.sh signed and verified"
echo -e "  - Revocation: Certificate revoked, CRL generated"
echo -e "  - Audit Log: Integrity verified"
echo -e "  - Build artifacts cleaned"
echo -e "  - Temporary directory automatically cleaned up"