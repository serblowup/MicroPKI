#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ $# -lt 3 ]; then
    echo "Аргументы не переданы, использую тестовые сертификаты"
    
    TEST_DIR=$(mktemp -d)
    
    cat > "$TEST_DIR/gen_certs.go" << 'EOF'
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "os"
    "time"
)

func main() {
    rootKey, _ := rsa.GenerateKey(rand.Reader, 4096)
    interKey, _ := rsa.GenerateKey(rand.Reader, 4096)
    leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)

    rootTemplate := &x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject:      pkix.Name{CommonName: "Test Root CA"},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(10, 0, 0),
        KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        IsCA:         true,
        BasicConstraintsValid: true,
    }

    rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
    rootCert, _ := x509.ParseCertificate(rootDER)
    
    interTemplate := &x509.Certificate{
        SerialNumber: big.NewInt(2),
        Subject:      pkix.Name{CommonName: "Test Intermediate CA"},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(5, 0, 0),
        KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        IsCA:         true,
        BasicConstraintsValid: true,
    }
    
    interDER, _ := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
    interCert, _ := x509.ParseCertificate(interDER)
    
    leafTemplate := &x509.Certificate{
        SerialNumber: big.NewInt(3),
        Subject:      pkix.Name{CommonName: "Test Leaf Cert"},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(1, 0, 0),
        KeyUsage:     x509.KeyUsageDigitalSignature,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
    }
    
    leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
    
    rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
    interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})
    leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
    
    os.WriteFile("root.pem", rootPEM, 0644)
    os.WriteFile("inter.pem", interPEM, 0644)
    os.WriteFile("leaf.pem", leafPEM, 0644)
}
EOF

    cd "$TEST_DIR"
    go run gen_certs.go
    
    ROOT="$TEST_DIR/root.pem"
    INTERMEDIATE="$TEST_DIR/inter.pem"
    LEAF="$TEST_DIR/leaf.pem"
else
    ROOT=$1
    INTERMEDIATE=$2
    LEAF=$3
fi

echo -e "${YELLOW}Проверка цепочки сертификатов...${NC}"

if [ ! -f "$ROOT" ]; then
    echo -e "${RED}Ошибка: корневой сертификат не найден: $ROOT${NC}"
    exit 1
fi

if [ ! -f "$INTERMEDIATE" ]; then
    echo -e "${RED}Ошибка: промежуточный сертификат не найден: $INTERMEDIATE${NC}"
    exit 1
fi

if [ ! -f "$LEAF" ]; then
    echo -e "${RED}Ошибка: конечный сертификат не найден: $LEAF${NC}"
    exit 1
fi

echo -e "\n${YELLOW}Информация о корневом сертификате:${NC}"
openssl x509 -in "$ROOT" -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After|CA:|Path Length" | sed 's/^/  /'

echo -e "\n${YELLOW}Информация о промежуточном сертификате:${NC}"
openssl x509 -in "$INTERMEDIATE" -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After|CA:|Path Length" | sed 's/^/  /'

echo -e "\n${YELLOW}Информация о конечном сертификате:${NC}"
openssl x509 -in "$LEAF" -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After|CA:|X509v3 Subject Alternative Name" | sed 's/^/  /'

echo -e "\n${YELLOW}Проверка подписей:${NC}"

echo -n "  Корневой → Промежуточный: "
if openssl verify -CAfile "$ROOT" "$INTERMEDIATE" >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}ОШИБКА${NC}"
    openssl verify -CAfile "$ROOT" "$INTERMEDIATE"
    exit 1
fi

echo -n "  Промежуточный → Конечный: "
TMP_CHAIN=$(mktemp)
cat "$INTERMEDIATE" "$ROOT" > "$TMP_CHAIN"
if openssl verify -CAfile "$ROOT" -untrusted "$INTERMEDIATE" "$LEAF" >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}ОШИБКА${NC}"
    openssl verify -CAfile "$ROOT" -untrusted "$INTERMEDIATE" "$LEAF"
    rm "$TMP_CHAIN"
    exit 1
fi
rm "$TMP_CHAIN"

echo -e "\n${GREEN}Цепочка сертификатов действительна${NC}"

if [ $# -lt 3 ]; then
    rm -rf "$TEST_DIR"
fi

exit 0