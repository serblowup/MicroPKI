#!/bin/bash

echo "Запуск тестов MicroPKI..."

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

run_tests() {
    local package=$1
    echo -e "${YELLOW}Тестирование $package...${NC}"
    
    output=$(go test -v "$package" 2>&1)
    exit_code=$?
    
    passed=$(echo "$output" | grep -c "PASS" || true)
    failed=$(echo "$output" | grep -c "FAIL" || true)
    total=$((passed + failed))
    
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}Все тесты пройены ($total тестов)${NC}"
    else
        echo -e "${RED}Обнаружены ошибки ($failed/$total тестов упало)${NC}"
        echo "$output" | grep -E "FAIL|panic|error" --color=always
    fi
    
    return $exit_code
}

cd "$(dirname "$0")/.." || exit 1

echo "Проверка зависимостей..."
go mod tidy

echo -e "\nЗапуск всех тестов...\n"

go test -v ./tests/...

exit_code=$?

echo -e "\n"
if [ $exit_code -eq 0 ]; then
    echo -e "${GREEN}Все тесты успешно пройдены!${NC}"
else
    echo -e "${RED}Некоторые тесты не пройдены${NC}"
fi

exit $exit_code
