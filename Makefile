.PHONY: all build clean test test-verbose coverage install run help

# Имя бинарного файла
BINARY_NAME=micropki
# Директория для бинарников
BIN_DIR=bin
# Директория для PKI
PKI_DIR ?= ./myca

all: clean test build

build:
	@echo "Сборка проекта..."
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(BINARY_NAME) cmd/micropki/main.go
	@echo "Бинарный файл создан: $(BIN_DIR)/$(BINARY_NAME)"
	@echo "Запустите: ./$(BIN_DIR)/$(BINARY_NAME) --help"

clean:
	@echo "Очистка..."
	@rm -rf $(BIN_DIR)
	@rm -rf pki/
	@rm -f *.log
	@rm -f *.pass
	@rm -f coverage.out coverage.html
	@echo "Очистка завершена"

test:
	@echo "Запуск тестов..."
	go test -v ./tests/...

test-verbose:
	@echo "Запуск тестов с детальным выводом..."
	go test -v -cover ./tests/...

coverage:
	@echo "Анализ покрытия кода тестами..."
	go test ./tests/... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Отчет о покрытии создан: coverage.html"

install:
	@echo "Установка в систему..."
	go install ./cmd/micropki
	@echo "Установлено. Запускайте: micropki"

run:
	@echo "Запуск приложения..."
	go run cmd/micropki/main.go

verify:
	@echo "Проверка сертификата из $(PKI_DIR)..."
	@if [ ! -f $(PKI_DIR)/certs/ca.cert.pem ]; then \
		echo "Ошибка: сертификат не найден в $(PKI_DIR)/certs/ca.cert.pem"; \
		echo "Сначала создайте УЦ: ./$(BIN_DIR)/$(BINARY_NAME) ca init ... --out-dir $(PKI_DIR)"; \
		exit 1; \
	fi
	@openssl x509 -in $(PKI_DIR)/certs/ca.cert.pem -text -noout | head -20
	@echo "..."
	@openssl verify -CAfile $(PKI_DIR)/certs/ca.cert.pem $(PKI_DIR)/certs/ca.cert.pem

help:
	@echo "Доступные команды:"
	@echo "  make build        - собрать бинарный файл"
	@echo "  make clean        - очистить все сгенерированные файлы"
	@echo "  make test         - запустить тесты"
	@echo "  make test-verbose - запустить тесты с детальным выводом"
	@echo "  make coverage     - анализ покрытия кода тестами"
	@echo "  make install      - установить в систему"
	@echo "  make run          - запустить приложение"
	@echo "  make verify       - проверить сертификат через openssl"
	@echo "  make all          - очистить, протестировать и собрать"
