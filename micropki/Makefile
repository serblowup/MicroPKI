.PHONY: build clean test test-short test-integration scripts verify help

BINARY_NAME=micropki
BIN_DIR=bin
PKG=./cmd/micropki
GOBUILD=go build
GOTEST=go test
GOFMT=gofmt
GOVET=go vet

VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

build:
	@echo "Сборка $(BINARY_NAME)..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME) $(PKG)
	@echo "Бинарный файл сохранен в $(BIN_DIR)/$(BINARY_NAME)"

clean:
	@echo "Очистка..."
	@rm -rf $(BIN_DIR)
	@rm -f coverage.out
	@echo "Готово"

test:
	@echo "Запуск всех тестов..."
	$(GOTEST) -v ./tests/...

test-short:
	@echo "Запуск коротких тестов..."
	$(GOTEST) -short -v ./tests/...

test-integration:
	@echo "Запуск интеграционных тестов..."
	$(GOTEST) -v ./tests/ -run TestFullPKIChain
	$(GOTEST) -v ./tests/ -run TestNegativeScenarios

scripts:
	@echo "Запуск всех скриптов..."
	@for script in scripts/*.sh; do \
		if [ -f "$$script" ] && [ -x "$$script" ]; then \
			echo "Запуск $$script..."; \
			$$script || exit 1; \
		else \
			echo "Пропуск $$script (не является исполняемым файлом)"; \
		fi \
	done

verify:
	@echo "Проверка форматирования..."
	@test -z $(shell $(GOFMT) -l .)
	@echo "Запуск go vet..."
	$(GOVET) ./...
	@echo "Проверка зависимостей..."
	@go mod verify

help:
	@echo "Доступные команды:"
	@echo "  make build          - сборка бинарного файла"
	@echo "  make clean          - очистка временных файлов"
	@echo "  make test           - запуск всех тестов"
	@echo "  make test-short     - запуск коротких тестов"
	@echo "  make test-integration - запуск интеграционных тестов"
	@echo "  make scripts        - запуск всех исполняемых скриптов"
	@echo "  make verify         - проверка кода (fmt, vet, mod verify)"
	@echo "  make help           - показать эту справку"