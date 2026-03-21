.PHONY: build clean test test-short test-integration scripts verify help db-init serve revoke gen-crl check-revoked test-crl test-revocation

BINARY_NAME=micropki
BIN_DIR=bin
PKG=./cmd/micropki
GOBUILD=go build
GOTEST=go test
GOFMT=gofmt
GOVET=go vet
GOMOD=go mod

CGO_CFLAGS=-Wno-discarded-qualifiers -Wno-incompatible-pointer-types
export CGO_CFLAGS

VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

SERIAL?=
REASON?=unspecified
CA?=intermediate
NEXT_UPDATE?=7

build:
	@echo "Сборка $(BINARY_NAME)..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME) $(PKG)
	@echo "Бинарный файл сохранен в $(BIN_DIR)/$(BINARY_NAME)"

build-verbose:
	@echo "Сборка $(BINARY_NAME) (с предупреждениями)..."
	@mkdir -p $(BIN_DIR)
	CGO_CFLAGS="" $(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME) $(PKG)
	@echo "Бинарный файл сохранен в $(BIN_DIR)/$(BINARY_NAME)"

clean:
	@echo "Очистка..."
	@rm -rf $(BIN_DIR)
	@rm -f coverage.out
	@rm -f *.db
	@rm -f *.db-journal
	@rm -f *.db-wal
	@rm -f *.db-shm
	@rm -rf ./pki
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
	$(GOTEST) -v ./tests/ -run TestRevocationLifecycle

test-db:
	@echo "Запуск тестов базы данных..."
	$(GOTEST) -v ./tests/database_test.go

test-repo:
	@echo "Запуск тестов репозитория..."
	$(GOTEST) -v ./tests/repository_test.go

test-crl:
	@echo "Запуск тестов CRL..."
	$(GOTEST) -v ./tests/crl_test.go

test-revocation:
	@echo "Запуск тестов отзыва..."
	$(GOTEST) -v ./tests/revocation_test.go

db-init:
	@echo "Инициализация базы данных..."
	./$(BIN_DIR)/$(BINARY_NAME) db init --db-path ./pki/micropki.db

db-init-force:
	@echo "Принудительная инициализация базы данных..."
	./$(BIN_DIR)/$(BINARY_NAME) db init --db-path ./pki/micropki.db --force

serve:
	@echo "Запуск HTTP сервера..."
	./$(BIN_DIR)/$(BINARY_NAME) repo serve --host 127.0.0.1 --port 8080

serve-public:
	@echo "Запуск HTTP сервера на всех интерфейсах..."
	./$(BIN_DIR)/$(BINARY_NAME) repo serve --host 0.0.0.0 --port 8080

status:
	@echo "Проверка статуса сервера..."
	./$(BIN_DIR)/$(BINARY_NAME) repo status

revoke:
	@echo "Отзыв сертификата..."
	@if [ -z "$(SERIAL)" ]; then \
		echo "Ошибка: необходимо указать SERIAL"; \
		echo "Пример: make revoke SERIAL=0baee839362091a1 REASON=keyCompromise"; \
		exit 1; \
	fi
	./$(BIN_DIR)/$(BINARY_NAME) ca revoke $(SERIAL) --reason $(REASON)

revoke-force:
	@echo "Принудительный отзыв сертификата..."
	@if [ -z "$(SERIAL)" ]; then \
		echo "Ошибка: необходимо указать SERIAL"; \
		echo "Пример: make revoke-force SERIAL=0baee839362091a1 REASON=keyCompromise"; \
		exit 1; \
	fi
	./$(BIN_DIR)/$(BINARY_NAME) ca revoke $(SERIAL) --reason $(REASON) --force

gen-crl:
	@echo "Генерация CRL..."
	./$(BIN_DIR)/$(BINARY_NAME) ca gen-crl --ca $(CA) --next-update $(NEXT_UPDATE)

gen-crl-root:
	@echo "Генерация CRL корневого УЦ..."
	./$(BIN_DIR)/$(BINARY_NAME) ca gen-crl --ca root --next-update $(NEXT_UPDATE)

gen-crl-intermediate:
	@echo "Генерация CRL промежуточного УЦ..."
	./$(BIN_DIR)/$(BINARY_NAME) ca gen-crl --ca intermediate --next-update $(NEXT_UPDATE)

check-revoked:
	@echo "Проверка статуса отзыва..."
	@if [ -z "$(SERIAL)" ]; then \
		echo "Ошибка: необходимо указать SERIAL"; \
		echo "Пример: make check-revoked SERIAL=0baee839362091a1"; \
		exit 1; \
	fi
	./$(BIN_DIR)/$(BINARY_NAME) ca check-revoked $(SERIAL)

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
	$(GOMOD) verify
	@echo "Проверка типов..."
	$(GOTEST) -vet=off ./internal/...

deps:
	@echo "Установка зависимостей..."
	$(GOMOD) download
	$(GOMOD) tidy

examples:
	@echo "Примеры использования:"
	@echo ""
	@echo "1. Инициализация БД:"
	@echo "   make db-init"
	@echo ""
	@echo "2. Создание корневого УЦ:"
	@echo "   echo 'myrootpass' > ./root.pass"
	@echo "   ./bin/micropki ca init --subject \"/CN=Test Root CA\" --passphrase-file ./root.pass"
	@echo ""
	@echo "3. Создание промежуточного УЦ:"
	@echo "   echo 'myinterpass' > ./inter.pass"
	@echo "   ./bin/micropki ca issue-intermediate \\"
	@echo "       --root-cert ./pki/certs/ca.cert.pem \\"
	@echo "       --root-key ./pki/private/ca.key.pem \\"
	@echo "       --root-pass-file ./root.pass \\"
	@echo "       --subject \"/CN=Test Intermediate CA\" \\"
	@echo "       --passphrase-file ./inter.pass"
	@echo ""
	@echo "4. Выпуск сертификата:"
	@echo "   ./bin/micropki ca issue-cert \\"
	@echo "       --ca-cert ./pki/certs/intermediate.cert.pem \\"
	@echo "       --ca-key ./pki/private/intermediate.key.pem \\"
	@echo "       --ca-pass-file ./inter.pass \\"
	@echo "       --template server \\"
	@echo "       --subject \"/CN=example.com\" \\"
	@echo "       --san dns:example.com"
	@echo ""
	@echo "5. Отзыв сертификата:"
	@echo "   make revoke SERIAL=\$$(./bin/micropki ca list-certs --format json | jq -r '.[0].serial_hex') REASON=keyCompromise"
	@echo ""
	@echo "6. Генерация CRL:"
	@echo "   make gen-crl CA=intermediate NEXT_UPDATE=14"
	@echo ""
	@echo "7. Проверка статуса отзыва:"
	@echo "   make check-revoked SERIAL=0baee839362091a1"
	@echo ""
	@echo "8. Просмотр сертификатов:"
	@echo "   ./bin/micropki ca list-certs --format table"
	@echo "   ./bin/micropki ca show-cert \$$(./bin/micropki ca list-certs --format json | jq -r '.[0].serial_hex')"
	@echo ""
	@echo "9. Запуск HTTP сервера:"
	@echo "   make serve"
	@echo ""
	@echo "10. Проверка API:"
	@echo "   curl http://127.0.0.1:8080/health"
	@echo "   curl http://127.0.0.1:8080/ca/root"
	@echo "   curl http://127.0.0.1:8080/ca/intermediate"
	@echo "   curl http://127.0.0.1:8080/crl"
	@echo "   curl http://127.0.0.1:8080/crl?ca=root"
	@echo "   curl http://127.0.0.1:8080/crl/intermediate.crl.pem"
	@echo ""
	@echo "11. Проверка CRL через OpenSSL:"
	@echo "   openssl crl -inform PEM -in ./pki/crl/intermediate.crl.pem -text -noout"
	@echo "   openssl crl -inform PEM -in ./pki/crl/intermediate.crl.pem -CAfile ./pki/certs/intermediate.cert.pem -noout"

help:
	@echo "Доступные команды:"
	@echo ""
	@echo "Сборка и тестирование:"
	@echo "  make build          - сборка бинарного файла (предупреждения скрыты)"
	@echo "  make build-verbose  - сборка с отображением предупреждений"
	@echo "  make clean          - очистка временных файлов"
	@echo "  make test           - запуск всех тестов"
	@echo "  make test-short     - запуск коротких тестов"
	@echo "  make test-integration - запуск интеграционных тестов"
	@echo "  make test-db        - запуск тестов БД"
	@echo "  make test-repo      - запуск тестов репозитория"
	@echo "  make test-crl       - запуск тестов CRL"
	@echo "  make test-revocation - запуск тестов отзыва"
	@echo "  make verify         - проверка кода (fmt, vet, mod verify)"
	@echo "  make deps           - установка зависимостей"
	@echo ""
	@echo "База данных:"
	@echo "  make db-init        - инициализация БД"
	@echo "  make db-init-force  - принудительная инициализация БД"
	@echo ""
	@echo "Управление УЦ и сертификатами:"
	@echo "  make revoke SERIAL=<hex> REASON=<reason> - отзыв сертификата"
	@echo "  make revoke-force SERIAL=<hex> REASON=<reason> - принудительный отзыв"
	@echo "  make gen-crl CA=<ca> NEXT_UPDATE=<days> - генерация CRL"
	@echo "  make gen-crl-root NEXT_UPDATE=<days> - генерация CRL корневого УЦ"
	@echo "  make gen-crl-intermediate NEXT_UPDATE=<days> - генерация CRL промежуточного УЦ"
	@echo "  make check-revoked SERIAL=<hex> - проверка статуса отзыва"
	@echo ""
	@echo "HTTP сервер:"
	@echo "  make serve          - запуск HTTP сервера (127.0.0.1)"
	@echo "  make serve-public   - запуск HTTP сервера (0.0.0.0)"
	@echo "  make status         - проверка статуса сервера"
	@echo ""
	@echo "Прочее:"
	@echo "  make scripts        - запуск всех исполняемых скриптов"
	@echo "  make examples       - показать примеры использования"
	@echo "  make help           - показать эту справку"
