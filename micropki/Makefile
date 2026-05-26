.PHONY: build clean test test-short test-integration scripts verify help db-init serve revoke gen-crl check-revoked test-crl test-revocation issue-ocsp-cert ocsp-serve test-ocsp test-ocsp-full test-csr csr request-cert validate check-status test-audit audit-query audit-verify audit-ct-verify compromise

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

SUBJECT?=
CA_CERT?=
CA_KEY?=
CA_PASS?=
SAN?=
OUT_DIR?=./pki/ocsp
OCSP_HOST?=127.0.0.1
OCSP_PORT?=8081
RESPONDER_CERT?=
RESPONDER_KEY?=
CACHE_TTL?=60

KEY_TYPE?=rsa
KEY_SIZE?=2048
OUT_KEY?=./key.pem
OUT_CSR?=./request.csr.pem
CSR?=
TEMPLATE?=
CA_URL?=http://localhost:8080
OUT_CERT?=./cert.pem
CERT?=
UNTRUSTED?=
TRUSTED?=./pki/certs/ca.cert.pem
CRL?=
OCSP?=false
MODE?=full
OCSP_URL?=

PROJECT_ROOT := $(shell pwd)

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

test-ocsp:
	@echo "Запуск тестов OCSP..."
	$(GOTEST) -v ./tests/ocsp_test.go

test-ocsp-full:
	@echo "Запуск полных тестов OCSP..."
	$(GOTEST) -v ./tests/ -run TestOCSP

test-csr:
	@echo "Запуск тестов CSR и клиента:"
	@echo ""
	@echo "Клиентские тесты..."
	@$(GOTEST) -v ./tests/client_test.go || exit 1
	@echo ""
	@echo "Тесты валидации..."
	@$(GOTEST) -v ./tests/validation_test.go || exit 1
	@echo ""
	@echo "Интеграционные тесты отзыва..."
	@$(GOTEST) -v ./tests/revocation_integration_test.go || exit 1
	@echo ""
	@echo "E2E тесты..."
	@$(GOTEST) -v ./tests/e2e_test.go || exit 1
	@echo ""
	@echo "Все тесты Спринта 6 пройдены!"

test-audit:
	@echo "Запуск всех тестов аудита..."
	@echo ""
	@echo "Тесты аудит-лога"
	@$(GOTEST) -v ./tests/audit_test.go || exit 1
	@echo ""
	@echo "Тесты политик безопасности"
	@$(GOTEST) -v ./tests/policy_test.go || exit 1
	@echo ""
	@echo "Тесты компрометации ключей"
	@$(GOTEST) -v ./tests/compromise_test.go || exit 1
	@echo ""
	@echo "Тесты Certificate Transparency"
	@$(GOTEST) -v ./tests/transparency_test.go || exit 1
	@echo ""
	@echo "Тесты rate limiting"
	@$(GOTEST) -v ./tests/ratelimit_test.go || exit 1
	@echo ""
	@echo "Интеграционный тест безопасности"
	@$(GOTEST) -v ./tests/audit_integration_test.go || exit 1
	@echo ""
	@echo "Все тесты Спринта 7 успешно пройдены!"

audit-query:
	@echo "Запрос аудит-лога..."
	./$(BIN_DIR)/$(BINARY_NAME) audit query --log-file ./pki/audit/audit.log

audit-verify:
	@echo "Проверка целостности аудит-лога..."
	./$(BIN_DIR)/$(BINARY_NAME) audit verify

audit-ct-verify:
	@echo "Проверка CT лога..."
	./$(BIN_DIR)/$(BINARY_NAME) audit ct-verify --serial $(SERIAL)

compromise:
	@echo "Симуляция компрометации ключа..."
	@if [ -z "$(CERT)" ]; then \
		echo "Ошибка: необходимо указать CERT"; \
		echo "Пример: make compromise CERT=./pki/certs/example.com.cert.pem"; \
		exit 1; \
	fi
	./$(BIN_DIR)/$(BINARY_NAME) ca compromise --cert $(CERT) --reason keyCompromise --force

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

csr:
	@echo "Генерация CSR..."
	@if [ -z "$(SUBJECT)" ]; then \
		echo "Ошибка: необходимо указать SUBJECT"; \
		echo "Пример: make csr SUBJECT=\"/CN=example.com\" SAN=\"dns:example.com\""; \
		exit 1; \
	fi
	./$(BIN_DIR)/$(BINARY_NAME) client gen-csr \
		--subject "$(SUBJECT)" \
		--key-type $(KEY_TYPE) \
		--key-size $(KEY_SIZE) \
		--san $(SAN) \
		--out-key $(OUT_KEY) \
		--out-csr $(OUT_CSR)

request-cert:
	@echo "Запрос сертификата..."
	@if [ -z "$(CSR)" ] || [ -z "$(TEMPLATE)" ]; then \
		echo "Ошибка: необходимо указать CSR и TEMPLATE"; \
		echo "Пример: make request-cert CSR=./request.csr.pem TEMPLATE=server CA_URL=http://localhost:8080"; \
		exit 1; \
	fi
	./$(BIN_DIR)/$(BINARY_NAME) client request-cert \
		--csr $(CSR) \
		--template $(TEMPLATE) \
		--ca-url $(CA_URL) \
		--out-cert $(OUT_CERT)

validate:
	@echo "Валидация цепочки сертификатов..."
	@if [ -z "$(CERT)" ]; then \
		echo "Ошибка: необходимо указать CERT"; \
		echo "Пример: make validate CERT=./cert.pem TRUSTED=./ca.pem"; \
		exit 1; \
	fi
	./$(BIN_DIR)/$(BINARY_NAME) client validate \
		--cert $(CERT) \
		--untrusted $(UNTRUSTED) \
		--trusted $(TRUSTED) \
		--crl $(CRL) \
		--ocsp=$(OCSP) \
		--mode $(MODE)

check-status:
	@echo "Проверка статуса отзыва..."
	@if [ -z "$(CERT)" ] || [ -z "$(CA_CERT)" ]; then \
		echo "Ошибка: необходимо указать CERT и CA_CERT"; \
		echo "Пример: make check-status CERT=./cert.pem CA_CERT=./ca.pem"; \
		exit 1; \
	fi
	./$(BIN_DIR)/$(BINARY_NAME) client check-status \
		--cert $(CERT) \
		--ca-cert $(CA_CERT) \
		--crl $(CRL) \
		--ocsp-url $(OCSP_URL)

issue-ocsp-cert:
	@echo "Выпуск сертификата OCSP-ответчика..."
	@if [ -z "$(SUBJECT)" ]; then \
		echo "Ошибка: необходимо указать SUBJECT"; \
		echo "Пример: make issue-ocsp-cert SUBJECT=\"CN=OCSP Responder\" CA_CERT=./pki/certs/intermediate.cert.pem CA_KEY=./pki/private/intermediate.key.pem CA_PASS=./inter.pass"; \
		exit 1; \
	fi
	./$(BIN_DIR)/$(BINARY_NAME) ca issue-ocsp-cert \
		--ca-cert $(CA_CERT) \
		--ca-key $(CA_KEY) \
		--ca-pass-file $(CA_PASS) \
		--subject "$(SUBJECT)" \
		--san $(SAN) \
		--out-dir $(OUT_DIR)

ocsp-serve:
	@echo "Запуск OCSP-ответчика..."
	./$(BIN_DIR)/$(BINARY_NAME) ocsp serve \
		--host $(OCSP_HOST) \
		--port $(OCSP_PORT) \
		--db-path $(DB_PATH) \
		--responder-cert $(RESPONDER_CERT) \
		--responder-key $(RESPONDER_KEY) \
		--ca-cert $(CA_CERT) \
		--cache-ttl $(CACHE_TTL)

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
	@echo "Базовые операции"
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
	@echo "Аудит и безопасность"
	@echo ""
	@echo "5. Запрос аудит-лога:"
	@echo "   make audit-query"
	@echo ""
	@echo "6. Проверка целостности аудит-лога:"
	@echo "   make audit-verify"
	@echo ""
	@echo "7. Проверка CT лога:"
	@echo "   make audit-ct-verify SERIAL=abc123"
	@echo ""
	@echo "8. Симуляция компрометации ключа:"
	@echo "   make compromise CERT=./pki/certs/example.com.cert.pem"
	@echo ""
	@echo "Клиентские команды"
	@echo ""
	@echo "9. Генерация CSR:"
	@echo "   make csr SUBJECT=\"/CN=app.example.com\" SAN=\"dns:app.example.com\""
	@echo ""
	@echo "10. Запрос сертификата:"
	@echo "    make request-cert CSR=./request.csr.pem TEMPLATE=server"
	@echo ""
	@echo "11. Валидация цепочки:"
	@echo "    make validate CERT=./cert.pem UNTRUSTED=./inter.pem TRUSTED=./ca.pem"
	@echo ""
	@echo "12. Проверка статуса отзыва:"
	@echo "    make check-status CERT=./cert.pem CA_CERT=./inter.pem"
	@echo ""
	@echo "Отзыв и CRL"
	@echo ""
	@echo "13. Отзыв сертификата:"
	@echo "    make revoke SERIAL=0baee839362091a1 REASON=keyCompromise"
	@echo ""
	@echo "14. Генерация CRL:"
	@echo "    make gen-crl CA=intermediate NEXT_UPDATE=14"
	@echo ""
	@echo "15. Проверка статуса отзыва (CA):"
	@echo "    make check-revoked SERIAL=0baee839362091a1"
	@echo ""
	@echo "HTTP Репозиторий"
	@echo ""
	@echo "16. Запуск HTTP сервера:"
	@echo "    make serve"
	@echo ""
	@echo "17. Проверка API:"
	@echo "    curl http://127.0.0.1:8080/health"
	@echo "    curl http://127.0.0.1:8080/ca/root"
	@echo "    curl -X POST http://127.0.0.1:8080/request-cert -F \"csr=@app.csr.pem\" -F \"template=server\""
	@echo ""
	@echo "Тестирование"
	@echo ""
	@echo "18. Запуск всех тестов:"
	@echo "    make test"

help:
	@echo "Доступные команды:"
	@echo ""
	@echo "Сборка и тестирование:"
	@echo "  make build          - сборка бинарного файла"
	@echo "  make build-verbose  - сборка с отображением предупреждений"
	@echo "  make clean          - очистка временных файлов"
	@echo "  make test           - запуск всех тестов"
	@echo "  make test-short     - запуск коротких тестов"
	@echo "  make test-integration - запуск интеграционных тестов"
	@echo "  make test-csr       - запуск тестов Спринта 6"
	@echo "  make test-db        - запуск тестов БД"
	@echo "  make test-repo      - запуск тестов репозитория"
	@echo "  make test-crl       - запуск тестов CRL"
	@echo "  make test-revocation - запуск тестов отзыва"
	@echo "  make test-ocsp      - запуск тестов OCSP"
	@echo "  make test-audit     - запуск всех тестов Sprint 7"
	@echo "  make verify         - проверка кода (fmt, vet, mod verify)"
	@echo "  make deps           - установка зависимостей"
	@echo ""
	@echo "Аудит и безопасность (Sprint 7):"
	@echo "  make audit-query     - запрос аудит-лога"
	@echo "  make audit-verify    - проверка целостности аудит-лога"
	@echo "  make audit-ct-verify - проверка CT лога"
	@echo "  make compromise      - симуляция компрометации ключа"
	@echo ""
	@echo "Клиентские команды:"
	@echo "  make csr            - генерация CSR"
	@echo "  make request-cert   - запрос сертификата"
	@echo "  make validate       - валидация цепочки"
	@echo "  make check-status   - проверка статуса отзыва"
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
	@echo "OCSP:"
	@echo "  make issue-ocsp-cert SUBJECT=<subject> CA_CERT=<path> CA_KEY=<path> CA_PASS=<path> - выпуск сертификата OCSP-ответчика"
	@echo "  make ocsp-serve RESPONDER_CERT=<path> RESPONDER_KEY=<path> CA_CERT=<path> - запуск OCSP-ответчика"
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

demo-run:
	@echo "Запуск демонстрации MicroPKI ..."
	@cd $(PROJECT_ROOT)/../demo && ./demo.sh