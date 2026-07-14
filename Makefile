# linkpulse-auth — Makefile

MIGRATE_VERSION := v4.19.1
POSTGRES_DSN ?= postgres://linkpulse:linkpulse@localhost:5432/linkpulse_auth?sslmode=disable
KEY_PATH ?= keys/jwt-private.pem

.DEFAULT_GOAL := help

.PHONY: help
help: ## Показать список целей
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: keys
keys: ## Сгенерировать dev-ключ RSA для подписи JWT (не коммитится)
	@mkdir -p keys
	@test -f $(KEY_PATH) || openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $(KEY_PATH)
	@echo "ключ: $(KEY_PATH)"

.PHONY: build
build: ## Собрать бинарник в bin/auth
	CGO_ENABLED=0 go build -o bin/auth ./cmd/auth

.PHONY: run
run: keys ## Запустить локально (нужны Postgres и GitHub OAuth App creds)
	POSTGRES_DSN="$(POSTGRES_DSN)" JWT_PRIVATE_KEY_PATH="$(KEY_PATH)" go run ./cmd/auth

.PHONY: test
test: ## Юнит-тесты с гонками
	go test -race -count=1 ./...

.PHONY: lint
lint: ## golangci-lint
	golangci-lint run

.PHONY: tools
tools: ## Установить golang-migrate CLI
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@$(MIGRATE_VERSION)

.PHONY: migrate-up
migrate-up: ## Накатить миграции
	migrate -path migrations -database "$(POSTGRES_DSN)" up

.PHONY: migrate-down
migrate-down: ## Откатить последнюю миграцию
	migrate -path migrations -database "$(POSTGRES_DSN)" down 1

.PHONY: docker
docker: ## Собрать Docker-образ
	docker build -t linkpulse-auth .
