.PHONY: build test lint schema cross-language sdk backup-restore supply-chain repository-check secret-scan license-scan state-machine verify compose-check compose-check-secrets compose-pull compose-deps-up compose-aor-up compose-up compose-ps

GOCACHE ?= $(CURDIR)/.cache/go-build
GOMODCACHE ?= $(CURDIR)/.cache/go-mod
export GOCACHE GOMODCACHE
export GOTOOLCHAIN = local

COMPOSE = docker compose --parallel 1 -f deploy/compose/docker-compose.yml
COMPOSE_DEPENDENCIES = postgres temporal temporal-ui nats minio opa identity
COMPOSE_INITIALIZERS = postgres-migrate temporal-init minio-init
COMPOSE_AOR = aor-api aor-model-gateway aor-tool-broker aor-worker

build:
	go build ./...

test:
	go test ./...

lint:
	go vet ./...
	go run ./cmd/aor-conformance source-format

schema:
	go run ./cmd/aor-conformance schemas

cross-language:
	node --experimental-strip-types conformance/contracts/cross-language/typescript.ts
	python3 conformance/contracts/cross-language/python.py

sdk:
	go run ./cmd/aor-sdkgen -check -root .
	go test ./sdk/go/aor
	node --experimental-strip-types conformance/contracts/sdk/typescript.ts
	python3 conformance/contracts/sdk/python.py

backup-restore:
	go test ./internal/backup ./internal/artifact

supply-chain:
	go test ./internal/supplychain

repository-check:
	go run ./cmd/aor-conformance repository

secret-scan:
	go run ./cmd/aor-conformance secrets

license-scan:
	go run ./cmd/aor-conformance licenses

state-machine:
	go run ./cmd/aor-conformance state-machine

verify: build lint test schema cross-language sdk backup-restore supply-chain repository-check secret-scan license-scan state-machine

compose-check-secrets:
	test -s deploy/compose/secrets/postgres_password
	test -s deploy/compose/secrets/postgres_app_password
	test -s deploy/compose/secrets/minio_root_user
	test -s deploy/compose/secrets/minio_root_password
	test -s deploy/compose/secrets/model_provider_openai_key
	test -s deploy/compose/secrets/model_provider_deepseek_key

compose-check:
	$(COMPOSE) config --quiet

compose-pull: compose-check-secrets compose-check
	$(COMPOSE) pull $(COMPOSE_DEPENDENCIES) $(COMPOSE_INITIALIZERS)

compose-deps-up: compose-check-secrets compose-check
	$(COMPOSE) up -d --wait --wait-timeout 240 $(COMPOSE_DEPENDENCIES)
	$(COMPOSE) up -d postgres-migrate
	$(COMPOSE) wait postgres-migrate
	$(COMPOSE) up -d temporal-init
	$(COMPOSE) wait temporal-init
	$(COMPOSE) up -d minio-init
	$(COMPOSE) wait minio-init

compose-aor-up: compose-deps-up
	$(COMPOSE) --profile aor build aor-api
	$(COMPOSE) --profile aor build aor-model-gateway
	$(COMPOSE) --profile aor build aor-tool-broker
	$(COMPOSE) --profile aor build aor-worker
	$(COMPOSE) --profile aor up -d --no-build --no-deps --wait --wait-timeout 240 $(COMPOSE_AOR)

compose-up: compose-pull compose-aor-up

compose-ps:
	$(COMPOSE) --profile aor ps --all
