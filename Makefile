.PHONY: build test lint schema cross-language sdk backup-restore supply-chain release-tool release-package-check repository-check secret-scan security-corpus license-scan state-machine postgres-reconciliation verify compose-init-secrets compose-check compose-check-secrets compose-check-infrastructure-secrets compose-pull compose-deps-up compose-aor-up compose-prebuilt-up compose-up compose-ps

GOCACHE ?= $(CURDIR)/.cache/go-build
GOMODCACHE ?= $(CURDIR)/.cache/go-mod
export GOCACHE GOMODCACHE
export GOTOOLCHAIN = local

COMPOSE = docker compose --parallel 1 -f deploy/compose/docker-compose.yml
COMPOSE_DEPENDENCIES = postgres temporal temporal-ui nats minio opa identity otel-collector
COMPOSE_INITIALIZERS = postgres-migrate temporal-init minio-init
COMPOSE_AOR = aor-api aor-curator aor-model-gateway aor-tool-broker aor-worker

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
	node conformance/contracts/cross-language/typescript.ts
	python3 conformance/contracts/cross-language/python.py

sdk:
	go run ./cmd/aor-sdkgen -check -root .
	go test ./sdk/go/aor
	node conformance/contracts/sdk/typescript.ts
	python3 conformance/contracts/sdk/python.py

backup-restore:
	go test ./internal/backup ./internal/artifact

supply-chain:
	go test ./internal/supplychain

release-tool:
	go build -trimpath -o bin/aor-release ./cmd/aor-release

release-package-check:
	test -n "$(AOR_RELEASE_PACKAGE)"
	test -n "$(AOR_RELEASE_PUBLIC_KEY)"
	go run ./cmd/aor-release verify --root "$(AOR_RELEASE_PACKAGE)" --public-key "$(AOR_RELEASE_PUBLIC_KEY)"

repository-check:
	go run ./cmd/aor-conformance repository

secret-scan:
	go run ./cmd/aor-conformance secrets

security-corpus:
	go run ./cmd/aor-conformance security-corpus

license-scan:
	go run ./cmd/aor-conformance licenses

state-machine:
	go run ./cmd/aor-conformance state-machine

postgres-reconciliation:
	@test -n "$(AOR_TEST_POSTGRES_DSN)"
	@test -n "$(AOR_TEST_POSTGRES_APP_DSN)"
	go test -race -p=1 ./internal/eventing ./internal/projection -run '^TestPostgres(LegacyReplayLoadsOnlyBoundCommandResult|ProjectCreationPersistsPlanningAgents|PlanPublicationSynchronizesExecutableRelations|DurableReconciliationDetectsOnlineDrift)$$' -count=1

verify: build lint test schema cross-language sdk backup-restore supply-chain repository-check secret-scan security-corpus license-scan state-machine

compose-init-secrets:
	command -v openssl >/dev/null
	mkdir -p deploy/compose/secrets
	chmod 0700 deploy/compose/secrets
	test -s deploy/compose/secrets/postgres_password || (umask 077; openssl rand -hex 32 > deploy/compose/secrets/postgres_password)
	test -s deploy/compose/secrets/postgres_app_password || (umask 077; openssl rand -hex 32 > deploy/compose/secrets/postgres_app_password)
	test -s deploy/compose/secrets/minio_root_user || (umask 077; openssl rand -hex 16 > deploy/compose/secrets/minio_root_user)
	test -s deploy/compose/secrets/minio_root_password || (umask 077; openssl rand -hex 32 > deploy/compose/secrets/minio_root_password)
	test -s deploy/compose/secrets/model_replay_key || (umask 077; openssl rand 32 > deploy/compose/secrets/model_replay_key)
	test -s deploy/compose/secrets/lease_signing_key || (umask 077; openssl rand -hex 32 > deploy/compose/secrets/lease_signing_key)
	test -s deploy/compose/secrets/aor_server_oauth_client_secret || (umask 077; openssl rand -hex 32 > deploy/compose/secrets/aor_server_oauth_client_secret)
	chmod 0444 deploy/compose/secrets/postgres_password deploy/compose/secrets/postgres_app_password deploy/compose/secrets/minio_root_user deploy/compose/secrets/minio_root_password deploy/compose/secrets/model_replay_key deploy/compose/secrets/lease_signing_key deploy/compose/secrets/aor_server_oauth_client_secret

compose-check-infrastructure-secrets: compose-init-secrets
	test -s deploy/compose/secrets/postgres_password
	test -s deploy/compose/secrets/postgres_app_password
	test -s deploy/compose/secrets/minio_root_user
	test -s deploy/compose/secrets/minio_root_password
	test -s deploy/compose/secrets/model_replay_key
	test "$$(wc -c < deploy/compose/secrets/model_replay_key)" -eq 32
	test -s deploy/compose/secrets/lease_signing_key
	test -s deploy/compose/secrets/aor_server_oauth_client_secret

compose-check-secrets: compose-check-infrastructure-secrets

compose-check: compose-check-secrets
	$(COMPOSE) config --quiet

compose-pull: compose-check-infrastructure-secrets
	$(COMPOSE) config --quiet
	$(COMPOSE) --profile aor pull $(COMPOSE_DEPENDENCIES) $(COMPOSE_INITIALIZERS)

compose-deps-up: compose-pull
	$(COMPOSE) up -d --wait --wait-timeout 240 $(COMPOSE_DEPENDENCIES)
	$(COMPOSE) up --no-deps --force-recreate --exit-code-from postgres-migrate postgres-migrate
	$(COMPOSE) up --no-deps --force-recreate --exit-code-from temporal-init temporal-init
	$(COMPOSE) up --no-deps --force-recreate --exit-code-from minio-init minio-init

compose-aor-up: compose-deps-up
	$(COMPOSE) --profile aor build aor-api aor-curator
	$(COMPOSE) --profile aor build aor-model-gateway
	$(COMPOSE) --profile aor build aor-tool-broker
	$(COMPOSE) --profile aor build aor-worker
	$(COMPOSE) --profile aor up -d --no-build --no-deps --wait --wait-timeout 240 $(COMPOSE_AOR)

compose-prebuilt-up: compose-deps-up
	$(COMPOSE) --profile aor pull $(COMPOSE_AOR)
	$(COMPOSE) --profile aor up -d --no-build --no-deps --wait --wait-timeout 240 $(COMPOSE_AOR)

compose-up: compose-aor-up

compose-ps:
	$(COMPOSE) --profile aor ps --all
