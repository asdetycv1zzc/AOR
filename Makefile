.PHONY: build test lint schema cross-language repository-check secret-scan license-scan verify

GOCACHE ?= $(CURDIR)/.cache/go-build
GOMODCACHE ?= $(CURDIR)/.cache/go-mod
export GOCACHE GOMODCACHE
export GOTOOLCHAIN = local

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

repository-check:
	go run ./cmd/aor-conformance repository

secret-scan:
	go run ./cmd/aor-conformance secrets

license-scan:
	go run ./cmd/aor-conformance licenses

verify: build lint test schema cross-language repository-check secret-scan license-scan
