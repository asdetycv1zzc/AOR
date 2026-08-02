# WP-00 Bootstrap Module Specification

- Task ID: `WP-00`
- Phase: `0`
- Goal baseline: `SPEC.md` version `2.0.0`
- Risk: `HIGH`
- Execution platform: `LINUX`
- Sandbox level: `CONTAINER`

## Purpose

Establish the repository, decision, conformance, security, and build baseline required before business implementation begins.

## Responsibilities

- Create the required repository layout and project metadata.
- Pin the Go toolchain and provide deterministic local build, lint, test, schema, secret, and license entry points.
- Record ADR-0001 through ADR-0025 with explicit operational and security consequences.
- Publish the initial threat model and machine-readable requirement catalog.
- Keep the repository buildable without external services.

## Non-responsibilities

- Implement control-plane state transitions.
- Invoke models or tools.
- Claim production readiness or sign release evidence.

## Allowed Paths

`README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`, `LICENSE`, `NOTICE`, `Makefile`, `go.mod`, `go.work`, `package.json`, `pnpm-workspace.yaml`, `buf.yaml`, `.editorconfig`, `.gitattributes`, `.gitignore`, `.github/workflows/`, `adr/`, `api/`, `cmd/`, `internal/`, `pkg/`, `agents/`, `prompts/`, `sandbox/`, `knowledge/`, `audit/`, `model-adapters/`, `tool-adapters/`, `migrations/`, `deploy/`, `policies/`, `observability/`, `security-corpus/`, `conformance/`, `tests/`, `runbooks/`, `scripts/`, `third_party/`, `work-packages/`.

## Forbidden Paths

`SPEC.md`, `AGENTS.md`, `.git/`, production credentials, private keys, and generated release signatures.

## Acceptance Criteria

1. `go test ./...` succeeds with an empty executable baseline.
2. Repository policy, threat model, all required ADRs, and the requirement catalog exist.
3. CI invokes build, format, unit, schema, secret, and license checks without bypass flags.
4. No generated artifact claims that the system is production ready.
