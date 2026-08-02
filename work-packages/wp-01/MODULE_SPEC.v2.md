# WP-01 Contracts Module Specification v2

- Task ID: `WP-01`
- ModuleSpec version: `2`
- Supersedes: `MODULE_SPEC.md` version `1`
- Reason: contract implementation requires the pinned Schema validator, RFC 8785 package, conformance command wiring, and canonical domain types omitted from the initial allowed-path list
- Goal baseline: `SPEC.md` version `2.0.0`
- Dependencies: `WP-00`
- Risk: `HIGH`
- Execution platform: `LINUX`
- Sandbox level: `CONTAINER`

## Purpose

Freeze and implement the external and internal protocol vocabulary before control-plane behavior.

## Responsibilities

- Define canonical identifiers, errors, Agent Card, AOP envelope, CloudEvents, GoalSpec, PlanSpec, ModuleSpec, Submission, Evidence, configuration, approval, and user-decision contracts.
- Publish OpenAPI 3.2.0, AsyncAPI 3.1.0, protobuf, and Draft 2020-12 Schemas.
- Provide Go protocol types, RFC 8785 canonical hashing, semantic validation, and offline conformance fixtures.
- Enforce ADR-0026 intent, attempt-series, Windows `NONE`, and completion semantics.

## Non-responsibilities

- Persist state or execute transitions.
- Authenticate principals, authorize tools, invoke models, or run sandboxes.
- Generate release signatures or claim production acceptance.

## Allowed Paths

`go.mod`, `go.sum`, `Makefile`, `api/`, `pkg/aop/`, `pkg/canonicaljson/`, `pkg/cloudevents/`, `pkg/contracts/`, `pkg/errors/`, `cmd/aor-conformance/`, `internal/contracts/`, `conformance/a2a/`, `conformance/aop/`, `conformance/cloudevents/`, `conformance/contracts/`, `conformance/requirements.yaml`, `work-packages/wp-01/`.

## Forbidden Paths

`SPEC.md`, `AGENTS.md`, `.git/`, `internal/state/`, `internal/workflow/`, `policies/`, `knowledge/`, `sandbox/`, `audit/hidden-test-runner/`, signing keys, and production credentials.

## Acceptance Criteria

1. All protocol Schemas compile with a Draft 2020-12 validator and positive/negative fixtures behave as declared.
2. Unknown optional AOP fields are ignored; unknown intents and required capabilities are rejected.
3. Canonical hashing rejects duplicate keys and is stable across object order.
4. CloudEvents validate the event catalog and aggregate metadata.
5. OpenAPI and AsyncAPI declare the complete versioned management surface and concurrency headers.
6. Stable errors expose only allowlisted public details.
7. `make verify` succeeds without experimental toolchain flags.
