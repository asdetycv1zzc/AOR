# WP-01 Contracts Module Specification

- Task ID: `WP-01`
- Phase: `1`
- Goal baseline: `SPEC.md` version `2.0.0`
- Dependencies: `WP-00`
- Risk: `HIGH`
- Execution platform: `LINUX`
- Sandbox level: `CONTAINER`

## Purpose

Freeze the external and internal protocol vocabulary before control-plane behavior is implemented.

## Responsibilities

- Define canonical identifiers, errors, Agent Card, AOP envelope, CloudEvents, GoalSpec, PlanSpec, ModuleSpec, Submission, Evidence, configuration, approval, and user-decision contracts.
- Publish OpenAPI 3.2.0 and AsyncAPI 3.1.0 documents.
- Provide Go protocol types and semantic validation.
- Enforce conditional AOP references by intent and canonical hash rules from ADR-0026.
- Provide compatibility and contract conformance fixtures.

## Non-responsibilities

- Persist state or execute transitions.
- Authenticate principals, authorize tools, invoke models, or run sandboxes.
- Generate release signatures or claim production acceptance.

## Allowed Paths

`api/`, `pkg/aop/`, `pkg/cloudevents/`, `pkg/errors/`, `cmd/aor-conformance/`, `internal/contracts/`, `conformance/a2a/`, `conformance/aop/`, `conformance/requirements.yaml`, `work-packages/wp-01/`.

## Forbidden Paths

`SPEC.md`, `AGENTS.md`, `.git/`, `internal/state/`, `internal/workflow/`, `policies/`, `knowledge/`, `sandbox/`, `audit/hidden-test-runner/`, signing keys, and production credentials.

## Acceptance Criteria

1. Every protocol JSON document declares Draft 2020-12 and validates representative positive and negative fixtures.
2. Unknown optional AOP fields are ignored; unknown intents and required capabilities are rejected.
3. CloudEvents validate naming, source, subject, content type, time, and trace context.
4. API write operations declare idempotency and optimistic concurrency requirements.
5. Errors expose stable AOR codes without sensitive values.
6. `make verify` succeeds.
