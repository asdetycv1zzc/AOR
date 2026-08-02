# WP-02 State Core Module Specification

- Task ID: `WP-02`
- Phase: `1`
- Goal baseline: `SPEC.md` version `2.0.0`
- Dependencies: `WP-00`, `WP-01`
- Risk: `CRITICAL`
- Execution platform: `LINUX`
- Sandbox level: `CONTAINER`

## Purpose

Implement the deterministic state authority, immutable event history, idempotent command boundary, transactional outbox, and replayable projections without any model dependency.

## Responsibilities

- Implement Project, Goal approval, Plan publication, ModuleTask, AttemptSeries, audit, integration, and completion transitions.
- Enforce expected aggregate version, exact spec digest, Goal approval, Lease fencing inputs, and attempt limit.
- Atomically persist projection, event, idempotency result, and outbox entry.
- Deduplicate Inbox messages and buffer/replay duplicate or out-of-order events.
- Define PostgreSQL migrations with tenant scope, restrictive references, immutable approvals, typed audit subjects, and attempt-series uniqueness.
- Provide deterministic workflow simulation and replay fixtures.

## Non-responsibilities

- Authenticate identities or evaluate OPA policy.
- Issue real Agent or Capability Leases.
- Invoke models, tools, sandboxes, Git, object storage, or event-bus clients.
- Mark unsigned releases production ready.

## Allowed Paths

`go.mod`, `go.sum`, `internal/state/`, `internal/eventing/`, `internal/idempotency/`, `internal/projection/`, `internal/orchestrator/`, `internal/workflow/`, `migrations/postgres/`, `migrations/workflow/`, `conformance/state-machine/`, `tests/integration/`, `tests/unit/`, `cmd/aor-conformance/`, `conformance/requirements.yaml`, `work-packages/wp-02/`.

## Forbidden Paths

`SPEC.md`, `AGENTS.md`, `.git/`, `policies/`, `knowledge/`, `sandbox/`, `audit/hidden-test-runner/`, provider keys, signing keys, and production credentials.

## Acceptance Criteria

1. Goal approval rejects unresolved items, wrong user binding, wrong version, and wrong canonical digest.
2. Repeating the same command 100 times produces one event/outbox effect and the original result; changing the body under the same key conflicts.
3. Every transition rejects stale expected versions and invalid state edges.
4. A third failed attempt blocks the module, freezes dependants, and exposes no automatic retry transition.
5. Duplicate, delayed, and out-of-order events rebuild the exact online projection.
6. A crash before commit produces no partial state; a crash after commit leaves an outbox event available for publication.
7. `make verify` and state-machine conformance succeed.
