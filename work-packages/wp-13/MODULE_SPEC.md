# WP-13 Observability Module Specification

- Task ID: `WP-13`
- Phase: `6`
- Dependencies: `WP-02`
- Dependency baselines: Go `1.26.0`, OpenTelemetry Collector configuration, Prometheus rules, Grafana dashboard schema `39`
- Data classification: application telemetry `INTERNAL`; security audit records `CONFIDENTIAL`
- Execution platform: `LINUX`
- Sandbox level: `CONTAINER`

## Purpose

Provide bounded and redacted trace, metric and log contracts for every AOR service, plus a separately stored tamper-evident security audit log and production SLO configuration.

## Responsibilities

- Validate W3C `traceparent` and `tracestate` propagation across service and workflow boundaries.
- Require every application log to carry Project, Workflow, Task and AgentRun identifiers or a reason for each empty identifier.
- Remove content fields and redact credential and PII patterns before export; enforce event and attribute limits.
- Retain all error, third-failure, security-denial, budget-denial and critical traces.
- Validate metric schemas and cap label and series cardinality.
- Hash-chain and sign append-only audit events using trusted time; audit audit-log reads.
- Supply collector, alert, fault-drill, dashboard and immutable-storage configurations.

## Non-responsibilities

- Provisioning the collector, Prometheus, Grafana, KMS or WORM object store.
- Instrumenting every WP-owned service; those owners call the contracts in `internal/observability`.
- Producing preproduction alert drill evidence or deciding Production readiness.

## Allowed paths

- `internal/observability/`
- `observability/`
- `work-packages/wp-13/`

## Forbidden paths

- State machine, API and event contracts outside the allowed paths.
- Provider credentials, Prompt/model/tool/source content, PII and hidden-test content.
- Deployment secrets or vendor-specific mutable audit buckets.

## Acceptance criteria

1. A simulated request-to-model-to-tool-to-Git-to-audit trace retains one Trace ID and correct parent relationships.
2. Logs without complete correlation identifiers or explicit empty reasons fail closed.
3. Content-key fields are removed, credential/PII patterns are redacted and serialized records remain bounded.
4. Raw high-cardinality identifier labels are rejected and controlled dimensions overflow into a bounded series.
5. Critical trace outcomes survive a zero-percent normal sampling rate.
6. Audit records are separately typed, append-only, signed, hash-chained and query reads create audit events.
7. Every required alert maps to a drill scenario; Production still requires recorded drill execution evidence.
