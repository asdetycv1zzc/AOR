# WP-04 Model Gateway Module Specification

- Task ID: `WP-04`
- Phase: `2`
- Dependencies: `WP-01`, `WP-03`
- Execution platform: `LINUX`
- Sandbox level: `CONTAINER`

## Purpose

Provide one deterministic, budget-enforcing and auditable boundary for all model-provider calls.

## Responsibilities

- Normalize provider requests and responses.
- Enforce model allowlists, token and cost budgets before provider calls.
- Reserve, settle, release and reconcile usage without double charging.
- Generate privacy-safe cache keys and redact provider credentials.
- Expose streaming cancellation and provider capability metadata.

## Non-responsibilities

- Agent lifecycle, prompt authoring, policy authoring, tool execution, or sandbox isolation.
- Deciding whether a business state transition is valid.

## Allowed paths

`internal/modelgateway/`, `model-adapters/`, `cmd/aor-model-gateway/`, `work-packages/wp-04/`, `conformance/requirements.yaml`.

## Acceptance criteria

1. Calls exceeding any hard budget are rejected before adapter invocation.
2. Reservation settlement is idempotent and leaves no unexplained balance delta.
3. Cache keys include actual model version, prompt/tool/policy digests and data classification.
4. Provider keys never appear in normalized requests, responses, errors or telemetry metadata.
5. Invalid structured output is rejected and retried at most twice.
