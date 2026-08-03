# WP-05 Tool Broker Module Specification

- Task ID: `WP-05`
- Phase: `3`
- Dependencies: `WP-01`, `WP-03`
- Execution platform: `LINUX`
- Sandbox level: `CONTAINER`

## Purpose

Make every MCP and local tool call pass through one schema-validating, lease-aware, policy-aware and auditable broker.

## Responsibilities

- Register and deterministically list versioned tool descriptors.
- Validate input/output schemas, size limits, lease and policy decisions.
- Revalidate permanent side effects immediately before execution.
- Enforce network destination restrictions and redact secret-like output.
- Store oversized output as content-addressed artifacts.

## Non-responsibilities

- Issuing leases, authoring policy, running containers, or exposing provider credentials.

## Allowed paths

`internal/toolbroker/`, `tool-adapters/`, `cmd/aor-tool-broker/`, `work-packages/wp-05/`, `conformance/requirements.yaml`.

## Acceptance criteria

1. Unknown tools, malformed arguments, expired leases and policy denials fail closed.
2. Descriptors list in stable order and duplicate versions conflict.
3. Irreversible calls revalidate authority and approval at execution time.
4. Output over 1 MiB becomes an artifact reference and secret patterns are redacted.
5. Private, loopback and cloud metadata destinations are denied by default.
