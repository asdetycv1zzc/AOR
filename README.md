# Agent Organization Runtime

AOR is a deterministic control plane for versioned, auditable multi-agent software delivery. The repository implements the production baseline in `SPEC.md` without treating model output or prompts as security boundaries.

## Status

The repository is under active implementation. It is not production ready until the signed Phase 7 acceptance, security-gate, and launch evidence is present.

## Prerequisites

- Go `1.26.0`
- GNU Make
- OCI-compatible Linux container runtime for Executor and Auditor workloads
- PostgreSQL, Temporal, NATS JetStream, S3-compatible storage, and OPA for deployed profiles

Windows workers intentionally provide native-process execution with `isolationLevel=NONE`. They reject untrusted production work and audits requiring hidden-test confidentiality.

## Verify

```bash
make verify
```

## Entry Points

- `aor-server`: user-facing control API and deterministic orchestrator
- `aor-worker`: workflow and activity worker
- `aor-cli`: complete administrative CLI
- `aor-model-gateway`: provider isolation and budget enforcement
- `aor-tool-broker`: authorized MCP and tool execution
- `aor-conformance`: contract, state, security, and release evidence runner

Architecture decisions are recorded in `adr/`; requirement coverage is recorded in `conformance/requirements.yaml`.
