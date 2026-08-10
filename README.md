# Agent Organization Runtime

AOR is a deterministic control plane for versioned, auditable multi-agent software delivery. The repository implements the production baseline in `SPEC.md` without treating model output or prompts as security boundaries.

## Status

The repository is under active implementation. It is not production ready until the signed Phase 7 acceptance, security-gate, and launch evidence is present.

The Compose `TEST` profile is the classroom core path: Goal negotiation, Plan, Execution, deterministic module tests, and blind module audit. When every active module passes, the project projection contains `coreSummary.status=COMPLETED`; the production Integration and Global Audit gates remain separate.

## Prerequisites

- Go `1.26.5`
- GNU Make
- OCI-compatible Linux container runtime for Executor and Auditor workloads
- PostgreSQL, Temporal, NATS JetStream, S3-compatible storage, OPA, and OpenTelemetry Collector for deployed profiles

Windows workers intentionally provide native-process execution with `isolationLevel=NONE`. They reject untrusted production work and audits requiring hidden-test confidentiality.

## Verify

```bash
make verify
```

The TEST worker runs each module's plan-owned `verificationEntrypoint` against an immutable submission checkout with the exact toolchains selected in GoalSpec and ModuleSpec placed first on `PATH`. Linux entrypoints are POSIX sh `.sh` files; Windows entrypoints are PowerShell `.ps1` files. The entrypoint is ordinary repository code written by the Executor and independently reviewed and run by the Auditor; there is no deployment-wide language-specific test command. Existing GoalSpec v1 artifacts remain readable, but active v1 projects must negotiate a GoalSpec v2 before they can use this verification path. This classroom path does not provide a security boundary for untrusted code.

## Entry Points

- `aor-server`: user-facing control API and deterministic orchestrator
- `aor-worker`: workflow and activity worker
- `aor-cli`: complete administrative CLI
- `aor-model-gateway`: provider isolation and budget enforcement
- `aor-tool-broker`: authorized MCP and tool execution
- `aor-conformance`: contract, state, security, and release evidence runner

Architecture decisions are recorded in `adr/`; requirement coverage is recorded in `conformance/requirements.yaml`.
