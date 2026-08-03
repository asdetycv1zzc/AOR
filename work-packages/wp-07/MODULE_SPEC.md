# WP-07 Agent Runtime Module Specification

- Task ID: `WP-07`
- Phase: `4`
- Dependencies: `WP-01`, `WP-02`, `WP-04`, `WP-05`
- Risk: `HIGH`
- Execution platform: `LINUX`
- Sandbox level: `CONTAINER`
- Data classification: inherited from the approved GoalSpec

## Purpose

Run one version-bound agent role through controlled model and tool boundaries without granting the agent control-plane credentials, direct state access, or completion authority.

## Responsibilities

- Enforce the declared Agent lifecycle and reject expired or incorrectly bound leases.
- Limit active model/tool operations to eight globally per allocator, with role soft limits, priority and aging.
- Assemble versioned Prompt Bundles and Context Manifests in the normative authority order.
- Exclude Executor narratives, scratchpads and prior free-form reasoning from blind Auditor contexts.
- Route model calls only through Model Gateway and tools only through Tool Broker.
- Bind accepted role output to AOP message, idempotency, trace, lease, prompt and context identifiers.
- Sign and validate the public A2A 1.0 Agent Card with the required AOP v1 extension.

## Non-responsibilities

- Business-state transitions, event persistence, Inbox/Outbox handling or completion decisions.
- Provider credentials, model adapter selection policy, tool execution, repository writes or sandbox mechanics.
- Authoring Prompt, Policy, Goal, Plan or Module content.
- HTTP/A2A transport parsing; WP-01 schemas remain authoritative at the transport edge.

## Allowed paths

- `internal/agentruntime/`
- `work-packages/wp-07/`

## Forbidden paths

- `internal/state/`, `internal/orchestrator/`, `internal/modelgateway/`, `internal/toolbroker/`
- `api/`, `policies/`, `knowledge/`, provider credential storage and hidden tests

## Acceptance criteria

1. Lifecycle tests cover every normal state and reject invalid or terminal transitions.
2. More than eight simultaneous active model/tool operations cannot acquire a slot; waiting states consume no slot.
3. Expired AOP messages are rejected at declaration; a lease is verified before and after external work and three missed 30-second heartbeats reject a late result.
4. Prompt/context hash mutation, credential-like input, trust relabeling and blind-audit contamination fail closed.
5. An Executor cannot emit `REPORT_MODULE_COMPLETE`; `COMPLETED` means only that Runtime accepted its role output.
6. Gateway and Broker requests are constructed from immutable run bindings, not model-provided tenant, project, role, lease, policy or budget values.
7. Cancellation reaches the active provider context and releases the global slot.
8. Agent Cards require HTTPS A2A 1.0 interfaces, `urn:aor:aop:v1`, explicit authentication and a valid detached signature.
