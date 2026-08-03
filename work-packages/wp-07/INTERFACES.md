# WP-07 Interfaces

## Construction

```go
func New(
    authority LeaseAuthority,
    gateway ModelGateway,
    broker ToolBroker,
    slots SlotAllocator,
    clock func() time.Time,
) (*Runtime, error)
```

Dependencies fail closed. `LeaseAuthority` validates, heartbeats and renews signed leases. `ModelGateway.Generate` is the only model path. `ToolBroker.Invoke` is the only tool path. `SlotAllocator.Acquire` scopes active capacity to a returned idempotent release function.

## Lifecycle

- `Declare(Declaration) error`
- `Queue(runID) error`
- `AssignLease(ctx, runID, AgentLease) error`
- `Start(ctx, runID) error`
- `Wait(runID, waitingState) error`
- `Resume(runID) error`
- `Heartbeat(ctx, runID) error`
- `RenewLease(ctx, runID) error`
- `Cancel(runID) error`
- `Terminate(runID) error`
- `ExpireStale() []string`
- `Snapshot(runID) (Snapshot, error)`

## Agent operations

- `Generate(ctx, runID, ModelCall) (modelgateway.NormalizedResponse, error)`
- `InvokeTool(ctx, runID, ToolCall) (toolbroker.ToolResult, error)`
- `Complete(ctx, runID, AgentOutput) (AcceptedResult, error)`
- `AcceptedResult(runID) (AcceptedResult, bool)`

`Complete` accepts a role output, not a Module or Project completion. Its intent allowlist is deterministic and denies unknown intents.

## Content contracts

- `DigestPromptBundle` and `ValidatePromptBundle`
- `DigestContextManifest` and `ValidateContextManifest`
- `DigestToolDefinitions`
- `AssemblePrompt`

All hashes use the `sha256:<lowercase-hex>` form and structured objects use the repository RFC 8785 boundary. `ContextItem.sha256` hashes injected content; `sourceSha256` binds versioned source Artifacts. Context is limited to 100 items, 32 KiB per item and 1 MiB total.

## Agent Card

- `SignAgentCard(ctx, card, signer, now) (aop.AgentCard, error)`
- `VerifyAgentCard(ctx, card, signer, now, revokedKeys) error`

`Declaration.Envelope` is the WP-01 `pkg/aop.Envelope`; the transport also validates it against `api/aop/aor-envelope.v1.schema.json`.
