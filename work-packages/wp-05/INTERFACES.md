# WP-05 Interfaces

- `Broker.Invoke(ctx, ToolRequest) -> ToolResult` is the only execution entry point.
- `ToolDescriptor` describes schema, risk, side effect, network and filesystem capabilities.
- `LeaseChecker` and `PolicyEvaluator` are fail-closed authorization adapters.
- `ToolExecutor` receives only descriptor and validated parameters.
- `ArtifactStore` receives oversized output after hashing.
