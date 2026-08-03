# WP-05 Design

`Broker` owns descriptor registration and call sequencing. `LeaseChecker`, `PolicyEvaluator`, `ToolExecutor`, `ArtifactStore` and `InvocationRecorder` are narrow injected interfaces. This keeps control decisions outside MCP servers and makes tests deterministic without granting a tool process control-plane credentials.
