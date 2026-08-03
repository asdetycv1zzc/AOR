# WP-07 Migration Plan

This package introduces no database migration. AgentRun persistence and event history remain owned by WP-02.

Deploy additively:

1. Publish Prompt Bundles, Context Manifest format and Agent Card metadata without scheduling new Runtime instances.
2. Deploy Runtime readers that accept the current AOP v1 schema and old workers in parallel.
3. Enable new scheduling for a canary tenant while pinning every existing run to its original prompt/context digest.
4. Drain old workers only after their leases expire or complete.

Rollback stops new scheduling and drains leases. Already accepted outputs retain their immutable prompt, context, AOP and lease bindings. Prompt changes never rewrite a running declaration; a new version requires a new run authorization.

