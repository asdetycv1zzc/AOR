# WP-08 Interfaces

- `Negotiator.Negotiate(ctx, NegotiationRequest) (NegotiationResult, error)`
- `Negotiator.Approve(ctx, ApprovalRequest) (orchestrator.ProjectOutcome, error)`
- `Planner.BuildAndPublish(ctx, PlanningRequest) (PlanningResult, error)`
- `ArtifactStore.Put/Get` for immutable scoped artifacts
- `AgentInvoker.Invoke` for WP-07 role runs
- `orchestrator.Service.PublishPlan` for atomic plan/task publication
- `contracts.ValidatePlanJSON` and `contracts.ValidateModuleJSON` for canonical digest binding

Callers supply stable idempotency, message, plan, task and attempt-series IDs. Retries reuse stable Agent invocation IDs and do not create new role runs after artifacts exist.
