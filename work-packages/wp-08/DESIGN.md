# WP-08 Design

`Negotiator` stores the user message first, then invokes fixed roles through the WP-07 boundary. In two-agent mode the provisional draft, independent challenge and revised draft receive separate immutable records. System-owned project/version/time/identity fields are stamped before canonical hashing. `Approve` never synthesizes user authority; it commits the supplied immutable approval through the state core and then materializes the approved envelope idempotently.

`Planner` requires the approved GoalSpec artifact and Planning project state. It freezes goal, plan and module references, rejects unresolved plan decisions and structural ownership conflicts, and creates a deterministic topological order and critical path. `orchestrator.PublishPlan` makes the Project `EXECUTING` transition and all initial ModuleTask definitions one transaction, including outbox events and the idempotent command result.

Goal changes use increasing PlanSpec and ModuleSpec versions. An unaffected task may be retained across the new plan only when its existing immutable ModuleSpec still matches the planned module and its dependent-task list is unchanged; otherwise publication fails and the caller must create a replacement task. Impacted tasks always receive a new task, attempt series and ModuleSpec version.

`EventArtifactStore` persists content and metadata as a tenant-scoped event projection. Events carry hashes and references, not prompt or user content. Artifact identity uses canonical JSON hashes where possible and raw SHA-256 for non-JSON messages.
