# WP-07 Threat Model

| Threat | Control | Residual boundary |
|---|---|---|
| Prompt injection changes authority | Ordered, separate JSON sections; untrusted items always carry `authority=false` | Prompt is defense in depth; Tool Broker and LeaseAuthority enforce permissions |
| Stale or replayed Agent submits output | AOP expiry plus lease pre/post validation, nonce/signature authority and heartbeat fence | Cross-process replay deduplication belongs to WP-02 Inbox |
| Executor claims completion | Static role-to-intent allowlist denies completion verdicts; Runtime completion has role-local semantics | Orchestrator remains sole business-state writer |
| Auditor is influenced by Executor narrative | Module Auditor context allowlist rejects narratives, scratchpads, identity and prior free-form reasoning | Audit Service owns deterministic evidence selection |
| Agent bypasses provider/tool controls | Runtime only accepts Model Gateway and Tool Broker dependencies | Deployment policy must block direct egress and credentials |
| Credential reaches a Prompt or Agent Card | Credential-pattern rejection and no credential fields | Upstream secret classification and Gateway scanning remain required |
| Concurrency budget exhaustion | Hard maximum eight, soft role quotas, context/output caps and cancelable acquisition | HA requires one authoritative SlotAllocator |
| Low-priority starvation | Effective priority increases with queue age | Scheduler policy sets initial critical-path priority |
| Late cancellation leaks capacity | Active contexts are canceled and release functions are idempotent | Provider adapters must honor context cancellation and reconcile unknown billing |
| Agent Card downgrade or metadata leak | HTTPS A2A 1.0 and required AOP URI are validated before detached signing | Key storage and certificate rotation belong to Identity/Deployment |

