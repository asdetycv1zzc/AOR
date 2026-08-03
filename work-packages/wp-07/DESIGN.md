# WP-07 Design

## Runtime boundary

`Runtime` is semi-trusted orchestration for one AgentRun. A declaration fixes tenant, project, task, role, Prompt Bundle, Context Manifest, tool schemas, policy version/digest, data classification and AOP correlation data. None may change after declaration.

The Runtime never imports a provider adapter or tool executor. It depends on the narrow `ModelGateway` and `ToolBroker` interfaces, and constructs their requests from the trusted declaration and authoritative lease. It returns `AcceptedResult` to the Orchestrator; it has no state-store dependency and cannot turn that result into a business transition.

## Lifecycle and leases

The lifecycle is `DECLARED -> QUEUED -> LEASED -> STARTING -> RUNNING`, with explicit waiting and terminal branches. External work is single-flight per run. Lease shape, binding, authoritative validity, capability and heartbeat freshness are checked before work. Validity is checked again after work so an expired or revoked Agent cannot submit a late result.

Heartbeat interval is fixed at 30 seconds. The local fence expires after three missed intervals, while `LeaseAuthority` remains responsible for signature, current policy, task, budget and permission validation. Renewal is accepted only when the authority returns the same run binding with a later expiry.

## Scheduling

`SlotAllocator` is the production seam for a deployment-wide allocator. `SlotPool` is the deterministic single-process implementation. It rejects limits above eight, tracks only model/tool operations as active, gives under-soft-limit role groups preference and adds waiting-time aging to caller-supplied priority. HA deployments must inject an allocator backed by the authoritative Scheduler rather than construct one pool per replica.

## Prompt and context

Prompt content enters only as a hash-verified, versioned `PromptBundle`. Assembly emits separate messages in this order: global safety, role, workflow, output schema, approved specification references, knowledge, task/evidence and untrusted content. Each context item is a JSON envelope with `authority=false`; JSON escaping prevents its content from changing envelope metadata.

`ContextManifest` is content-addressed, bounded and deterministically sorted. Each item separates its injected-content hash from the immutable source Artifact hash. Goal/Plan/Module source hashes are matched to the WP-01 AOP envelope before a run is accepted. Untrusted repository, user and tool inputs cannot be relabeled as curated. Module Auditor manifests use an allowlist matching the blind-audit contract.

## Protocol

`Declaration.Envelope` uses WP-01's `pkg/aop.Envelope` directly. Runtime validates the complete AOP v1 envelope, immutable specification scope, expiry and W3C trace binding when accepting the declaration. After acceptance, lease expiry governs the run; message expiry is not incorrectly reused as an AgentRun deadline. WP-01/WP-02 own compatibility and idempotent command persistence.
