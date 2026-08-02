# ADR-0026: Conservative Resolution Of Specification Conflicts

## Context

`SPEC.md` 2.0.0 contains overlapping examples and several inconsistent enumerations. Section 48 requires an ADR before implementation may choose semantics. The governing rule is to preserve every security invariant and choose the stricter, independently verifiable behavior.

## Decision

1. `DONE` is a computed completion predicate, not a persisted `ModuleTaskState`. It becomes true only when the persisted state is `INTEGRATED` and all section 38.1 evidence predicates pass.
2. `ProjectState=COMPLETED` requires every section 16.9 and 38.2 condition, including an immutable user `APPROVE_RELEASE` record. Deployment remains a separate release action.
3. Section 41.2 decision names are canonical. Section 16.6 aliases map to them, except `ACCEPT_RISK_AND_CONTINUE`, which is rejected because it conflicts with the explicit prohibition on ignoring audit to complete work.
4. Attempts belong to an immutable `attempt_series_id` bound to `module_task_id + module_spec_version`. Uniqueness is `(attempt_series_id, attempt)`. A user-authorized reset creates a new series and never deletes history.
5. The canonical GoalSpec Schema is the union of sections 7.1.3 and 42.1. Approval metadata and computed digest are envelope fields. `contentSha256` is RFC 8785 JSON canonicalization of the immutable content object only, excluding status, approval, digest, and signature fields.
6. Submission and Evidence manifests use the same canonicalization rule: the digest excludes the digest and signature fields. Evidence uses the richer union of sections 22 and 42; incompatible aliases are normalized at the API boundary.
7. AOP envelope references are conditional by intent. Goal intents require Goal draft identity but no Plan/Module reference; planning requires approved Goal; module intents require the references available at that stage. Schema `if/then` guards enforce this.
8. Goal supersession moves the Project to `PAUSED` or `GOAL_NEGOTIATING` and only impacted ModuleTasks to `SUPERSEDED`; `SUPERSEDED` is never a Project state.
9. Eight active Agents is a system-wide hard limit. A project concurrency limit is an additional limit in range 1 through 8 and cannot multiply the global limit.
10. Project-scoped roles use a typed `subject_type + subject_id`; `task_id` is nullable until a role is attached to a task. Authorization never accepts an untyped nullable subject.
11. Sandbox configuration adds `networkPolicy.mode=UNRESTRICTED` only for `WINDOWS+NONE` and represents unenforced Windows resource wishes as disclosures, not attestations. All other uses of `UNRESTRICTED` fail validation.
12. The API and CLI add project export, deletion request, release approval, user-decision report download, and administrative equivalents so management capabilities remain available without a Web console.
13. High-cardinality project IDs are Trace/Log attributes, not ordinary Metric labels. Each span records applicable attributes and a structured `not_applicable` reason for fields unavailable at that lifecycle stage.
14. The stricter retention values govern conflicts: prompt/response content at most 30 days and security audit logs at least 400 days. Configuration defaults use those values.
15. Explicit `AOR-*` IDs remain authoritative. Normative unnumbered statements receive immutable catalog IDs `AOR-NORM-S<section>-<ordinal>` assigned in source order once and retained across later edits; deleted entries are marked retired rather than reused.
16. Data modeling includes Tenant, IntegrationTask, AttemptSeries, UserDecision, and a typed Audit subject so Global Audit does not require a Submission.

## Alternatives

Editing `SPEC.md` would alter the user-owned baseline. Selecting the weaker behavior would violate invariants. Deferring conflicts to runtime would produce incompatible persistence and protocol contracts.

## Security Consequences

These resolutions add no privilege or completion bypass. They make approval, attempt reset, hashing, task scope, Windows capability, and release semantics more restrictive and testable.

## Operational Consequences

The implementation and conformance suite must test alias normalization, canonical hashing, computed completion, global scheduling, typed subjects, stricter retention, and the extended management surface.

## Migration

This is the initial implementation baseline. A future signed SPEC that resolves a conflict supersedes the corresponding item through a new ADR and explicit data/protocol migration.

## Status

Accepted
