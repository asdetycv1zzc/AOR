# WP-08 Goal and Plan Module Specification

- Task ID: `WP-08`
- Phase: `4`
- Dependencies: `WP-02`, `WP-07`
- Risk: `HIGH`

## Purpose

Turn user intent into immutable GoalSpec versions and turn an explicitly approved GoalSpec into one validated PlanSpec, immutable ModuleSpecs, and an atomically published task DAG.

## Responsibilities

- Persist user messages, drafts, challenges, approvals, plans, modules and plan analysis as tenant/project-scoped immutable artifacts.
- Assign GoalProposer and GoalChallenger deterministically for one- and two-agent modes.
- Permit unlimited goal rounds without automatic approval or planning.
- Bind approval to GoalSpec ID, version, content hash and user principal.
- Validate plan DAG, platform/isolation pairs, ownership, interfaces, acceptance criteria and open decisions.
- Freeze system-owned ModuleSpec fields from the PlanSpec.
- Publish the plan transition and every initial ModuleTask in one event-store transaction.

## Non-responsibilities

- Model execution internals, authorization policy evaluation, sandbox creation, repository execution and audit verdicts.
- Inferring semantic ownership beyond explicit structured responsibilities, paths and interfaces.

## Allowed paths

`internal/goalplan/`, `internal/orchestrator/plan.go`, `internal/orchestrator/query.go`, `pkg/contracts/`, `api/json-schema/plan-spec.v1.schema.json`, `work-packages/wp-08/`, `conformance/requirements.yaml`.

## Acceptance criteria

1. One-agent and two-agent negotiations preserve immutable role records and cannot advance to planning without user approval.
2. One hundred goal rounds preserve the version chain without automatic approval or Plan creation.
3. Approved changes create a new GoalSpec version and supersede only explicitly impacted tasks.
4. Plans with cycles, unknown dependencies, overlapping path/interface ownership, open decisions or invalid platform isolation are rejected before state mutation.
5. A successful publication writes the project transition and all task projections/events atomically and idempotently.
6. A revised plan can retain an unaffected existing task only when its immutable ModuleSpec, attempt series and dependent-task topology still match.
