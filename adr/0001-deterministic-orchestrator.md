# ADR-0001: Deterministic Orchestrator And Workflow Engine

## Context
AOR needs durable history, deterministic replay, signals, timers, activity retry, and version migration while keeping all model and tool effects outside workflow code.

## Decision
Use Temporal as the production workflow engine. Keep business transitions in a deterministic Go state package and invoke PostgreSQL, model, network, file, and tool side effects only through idempotent activities. Workflow histories pin code-version markers.

## Alternatives
A bespoke queue loop lacks proven replay and migration semantics. A database-only scheduler increases recovery complexity.

## Security Consequences
Workflow workers receive only workload identity and activity-scoped capability; Agent runtimes never receive Temporal control credentials.

## Operational Consequences
Temporal is an additional HA dependency and requires history retention, worker compatibility, and stuck-workflow runbooks.

## Migration
The orchestration port isolates workflow definitions. New incompatible histories use a new workflow type or version marker.

## Status
Accepted
