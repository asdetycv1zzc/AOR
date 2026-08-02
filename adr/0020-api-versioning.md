# ADR-0020: API Compatibility And Deprecation

## Context
HTTP, events, Schemas, prompts, policies, workflows, and evidence evolve independently while long-running projects remain active.

## Decision
Use Semantic Versioning per product and contract family. Minor versions add optional fields only; semantic changes require a major. Deprecation lasts at least two minor releases or 180 days, whichever is longer.

## Alternatives
Lockstep versioning causes unnecessary breaks. Silent semantic changes make replay and audits unreliable.

## Security Consequences
Consumers reject unknown required capabilities and intents while ignoring unknown optional fields. Downgrades never weaken security silently.

## Operational Consequences
Compatibility fixtures and generated-client tests cover supported windows.

## Migration
Run adjacent majors in parallel and use pure, tested conversions with documented field loss.

## Status
Accepted
