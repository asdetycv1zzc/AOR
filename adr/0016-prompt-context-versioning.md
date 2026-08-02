# ADR-0016: Prompt Versioning And Context Manifests

## Context
Prompt changes and unmarked source mixing make model behavior unauditable and reduce cache correctness.

## Decision
Assemble prompts in fixed authority order from immutable components. Pin each AgentRun to a content-addressed Prompt Bundle and Context Manifest containing source kind, trust level, revision, hash, range, and token estimate.

## Alternatives
A single concatenated string loses provenance. Mutable role prompts silently change running work.

## Security Consequences
Untrusted content is explicitly delimited and cannot introduce authority. Prompt text is not an authorization boundary and is absent from logs by default.

## Operational Consequences
Bundle storage, evaluation, token budgeting, and cache invalidation use stable hashes.

## Migration
New bundles affect new AgentRuns only unless a critical signed policy forces migration and lease revalidation.

## Status
Accepted
