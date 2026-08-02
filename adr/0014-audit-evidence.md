# ADR-0014: Fixed Audit Order And Evidence Bundle

## Context
Audits must be repeatable, independent of Executor claims, and verifiable after the original run.

## Decision
Audit in topology, normalized package, and Unicode-code-point path order. Run the fixed deterministic gates before creating a fresh blind Auditor. Store a content-addressed Evidence Bundle whose signature covers canonical manifest bytes and referenced hashes.

## Alternatives
Agent-selected checks and file order are manipulable. Sending Executor explanations biases review.

## Security Consequences
Auditors cannot write source, policies, hidden tests, or their evidence. Hidden tests run only in a separate Linux audit boundary.

## Operational Consequences
Pipeline versions, tool digests, raw result artifacts, findings, and signing identity must be retained and replayable.

## Migration
Pipeline changes create a new version. A pending submission pins the version under which it entered audit.

## Status
Accepted
