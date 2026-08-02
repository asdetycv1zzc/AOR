# ADR-0024: Configuration And Feature Flags

## Context
Security-sensitive defaults and experimental protocol support must not change silently or through Agent requests.

## Decision
Validate configuration with Draft 2020-12 Schema and reject unknown fields. Static security settings require restart; approved hot reload records old and new hashes. Flags have owner, purpose, default, expiry, classification, and removal criterion.

## Alternatives
Permissive decoding hides typos. Permanent undocumented flags create untested product variants.

## Security Consequences
Agents cannot alter concurrency, policy, isolation, retention, or release flags. Secrets appear only as references.

## Operational Consequences
Configuration snapshots and reload events are observable and rollbackable.

## Migration
Renamed fields overlap for a documented compatibility period; expired flags fail repository conformance.

## Status
Accepted
