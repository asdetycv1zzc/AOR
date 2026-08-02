# ADR-0023: Model Cache, Privacy, And Provider Data Policy

## Context
Prompt caching can reduce cost but may cross model versions, policy changes, classifications, or retention boundaries.

## Decision
Cache keys include actual model version, Prompt Bundle hash, tool Schema hash, policy version, tenant, and data classification. Remote cache is disabled for confidential or restricted data unless provider, residency, contract, and organization policy explicitly allow it.

## Alternatives
Content-only cache keys risk cross-tenant leakage. Disabling all caching wastes approved provider capabilities.

## Security Consequences
Cache hits still authorize, reserve budget, and emit audit metadata. Cached sensitive content follows the shortest applicable retention.

## Operational Consequences
Track hit rate, invalidation, provider retention, and unexplained usage separately.

## Migration
Any key-format or provider-policy change uses a new namespace; old entries expire without reinterpretation.

## Status
Accepted
