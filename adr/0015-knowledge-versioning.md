# ADR-0015: Knowledge Versioning, References, And Write Authority

## Context
Long-lived Agents need precise knowledge without cross-project pollution or silent line-reference drift.

## Decision
Store curated knowledge in versioned, project-isolated trees. Only the Knowledge Curator service account may write after approval. Searches return revision, normalized SHA-256, and inclusive line references; reads resolve that exact revision.

## Alternatives
Direct shared filesystem access bypasses policy. Returning current content for old references corrupts evidence.

## Security Consequences
All other roles and sandboxes are read-only through Knowledge Service. Inheritance is explicit, ordered, and conflict-checked.

## Operational Consequences
Indexes are rebuildable from source, and unavailable revisions return an explicit error.

## Migration
Knowledge changes create commits and manifests; parent changes never mutate a child's inherited snapshot.

## Status
Accepted
