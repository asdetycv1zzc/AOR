# ADR-0006: Project And Tenant Isolation

## Context
Every Goal, task, event, budget, artifact, and knowledge reference belongs to a project isolation boundary.

## Decision
Bind all rows and object keys to tenant and project IDs. Enforce service-layer authorization plus PostgreSQL row-level policies in production. Use per-project repository workspaces and object prefixes; never authorize by resource ID alone.

## Alternatives
Application checks alone are vulnerable to missed filters. A database per project is operationally excessive for the baseline.

## Security Consequences
Cross-project identifiers return non-enumerating errors. Background jobs and administrators use explicit scoped principals.

## Operational Consequences
RLS context, backup/restore, deletion, and support tooling must preserve tenant scope.

## Migration
Add project ownership before exposing a new resource type; backfills reject ambiguous ownership.

## Status
Accepted
