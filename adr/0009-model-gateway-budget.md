# ADR-0009: Model Gateway, Budget, And Key Isolation

## Context
Provider differences, credentials, pricing, rate limits, and data policies cannot be delegated to Agent runtimes.

## Decision
All model calls use a normalized Gateway port. Before a call, reserve worst-case cost transactionally across project, role, task, agent, provider, model, pool, daily, and lifetime dimensions; settle actual usage afterward. Keys remain in Secret Manager and Gateway memory only.

## Alternatives
Provider SDKs in Agent processes expose keys. Key quotas alone cannot provide hard multi-dimensional budgets.

## Security Consequences
Requests enforce model allowlists, data classification, output size and Schema. Logs retain hashes and usage, not sensitive content by default.

## Operational Consequences
Unknown provider results retain reservations for reconciliation. Pricing tables, breakers, and pool health are versioned.

## Migration
Adapters implement a stable normalized contract. High-risk roles never switch to an unapproved model automatically.

## Status
Accepted
