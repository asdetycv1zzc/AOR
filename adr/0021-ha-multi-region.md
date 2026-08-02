# ADR-0021: High Availability And Regional Recovery

## Context
The production HA profile needs service redundancy and regional recovery without dual control-plane writers.

## Decision
Run at least two API and gateway replicas and three workflow workers across zones, with HA PostgreSQL, Temporal, NATS JetStream, and replicated S3 storage. A region owns workflow execution through engine fencing; regional recovery is controlled, not active-active business writes.

## Alternatives
Uncoordinated active-active writes risk split brain. A single node is supported only without an HA claim.

## Security Consequences
Trust domains, data residency, keys, and policy bundles are region-scoped and revalidated on failover.

## Operational Consequences
Target control-plane RPO is zero for committed transactions and RTO is 60 minutes for regional recovery, subject to deployment profile tests.

## Migration
Add regions through replicated backups and rehearsed promotion before routing production traffic.

## Status
Accepted
