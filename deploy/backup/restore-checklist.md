# Restore Checklist

1. Restore PostgreSQL and replay the transactional outbox.
2. Restore immutable artifact manifests and verify every referenced hash.
3. Restore audit records and verify the complete signature/hash chain.
4. Rebuild projections and compare Project, Goal, Plan, Task, Audit, and Artifact counts.
5. Record RPO, RTO, operator identities, and evidence URI before reopening traffic.
