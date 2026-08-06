# Restore Checklist

1. Restore PostgreSQL and replay the transactional outbox.
2. Restore immutable artifact manifests and verify every referenced hash.
3. Restore audit records and verify the complete signature/hash chain.
4. Rebuild projections and compare Project, Goal, Plan, Task, Audit, and Artifact counts.
5. While the restored API is isolated from user traffic, run `aor --server <restored-api> --token-env AOR_TOKEN --json admin backup verify --idempotency-key <drill-id>`. The break-glass token's tenant is the verification scope; repeat for every restored tenant and preserve each returned graph digest and counts.
6. Record RPO, RTO, operator identities, and evidence URI before reopening traffic.
