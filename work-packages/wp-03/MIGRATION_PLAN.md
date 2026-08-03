# WP-03 Migration Plan

The reference implementation is storage-neutral and uses `LeaseStore`; no WP-02 migration is changed. Production adoption adds tenant-scoped `agent_instances` and `agent_leases` tables using expand-migrate-contract, with `nonce` stored only as a hash and a unique `(tenant_id, id)` key. Lease writes use a compare-and-fence transaction (`state = ACTIVE` and expected fencing token), and revocation is an append-only audit event.

Rollout order:

1. Deploy nullable identity/lease tables and policy-bundle version metadata.
2. Backfill active workload metadata without importing bearer tokens or signing keys.
3. Run shadow authentication and policy decisions; compare only safe decision metadata.
4. Enable lease-gated writes for new workers, then drain old workers before enforcing the constraint.
5. Roll back by disabling new issuance and allowing already-issued leases to expire; never extend or rewrite revoked leases.

Policy bundle changes are versioned and signed. A critical forced migration revokes affected leases and requires each call to reauthorize against the new bundle.
