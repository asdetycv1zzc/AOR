BEGIN;

ALTER TABLE agent_leases
  ADD COLUMN idempotency_key text
    CHECK (idempotency_key IS NULL OR (idempotency_key <> '' AND length(idempotency_key) <= 256 AND idempotency_key = btrim(idempotency_key) AND idempotency_key !~ E'[\\r\\n]'));

CREATE UNIQUE INDEX agent_leases_issue_idempotency_key_idx
  ON agent_leases (tenant_id, principal_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

COMMIT;
