BEGIN;

ALTER TABLE budget_reservations
  ADD COLUMN idempotency_key text;

UPDATE budget_reservations
SET idempotency_key = id
WHERE idempotency_key IS NULL;

CREATE UNIQUE INDEX budget_reservations_idempotency_key_idx
  ON budget_reservations (tenant_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

COMMIT;
