BEGIN;

ALTER TABLE budget_reservations
  ADD COLUMN idempotency_key text;

UPDATE budget_reservations
SET idempotency_key = id
WHERE idempotency_key IS NULL;

ALTER TABLE budget_reservations
  ALTER COLUMN idempotency_key SET NOT NULL;

CREATE UNIQUE INDEX budget_reservations_idempotency_key_idx
  ON budget_reservations (tenant_id, idempotency_key);

COMMIT;
