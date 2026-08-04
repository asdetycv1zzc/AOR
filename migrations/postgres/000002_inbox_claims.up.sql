BEGIN;

ALTER TABLE inbox
  ADD COLUMN status text NOT NULL DEFAULT 'RETRYABLE',
  ADD COLUMN result_jsonb jsonb,
  ADD COLUMN claim_token text,
  ADD COLUMN claim_attempt integer NOT NULL DEFAULT 0,
  ADD COLUMN claimed_at timestamptz,
  ADD COLUMN lease_expires_at timestamptz;

ALTER TABLE inbox
  ALTER COLUMN result_sha256 DROP NOT NULL;

ALTER TABLE inbox
  ADD CONSTRAINT inbox_status_check
  CHECK (status IN ('PROCESSING', 'RETRYABLE', 'COMPLETED')),
  ADD CONSTRAINT inbox_completed_result_check
  CHECK (status <> 'COMPLETED' OR (result_jsonb IS NOT NULL AND result_sha256 IS NOT NULL)),
  ADD CONSTRAINT inbox_claim_attempt_check
  CHECK (claim_attempt >= 0),
  ADD CONSTRAINT inbox_processing_claim_check
  CHECK (status <> 'PROCESSING' OR (claim_token IS NOT NULL AND claimed_at IS NOT NULL AND lease_expires_at IS NOT NULL));

CREATE INDEX inbox_retryable_claim_index
  ON inbox (tenant_id, consumer_id, lease_expires_at)
  WHERE status <> 'COMPLETED';

COMMIT;
