BEGIN;

ALTER TABLE model_calls
  ADD COLUMN reconciliation_receipt_sha256 aor_sha256,
  ADD COLUMN reconciled_at timestamptz,
  ADD CONSTRAINT model_calls_reconciliation_complete CHECK (
    (status = 'RECONCILED' AND reconciliation_receipt_sha256 IS NOT NULL AND reconciled_at IS NOT NULL)
    OR
    (status <> 'RECONCILED' AND reconciliation_receipt_sha256 IS NULL AND reconciled_at IS NULL)
  ),
  ADD CONSTRAINT model_calls_reconciled_after_creation CHECK (
    reconciled_at IS NULL OR reconciled_at >= created_at
  );

GRANT UPDATE (
  actual_model_version, input_tokens, output_tokens, cost_micros, status,
  provider_request_id, reconciliation_receipt_sha256, reconciled_at
) ON TABLE public.model_calls TO aor_app;

COMMIT;
