BEGIN;

ALTER TABLE submissions
  ADD COLUMN idempotency_key text NOT NULL DEFAULT 'legacy-import'
    CHECK (idempotency_key <> '' AND length(idempotency_key) <= 256),
  ADD COLUMN request_sha256 aor_sha256 NOT NULL
    DEFAULT 'sha256:0000000000000000000000000000000000000000000000000000000000000000';

ALTER TABLE submissions
  ALTER COLUMN idempotency_key DROP DEFAULT,
  ALTER COLUMN request_sha256 DROP DEFAULT;

GRANT SELECT, INSERT ON TABLE public.submissions TO aor_app;

COMMIT;
