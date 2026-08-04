BEGIN;

ALTER TABLE integration_tasks
  ADD COLUMN merge_request_sha256 aor_sha256,
  ADD COLUMN merge_audit_sha256 aor_sha256,
  ADD COLUMN merge_result_jsonb jsonb,
  ADD COLUMN merge_commit text CHECK (merge_commit IS NULL OR merge_commit ~ '^[0-9a-f]{40}$'),
  ADD COLUMN merge_pending boolean,
  ADD CONSTRAINT integration_tasks_merge_result_object CHECK (
    merge_result_jsonb IS NULL OR jsonb_typeof(merge_result_jsonb) = 'object'
  ),
  ADD CONSTRAINT integration_tasks_merge_fields CHECK (
    (merge_request_sha256 IS NULL
      AND merge_audit_sha256 IS NULL
      AND merge_result_jsonb IS NULL
      AND merge_commit IS NULL
      AND merge_pending IS NULL)
    OR
    (merge_request_sha256 IS NOT NULL
      AND merge_audit_sha256 IS NOT NULL
      AND merge_result_jsonb IS NOT NULL
      AND merge_pending IS NOT NULL
      AND ((merge_pending AND merge_commit IS NULL)
        OR (NOT merge_pending AND merge_commit IS NOT NULL)))
  );

CREATE INDEX integration_tasks_pending_merge_idx
  ON integration_tasks (tenant_id, updated_at, id)
  WHERE merge_pending = true;

GRANT SELECT, INSERT, UPDATE ON TABLE public.audit_runs TO aor_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.audit_findings TO aor_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.integration_tasks TO aor_app;

COMMIT;
