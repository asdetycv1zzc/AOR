BEGIN;

CREATE TABLE workflow_activity_results (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  idempotency_key text NOT NULL CHECK (idempotency_key <> '' AND length(idempotency_key) <= 256),
  request_sha256 aor_sha256 NOT NULL,
  output_jsonb jsonb NOT NULL CHECK (jsonb_typeof(output_jsonb) IS NOT NULL),
  output_sha256 aor_sha256 NOT NULL,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (tenant_id, idempotency_key)
);

ALTER TABLE workflow_activity_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_activity_results FORCE ROW LEVEL SECURITY;

CREATE POLICY workflow_activity_results_tenant_policy ON workflow_activity_results
  USING (tenant_id = aor_current_tenant())
  WITH CHECK (tenant_id = aor_current_tenant());

GRANT SELECT, INSERT ON TABLE workflow_activity_results TO aor_app;

COMMIT;
