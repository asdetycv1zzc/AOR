BEGIN;

CREATE TABLE module_audit_coordinations (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  module_task_id uuid NOT NULL,
  attempt_series_id uuid NOT NULL,
  attempt smallint NOT NULL CHECK (attempt BETWEEN 1 AND 3),
  submission_id uuid NOT NULL,
  audit_run_id uuid NOT NULL,
  input_sha256 aor_sha256 NOT NULL,
  policy_digest aor_sha256 NOT NULL,
  execution_platform text NOT NULL CHECK (execution_platform IN ('LINUX', 'WINDOWS')),
  isolation_level text NOT NULL CHECK (
    (execution_platform = 'LINUX' AND isolation_level = 'CONTAINER') OR
    (execution_platform = 'WINDOWS' AND isolation_level = 'NONE')
  ),
  sandbox_attestation text NOT NULL CHECK (
    (execution_platform = 'LINUX' AND sandbox_attestation ~ '^oci:sha256:[0-9a-f]{64}$') OR
    (execution_platform = 'WINDOWS' AND sandbox_attestation = 'windows:none')
  ),
  state text NOT NULL CHECK (state IN ('DETERMINISTIC_AUDIT', 'LLM_AUDIT', 'COMPLETED')),
  deterministic_sha256 aor_sha256,
  evidence_sha256 aor_sha256,
  outcome text CHECK (outcome IS NULL OR outcome IN (
    'DETERMINISTIC_FAILURE', 'LLM_SUCCESS', 'LLM_FAILURE'
  )),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  completed_at timestamptz,
  PRIMARY KEY (tenant_id, module_task_id, attempt_series_id, attempt),
  UNIQUE (tenant_id, audit_run_id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, module_task_id) REFERENCES module_tasks(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, attempt_series_id) REFERENCES attempt_series(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, submission_id) REFERENCES submissions(tenant_id, id) ON DELETE RESTRICT,
  CHECK (
    (state = 'DETERMINISTIC_AUDIT'
      AND deterministic_sha256 IS NULL
      AND evidence_sha256 IS NULL
      AND outcome IS NULL
      AND completed_at IS NULL)
    OR
    (state = 'LLM_AUDIT'
      AND deterministic_sha256 IS NOT NULL
      AND evidence_sha256 IS NULL
      AND outcome IS NULL
      AND completed_at IS NULL)
    OR
    (state = 'COMPLETED'
      AND evidence_sha256 IS NOT NULL
      AND outcome IS NOT NULL
      AND completed_at IS NOT NULL
      AND ((outcome = 'DETERMINISTIC_FAILURE' AND deterministic_sha256 IS NULL)
        OR (outcome IN ('LLM_SUCCESS', 'LLM_FAILURE') AND deterministic_sha256 IS NOT NULL)))
  ),
  CHECK (updated_at >= created_at),
  CHECK (completed_at IS NULL OR completed_at >= created_at)
);

CREATE INDEX module_audit_coordinations_active_idx
  ON module_audit_coordinations (tenant_id, updated_at, audit_run_id)
  WHERE state <> 'COMPLETED';

ALTER TABLE module_audit_coordinations ENABLE ROW LEVEL SECURITY;
ALTER TABLE module_audit_coordinations FORCE ROW LEVEL SECURITY;

CREATE POLICY module_audit_coordinations_tenant_policy ON module_audit_coordinations
  USING (tenant_id = aor_current_tenant())
  WITH CHECK (tenant_id = aor_current_tenant());

GRANT SELECT, INSERT, UPDATE ON TABLE module_audit_coordinations TO aor_app;

COMMIT;
