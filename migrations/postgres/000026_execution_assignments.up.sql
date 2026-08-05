BEGIN;

CREATE TABLE execution_assignments (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  module_task_id uuid NOT NULL,
  module_spec_id uuid NOT NULL,
  attempt_series_id uuid NOT NULL,
  execution_id text NOT NULL CHECK (execution_id <> '' AND length(execution_id) <= 256),
  agent_instance_id text NOT NULL,
  sandbox_id text NOT NULL CHECK (sandbox_id <> '' AND length(sandbox_id) <= 256),
  fencing_token bigint NOT NULL CHECK (fencing_token >= 1),
  lease_id text CHECK (lease_id IS NULL OR (lease_id <> '' AND length(lease_id) <= 256)),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  runtime_bound_at timestamptz,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, execution_id),
  UNIQUE (tenant_id, module_task_id, attempt_series_id, fencing_token),
  UNIQUE (tenant_id, lease_id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, module_task_id) REFERENCES module_tasks(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, module_spec_id) REFERENCES module_specs(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, attempt_series_id) REFERENCES attempt_series(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, agent_instance_id) REFERENCES agent_instances(tenant_id, id) ON DELETE RESTRICT,
  CHECK ((lease_id IS NULL) = (runtime_bound_at IS NULL))
);

ALTER TABLE execution_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE execution_assignments FORCE ROW LEVEL SECURITY;

CREATE POLICY execution_assignments_tenant_policy ON execution_assignments
  USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());

GRANT SELECT, INSERT, UPDATE ON TABLE execution_assignments TO aor_app;

COMMIT;
