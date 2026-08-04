BEGIN;

CREATE TABLE project_repositories (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  repository_path text NOT NULL CHECK (
    repository_path <> '' AND length(repository_path) <= 4096
  ),
  default_branch text NOT NULL CHECK (
    default_branch <> '' AND length(default_branch) <= 255
    AND default_branch !~ '[[:cntrl:]]'
  ),
  baseline_commit text NOT NULL CHECK (baseline_commit ~ '^[0-9a-f]{40}$'),
  initialization text NOT NULL CHECK (initialization IN ('EMPTY', 'IMPORT')),
  source_sha256 aor_sha256 NOT NULL,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (tenant_id, project_id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE repository_workspaces (
  id text NOT NULL CHECK (id <> '' AND length(id) <= 512),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  module_task_id uuid NOT NULL,
  attempt_series_id uuid NOT NULL,
  attempt smallint NOT NULL CHECK (attempt BETWEEN 1 AND 3),
  workspace_jsonb jsonb NOT NULL CHECK (jsonb_typeof(workspace_jsonb) = 'object'),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, attempt_series_id, attempt),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, module_task_id) REFERENCES module_tasks(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, attempt_series_id) REFERENCES attempt_series(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX repository_workspaces_task_lookup_idx
  ON repository_workspaces (tenant_id, module_task_id, attempt);

CREATE TRIGGER project_repositories_immutable
BEFORE UPDATE OR DELETE ON project_repositories
FOR EACH ROW EXECUTE FUNCTION aor_reject_immutable_mutation();

CREATE TRIGGER repository_workspaces_immutable
BEFORE UPDATE OR DELETE ON repository_workspaces
FOR EACH ROW EXECUTE FUNCTION aor_reject_immutable_mutation();

ALTER TABLE project_repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_repositories FORCE ROW LEVEL SECURITY;
ALTER TABLE repository_workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE repository_workspaces FORCE ROW LEVEL SECURITY;

CREATE POLICY project_repositories_tenant_policy ON project_repositories
  USING (tenant_id = aor_current_tenant())
  WITH CHECK (tenant_id = aor_current_tenant());

CREATE POLICY repository_workspaces_tenant_policy ON repository_workspaces
  USING (tenant_id = aor_current_tenant())
  WITH CHECK (tenant_id = aor_current_tenant());

GRANT SELECT, INSERT ON TABLE public.project_repositories TO aor_app;
GRANT SELECT, INSERT ON TABLE public.repository_workspaces TO aor_app;

COMMIT;
