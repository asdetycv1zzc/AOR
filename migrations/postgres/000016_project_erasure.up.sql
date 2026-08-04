BEGIN;

ALTER TABLE projects
  ADD COLUMN deletion_status text
    CHECK (deletion_status IN ('BLOCKED_LEGAL_HOLD', 'READY', 'ERASING', 'COMPLETED')),
  ADD COLUMN deletion_id text
    CHECK (deletion_id IS NULL OR (deletion_id <> '' AND length(deletion_id) <= 256)),
  ADD CONSTRAINT projects_deletion_identity_check
    CHECK ((deletion_status IS NULL) = (deletion_id IS NULL));

CREATE TABLE project_erasure_jobs (
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  deletion_id text NOT NULL CHECK (deletion_id <> '' AND length(deletion_id) <= 256),
  status text NOT NULL CHECK (status IN ('PREPARED', 'COMPLETE')),
  prepared_at timestamptz NOT NULL,
  completed_at timestamptz,
  records_deleted bigint NOT NULL DEFAULT 0 CHECK (records_deleted >= 0),
  objects_deleted bigint NOT NULL DEFAULT 0 CHECK (objects_deleted >= 0),
  cache_entries_deleted bigint NOT NULL DEFAULT 0 CHECK (cache_entries_deleted >= 0),
  PRIMARY KEY (tenant_id, project_id),
  UNIQUE (tenant_id, project_id, deletion_id),
  UNIQUE (tenant_id, deletion_id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  CHECK ((status = 'COMPLETE') = (completed_at IS NOT NULL)),
  CHECK (completed_at IS NULL OR completed_at >= prepared_at)
);

CREATE TABLE project_erasure_items (
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  deletion_id text NOT NULL,
  artifact_id uuid NOT NULL,
  object_name text NOT NULL CHECK (object_name <> '' AND length(object_name) <= 1024),
  legacy_object_name text CHECK (legacy_object_name IS NULL OR (legacy_object_name <> '' AND length(legacy_object_name) <= 1024)),
  removed_at timestamptz,
  PRIMARY KEY (tenant_id, project_id, deletion_id, artifact_id),
  FOREIGN KEY (tenant_id, project_id, deletion_id)
    REFERENCES project_erasure_jobs(tenant_id, project_id, deletion_id) ON DELETE RESTRICT,
  CHECK (removed_at IS NULL OR removed_at > '2000-01-01'::timestamptz)
);

CREATE INDEX project_erasure_items_pending_idx
  ON project_erasure_items (tenant_id, project_id, deletion_id)
  WHERE removed_at IS NULL;

CREATE TABLE project_key_revocations (
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  deletion_id text NOT NULL,
  revoked_at timestamptz NOT NULL,
  reason text NOT NULL CHECK (reason <> '' AND length(reason) <= 256),
  PRIMARY KEY (tenant_id, project_id, deletion_id),
  FOREIGN KEY (tenant_id, project_id, deletion_id)
    REFERENCES project_erasure_jobs(tenant_id, project_id, deletion_id) ON DELETE RESTRICT
);

ALTER TABLE project_erasure_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_erasure_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_key_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_erasure_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE project_erasure_items FORCE ROW LEVEL SECURITY;
ALTER TABLE project_key_revocations FORCE ROW LEVEL SECURITY;

CREATE POLICY project_erasure_jobs_tenant_policy ON project_erasure_jobs
  USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY project_erasure_items_tenant_policy ON project_erasure_items
  USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY project_key_revocations_tenant_policy ON project_key_revocations
  USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());

GRANT SELECT, INSERT, UPDATE ON TABLE public.project_erasure_jobs TO aor_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.project_erasure_items TO aor_app;
GRANT SELECT, INSERT ON TABLE public.project_key_revocations TO aor_app;
GRANT DELETE ON TABLE public.model_call_replays, public.model_calls, public.tool_invocations,
  public.agent_leases, public.agent_instances, public.budget_reservations, public.budget_accounts,
  public.artifacts, public.aggregate_projections TO aor_app;

COMMIT;
