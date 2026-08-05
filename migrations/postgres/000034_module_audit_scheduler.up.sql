BEGIN;

CREATE TABLE module_audit_requests (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  module_task_id uuid NOT NULL,
  task_version bigint NOT NULL CHECK (task_version > 0),
  attempt_series_id uuid NOT NULL,
  attempt smallint NOT NULL CHECK (attempt BETWEEN 1 AND 3),
  audit_run_id uuid PRIMARY KEY,
  workflow_id text NOT NULL CHECK (workflow_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  UNIQUE (tenant_id, module_task_id, task_version, attempt_series_id, attempt),
  UNIQUE (tenant_id, module_task_id, audit_run_id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, module_task_id) REFERENCES module_tasks(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, attempt_series_id) REFERENCES attempt_series(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX module_audit_requests_task_idx
  ON module_audit_requests (tenant_id, module_task_id, task_version, attempt_series_id, attempt);

ALTER TABLE module_audit_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE module_audit_requests FORCE ROW LEVEL SECURITY;

CREATE POLICY module_audit_requests_tenant_policy ON module_audit_requests
  USING (tenant_id = aor_current_tenant())
  WITH CHECK (tenant_id = aor_current_tenant());

GRANT SELECT, INSERT, UPDATE ON TABLE public.module_audit_requests TO aor_app;

CREATE FUNCTION aor_module_audit_candidates(
  requested_limit integer
) RETURNS TABLE (
  tenant_id uuid,
  project_id uuid,
  task_id uuid,
  task_version bigint,
  attempt_series_id uuid,
  attempt smallint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
  SELECT task.tenant_id,
         task.project_id,
         task.id,
         task.state_version,
         task.active_attempt_series_id,
         task.attempt_count
  FROM public.module_tasks AS task
  JOIN public.projects AS project
    ON project.tenant_id = task.tenant_id
   AND project.id = task.project_id
  JOIN public.submissions AS submission
    ON submission.tenant_id = task.tenant_id
   AND submission.project_id = task.project_id
   AND submission.module_task_id = task.id
   AND submission.attempt_series_id = task.active_attempt_series_id
   AND submission.attempt = task.attempt_count
  WHERE requested_limit BETWEEN 1 AND 64
    AND project.state = 'EXECUTING'
    AND task.state = 'SUBMITTED'
    AND task.active_attempt_series_id IS NOT NULL
    AND task.attempt_count BETWEEN 1 AND 3
    AND NOT EXISTS (
      SELECT 1
      FROM public.module_audit_coordinations AS coordination
      WHERE coordination.tenant_id = task.tenant_id
        AND coordination.module_task_id = task.id
        AND coordination.attempt_series_id = task.active_attempt_series_id
        AND coordination.attempt = task.attempt_count
    )
    AND NOT EXISTS (
      SELECT 1
      FROM public.audit_runs AS audit
      WHERE audit.tenant_id = submission.tenant_id
        AND audit.submission_id = submission.id
        AND audit.phase IN ('DETERMINISTIC', 'LLM')
        AND audit.state = 'COMPLETED'
    )
  ORDER BY task.updated_at, task.tenant_id, task.project_id, task.id
  LIMIT requested_limit;
$$;

CREATE FUNCTION aor_ensure_module_audit_request(
  requested_tenant uuid,
  requested_project uuid,
  requested_task uuid,
  requested_task_version bigint,
  requested_attempt_series uuid,
  requested_attempt smallint,
  requested_run uuid,
  requested_workflow text
) RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
DECLARE
  durable_run uuid;
BEGIN
  INSERT INTO public.module_audit_requests
    (tenant_id, project_id, module_task_id, task_version, attempt_series_id,
     attempt, audit_run_id, workflow_id)
  VALUES
    (requested_tenant, requested_project, requested_task, requested_task_version,
     requested_attempt_series, requested_attempt, requested_run, requested_workflow)
  ON CONFLICT (tenant_id, module_task_id, task_version, attempt_series_id, attempt)
  DO NOTHING;

  SELECT request.audit_run_id
    INTO durable_run
  FROM public.module_audit_requests AS request
  WHERE request.tenant_id = requested_tenant
    AND request.module_task_id = requested_task
    AND request.task_version = requested_task_version
    AND request.attempt_series_id = requested_attempt_series
    AND request.attempt = requested_attempt;
  RETURN durable_run;
END;
$$;

REVOKE ALL PRIVILEGES ON FUNCTION aor_module_audit_candidates(integer) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION aor_ensure_module_audit_request(uuid, uuid, uuid, bigint, uuid, smallint, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aor_module_audit_candidates(integer) TO aor_app;
GRANT EXECUTE ON FUNCTION aor_ensure_module_audit_request(uuid, uuid, uuid, bigint, uuid, smallint, uuid, text) TO aor_app;

COMMIT;
