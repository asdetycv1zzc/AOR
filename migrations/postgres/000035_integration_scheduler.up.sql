BEGIN;

CREATE TABLE integration_requests (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  project_version bigint NOT NULL CHECK (project_version > 0),
  integration_id uuid PRIMARY KEY,
  workflow_id text NOT NULL CHECK (workflow_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  UNIQUE (tenant_id, project_id, project_version),
  UNIQUE (tenant_id, project_id, integration_id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX integration_requests_project_idx
  ON integration_requests (tenant_id, project_id, project_version);

ALTER TABLE integration_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_requests FORCE ROW LEVEL SECURITY;

CREATE POLICY integration_requests_tenant_policy ON integration_requests
  USING (tenant_id = aor_current_tenant())
  WITH CHECK (tenant_id = aor_current_tenant());

GRANT SELECT, INSERT, UPDATE ON TABLE public.integration_requests TO aor_app;

CREATE FUNCTION aor_integration_candidates(
  requested_limit integer
) RETURNS TABLE (
  tenant_id uuid,
  project_id uuid,
  project_version bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
  SELECT project.tenant_id, project.id, project.state_version
  FROM public.projects AS project
  WHERE requested_limit BETWEEN 1 AND 64
    AND project.state = 'INTEGRATING'
    AND EXISTS (
      SELECT 1
      FROM public.module_tasks AS task
      WHERE task.tenant_id = project.tenant_id
        AND task.project_id = project.id
        AND task.state = 'PASSED'
    )
    AND NOT EXISTS (
      SELECT 1
      FROM public.module_tasks AS task
      WHERE task.tenant_id = project.tenant_id
        AND task.project_id = project.id
        AND task.state NOT IN ('PASSED', 'INTEGRATED', 'CANCELED', 'SUPERSEDED')
    )
    AND NOT EXISTS (
      SELECT 1
      FROM public.integration_requests AS request
      JOIN public.integration_tasks AS task
        ON task.tenant_id = request.tenant_id
       AND task.project_id = request.project_id
       AND task.id = request.integration_id
      WHERE request.tenant_id = project.tenant_id
        AND request.project_id = project.id
        AND request.project_version = project.state_version
        AND task.state = 'DONE'
    )
  ORDER BY project.updated_at, project.tenant_id, project.id
  LIMIT requested_limit;
$$;

CREATE FUNCTION aor_ensure_integration_request(
  requested_tenant uuid,
  requested_project uuid,
  requested_version bigint,
  requested_integration uuid,
  requested_workflow text
) RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
DECLARE
  durable_integration uuid;
BEGIN
  INSERT INTO public.integration_requests
    (tenant_id, project_id, project_version, integration_id, workflow_id)
  VALUES
    (requested_tenant, requested_project, requested_version, requested_integration, requested_workflow)
  ON CONFLICT (tenant_id, project_id, project_version) DO NOTHING;

  SELECT request.integration_id
    INTO durable_integration
  FROM public.integration_requests AS request
  WHERE request.tenant_id = requested_tenant
    AND request.project_id = requested_project
    AND request.project_version = requested_version;
  RETURN durable_integration;
END;
$$;

REVOKE ALL PRIVILEGES ON FUNCTION aor_integration_candidates(integer) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION aor_ensure_integration_request(uuid, uuid, bigint, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aor_integration_candidates(integer) TO aor_app;
GRANT EXECUTE ON FUNCTION aor_ensure_integration_request(uuid, uuid, bigint, uuid, text) TO aor_app;

COMMIT;
