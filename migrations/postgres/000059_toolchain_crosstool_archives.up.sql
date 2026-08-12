BEGIN;

DO $$
DECLARE
  constraint_row record;
BEGIN
  FOR constraint_row IN
    SELECT conname
    FROM pg_constraint
    WHERE conrelid = 'public.toolchain_installations'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%tool_jsonb%'
  LOOP
    EXECUTE format('ALTER TABLE public.toolchain_installations DROP CONSTRAINT %I', constraint_row.conname);
  END LOOP;
END;
$$;

ALTER TABLE toolchain_installations
  ADD CONSTRAINT toolchain_installations_tool_jsonb_object_check CHECK (
    jsonb_typeof(tool_jsonb) = 'object'
  ),
  ADD CONSTRAINT toolchain_installations_tool_source_check CHECK (
    tool_jsonb ->> 'source' = 'INSTALL_REQUIRED'
  ),
  ADD CONSTRAINT toolchain_installations_toolchain_source_check CHECK (
    tool_jsonb #>> '{install,authorized}' = 'true'
    AND tool_jsonb #>> '{install,evidenceRef}' ~ '^artifact://sha256/[0-9a-f]{64}$'
    AND (
      (
        tool_jsonb #>> '{install,method}' = 'USER_ARCHIVE'
        AND tool_jsonb #>> '{install,downloadUrl}' ~ '^https://[^[:space:]]+$'
        AND (
          tool_jsonb #>> '{install,sourceSha256}' ~ '^sha256:[0-9a-f]{64}$'
          OR state IN ('INSTALLED', 'FAILED')
             AND COALESCE(tool_jsonb #>> '{install,sourceSha256}', '') = ''
        )
        AND COALESCE(tool_jsonb #>> '{install,artifactId}', '') = ''
        AND COALESCE(tool_jsonb #>> '{install,artifactRef}', '') = ''
      ) OR (
        tool_jsonb #>> '{install,method}' = 'CROSSTOOL_NG_ARCHIVE'
        AND tool_jsonb #>> '{install,artifactId}' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND tool_jsonb #>> '{install,artifactRef}' ~ '^artifact://sha256/[0-9a-f]{64}$'
        AND tool_jsonb #>> '{install,sourceSha256}' ~ '^sha256:[0-9a-f]{64}$'
        AND tool_jsonb #>> '{install,artifactRef}' = 'artifact://sha256/' || substring(tool_jsonb #>> '{install,sourceSha256}' from 8)
        AND COALESCE(tool_jsonb #>> '{install,downloadUrl}', '') = ''
      )
    )
  );

CREATE OR REPLACE FUNCTION aor_toolchain_schedule_reconciliation_tenants(
  requested_limit integer
) RETURNS TABLE (tenant_id uuid)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
  SELECT project.tenant_id
  FROM public.aggregate_projections AS project
  WHERE requested_limit BETWEEN 1 AND 1000
    AND project.aggregate_type = 'project'
    AND project.aggregate_id = project.project_id::text
    AND project.state_jsonb ->> 'state' IN ('GOAL_NEGOTIATING', 'GOAL_SUSPENDED')
    AND COALESCE(project.state_jsonb -> 'goal' ->> 'approvedBy', '') = ''
    AND EXISTS (
      SELECT 1
      FROM public.aggregate_projections AS goal
      WHERE goal.tenant_id = project.tenant_id
        AND goal.project_id = project.project_id
        AND goal.aggregate_type = 'goal_spec'
        AND goal.state_jsonb ->> 'goalSpecId' = project.state_jsonb -> 'goal' ->> 'id'
        AND (goal.state_jsonb -> 'spec' -> 'content' ->> 'version')::integer =
            (project.state_jsonb -> 'goal' ->> 'version')::integer
        AND goal.state_jsonb -> 'spec' ->> 'status' = 'DRAFT'
        AND EXISTS (
          SELECT 1
          FROM jsonb_array_elements(
            COALESCE(goal.state_jsonb -> 'spec' -> 'content' -> 'toolchain' -> 'tools', '[]'::jsonb)
          ) AS tool
          WHERE tool ->> 'source' = 'INSTALL_REQUIRED'
            AND tool -> 'install' ->> 'method' IN ('USER_ARCHIVE', 'CROSSTOOL_NG_ARCHIVE')
            AND tool -> 'install' ->> 'authorized' = 'true'
        )
        AND NOT EXISTS (
          SELECT 1
          FROM public.toolchain_installation_batches AS batch
          WHERE batch.tenant_id = project.tenant_id
            AND batch.project_id = project.project_id
            AND batch.goal_spec_id::text = project.state_jsonb -> 'goal' ->> 'id'
            AND batch.goal_version = (project.state_jsonb -> 'goal' ->> 'version')::integer
        )
    )
  GROUP BY project.tenant_id
  ORDER BY project.tenant_id
  LIMIT requested_limit;
$$;

REVOKE ALL PRIVILEGES ON FUNCTION aor_toolchain_schedule_reconciliation_tenants(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aor_toolchain_schedule_reconciliation_tenants(integer) TO aor_app;

COMMIT;
