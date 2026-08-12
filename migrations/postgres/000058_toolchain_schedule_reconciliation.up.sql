BEGIN;

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
            AND tool -> 'install' ->> 'method' = 'USER_ARCHIVE'
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
