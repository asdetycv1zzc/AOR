BEGIN;

CREATE INDEX artifacts_retention_expiry_idx
  ON artifacts (retention_until, tenant_id, project_id, id)
  WHERE retention_until IS NOT NULL;

CREATE OR REPLACE FUNCTION aor_expired_artifact_tenants(
  requested_at timestamptz,
  requested_limit integer
) RETURNS TABLE (tenant_id uuid)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
  SELECT artifacts.tenant_id
  FROM public.artifacts AS artifacts
  JOIN public.projects AS projects
    ON projects.tenant_id = artifacts.tenant_id
   AND projects.id = artifacts.project_id
  JOIN public.aggregate_projections AS projection
    ON projection.tenant_id = projects.tenant_id
   AND projection.project_id = projects.id
   AND projection.aggregate_type = 'project'
   AND projection.aggregate_id = projects.id::text
  WHERE artifacts.retention_until IS NOT NULL
    AND artifacts.retention_until <= requested_at
    AND projects.state IN ('COMPLETED', 'ABORTED', 'ARCHIVED')
    AND projects.deletion_status IS NULL
    AND NOT EXISTS (
      SELECT 1
      FROM jsonb_array_elements(
        CASE
          WHEN jsonb_typeof(projection.state_jsonb -> 'legalHolds') = 'array'
            THEN projection.state_jsonb -> 'legalHolds'
          ELSE '[]'::jsonb
        END
      ) AS legal_hold
      WHERE COALESCE(legal_hold ->> 'releasedAt', '') = ''
    )
    AND requested_limit BETWEEN 1 AND 1000
  GROUP BY artifacts.tenant_id
  ORDER BY min(artifacts.retention_until), artifacts.tenant_id
  LIMIT CASE WHEN requested_limit BETWEEN 1 AND 1000 THEN requested_limit ELSE 0 END
$$;

REVOKE ALL PRIVILEGES ON FUNCTION aor_expired_artifact_tenants(timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aor_expired_artifact_tenants(timestamptz, integer) TO aor_app;

COMMIT;
