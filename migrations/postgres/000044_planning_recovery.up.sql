BEGIN;

CREATE TABLE planning_recoveries (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  project_version bigint NOT NULL CHECK (project_version > 0),
  principal_id text NOT NULL CHECK (principal_id <> ''),
  principal_type text NOT NULL CHECK (principal_type IN ('USER', 'BREAK_GLASS_ADMIN')),
  principal_role text NOT NULL CHECK (principal_role <> ''),
  goal_spec_id text NOT NULL CHECK (goal_spec_id <> ''),
  goal_version integer NOT NULL CHECK (goal_version > 0),
  goal_sha256 aor_sha256 NOT NULL,
  plan_spec_id text NOT NULL CHECK (plan_spec_id <> ''),
  idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
  attempt bigint NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (tenant_id, project_id, project_version),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT
);

ALTER TABLE planning_recoveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE planning_recoveries FORCE ROW LEVEL SECURITY;

CREATE POLICY planning_recoveries_tenant_policy ON planning_recoveries
  USING (tenant_id = aor_current_tenant())
  WITH CHECK (tenant_id = aor_current_tenant());

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.planning_recoveries TO aor_app;

CREATE FUNCTION aor_schedule_planning_recovery(
  requested_tenant uuid,
  requested_project uuid,
  requested_version bigint,
  requested_principal text,
  requested_principal_type text,
  requested_principal_role text,
  requested_goal_spec text,
  requested_goal_version integer,
  requested_goal_sha256 aor_sha256,
  requested_plan_spec text,
  requested_idempotency_key text
) RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
BEGIN
  INSERT INTO public.planning_recoveries
    (tenant_id, project_id, project_version, principal_id, principal_type,
     principal_role, goal_spec_id,
     goal_version, goal_sha256, plan_spec_id, idempotency_key)
  SELECT requested_tenant, requested_project, requested_version, requested_principal,
         requested_principal_type, requested_principal_role,
         requested_goal_spec, requested_goal_version, requested_goal_sha256,
         requested_plan_spec, requested_idempotency_key
  FROM public.projects AS project
  WHERE project.tenant_id = requested_tenant
    AND project.id = requested_project
    AND project.state_version = requested_version
    AND project.state = 'PLANNING'
    AND project.active_plan_spec_id IS NULL
    AND requested_principal_type IN ('USER', 'BREAK_GLASS_ADMIN')
  ON CONFLICT (tenant_id, project_id, project_version) DO NOTHING;
  RETURN FOUND;
END;
$$;

CREATE FUNCTION aor_claim_planning_recoveries(
  requested_limit integer
) RETURNS TABLE (
  tenant_id uuid,
  project_id uuid,
  project_version bigint,
  principal_id text,
  principal_type text,
  principal_role text,
  goal_spec_id text,
  goal_version integer,
  goal_sha256 aor_sha256,
  plan_spec_id text,
  idempotency_key text,
  attempt bigint
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
  WITH candidates AS (
    SELECT recovery.tenant_id, recovery.project_id, recovery.project_version
    FROM public.planning_recoveries AS recovery
    JOIN public.projects AS project
      ON project.tenant_id = recovery.tenant_id
     AND project.id = recovery.project_id
     AND project.state_version = recovery.project_version
     AND project.state = 'PLANNING'
     AND project.active_plan_spec_id IS NULL
    WHERE requested_limit BETWEEN 1 AND 8
      AND recovery.available_at <= clock_timestamp()
    ORDER BY recovery.available_at, recovery.tenant_id, recovery.project_id
    FOR UPDATE OF recovery SKIP LOCKED
    LIMIT requested_limit
  )
  UPDATE public.planning_recoveries AS recovery
  SET attempt = recovery.attempt + 1,
      available_at = clock_timestamp() + interval '15 minutes'
  FROM candidates
  WHERE recovery.tenant_id = candidates.tenant_id
    AND recovery.project_id = candidates.project_id
    AND recovery.project_version = candidates.project_version
  RETURNING recovery.tenant_id, recovery.project_id, recovery.project_version,
            recovery.principal_id, recovery.principal_type, recovery.principal_role,
            recovery.goal_spec_id, recovery.goal_version,
            recovery.goal_sha256, recovery.plan_spec_id, recovery.idempotency_key,
            recovery.attempt;
$$;

CREATE FUNCTION aor_finish_planning_recovery(
  requested_tenant uuid,
  requested_project uuid,
  requested_version bigint,
  requested_attempt bigint,
  retry boolean
) RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
BEGIN
  IF retry THEN
    UPDATE public.planning_recoveries
    SET available_at = clock_timestamp() + interval '5 seconds'
    WHERE tenant_id = requested_tenant
      AND project_id = requested_project
      AND project_version = requested_version
      AND attempt = requested_attempt;
  ELSE
    DELETE FROM public.planning_recoveries
    WHERE tenant_id = requested_tenant
      AND project_id = requested_project
      AND project_version = requested_version
      AND attempt = requested_attempt;
  END IF;
  RETURN FOUND;
END;
$$;

REVOKE ALL PRIVILEGES ON FUNCTION aor_schedule_planning_recovery(uuid, uuid, bigint, text, text, text, text, integer, aor_sha256, text, text) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION aor_claim_planning_recoveries(integer) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION aor_finish_planning_recovery(uuid, uuid, bigint, bigint, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aor_schedule_planning_recovery(uuid, uuid, bigint, text, text, text, text, integer, aor_sha256, text, text) TO aor_app;
GRANT EXECUTE ON FUNCTION aor_claim_planning_recoveries(integer) TO aor_app;
GRANT EXECUTE ON FUNCTION aor_finish_planning_recovery(uuid, uuid, bigint, bigint, boolean) TO aor_app;

COMMIT;
