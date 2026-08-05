BEGIN;

-- A side-effect lease at the current task generation is valid.  The original
-- function only reported a successful strictly-greater update, which rejected
-- operation leases whose fencing token equaled the task projection.
CREATE OR REPLACE FUNCTION aor_advance_task_fencing(
  requested_tenant uuid,
  requested_project uuid,
  requested_task uuid,
  requested_token bigint
) RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  UPDATE public.module_tasks
  SET latest_fencing_token = requested_token,
      updated_at = transaction_timestamp()
  WHERE tenant_id = requested_tenant
    AND tenant_id = public.aor_current_tenant()
    AND project_id = requested_project
    AND id = requested_task
    AND requested_token >= 1
    AND latest_fencing_token <= requested_token
  RETURNING true
$$;

REVOKE ALL PRIVILEGES ON FUNCTION aor_advance_task_fencing(uuid, uuid, uuid, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aor_advance_task_fencing(uuid, uuid, uuid, bigint) TO aor_app;

COMMIT;
