BEGIN;

CREATE OR REPLACE FUNCTION aor_ready_execution_tasks(
  requested_limit integer
) RETURNS TABLE (
  tenant_id uuid,
  project_id uuid,
  task_id uuid,
  state_version bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
  WITH global_capacity AS (
    SELECT greatest(8 - count(DISTINCT lease.agent_instance_id), 0)::bigint AS available
    FROM public.agent_leases AS lease
    WHERE lease.state = 'ACTIVE'
      AND lease.expires_at > CURRENT_TIMESTAMP
      AND lease.last_heartbeat_at
          + lease.heartbeat_interval_seconds * interval '3 seconds' > CURRENT_TIMESTAMP
  ), project_capacity AS (
    SELECT project.tenant_id,
           project.id AS project_id,
           greatest(project.concurrency_limit - count(task.id) FILTER (WHERE task.state = 'EXECUTING'), 0)::bigint AS available
    FROM public.projects AS project
    LEFT JOIN public.module_tasks AS task
      ON task.tenant_id = project.tenant_id AND task.project_id = project.id
    WHERE project.state = 'EXECUTING'
    GROUP BY project.tenant_id, project.id, project.concurrency_limit
  ), candidates AS (
    SELECT task.tenant_id,
           task.project_id,
           task.id AS task_id,
           task.state_version,
           capacity.available AS project_available,
           task.priority::bigint
             + floor(greatest(extract(epoch FROM CURRENT_TIMESTAMP - task.updated_at), 0) / 60)::bigint
               AS effective_priority,
           task.critical_path_score,
           task.updated_at
    FROM public.module_tasks AS task
    JOIN project_capacity AS capacity
      ON capacity.tenant_id = task.tenant_id AND capacity.project_id = task.project_id
    WHERE task.state = 'READY_EXECUTION'
      AND task.attempt_count < 3
      AND task.active_attempt_series_id IS NOT NULL
  ), ranked AS (
    SELECT candidate.*,
           row_number() OVER (
             PARTITION BY candidate.tenant_id, candidate.project_id
             ORDER BY candidate.effective_priority DESC, candidate.critical_path_score DESC,
                      candidate.updated_at, candidate.task_id
           ) AS project_rank
    FROM candidates AS candidate
  ), eligible AS (
    SELECT ready.*,
           row_number() OVER (
             ORDER BY ready.project_rank, ready.effective_priority DESC, ready.critical_path_score DESC,
                      ready.updated_at, ready.tenant_id, ready.project_id, ready.task_id
           ) AS global_rank
    FROM ranked AS ready
    WHERE ready.project_rank <= ready.project_available
  )
  SELECT ready.tenant_id, ready.project_id, ready.task_id, ready.state_version
  FROM eligible AS ready
  CROSS JOIN global_capacity
  WHERE requested_limit BETWEEN 1 AND 64
    AND ready.global_rank <= least(requested_limit::bigint, global_capacity.available)
  ORDER BY ready.project_rank, ready.effective_priority DESC, ready.critical_path_score DESC,
           ready.updated_at, ready.tenant_id, ready.project_id, ready.task_id
$$;

REVOKE ALL PRIVILEGES ON FUNCTION aor_ready_execution_tasks(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aor_ready_execution_tasks(integer) TO aor_app;

COMMIT;
