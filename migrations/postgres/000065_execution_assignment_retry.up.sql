BEGIN;

ALTER TABLE public.execution_assignments
  ADD COLUMN IF NOT EXISTS last_retry_dispatched_at timestamptz;

-- Older schedulers must never create a new generation while the current
-- assignment is waiting for its original workflow to bind a runtime lease.
CREATE OR REPLACE FUNCTION aor_ready_execution_tasks_v2(
  requested_limit integer
) RETURNS TABLE (
  tenant_id uuid,
  project_id uuid,
  task_id uuid,
  state_version bigint,
  task_state text,
  fencing_token bigint,
  recovery boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
  WITH healthy_execution AS (
    SELECT DISTINCT ea.tenant_id, ea.project_id, ea.module_task_id,
           ea.fencing_token, lease.agent_instance_id
    FROM public.execution_assignments AS ea
    JOIN public.agent_leases AS lease
      ON lease.tenant_id = ea.tenant_id AND lease.id = ea.lease_id
    WHERE lease.state = 'ACTIVE'
      AND lease.expires_at > CURRENT_TIMESTAMP
      AND lease.last_heartbeat_at
          + lease.heartbeat_interval_seconds * interval '3 seconds' > CURRENT_TIMESTAMP
  ), global_capacity AS (
    SELECT greatest(8 - count(DISTINCT lease.agent_instance_id), 0)::bigint AS available
    FROM public.agent_leases AS lease
    WHERE lease.state = 'ACTIVE'
      AND lease.expires_at > CURRENT_TIMESTAMP
      AND lease.last_heartbeat_at
          + lease.heartbeat_interval_seconds * interval '3 seconds' > CURRENT_TIMESTAMP
  ), project_capacity AS (
    SELECT project.tenant_id,
           project.id AS project_id,
           greatest(project.concurrency_limit - count(DISTINCT task.id) FILTER (
             WHERE task.state = 'EXECUTING'
               AND healthy.module_task_id IS NOT NULL
               AND healthy.fencing_token = task.latest_fencing_token
           ), 0)::bigint AS available
    FROM public.projects AS project
    LEFT JOIN public.module_tasks AS task
      ON task.tenant_id = project.tenant_id AND task.project_id = project.id
    LEFT JOIN healthy_execution AS healthy
      ON healthy.tenant_id = task.tenant_id AND healthy.project_id = task.project_id
     AND healthy.module_task_id = task.id
     AND healthy.fencing_token = task.latest_fencing_token
    WHERE project.state = 'EXECUTING'
    GROUP BY project.tenant_id, project.id, project.concurrency_limit
  ), candidates AS (
    SELECT task.tenant_id,
           task.project_id,
           task.id AS task_id,
           task.state_version,
           task.state AS task_state,
           task.latest_fencing_token AS fencing_token,
           (task.state = 'EXECUTING') AS recovery,
           capacity.available AS project_available,
           task.priority::bigint
             + floor(greatest(extract(epoch FROM CURRENT_TIMESTAMP - task.updated_at), 0) / 60)::bigint
               AS effective_priority,
           task.critical_path_score,
           task.updated_at
    FROM public.module_tasks AS task
    JOIN project_capacity AS capacity
      ON capacity.tenant_id = task.tenant_id AND capacity.project_id = task.project_id
    WHERE task.attempt_count < 3
      AND task.active_attempt_series_id IS NOT NULL
      AND (
        task.state = 'READY_EXECUTION'
        OR (
          task.state = 'EXECUTING'
          AND NOT EXISTS (
            SELECT 1
            FROM healthy_execution AS current_lease
            WHERE current_lease.tenant_id = task.tenant_id
              AND current_lease.project_id = task.project_id
              AND current_lease.module_task_id = task.id
              AND current_lease.fencing_token = task.latest_fencing_token
          )
          AND NOT EXISTS (
            SELECT 1
            FROM public.execution_assignments AS pending
            WHERE pending.tenant_id = task.tenant_id
              AND pending.project_id = task.project_id
              AND pending.module_task_id = task.id
              AND pending.attempt_series_id = task.active_attempt_series_id
              AND pending.fencing_token = task.latest_fencing_token
              AND pending.lease_id IS NULL
          )
        )
      )
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
  SELECT ready.tenant_id, ready.project_id, ready.task_id, ready.state_version,
         ready.task_state, ready.fencing_token, ready.recovery
  FROM eligible AS ready
  CROSS JOIN global_capacity
  WHERE requested_limit BETWEEN 1 AND 64
    AND ready.global_rank <= least(requested_limit::bigint, global_capacity.available)
  ORDER BY ready.project_rank, ready.effective_priority DESC, ready.critical_path_score DESC,
           ready.updated_at, ready.tenant_id, ready.project_id, ready.task_id
$$;

REVOKE ALL PRIVILEGES ON FUNCTION aor_ready_execution_tasks_v2(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aor_ready_execution_tasks_v2(integer) TO aor_app;

-- The v3 scheduler claims retry slots by updating the durable assignment in
-- the same statement that returns its original execution identity.
CREATE OR REPLACE FUNCTION aor_ready_execution_tasks_v3(
  requested_limit integer
) RETURNS TABLE (
  tenant_id uuid,
  project_id uuid,
  task_id uuid,
  state_version bigint,
  task_state text,
  fencing_token bigint,
  recovery boolean,
  reusable_execution_id text
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
  WITH healthy_execution AS (
    SELECT DISTINCT ea.tenant_id, ea.project_id, ea.module_task_id,
           ea.fencing_token, lease.agent_instance_id
    FROM public.execution_assignments AS ea
    JOIN public.agent_leases AS lease
      ON lease.tenant_id = ea.tenant_id AND lease.id = ea.lease_id
    WHERE lease.state = 'ACTIVE'
      AND lease.expires_at > CURRENT_TIMESTAMP
      AND lease.last_heartbeat_at
          + lease.heartbeat_interval_seconds * interval '3 seconds' > CURRENT_TIMESTAMP
  ), global_capacity AS (
    SELECT greatest(8 - count(DISTINCT lease.agent_instance_id), 0)::bigint AS available
    FROM public.agent_leases AS lease
    WHERE lease.state = 'ACTIVE'
      AND lease.expires_at > CURRENT_TIMESTAMP
      AND lease.last_heartbeat_at
          + lease.heartbeat_interval_seconds * interval '3 seconds' > CURRENT_TIMESTAMP
  ), project_capacity AS (
    SELECT project.tenant_id,
           project.id AS project_id,
           greatest(project.concurrency_limit - count(DISTINCT task.id) FILTER (
             WHERE task.state = 'EXECUTING'
               AND healthy.module_task_id IS NOT NULL
               AND healthy.fencing_token = task.latest_fencing_token
           ), 0)::bigint AS available
    FROM public.projects AS project
    LEFT JOIN public.module_tasks AS task
      ON task.tenant_id = project.tenant_id AND task.project_id = project.id
    LEFT JOIN healthy_execution AS healthy
      ON healthy.tenant_id = task.tenant_id AND healthy.project_id = task.project_id
     AND healthy.module_task_id = task.id
     AND healthy.fencing_token = task.latest_fencing_token
    WHERE project.state = 'EXECUTING'
    GROUP BY project.tenant_id, project.id, project.concurrency_limit
  ), candidates AS (
    SELECT task.tenant_id,
           task.project_id,
           task.id AS task_id,
           task.state_version,
           task.state AS task_state,
           task.latest_fencing_token AS fencing_token,
           (task.state = 'EXECUTING') AS recovery,
           CASE
             WHEN task.state = 'EXECUTING' AND current_assignment.lease_id IS NULL
               THEN current_assignment.id
             ELSE NULL
           END AS reusable_assignment_id,
           capacity.available AS project_available,
           task.priority::bigint
             + floor(greatest(extract(epoch FROM CURRENT_TIMESTAMP - task.updated_at), 0) / 60)::bigint
               AS effective_priority,
           task.critical_path_score,
           task.updated_at
    FROM public.module_tasks AS task
    JOIN project_capacity AS capacity
      ON capacity.tenant_id = task.tenant_id AND capacity.project_id = task.project_id
    LEFT JOIN public.execution_assignments AS current_assignment
      ON current_assignment.tenant_id = task.tenant_id
     AND current_assignment.project_id = task.project_id
     AND current_assignment.module_task_id = task.id
     AND current_assignment.attempt_series_id = task.active_attempt_series_id
     AND current_assignment.fencing_token = task.latest_fencing_token
    WHERE task.attempt_count < 3
      AND task.active_attempt_series_id IS NOT NULL
      AND (
        task.state = 'READY_EXECUTION'
        OR (
          task.state = 'EXECUTING'
          AND NOT EXISTS (
            SELECT 1
            FROM healthy_execution AS current_lease
            WHERE current_lease.tenant_id = task.tenant_id
              AND current_lease.project_id = task.project_id
              AND current_lease.module_task_id = task.id
              AND current_lease.fencing_token = task.latest_fencing_token
          )
          AND (
            current_assignment.id IS NULL
            OR current_assignment.lease_id IS NOT NULL
            OR COALESCE(current_assignment.last_retry_dispatched_at, current_assignment.created_at)
                 <= CURRENT_TIMESTAMP - interval '5 minutes'
          )
        )
      )
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
  ), selected AS MATERIALIZED (
    SELECT ready.*
    FROM eligible AS ready
    CROSS JOIN global_capacity
    WHERE requested_limit BETWEEN 1 AND 64
      AND ready.global_rank <= least(requested_limit::bigint, global_capacity.available)
    ORDER BY ready.project_rank, ready.effective_priority DESC, ready.critical_path_score DESC,
             ready.updated_at, ready.tenant_id, ready.project_id, ready.task_id
  ), retry_claims AS (
    UPDATE public.execution_assignments AS assignment
    SET last_retry_dispatched_at = transaction_timestamp()
    FROM selected
    WHERE assignment.id = selected.reusable_assignment_id
      AND assignment.lease_id IS NULL
      AND COALESCE(assignment.last_retry_dispatched_at, assignment.created_at)
            <= CURRENT_TIMESTAMP - interval '5 minutes'
    RETURNING assignment.id, assignment.execution_id
  )
  SELECT selected.tenant_id, selected.project_id, selected.task_id, selected.state_version,
         selected.task_state, selected.fencing_token, selected.recovery,
         retry_claims.execution_id AS reusable_execution_id
  FROM selected
  LEFT JOIN retry_claims ON retry_claims.id = selected.reusable_assignment_id
  WHERE selected.reusable_assignment_id IS NULL OR retry_claims.id IS NOT NULL
  ORDER BY selected.project_rank, selected.effective_priority DESC, selected.critical_path_score DESC,
           selected.updated_at, selected.tenant_id, selected.project_id, selected.task_id
$$;

REVOKE ALL PRIVILEGES ON FUNCTION aor_ready_execution_tasks_v3(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aor_ready_execution_tasks_v3(integer) TO aor_app;

COMMIT;
