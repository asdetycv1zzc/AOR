BEGIN;

ALTER TABLE integration_tasks
  ADD CONSTRAINT integration_tasks_lifecycle CHECK (
    (state = 'REWORK_REQUIRED'
      AND owner_module_task_id IS NOT NULL
      AND attempt_count BETWEEN 0 AND 2
      AND merge_request_sha256 IS NULL
      AND merge_audit_sha256 IS NULL
      AND merge_result_jsonb IS NULL
      AND merge_commit IS NULL
      AND merge_pending IS NULL)
    OR
    (state = 'EXECUTING'
      AND owner_module_task_id IS NOT NULL
      AND attempt_count BETWEEN 1 AND 3
      AND merge_request_sha256 IS NULL
      AND merge_audit_sha256 IS NULL
      AND merge_result_jsonb IS NULL
      AND merge_commit IS NULL
      AND merge_pending IS NULL)
    OR
    (state = 'BLOCKED_USER_DECISION'
      AND owner_module_task_id IS NOT NULL
      AND attempt_count = 3
      AND merge_request_sha256 IS NULL
      AND merge_audit_sha256 IS NULL
      AND merge_result_jsonb IS NULL
      AND merge_commit IS NULL
      AND merge_pending IS NULL)
    OR
    (state = 'MERGE_RESERVED'
      AND ((attempt_count = 0 AND owner_module_task_id IS NULL)
        OR (attempt_count BETWEEN 1 AND 3 AND owner_module_task_id IS NOT NULL))
      AND merge_request_sha256 IS NOT NULL
      AND merge_audit_sha256 IS NOT NULL
      AND merge_result_jsonb IS NOT NULL
      AND merge_commit IS NULL
      AND merge_pending = true)
    OR
    (state = 'DONE'
      AND ((attempt_count = 0 AND owner_module_task_id IS NULL)
        OR (attempt_count BETWEEN 1 AND 3 AND owner_module_task_id IS NOT NULL))
      AND merge_request_sha256 IS NOT NULL
      AND merge_audit_sha256 IS NOT NULL
      AND merge_result_jsonb IS NOT NULL
      AND merge_commit IS NOT NULL
      AND merge_pending = false)
  ) NOT VALID;

CREATE INDEX integration_tasks_recovery_idx
  ON integration_tasks (tenant_id, project_id, state, attempt_count, updated_at, id)
  WHERE state IN ('REWORK_REQUIRED', 'EXECUTING', 'MERGE_RESERVED', 'BLOCKED_USER_DECISION');

COMMIT;
