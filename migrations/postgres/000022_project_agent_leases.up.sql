BEGIN;

ALTER TABLE agent_leases
  ALTER COLUMN task_id DROP NOT NULL,
  ALTER COLUMN spec_sha256 DROP NOT NULL;

ALTER TABLE agent_leases
  ADD CONSTRAINT agent_leases_task_scope_check CHECK (
    (task_id IS NULL
      AND task_version = 0
      AND spec_sha256 IS NULL
      AND role IN ('GOAL_PROPOSER', 'GOAL_CHALLENGER', 'PLAN_SUPERVISOR')
      AND action = 'model.generate')
    OR
    (task_id IS NOT NULL AND spec_sha256 IS NOT NULL)
  );

COMMIT;
