BEGIN;

-- Goal and planning agents execute before a module task exists. Their model
-- calls remain project-scoped and auditable; module execution calls continue
-- to carry the task foreign key.
ALTER TABLE model_calls ALTER COLUMN task_id DROP NOT NULL;

COMMIT;
