BEGIN;

ALTER TABLE tool_invocations
  ALTER COLUMN task_id DROP NOT NULL,
  ADD CONSTRAINT tool_invocations_project_scoped_read_only CHECK (
    task_id IS NOT NULL OR tool_id IN (
      'artifact.read',
      'knowledge.read_range',
      'knowledge.search',
      'repository.file.read'
    )
  );

COMMIT;
