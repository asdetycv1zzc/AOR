BEGIN;

ALTER TABLE agent_leases
  ALTER COLUMN agent_instance_id DROP NOT NULL;

ALTER TABLE agent_leases
  ADD CONSTRAINT agent_leases_principal_reference_check CHECK (
    principal_type = 'SERVICE' OR agent_instance_id IS NOT NULL
  );

ALTER TABLE agent_leases
  DROP CONSTRAINT agent_leases_task_scope_check;

ALTER TABLE agent_leases
  ADD CONSTRAINT agent_leases_task_scope_check CHECK (
    (task_id IS NULL
      AND task_version = 0
      AND spec_sha256 IS NULL
      AND (
        (action = 'model.generate' AND role IN (
          'GOAL_PROPOSER', 'GOAL_CHALLENGER', 'PLAN_SUPERVISOR',
          'GLOBAL_AUDITOR', 'KNOWLEDGE_CURATOR', 'SERVICE'
        ))
        OR (action = 'tool.invoke' AND role = 'GLOBAL_AUDITOR')
        OR (action = 'knowledge.write' AND role = 'KNOWLEDGE_CURATOR')
        OR (action IN ('artifact.publish', 'integration.merge') AND role = 'SERVICE')
      ))
    OR
    (task_id IS NOT NULL AND spec_sha256 IS NOT NULL)
  );

GRANT SELECT ON TABLE public.approvals TO aor_app;

COMMIT;
