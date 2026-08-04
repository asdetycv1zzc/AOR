BEGIN;

ALTER TABLE module_tasks
  ADD COLUMN planning_spec_id uuid,
  ADD COLUMN module_id text;

ALTER TABLE module_tasks
  ALTER COLUMN module_spec_id DROP NOT NULL,
  ADD CONSTRAINT module_tasks_planning_spec_fk
    FOREIGN KEY (tenant_id, planning_spec_id) REFERENCES plan_specs(tenant_id, id) ON DELETE RESTRICT NOT VALID,
  ADD CONSTRAINT module_tasks_planning_binding_check CHECK (
    (planning_spec_id IS NULL AND module_id IS NULL AND module_spec_id IS NOT NULL)
    OR
    (
      planning_spec_id IS NOT NULL
      AND module_id IS NOT NULL
      AND module_id <> ''
      AND (
        (state IN ('QUEUED_PLANNING', 'PLANNING') AND module_spec_id IS NULL AND active_attempt_series_id IS NULL AND attempt_count = 0)
        OR
        (state NOT IN ('QUEUED_PLANNING', 'PLANNING') AND module_spec_id IS NOT NULL)
      )
    )
  ) NOT VALID;

ALTER TABLE plan_specs
  ADD COLUMN planning_agent_id text;

INSERT INTO agent_instances
  (id, tenant_id, project_id, role, provider, logical_model, actual_model_version,
   prompt_bundle_version, state, created_at)
SELECT project.id::text || ':PLAN_SUPERVISOR', project.tenant_id, project.id,
       'PLAN_SUPERVISOR', 'UNASSIGNED', 'UNASSIGNED', 'UNASSIGNED',
       proposer.prompt_bundle_version, 'DECLARED', transaction_timestamp()
FROM projects AS project
JOIN agent_instances AS proposer
  ON proposer.tenant_id = project.tenant_id
 AND proposer.project_id = project.id
 AND proposer.id = project.id::text || ':GOAL_PROPOSER'
 AND proposer.role = 'GOAL_PROPOSER'
ON CONFLICT DO NOTHING;

ALTER TABLE plan_specs
  ADD CONSTRAINT plan_specs_planning_agent_fk
    FOREIGN KEY (tenant_id, planning_agent_id) REFERENCES agent_instances(tenant_id, id) ON DELETE RESTRICT NOT VALID;

ALTER TABLE module_specs
  ADD COLUMN created_by_agent_id text,
  ADD CONSTRAINT module_specs_created_by_agent_fk
    FOREIGN KEY (tenant_id, created_by_agent_id) REFERENCES agent_instances(tenant_id, id) ON DELETE RESTRICT NOT VALID;

COMMIT;
