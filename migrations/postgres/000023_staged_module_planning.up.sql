BEGIN;

ALTER TABLE module_tasks
  ADD COLUMN planning_spec_id uuid,
  ADD COLUMN module_id text;

UPDATE module_tasks AS task
SET planning_spec_id = spec.plan_spec_id,
    module_id = spec.module_id
FROM module_specs AS spec
WHERE spec.tenant_id = task.tenant_id
  AND spec.id = task.module_spec_id;

ALTER TABLE module_tasks
  ALTER COLUMN planning_spec_id SET NOT NULL,
  ALTER COLUMN module_id SET NOT NULL,
  ALTER COLUMN module_spec_id DROP NOT NULL,
  ADD CONSTRAINT module_tasks_planning_spec_fk
    FOREIGN KEY (tenant_id, planning_spec_id) REFERENCES plan_specs(tenant_id, id) ON DELETE RESTRICT,
  ADD CONSTRAINT module_tasks_planning_binding_check CHECK (
    module_id <> ''
    AND (
      (state IN ('QUEUED_PLANNING', 'PLANNING') AND module_spec_id IS NULL AND active_attempt_series_id IS NULL AND attempt_count = 0)
      OR
      (state NOT IN ('QUEUED_PLANNING', 'PLANNING') AND module_spec_id IS NOT NULL)
    )
  );

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
  ADD CONSTRAINT plan_specs_created_by_agent_fk
    FOREIGN KEY (tenant_id, created_by_agent_id) REFERENCES agent_instances(tenant_id, id) ON DELETE RESTRICT NOT VALID;

ALTER TABLE module_specs
  ADD COLUMN created_by_agent_id text,
  ADD CONSTRAINT module_specs_created_by_agent_fk
    FOREIGN KEY (tenant_id, created_by_agent_id) REFERENCES agent_instances(tenant_id, id) ON DELETE RESTRICT NOT VALID;

COMMIT;
