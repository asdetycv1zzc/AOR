BEGIN;

CREATE DOMAIN aor_sha256 AS text
  CHECK (VALUE ~ '^sha256:[0-9a-f]{64}$');

CREATE TABLE tenants (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE projects (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  name text NOT NULL,
  state text NOT NULL CHECK (state IN (
    'CREATED', 'GOAL_NEGOTIATING', 'GOAL_SUSPENDED', 'PLANNING', 'EXECUTING',
    'INTEGRATING', 'GLOBAL_AUDIT', 'BLOCKED_USER_DECISION', 'PAUSED',
    'COMPLETED', 'ABORTED', 'FAILED_SYSTEM', 'ARCHIVED'
  )),
  state_version bigint NOT NULL CHECK (state_version >= 0),
  active_goal_spec_id uuid,
  active_plan_spec_id uuid,
  data_classification text NOT NULL CHECK (data_classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
  risk_tolerance text NOT NULL CHECK (risk_tolerance IN ('LOW', 'MEDIUM', 'HIGH')),
  goal_agent_count smallint NOT NULL CHECK (goal_agent_count IN (1, 2)),
  concurrency_limit smallint NOT NULL DEFAULT 8 CHECK (concurrency_limit BETWEEN 1 AND 8),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  archived_at timestamptz,
  UNIQUE (tenant_id, id)
);

CREATE TABLE goal_specs (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  version integer NOT NULL CHECK (version >= 1),
  status text NOT NULL CHECK (status IN ('DRAFT', 'APPROVED', 'SUPERSEDED', 'REJECTED')),
  schema_version integer NOT NULL CHECK (schema_version >= 1),
  content_jsonb jsonb NOT NULL CHECK (jsonb_typeof(content_jsonb) = 'object'),
  content_sha256 aor_sha256 NOT NULL,
  proposer_agent_id text NOT NULL,
  challenger_agent_id text,
  approved_by text,
  approved_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, project_id, version),
  UNIQUE (tenant_id, project_id, content_sha256),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  CHECK ((status = 'APPROVED') = (approved_by IS NOT NULL AND approved_at IS NOT NULL))
);

CREATE TABLE plan_specs (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  goal_spec_id uuid NOT NULL,
  version integer NOT NULL CHECK (version >= 1),
  status text NOT NULL CHECK (status IN ('DRAFT', 'PUBLISHED', 'SUPERSEDED')),
  schema_version integer NOT NULL CHECK (schema_version >= 1),
  content_jsonb jsonb NOT NULL CHECK (jsonb_typeof(content_jsonb) = 'object'),
  content_sha256 aor_sha256 NOT NULL,
  created_by_agent_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, project_id, version),
  UNIQUE (tenant_id, project_id, content_sha256),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, goal_spec_id) REFERENCES goal_specs(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE module_specs (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  plan_spec_id uuid NOT NULL,
  module_id text NOT NULL,
  version integer NOT NULL CHECK (version >= 1),
  risk_level text NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  execution_platform text NOT NULL CHECK (execution_platform IN ('LINUX', 'WINDOWS')),
  isolation_level text NOT NULL CHECK (
    (execution_platform = 'LINUX' AND isolation_level = 'CONTAINER') OR
    (execution_platform = 'WINDOWS' AND isolation_level = 'NONE')
  ),
  schema_version integer NOT NULL CHECK (schema_version >= 1),
  content_jsonb jsonb NOT NULL CHECK (jsonb_typeof(content_jsonb) = 'object'),
  content_sha256 aor_sha256 NOT NULL,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, module_id, version),
  UNIQUE (tenant_id, module_id, content_sha256),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, plan_spec_id) REFERENCES plan_specs(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE module_tasks (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  module_spec_id uuid NOT NULL,
  state text NOT NULL CHECK (state IN (
    'DEFINED', 'QUEUED_PLANNING', 'PLANNING', 'READY_EXECUTION', 'QUEUED_EXECUTION',
    'EXECUTING', 'SUBMITTED', 'DETERMINISTIC_AUDIT', 'LLM_AUDIT', 'REWORK_REQUIRED',
    'BLOCKED_DEPENDENCY', 'BLOCKED_USER_DECISION', 'PASSED', 'INTEGRATED',
    'CANCELED', 'SUPERSEDED'
  )),
  state_version bigint NOT NULL CHECK (state_version >= 0),
  attempt_count smallint NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 3),
  active_attempt_series_id uuid,
  latest_fencing_token bigint NOT NULL DEFAULT 0 CHECK (latest_fencing_token >= 0),
  priority integer NOT NULL DEFAULT 0,
  critical_path_score integer NOT NULL DEFAULT 0,
  blocked_reason text,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, module_spec_id) REFERENCES module_specs(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE task_dependencies (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  task_id uuid NOT NULL,
  depends_on_task_id uuid NOT NULL,
  dependency_type text NOT NULL,
  PRIMARY KEY (tenant_id, task_id, depends_on_task_id),
  CHECK (task_id <> depends_on_task_id),
  FOREIGN KEY (tenant_id, task_id) REFERENCES module_tasks(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, depends_on_task_id) REFERENCES module_tasks(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE approvals (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  approval_type text NOT NULL,
  subject_type text NOT NULL,
  subject_id text NOT NULL,
  subject_version integer NOT NULL CHECK (subject_version >= 1),
  subject_sha256 aor_sha256 NOT NULL,
  principal_id text NOT NULL,
  reason text NOT NULL,
  constraints_jsonb jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(constraints_jsonb) = 'object'),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz,
  revoked_at timestamptz,
  signature text NOT NULL,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  CHECK (expires_at IS NULL OR expires_at > issued_at),
  CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
);

CREATE TABLE attempt_series (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  module_task_id uuid NOT NULL,
  module_spec_id uuid NOT NULL,
  series_number integer NOT NULL CHECK (series_number >= 1),
  authorized_by_approval_id uuid,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  closed_at timestamptz,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, module_task_id, series_number),
  FOREIGN KEY (tenant_id, module_task_id) REFERENCES module_tasks(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, module_spec_id) REFERENCES module_specs(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, authorized_by_approval_id) REFERENCES approvals(tenant_id, id) ON DELETE RESTRICT
);

ALTER TABLE module_tasks
  ADD CONSTRAINT module_tasks_active_attempt_series_fk
  FOREIGN KEY (tenant_id, active_attempt_series_id) REFERENCES attempt_series(tenant_id, id) ON DELETE RESTRICT;

CREATE TABLE integration_tasks (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  state text NOT NULL,
  state_version bigint NOT NULL CHECK (state_version >= 0),
  attempt_count smallint NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 3),
  owner_module_task_id uuid,
  conflict_jsonb jsonb NOT NULL CHECK (jsonb_typeof(conflict_jsonb) = 'object'),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, owner_module_task_id) REFERENCES module_tasks(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE submissions (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  module_task_id uuid NOT NULL,
  attempt_series_id uuid NOT NULL,
  attempt smallint NOT NULL CHECK (attempt BETWEEN 1 AND 3),
  base_commit text NOT NULL CHECK (base_commit ~ '^[0-9a-f]{40}$'),
  head_commit text NOT NULL CHECK (head_commit ~ '^[0-9a-f]{40}$' AND head_commit <> base_commit),
  schema_version integer NOT NULL CHECK (schema_version >= 1),
  manifest_jsonb jsonb NOT NULL CHECK (jsonb_typeof(manifest_jsonb) = 'object'),
  manifest_sha256 aor_sha256 NOT NULL,
  created_by_agent_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, attempt_series_id, attempt),
  UNIQUE (tenant_id, module_task_id, head_commit),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, module_task_id) REFERENCES module_tasks(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, attempt_series_id) REFERENCES attempt_series(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE audit_runs (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  subject_type text NOT NULL CHECK (subject_type IN ('SUBMISSION', 'INTEGRATION_TASK', 'PROJECT')),
  subject_id text NOT NULL,
  submission_id uuid,
  phase text NOT NULL CHECK (phase IN ('DETERMINISTIC', 'LLM', 'INTEGRATION', 'GLOBAL')),
  state text NOT NULL,
  pipeline_version text NOT NULL,
  execution_platform text NOT NULL CHECK (execution_platform IN ('LINUX', 'WINDOWS')),
  isolation_level text NOT NULL CHECK (
    (execution_platform = 'LINUX' AND isolation_level = 'CONTAINER') OR
    (execution_platform = 'WINDOWS' AND isolation_level = 'NONE')
  ),
  sandbox_image_digest aor_sha256,
  auditor_agent_id text,
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  verdict text CHECK (verdict IS NULL OR verdict IN ('PASS', 'FAIL', 'INCONCLUSIVE')),
  evidence_bundle_ref text,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, submission_id) REFERENCES submissions(tenant_id, id) ON DELETE RESTRICT,
  CHECK ((subject_type = 'SUBMISSION') = (submission_id IS NOT NULL))
);

CREATE TABLE audit_findings (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  audit_run_id uuid NOT NULL,
  stable_fingerprint aor_sha256 NOT NULL,
  severity text NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  category text NOT NULL,
  rule_id text NOT NULL,
  file_path text,
  line_start integer CHECK (line_start IS NULL OR line_start >= 1),
  line_end integer CHECK (line_end IS NULL OR line_end >= line_start),
  status text NOT NULL CHECK (status IN ('OPEN', 'FIXED', 'ACCEPTED', 'FALSE_POSITIVE')),
  content_jsonb jsonb NOT NULL CHECK (jsonb_typeof(content_jsonb) = 'object'),
  evidence_refs_jsonb jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(evidence_refs_jsonb) = 'array'),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  UNIQUE (tenant_id, audit_run_id, stable_fingerprint),
  FOREIGN KEY (tenant_id, audit_run_id) REFERENCES audit_runs(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE user_decisions (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  module_task_id uuid NOT NULL,
  attempt_series_id uuid NOT NULL,
  decision text NOT NULL CHECK (decision IN (
    'ABORT_PROJECT', 'ABORT_MODULE', 'REVISE_GOAL', 'REVISE_MODULE_SPEC',
    'HAND_OFF_TO_HUMAN', 'AUTHORIZE_NEW_ATTEMPT_SERIES'
  )),
  report_sha256 aor_sha256 NOT NULL,
  principal_id text NOT NULL,
  approval_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, module_task_id) REFERENCES module_tasks(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, attempt_series_id) REFERENCES attempt_series(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, approval_id) REFERENCES approvals(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE aggregate_projections (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  aggregate_type text NOT NULL,
  aggregate_id text NOT NULL,
  aggregate_version bigint NOT NULL CHECK (aggregate_version >= 1),
  schema_version integer NOT NULL CHECK (schema_version >= 1),
  state_jsonb jsonb NOT NULL CHECK (jsonb_typeof(state_jsonb) = 'object'),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (tenant_id, aggregate_type, aggregate_id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE domain_events (
  event_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  aggregate_type text NOT NULL,
  aggregate_id text NOT NULL,
  aggregate_version bigint NOT NULL CHECK (aggregate_version >= 1),
  event_type text NOT NULL CHECK (event_type ~ '^io[.]aor[.][a-z][a-z0-9-]*[.][a-z][a-z0-9-]*[.]v[1-9][0-9]*$'),
  schema_version integer NOT NULL CHECK (schema_version >= 1),
  payload_jsonb jsonb NOT NULL CHECK (jsonb_typeof(payload_jsonb) = 'object'),
  payload_sha256 aor_sha256 NOT NULL,
  metadata_jsonb jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata_jsonb) = 'object'),
  created_at timestamptz NOT NULL,
  UNIQUE (tenant_id, event_id),
  UNIQUE (tenant_id, aggregate_type, aggregate_id, aggregate_version),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE command_results (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  principal_id text NOT NULL,
  idempotency_key text NOT NULL,
  request_sha256 aor_sha256 NOT NULL,
  result_jsonb jsonb NOT NULL CHECK (jsonb_typeof(result_jsonb) = 'object'),
  result_sha256 aor_sha256 NOT NULL,
  event_ids_jsonb jsonb NOT NULL CHECK (jsonb_typeof(event_ids_jsonb) = 'array'),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (tenant_id, principal_id, idempotency_key)
);

CREATE TABLE outbox (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  event_id uuid NOT NULL UNIQUE,
  payload_jsonb jsonb NOT NULL CHECK (jsonb_typeof(payload_jsonb) = 'object'),
  published_at timestamptz,
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  next_attempt_at timestamptz NOT NULL,
  FOREIGN KEY (tenant_id, event_id) REFERENCES domain_events(tenant_id, event_id) ON DELETE RESTRICT
);

CREATE TABLE inbox (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  consumer_id text NOT NULL,
  message_id text NOT NULL,
  request_sha256 aor_sha256 NOT NULL,
  processed_at timestamptz NOT NULL,
  result_sha256 aor_sha256 NOT NULL,
  PRIMARY KEY (tenant_id, consumer_id, message_id)
);

ALTER TABLE projects
  ADD CONSTRAINT projects_active_goal_spec_fk
  FOREIGN KEY (tenant_id, active_goal_spec_id) REFERENCES goal_specs(tenant_id, id) ON DELETE RESTRICT,
  ADD CONSTRAINT projects_active_plan_spec_fk
  FOREIGN KEY (tenant_id, active_plan_spec_id) REFERENCES plan_specs(tenant_id, id) ON DELETE RESTRICT;

CREATE FUNCTION aor_reject_immutable_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'immutable AOR record cannot be updated or deleted';
END;
$$;

CREATE TRIGGER domain_events_immutable
  BEFORE UPDATE OR DELETE ON domain_events
  FOR EACH ROW EXECUTE FUNCTION aor_reject_immutable_mutation();
CREATE TRIGGER approvals_immutable
  BEFORE UPDATE OR DELETE ON approvals
  FOR EACH ROW EXECUTE FUNCTION aor_reject_immutable_mutation();
CREATE TRIGGER user_decisions_immutable
  BEFORE UPDATE OR DELETE ON user_decisions
  FOR EACH ROW EXECUTE FUNCTION aor_reject_immutable_mutation();
CREATE TRIGGER submissions_immutable
  BEFORE UPDATE OR DELETE ON submissions
  FOR EACH ROW EXECUTE FUNCTION aor_reject_immutable_mutation();
CREATE TRIGGER command_results_immutable
  BEFORE UPDATE OR DELETE ON command_results
  FOR EACH ROW EXECUTE FUNCTION aor_reject_immutable_mutation();

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE goal_specs ENABLE ROW LEVEL SECURITY;
ALTER TABLE plan_specs ENABLE ROW LEVEL SECURITY;
ALTER TABLE module_specs ENABLE ROW LEVEL SECURITY;
ALTER TABLE module_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE task_dependencies ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE attempt_series ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE aggregate_projections ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE command_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE inbox ENABLE ROW LEVEL SECURITY;

ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
ALTER TABLE goal_specs FORCE ROW LEVEL SECURITY;
ALTER TABLE plan_specs FORCE ROW LEVEL SECURITY;
ALTER TABLE module_specs FORCE ROW LEVEL SECURITY;
ALTER TABLE module_tasks FORCE ROW LEVEL SECURITY;
ALTER TABLE task_dependencies FORCE ROW LEVEL SECURITY;
ALTER TABLE approvals FORCE ROW LEVEL SECURITY;
ALTER TABLE attempt_series FORCE ROW LEVEL SECURITY;
ALTER TABLE integration_tasks FORCE ROW LEVEL SECURITY;
ALTER TABLE submissions FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_findings FORCE ROW LEVEL SECURITY;
ALTER TABLE user_decisions FORCE ROW LEVEL SECURITY;
ALTER TABLE aggregate_projections FORCE ROW LEVEL SECURITY;
ALTER TABLE domain_events FORCE ROW LEVEL SECURITY;
ALTER TABLE command_results FORCE ROW LEVEL SECURITY;
ALTER TABLE outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE inbox FORCE ROW LEVEL SECURITY;

CREATE FUNCTION aor_current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT nullif(current_setting('aor.tenant_id', true), '')::uuid
$$;

CREATE POLICY tenants_tenant_policy ON tenants USING (id = aor_current_tenant()) WITH CHECK (id = aor_current_tenant());
CREATE POLICY projects_tenant_policy ON projects USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY goal_specs_tenant_policy ON goal_specs USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY plan_specs_tenant_policy ON plan_specs USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY module_specs_tenant_policy ON module_specs USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY module_tasks_tenant_policy ON module_tasks USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY task_dependencies_tenant_policy ON task_dependencies USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY approvals_tenant_policy ON approvals USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY attempt_series_tenant_policy ON attempt_series USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY integration_tasks_tenant_policy ON integration_tasks USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY submissions_tenant_policy ON submissions USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY audit_runs_tenant_policy ON audit_runs USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY audit_findings_tenant_policy ON audit_findings USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY user_decisions_tenant_policy ON user_decisions USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY aggregate_projections_tenant_policy ON aggregate_projections USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY domain_events_tenant_policy ON domain_events USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY command_results_tenant_policy ON command_results USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY outbox_tenant_policy ON outbox USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY inbox_tenant_policy ON inbox USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());

COMMIT;
