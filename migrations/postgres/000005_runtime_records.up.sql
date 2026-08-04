BEGIN;

CREATE TABLE agent_instances (
  id text PRIMARY KEY CHECK (id <> '' AND length(id) <= 256),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  role text NOT NULL CHECK (role <> '' AND length(role) <= 128),
  provider text NOT NULL CHECK (provider <> '' AND length(provider) <= 128),
  logical_model text NOT NULL CHECK (logical_model <> '' AND length(logical_model) <= 256),
  actual_model_version text NOT NULL CHECK (actual_model_version <> '' AND length(actual_model_version) <= 256),
  prompt_bundle_version text NOT NULL CHECK (prompt_bundle_version <> '' AND length(prompt_bundle_version) <= 256),
  state text NOT NULL CHECK (state IN (
    'DECLARED', 'QUEUED', 'LEASED', 'STARTING', 'RUNNING', 'WAITING_INPUT',
    'WAITING_TOOL', 'WAITING_DEPENDENCY', 'COMPLETED', 'FAILED', 'CANCELED',
    'EXPIRED', 'TERMINATED'
  )),
  created_at timestamptz NOT NULL,
  terminated_at timestamptz,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  CHECK (terminated_at IS NULL OR terminated_at >= created_at)
);

CREATE TABLE agent_leases (
  id text PRIMARY KEY CHECK (id <> '' AND length(id) <= 256),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  agent_instance_id text NOT NULL,
  task_id uuid NOT NULL,
  principal_id text NOT NULL CHECK (principal_id <> '' AND length(principal_id) <= 256),
  principal_type text NOT NULL CHECK (principal_type IN ('USER', 'SERVICE', 'AGENT_RUNTIME', 'AGENT_INSTANCE')),
  role text NOT NULL CHECK (role <> '' AND length(role) <= 128),
  action text NOT NULL CHECK (action <> '' AND length(action) <= 128),
  project_version bigint NOT NULL CHECK (project_version >= 0),
  task_version bigint NOT NULL CHECK (task_version >= 0),
  spec_sha256 aor_sha256 NOT NULL,
  resource_jsonb jsonb NOT NULL CHECK (jsonb_typeof(resource_jsonb) = 'object'),
  parameter_sha256 aor_sha256 NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  last_heartbeat_at timestamptz NOT NULL,
  heartbeat_interval_seconds integer NOT NULL CHECK (heartbeat_interval_seconds BETWEEN 1 AND 300),
  capabilities_jsonb jsonb NOT NULL CHECK (jsonb_typeof(capabilities_jsonb) = 'array'),
  policy_version text NOT NULL CHECK (policy_version <> '' AND length(policy_version) <= 256),
  budget_account_id text NOT NULL,
  nonce_hash aor_sha256 NOT NULL,
  fencing_token bigint NOT NULL CHECK (fencing_token >= 1),
  state text NOT NULL CHECK (state IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
  revoked_at timestamptz,
  signature text NOT NULL CHECK (signature <> '' AND length(signature) <= 1024),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, agent_instance_id) REFERENCES agent_instances(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, task_id) REFERENCES module_tasks(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, budget_account_id) REFERENCES budget_accounts(tenant_id, id) ON DELETE RESTRICT,
  CHECK (expires_at > issued_at),
  CHECK (last_heartbeat_at >= issued_at AND last_heartbeat_at <= expires_at),
  CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
);

CREATE INDEX agent_leases_active_task_idx
  ON agent_leases (tenant_id, task_id, expires_at)
  WHERE state = 'ACTIVE';

CREATE TABLE model_calls (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  request_id text NOT NULL CHECK (request_id <> '' AND length(request_id) <= 256),
  project_id uuid NOT NULL,
  task_id uuid NOT NULL,
  agent_instance_id text NOT NULL,
  provider text NOT NULL CHECK (provider <> '' AND length(provider) <= 128),
  logical_model text NOT NULL CHECK (logical_model <> '' AND length(logical_model) <= 256),
  actual_model_version text NOT NULL CHECK (actual_model_version <> '' AND length(actual_model_version) <= 256),
  prompt_bundle_version text NOT NULL CHECK (prompt_bundle_version <> '' AND length(prompt_bundle_version) <= 256),
  input_sha256 aor_sha256 NOT NULL,
  output_sha256 aor_sha256,
  input_tokens bigint NOT NULL CHECK (input_tokens >= 0),
  output_tokens bigint NOT NULL CHECK (output_tokens >= 0),
  cache_read_tokens bigint CHECK (cache_read_tokens IS NULL OR cache_read_tokens >= 0),
  cache_write_tokens bigint CHECK (cache_write_tokens IS NULL OR cache_write_tokens >= 0),
  cost_micros bigint NOT NULL CHECK (cost_micros >= 0),
  latency_ms bigint NOT NULL CHECK (latency_ms >= 0),
  status text NOT NULL CHECK (status <> '' AND length(status) <= 64),
  provider_request_id text CHECK (provider_request_id IS NULL OR length(provider_request_id) <= 512),
  created_at timestamptz NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, request_id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, task_id) REFERENCES module_tasks(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, agent_instance_id) REFERENCES agent_instances(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX model_calls_project_created_idx
  ON model_calls (tenant_id, project_id, created_at, id);

CREATE TABLE tool_invocations (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  request_id text NOT NULL CHECK (request_id <> '' AND length(request_id) <= 256),
  project_id uuid NOT NULL,
  task_id uuid NOT NULL,
  agent_instance_id text NOT NULL,
  tool_id text NOT NULL CHECK (tool_id <> '' AND length(tool_id) <= 256),
  tool_version text NOT NULL CHECK (tool_version <> '' AND length(tool_version) <= 256),
  risk_level text NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  policy_version text NOT NULL CHECK (policy_version <> '' AND length(policy_version) <= 256),
  decision text NOT NULL CHECK (decision IN ('ALLOW', 'DENY')),
  input_sha256 aor_sha256 NOT NULL,
  output_sha256 aor_sha256,
  sandbox_id text CHECK (sandbox_id IS NULL OR length(sandbox_id) <= 256),
  status text NOT NULL CHECK (status <> '' AND length(status) <= 64),
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, request_id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, task_id) REFERENCES module_tasks(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, agent_instance_id) REFERENCES agent_instances(tenant_id, id) ON DELETE RESTRICT,
  CHECK (completed_at IS NULL OR completed_at >= started_at)
);

CREATE INDEX tool_invocations_project_started_idx
  ON tool_invocations (tenant_id, project_id, started_at, id);

CREATE TABLE artifacts (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  uri text NOT NULL CHECK (uri <> '' AND length(uri) <= 4096),
  sha256 aor_sha256 NOT NULL,
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  content_type text NOT NULL CHECK (content_type <> '' AND length(content_type) <= 256),
  classification text NOT NULL CHECK (classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
  created_by_principal text NOT NULL CHECK (created_by_principal <> '' AND length(created_by_principal) <= 256),
  metadata_jsonb jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata_jsonb) = 'object'),
  created_at timestamptz NOT NULL,
  retention_until timestamptz,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, uri),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  CHECK (retention_until IS NULL OR retention_until >= created_at)
);

CREATE INDEX artifacts_project_created_idx
  ON artifacts (tenant_id, project_id, created_at, id);

ALTER TABLE agent_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE model_calls ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_invocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifacts ENABLE ROW LEVEL SECURITY;

ALTER TABLE agent_instances FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_leases FORCE ROW LEVEL SECURITY;
ALTER TABLE model_calls FORCE ROW LEVEL SECURITY;
ALTER TABLE tool_invocations FORCE ROW LEVEL SECURITY;
ALTER TABLE artifacts FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_instances_tenant_policy ON agent_instances
  USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY agent_leases_tenant_policy ON agent_leases
  USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY model_calls_tenant_policy ON model_calls
  USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY tool_invocations_tenant_policy ON tool_invocations
  USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());
CREATE POLICY artifacts_tenant_policy ON artifacts
  USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());

GRANT SELECT, INSERT, UPDATE ON TABLE agent_instances TO aor_app;
GRANT SELECT, INSERT, UPDATE ON TABLE agent_leases TO aor_app;
GRANT SELECT, INSERT ON TABLE model_calls TO aor_app;
GRANT SELECT, INSERT, UPDATE ON TABLE tool_invocations TO aor_app;
GRANT SELECT, INSERT, UPDATE ON TABLE artifacts TO aor_app;

COMMIT;
