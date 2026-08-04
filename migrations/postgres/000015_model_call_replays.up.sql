BEGIN;

CREATE TABLE model_call_replays (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  request_id text NOT NULL CHECK (request_id <> '' AND length(request_id) <= 256),
  input_sha256 aor_sha256 NOT NULL,
  key_id text NOT NULL CHECK (key_id <> '' AND length(key_id) <= 128),
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
  response_ciphertext bytea NOT NULL CHECK (
    octet_length(response_ciphertext) > 16 AND octet_length(response_ciphertext) <= 5242880
  ),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, request_id),
  FOREIGN KEY (tenant_id, request_id) REFERENCES model_calls(tenant_id, request_id) ON DELETE CASCADE,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 days')
);

CREATE INDEX model_call_replays_expiry_idx
  ON model_call_replays (expires_at, tenant_id, request_id);

ALTER TABLE model_call_replays ENABLE ROW LEVEL SECURITY;
ALTER TABLE model_call_replays FORCE ROW LEVEL SECURITY;

CREATE POLICY model_call_replays_tenant_policy ON model_call_replays
  USING (tenant_id = aor_current_tenant())
  WITH CHECK (tenant_id = aor_current_tenant());

GRANT SELECT, INSERT, DELETE ON TABLE model_call_replays TO aor_app;

COMMIT;
