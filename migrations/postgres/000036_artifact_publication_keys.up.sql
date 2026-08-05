BEGIN;

-- Keep logical retry identities separate from artifact primary keys. The
-- application allocates both IDs as random UUIDv7 values.
ALTER TABLE artifacts
  ADD CONSTRAINT artifacts_tenant_project_id_key
  UNIQUE (tenant_id, project_id, id);

CREATE TABLE artifact_publication_keys (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  idempotency_key text NOT NULL
    CHECK (idempotency_key <> '' AND length(idempotency_key) <= 256 AND idempotency_key = btrim(idempotency_key) AND idempotency_key !~ E'[\r\n]'),
  artifact_id uuid NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, project_id, idempotency_key),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, project_id, artifact_id) REFERENCES artifacts(tenant_id, project_id, id) ON DELETE RESTRICT
);

CREATE INDEX artifact_publication_keys_artifact_idx
  ON artifact_publication_keys (tenant_id, project_id, artifact_id);

ALTER TABLE artifact_publication_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_publication_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY artifact_publication_keys_tenant_policy ON artifact_publication_keys
  USING (tenant_id = aor_current_tenant()) WITH CHECK (tenant_id = aor_current_tenant());

GRANT SELECT, INSERT ON TABLE public.artifact_publication_keys TO aor_app;
GRANT DELETE ON TABLE public.artifact_publication_keys TO aor_app;

COMMIT;
