DO $migration$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.artifacts'::regclass
      AND conname = 'artifacts_tenant_project_uri_key'
  ) THEN
    ALTER TABLE artifacts
      ADD CONSTRAINT artifacts_tenant_project_uri_key
      UNIQUE (tenant_id, project_id, uri);
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.artifacts'::regclass
      AND conname = 'artifacts_tenant_id_uri_key'
  ) THEN
    ALTER TABLE artifacts
      DROP CONSTRAINT artifacts_tenant_id_uri_key;
  END IF;
END
$migration$;
