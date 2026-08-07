BEGIN;

DO $migration$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.module_specs'::regclass
      AND conname = 'module_specs_tenant_project_module_version_key'
  ) THEN
    ALTER TABLE public.module_specs
      ADD CONSTRAINT module_specs_tenant_project_module_version_key
      UNIQUE (tenant_id, project_id, module_id, version);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.module_specs'::regclass
      AND conname = 'module_specs_tenant_project_module_content_key'
  ) THEN
    ALTER TABLE public.module_specs
      ADD CONSTRAINT module_specs_tenant_project_module_content_key
      UNIQUE (tenant_id, project_id, module_id, content_sha256);
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.module_specs'::regclass
      AND conname = 'module_specs_tenant_id_module_id_version_key'
  ) THEN
    ALTER TABLE public.module_specs
      DROP CONSTRAINT module_specs_tenant_id_module_id_version_key;
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.module_specs'::regclass
      AND conname = 'module_specs_tenant_id_module_id_content_sha256_key'
  ) THEN
    ALTER TABLE public.module_specs
      DROP CONSTRAINT module_specs_tenant_id_module_id_content_sha256_key;
  END IF;
END
$migration$;

COMMIT;
