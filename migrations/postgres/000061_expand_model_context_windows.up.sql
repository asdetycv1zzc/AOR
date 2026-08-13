BEGIN;

ALTER TABLE public.tenant_model_provider_settings
  DROP CONSTRAINT IF EXISTS tenant_model_provider_settings_context_windows_check;

ALTER TABLE public.tenant_model_provider_settings
  ADD CONSTRAINT tenant_model_provider_settings_context_windows_check
  CHECK (
    jsonb_typeof(model_context_windows_jsonb) = 'object'
    AND NOT jsonb_path_exists(model_context_windows_jsonb, '$.* ? (@.type() != "number" || @ < 1 || @ > 64000000)')
  );

COMMIT;
