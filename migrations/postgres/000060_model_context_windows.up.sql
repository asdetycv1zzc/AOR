BEGIN;

ALTER TABLE public.tenant_model_provider_settings
  ADD COLUMN IF NOT EXISTS model_context_windows_jsonb jsonb NOT NULL DEFAULT '{}'::jsonb;

UPDATE public.tenant_model_provider_settings AS setting
SET model_context_windows_jsonb = CASE setting.provider_id
  WHEN 'openai' THEN (
    SELECT COALESCE(jsonb_object_agg(model_name, to_jsonb(CASE WHEN model_name = 'gpt-5.4-mini' THEN 400000 ELSE 1050000 END)), '{}'::jsonb)
    FROM jsonb_array_elements_text(setting.models_jsonb) AS stored_model(model_name)
  )
  WHEN 'deepseek' THEN (
    SELECT COALESCE(jsonb_object_agg(model_name, to_jsonb(1000000)), '{}'::jsonb)
    FROM jsonb_array_elements_text(setting.models_jsonb) AS stored_model(model_name)
  )
  WHEN 'claude' THEN (
    SELECT COALESCE(jsonb_object_agg(model_name, to_jsonb(CASE WHEN model_name IN ('claude-sonnet-4-5', 'claude-opus-4-5', 'claude-haiku-4-5') THEN 200000 ELSE 1000000 END)), '{}'::jsonb)
    FROM jsonb_array_elements_text(setting.models_jsonb) AS stored_model(model_name)
  )
  WHEN 'grok' THEN (
    SELECT COALESCE(jsonb_object_agg(model_name, to_jsonb(500000)), '{}'::jsonb)
    FROM jsonb_array_elements_text(setting.models_jsonb) AS stored_model(model_name)
  )
  ELSE (
    SELECT COALESCE(jsonb_object_agg(model_name, to_jsonb(1000000)), '{}'::jsonb)
    FROM jsonb_array_elements_text(setting.models_jsonb) AS stored_model(model_name)
  )
END
WHERE model_context_windows_jsonb = '{}'::jsonb;

ALTER TABLE public.tenant_model_provider_settings
  DROP CONSTRAINT IF EXISTS tenant_model_provider_settings_context_windows_check;

ALTER TABLE public.tenant_model_provider_settings
  ADD CONSTRAINT tenant_model_provider_settings_context_windows_check
  CHECK (
    jsonb_typeof(model_context_windows_jsonb) = 'object'
    AND NOT jsonb_path_exists(model_context_windows_jsonb, '$.* ? (@.type() != "number" || @ < 1 || @ > 10000000)')
  );

COMMIT;
