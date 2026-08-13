BEGIN;

UPDATE public.tenant_model_provider_settings AS setting
SET model_context_windows_jsonb = (
  SELECT COALESCE(jsonb_object_agg(model_name, to_jsonb(400000)), '{}'::jsonb)
  FROM jsonb_array_elements_text(setting.models_jsonb) AS stored_model(model_name)
)
WHERE setting.provider_id = 'openai';

COMMIT;
