BEGIN;

WITH desired AS (
  SELECT setting.tenant_id, setting.provider_id,
         (
           SELECT COALESCE(jsonb_object_agg(model_name, to_jsonb(1000000)), '{}'::jsonb)
           FROM jsonb_array_elements_text(setting.models_jsonb) AS stored_model(model_name)
         ) AS context_windows
  FROM public.tenant_model_provider_settings AS setting
  WHERE setting.provider_id = 'deepseek'
)
UPDATE public.tenant_model_provider_settings AS setting
SET protocol = 'openai-responses',
    model_context_windows_jsonb = desired.context_windows,
    version = setting.version + 1,
    updated_at = now()
FROM desired
WHERE setting.tenant_id = desired.tenant_id
  AND setting.provider_id = desired.provider_id
  AND (
    setting.protocol <> 'openai-responses'
    OR setting.model_context_windows_jsonb IS DISTINCT FROM desired.context_windows
  );

COMMIT;
