BEGIN;

ALTER TABLE public.tenant_model_provider_settings
  DROP CONSTRAINT IF EXISTS tenant_model_provider_settings_provider_id_check,
  ADD COLUMN IF NOT EXISTS display_name text NOT NULL DEFAULT '';

UPDATE public.tenant_model_provider_settings
SET display_name = CASE provider_id
  WHEN 'openai' THEN 'OpenAI'
  WHEN 'deepseek' THEN 'DeepSeek'
  WHEN 'claude' THEN 'Claude'
  WHEN 'grok' THEN 'Grok'
  ELSE provider_id
END
WHERE display_name = '';

COMMIT;
