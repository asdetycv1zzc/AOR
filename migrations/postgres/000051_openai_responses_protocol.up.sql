BEGIN;

ALTER TABLE public.tenant_model_provider_settings
  DROP CONSTRAINT IF EXISTS tenant_model_provider_settings_protocol_check,
  DROP CONSTRAINT IF EXISTS tenant_model_provider_settings_check3,
  DROP CONSTRAINT IF EXISTS tenant_model_provider_settings_provider_protocol_check;

ALTER TABLE public.tenant_model_provider_settings
  ADD CONSTRAINT tenant_model_provider_settings_protocol_check
    CHECK (protocol IN ('openai-compatible', 'openai-responses', 'anthropic-messages')),
  ADD CONSTRAINT tenant_model_provider_settings_provider_protocol_check
    CHECK (
      (provider = 'openai' AND protocol IN ('openai-compatible', 'openai-responses')) OR
      (provider = 'claude' AND protocol IN ('openai-compatible', 'anthropic-messages')) OR
      (provider IN ('deepseek', 'grok') AND protocol = 'openai-compatible')
    );

COMMIT;
