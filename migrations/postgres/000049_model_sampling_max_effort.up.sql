ALTER TABLE public.tenant_model_sampling_settings
  DROP CONSTRAINT IF EXISTS tenant_model_sampling_settings_reasoning_effort_check;

ALTER TABLE public.tenant_model_sampling_settings
  ADD CONSTRAINT tenant_model_sampling_settings_reasoning_effort_check
  CHECK (reasoning_effort IN ('', 'none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max'));
