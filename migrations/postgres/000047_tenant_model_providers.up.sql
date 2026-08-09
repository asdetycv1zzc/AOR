BEGIN;

CREATE TABLE public.tenant_model_provider_settings (
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT,
  provider_id text NOT NULL CHECK (provider_id IN ('openai', 'deepseek', 'claude', 'grok')),
  provider text NOT NULL CHECK (provider = provider_id),
  base_url text NOT NULL,
  protocol text NOT NULL CHECK (protocol IN ('openai-compatible', 'anthropic-messages')),
  enabled boolean NOT NULL DEFAULT false,
  models_jsonb jsonb NOT NULL CHECK (jsonb_typeof(models_jsonb) = 'array'),
  api_key_nonce bytea,
  api_key_ciphertext bytea,
  version bigint NOT NULL CHECK (version > 0),
  input_micros_per_token bigint NOT NULL DEFAULT 1 CHECK (input_micros_per_token >= 0),
  output_micros_per_token bigint NOT NULL DEFAULT 4 CHECK (output_micros_per_token >= 0),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (tenant_id, provider_id),
  CHECK ((api_key_nonce IS NULL) = (api_key_ciphertext IS NULL)),
  CHECK (NOT enabled OR (base_url <> '' AND api_key_ciphertext IS NOT NULL)),
  CHECK (provider = 'claude' OR protocol = 'openai-compatible')
);

ALTER TABLE public.tenant_model_provider_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_model_provider_settings FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_model_provider_settings_tenant_policy ON public.tenant_model_provider_settings
  USING (tenant_id = aor_current_tenant())
  WITH CHECK (tenant_id = aor_current_tenant());

GRANT SELECT, INSERT, UPDATE ON TABLE public.tenant_model_provider_settings TO aor_app;

COMMIT;
