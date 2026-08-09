BEGIN;

CREATE TABLE public.tenant_model_sampling_settings (
  tenant_id uuid PRIMARY KEY REFERENCES public.tenants(id) ON DELETE RESTRICT,
  temperature double precision NOT NULL CHECK (temperature >= 0 AND temperature <= 2),
  top_p double precision NOT NULL CHECK (top_p >= 0 AND top_p <= 1),
  top_k integer NOT NULL CHECK (top_k >= 0 AND top_k <= 500),
  reasoning_effort text NOT NULL CHECK (reasoning_effort IN ('', 'none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max')),
  version bigint NOT NULL CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

ALTER TABLE public.tenant_model_sampling_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_model_sampling_settings FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_model_sampling_settings_tenant_policy ON public.tenant_model_sampling_settings
  USING (tenant_id = aor_current_tenant())
  WITH CHECK (tenant_id = aor_current_tenant());

GRANT SELECT, INSERT, UPDATE ON TABLE public.tenant_model_sampling_settings TO aor_app;

COMMIT;
