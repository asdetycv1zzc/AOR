BEGIN;

CREATE TABLE public.tenant_model_route_settings (
  tenant_id uuid PRIMARY KEY REFERENCES public.tenants(id) ON DELETE RESTRICT,
  model_routes_jsonb jsonb NOT NULL CHECK (jsonb_typeof(model_routes_jsonb) = 'object'),
  version bigint NOT NULL CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

ALTER TABLE public.tenant_model_route_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_model_route_settings FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_model_route_settings_tenant_policy ON public.tenant_model_route_settings
  USING (tenant_id = aor_current_tenant())
  WITH CHECK (tenant_id = aor_current_tenant());

GRANT SELECT, INSERT, UPDATE ON TABLE public.tenant_model_route_settings TO aor_app;

COMMIT;
