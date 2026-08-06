BEGIN;

GRANT SELECT, INSERT ON TABLE public.tenants TO aor_app;

COMMIT;
