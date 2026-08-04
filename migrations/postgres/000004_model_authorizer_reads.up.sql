BEGIN;

-- Model authorization reads only the immutable task/spec scope. RLS still
-- requires aor.tenant_id for every query, so this does not widen tenants.
GRANT SELECT ON TABLE public.module_specs, public.module_tasks TO aor_app;

COMMIT;
