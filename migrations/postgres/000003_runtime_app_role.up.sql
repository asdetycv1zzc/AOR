BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aor_app') THEN
    CREATE ROLE aor_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
END;
$$;

\getenv aor_app_password AOR_APP_PASSWORD
\if :{?aor_app_password}
\else
  SELECT 1 / 0;
\endif
SELECT format(
  'ALTER ROLE aor_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L',
  :'aor_app_password'
) \gexec
\unset aor_app_password

REVOKE ALL PRIVILEGES ON DATABASE aor FROM aor_app;
GRANT CONNECT ON DATABASE aor TO aor_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM aor_app;
GRANT USAGE ON SCHEMA public TO aor_app;

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM aor_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.aggregate_projections TO aor_app;
GRANT INSERT ON TABLE public.approvals TO aor_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.budget_accounts TO aor_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.budget_reservations TO aor_app;
GRANT SELECT, INSERT ON TABLE public.command_results TO aor_app;
GRANT SELECT, INSERT ON TABLE public.domain_events TO aor_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.inbox TO aor_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.outbox TO aor_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.projects TO aor_app;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM aor_app;

REVOKE ALL PRIVILEGES ON FUNCTION public.aor_current_tenant() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.aor_reject_immutable_mutation() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.aor_current_tenant() TO aor_app;

COMMIT;
