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
