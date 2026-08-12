BEGIN;

ALTER TABLE toolchain_installation_batches
  DROP CONSTRAINT IF EXISTS toolchain_installation_batches_tenant_id_goal_spec_id_fkey;
ALTER TABLE toolchain_installations
  DROP CONSTRAINT IF EXISTS toolchain_installations_tenant_id_goal_spec_id_fkey;

UPDATE toolchain_installations
SET state = 'FAILED',
    lease_token = NULL,
    lease_expires_at = NULL,
    claimed_attempt = NULL,
    last_error_code = 'AOR_TOOLCHAIN_SOURCE_DIGEST_REQUIRED',
    last_error_message = 'the authorized archive SHA-256 is missing',
    updated_at = clock_timestamp(),
    finished_at = clock_timestamp()
WHERE state IN ('QUEUED', 'INSTALLING')
  AND COALESCE(tool_jsonb #>> '{install,sourceSha256}', '') !~ '^sha256:[0-9a-f]{64}$';

ALTER TABLE toolchain_installations
  DROP CONSTRAINT IF EXISTS toolchain_installations_source_digest_check;
ALTER TABLE toolchain_installations
  ADD CONSTRAINT toolchain_installations_source_digest_check CHECK (
    state IN ('INSTALLED', 'FAILED') OR (
      tool_jsonb #>> '{install,method}' = 'USER_ARCHIVE'
      AND tool_jsonb #>> '{install,sourceSha256}' ~ '^sha256:[0-9a-f]{64}$'
    )
  );

CREATE OR REPLACE FUNCTION aor_extend_toolchain_installation_lease(
  requested_id uuid,
  requested_lease_token text,
  requested_attempt smallint,
  requested_lease_seconds integer
) RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
BEGIN
  IF requested_lease_seconds < 30 OR requested_lease_seconds > 3600 THEN
    RETURN false;
  END IF;
  UPDATE public.toolchain_installations AS installation
  SET lease_expires_at = clock_timestamp() + make_interval(secs => requested_lease_seconds),
      updated_at = clock_timestamp()
  WHERE installation.id = requested_id
    AND installation.state = 'INSTALLING'
    AND installation.lease_token = requested_lease_token
    AND installation.claimed_attempt = requested_attempt
    AND installation.lease_expires_at > clock_timestamp();
  RETURN FOUND;
END;
$$;

REVOKE ALL PRIVILEGES ON FUNCTION aor_extend_toolchain_installation_lease(uuid, text, smallint, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aor_extend_toolchain_installation_lease(uuid, text, smallint, integer) TO aor_app;

COMMIT;
