BEGIN;

CREATE TABLE toolchain_installation_batches (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id uuid NOT NULL,
  goal_spec_id uuid NOT NULL,
  goal_version integer NOT NULL CHECK (goal_version > 0),
  message_id text NOT NULL CHECK (message_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'),
  principal_id text NOT NULL CHECK (principal_id <> '' AND length(principal_id) <= 512),
  principal_type text NOT NULL CHECK (principal_type IN ('USER', 'BREAK_GLASS_ADMIN')),
  principal_role text NOT NULL CHECK (principal_role <> '' AND length(principal_role) <= 128),
  state text NOT NULL CHECK (state IN ('WAITING', 'READY', 'RECOVERING', 'COMPLETED', 'FAILED')),
  recovery_attempt smallint NOT NULL DEFAULT 0 CHECK (recovery_attempt BETWEEN 0 AND 5),
  recovery_available_at timestamptz NOT NULL,
  recovery_lease_token text,
  recovery_lease_expires_at timestamptz,
  recovery_claimed_attempt smallint,
  last_error_code text,
  last_error_message text,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  finished_at timestamptz,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, project_id, goal_spec_id, goal_version),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  CHECK ((recovery_lease_token IS NOT NULL AND recovery_lease_expires_at IS NOT NULL AND recovery_claimed_attempt IS NOT NULL) = (state = 'RECOVERING')),
  CHECK (recovery_claimed_attempt IS NULL OR recovery_claimed_attempt = recovery_attempt),
  CHECK ((finished_at IS NOT NULL) = (state IN ('COMPLETED', 'FAILED'))),
  CHECK (recovery_lease_token IS NULL OR recovery_lease_token ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'),
  CHECK (last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 128),
  CHECK (last_error_message IS NULL OR length(last_error_message) BETWEEN 1 AND 4096)
);

CREATE TABLE toolchain_installations (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  batch_id uuid NOT NULL,
  project_id uuid NOT NULL,
  goal_spec_id uuid NOT NULL,
  goal_version integer NOT NULL CHECK (goal_version > 0),
  tool_key aor_sha256 NOT NULL,
  tool_jsonb jsonb NOT NULL CHECK (jsonb_typeof(tool_jsonb) = 'object'),
  state text NOT NULL CHECK (state IN ('QUEUED', 'INSTALLING', 'INSTALLED', 'FAILED')),
  attempt smallint NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 5),
  available_at timestamptz NOT NULL,
  lease_token text,
  lease_expires_at timestamptz,
  claimed_attempt smallint,
  inventory_id text,
  last_error_code text,
  last_error_message text,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  finished_at timestamptz,
  UNIQUE (tenant_id, project_id, goal_spec_id, goal_version, tool_key),
  FOREIGN KEY (tenant_id, batch_id) REFERENCES toolchain_installation_batches(tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id) ON DELETE RESTRICT,
  CHECK (tool_jsonb ->> 'source' = 'INSTALL_REQUIRED'),
  CHECK (tool_jsonb #>> '{install,method}' = 'USER_ARCHIVE'),
  CHECK (tool_jsonb #>> '{install,authorized}' = 'true'),
  CHECK (tool_jsonb #>> '{install,downloadUrl}' ~ '^https://[^[:space:]]+$'),
  CHECK (tool_jsonb #>> '{install,evidenceRef}' ~ '^artifact://sha256/[0-9a-f]{64}$'),
  CHECK ((lease_token IS NOT NULL AND lease_expires_at IS NOT NULL AND claimed_attempt IS NOT NULL) = (state = 'INSTALLING')),
  CHECK (claimed_attempt IS NULL OR claimed_attempt = attempt),
  CHECK ((inventory_id IS NOT NULL) = (state = 'INSTALLED')),
  CHECK ((finished_at IS NOT NULL) = (state IN ('INSTALLED', 'FAILED'))),
  CHECK (lease_token IS NULL OR lease_token ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'),
  CHECK (inventory_id IS NULL OR inventory_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  CHECK (last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 128),
  CHECK (last_error_message IS NULL OR length(last_error_message) BETWEEN 1 AND 4096)
);

CREATE INDEX toolchain_installations_claim_idx
  ON toolchain_installations (available_at, created_at, id)
  WHERE state IN ('QUEUED', 'INSTALLING');

CREATE INDEX toolchain_installations_goal_idx
  ON toolchain_installations (tenant_id, project_id, goal_spec_id, goal_version, state);

CREATE INDEX toolchain_installation_batches_recovery_idx
  ON toolchain_installation_batches (recovery_available_at, created_at, id)
  WHERE state IN ('WAITING', 'READY', 'RECOVERING');

ALTER TABLE toolchain_installation_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE toolchain_installation_batches FORCE ROW LEVEL SECURITY;

ALTER TABLE toolchain_installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE toolchain_installations FORCE ROW LEVEL SECURITY;

CREATE POLICY toolchain_installations_tenant_policy ON toolchain_installations
  USING (tenant_id = aor_current_tenant())
  WITH CHECK (tenant_id = aor_current_tenant());

CREATE POLICY toolchain_installation_batches_tenant_policy ON toolchain_installation_batches
  USING (tenant_id = aor_current_tenant())
  WITH CHECK (tenant_id = aor_current_tenant());

GRANT SELECT, INSERT, UPDATE ON TABLE public.toolchain_installations TO aor_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.toolchain_installation_batches TO aor_app;

CREATE FUNCTION aor_claim_toolchain_installations(
  requested_limit integer,
  requested_lease_token text,
  requested_lease_seconds integer
) RETURNS TABLE (
  id uuid,
  tenant_id uuid,
  project_id uuid,
  goal_spec_id uuid,
  goal_version integer,
  tool_key aor_sha256,
  tool_jsonb jsonb,
  state text,
  attempt smallint,
  available_at timestamptz,
  lease_token text,
  lease_expires_at timestamptz,
  claimed_attempt smallint,
  inventory_id text,
  last_error_code text,
  last_error_message text,
  created_at timestamptz,
  updated_at timestamptz,
  finished_at timestamptz
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
  WITH candidates AS (
    SELECT installation.id
    FROM public.toolchain_installations AS installation
    WHERE requested_limit BETWEEN 1 AND 16
      AND requested_lease_token ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'
      AND requested_lease_seconds BETWEEN 30 AND 3600
      AND installation.attempt < 5
      AND installation.available_at <= clock_timestamp()
      AND (
        installation.state = 'QUEUED'
        OR installation.state = 'INSTALLING'
          AND installation.lease_expires_at <= clock_timestamp()
      )
    ORDER BY installation.available_at, installation.created_at, installation.id
    FOR UPDATE OF installation SKIP LOCKED
    LIMIT requested_limit
  )
  UPDATE public.toolchain_installations AS installation
  SET state = 'INSTALLING',
      attempt = installation.attempt + 1,
      lease_token = requested_lease_token,
      lease_expires_at = clock_timestamp() + make_interval(secs => requested_lease_seconds),
      claimed_attempt = installation.attempt + 1,
      last_error_code = NULL,
      last_error_message = NULL,
      updated_at = clock_timestamp(),
      finished_at = NULL
  FROM candidates
  WHERE installation.id = candidates.id
  RETURNING installation.id, installation.tenant_id, installation.project_id,
            installation.goal_spec_id, installation.goal_version, installation.tool_key,
            installation.tool_jsonb, installation.state, installation.attempt,
            installation.available_at, installation.lease_token,
            installation.lease_expires_at, installation.claimed_attempt, installation.inventory_id,
            installation.last_error_code, installation.last_error_message,
            installation.created_at, installation.updated_at, installation.finished_at;
$$;

CREATE FUNCTION aor_expire_toolchain_installation_leases()
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
DECLARE
  expired_count bigint;
BEGIN
  UPDATE public.toolchain_installations AS installation
  SET state = 'FAILED',
      lease_token = NULL,
      lease_expires_at = NULL,
      claimed_attempt = NULL,
      last_error_code = 'AOR_TOOLCHAIN_INSTALL_LEASE_EXHAUSTED',
      last_error_message = 'installation lease expired after the maximum number of attempts',
      updated_at = clock_timestamp(),
      finished_at = clock_timestamp()
  WHERE installation.state = 'INSTALLING'
    AND installation.attempt >= 5
    AND installation.lease_expires_at <= clock_timestamp();
  GET DIAGNOSTICS expired_count = ROW_COUNT;
  RETURN expired_count;
END;
$$;

CREATE FUNCTION aor_claimed_toolchain_installation(
  requested_id uuid,
  requested_lease_token text,
  requested_attempt smallint
) RETURNS TABLE (tenant_id uuid)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
  SELECT installation.tenant_id
  FROM public.toolchain_installations AS installation
  WHERE installation.id = requested_id
    AND installation.state = 'INSTALLING'
    AND installation.lease_token = requested_lease_token
    AND installation.claimed_attempt = requested_attempt
    AND installation.lease_expires_at > clock_timestamp();
$$;

CREATE FUNCTION aor_reconcile_toolchain_installation_batches()
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
DECLARE
  changed_count bigint;
  current_count bigint;
BEGIN
  UPDATE public.toolchain_installation_batches AS batch
  SET state = 'FAILED',
      last_error_code = 'AOR_TOOLCHAIN_INSTALLATION_FAILED',
      last_error_message = 'one or more prerequisite toolchain installations failed',
      updated_at = clock_timestamp(),
      finished_at = clock_timestamp()
  WHERE batch.state = 'WAITING'
    AND EXISTS (
      SELECT 1 FROM public.toolchain_installations AS installation
      WHERE installation.tenant_id = batch.tenant_id
        AND installation.batch_id = batch.id
        AND installation.state = 'FAILED'
    );
  GET DIAGNOSTICS changed_count = ROW_COUNT;

  UPDATE public.toolchain_installation_batches AS batch
  SET state = 'READY', updated_at = clock_timestamp()
  WHERE batch.state = 'WAITING'
    AND EXISTS (
      SELECT 1 FROM public.toolchain_installations AS installation
      WHERE installation.tenant_id = batch.tenant_id
        AND installation.batch_id = batch.id
    )
    AND NOT EXISTS (
      SELECT 1 FROM public.toolchain_installations AS installation
      WHERE installation.tenant_id = batch.tenant_id
        AND installation.batch_id = batch.id
        AND installation.state <> 'INSTALLED'
    );
  GET DIAGNOSTICS current_count = ROW_COUNT;
  RETURN changed_count + current_count;
END;
$$;

CREATE FUNCTION aor_expire_toolchain_installation_batch_leases()
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
DECLARE
  expired_count bigint;
BEGIN
  UPDATE public.toolchain_installation_batches AS batch
  SET state = 'FAILED',
      recovery_lease_token = NULL,
      recovery_lease_expires_at = NULL,
      recovery_claimed_attempt = NULL,
      last_error_code = 'AOR_TOOLCHAIN_RECOVERY_LEASE_EXHAUSTED',
      last_error_message = 'toolchain recovery lease expired after the maximum number of attempts',
      updated_at = clock_timestamp(),
      finished_at = clock_timestamp()
  WHERE batch.state = 'RECOVERING'
    AND batch.recovery_attempt >= 5
    AND batch.recovery_lease_expires_at <= clock_timestamp();
  GET DIAGNOSTICS expired_count = ROW_COUNT;
  RETURN expired_count;
END;
$$;

CREATE FUNCTION aor_claim_ready_toolchain_installation_batches(
  requested_limit integer,
  requested_lease_token text,
  requested_lease_seconds integer
) RETURNS TABLE (
  id uuid,
  tenant_id uuid,
  project_id uuid,
  goal_spec_id uuid,
  goal_version integer,
  message_id text,
  principal_id text,
  principal_type text,
  principal_role text,
  recovery_attempt smallint,
  recovery_lease_expires_at timestamptz
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
  WITH candidates AS (
    SELECT batch.id
    FROM public.toolchain_installation_batches AS batch
    WHERE requested_limit BETWEEN 1 AND 16
      AND requested_lease_token ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'
      AND requested_lease_seconds BETWEEN 30 AND 3600
      AND batch.recovery_attempt < 5
      AND batch.recovery_available_at <= clock_timestamp()
      AND (
        batch.state = 'READY'
        OR batch.state = 'RECOVERING'
          AND batch.recovery_lease_expires_at <= clock_timestamp()
      )
    ORDER BY batch.recovery_available_at, batch.created_at, batch.id
    FOR UPDATE OF batch SKIP LOCKED
    LIMIT requested_limit
  )
  UPDATE public.toolchain_installation_batches AS batch
  SET state = 'RECOVERING',
      recovery_attempt = batch.recovery_attempt + 1,
      recovery_lease_token = requested_lease_token,
      recovery_lease_expires_at = clock_timestamp() + make_interval(secs => requested_lease_seconds),
      recovery_claimed_attempt = batch.recovery_attempt + 1,
      last_error_code = NULL,
      last_error_message = NULL,
      updated_at = clock_timestamp(),
      finished_at = NULL
  FROM candidates
  WHERE batch.id = candidates.id
  RETURNING batch.id, batch.tenant_id, batch.project_id, batch.goal_spec_id,
            batch.goal_version, batch.message_id, batch.principal_id,
            batch.principal_type, batch.principal_role, batch.recovery_attempt,
            batch.recovery_lease_expires_at;
$$;

CREATE FUNCTION aor_finish_toolchain_installation_batch(
  requested_id uuid,
  requested_lease_token text,
  requested_attempt smallint,
  succeeded boolean,
  retry boolean,
  requested_error_code text,
  requested_error_message text
) RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
BEGIN
  IF succeeded THEN
    UPDATE public.toolchain_installation_batches AS batch
    SET state = 'COMPLETED', recovery_lease_token = NULL,
        recovery_lease_expires_at = NULL, recovery_claimed_attempt = NULL,
        last_error_code = NULL, last_error_message = NULL,
        updated_at = clock_timestamp(), finished_at = clock_timestamp()
    WHERE batch.id = requested_id AND batch.state = 'RECOVERING'
      AND batch.recovery_lease_token = requested_lease_token
      AND batch.recovery_claimed_attempt = requested_attempt
      AND batch.recovery_lease_expires_at > clock_timestamp();
  ELSIF retry AND requested_attempt < 5 THEN
    UPDATE public.toolchain_installation_batches AS batch
    SET state = 'READY', recovery_available_at = clock_timestamp() + interval '5 seconds',
        recovery_lease_token = NULL, recovery_lease_expires_at = NULL,
        recovery_claimed_attempt = NULL, last_error_code = requested_error_code,
        last_error_message = requested_error_message, updated_at = clock_timestamp(),
        finished_at = NULL
    WHERE batch.id = requested_id AND batch.state = 'RECOVERING'
      AND batch.recovery_lease_token = requested_lease_token
      AND batch.recovery_claimed_attempt = requested_attempt;
  ELSE
    UPDATE public.toolchain_installation_batches AS batch
    SET state = 'FAILED', recovery_lease_token = NULL,
        recovery_lease_expires_at = NULL, recovery_claimed_attempt = NULL,
        last_error_code = requested_error_code, last_error_message = requested_error_message,
        updated_at = clock_timestamp(), finished_at = clock_timestamp()
    WHERE batch.id = requested_id AND batch.state = 'RECOVERING'
      AND batch.recovery_lease_token = requested_lease_token
      AND batch.recovery_claimed_attempt = requested_attempt;
  END IF;
  RETURN FOUND;
END;
$$;

REVOKE ALL PRIVILEGES ON FUNCTION aor_claim_toolchain_installations(integer, text, integer) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION aor_expire_toolchain_installation_leases() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION aor_claimed_toolchain_installation(uuid, text, smallint) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION aor_reconcile_toolchain_installation_batches() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION aor_expire_toolchain_installation_batch_leases() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION aor_claim_ready_toolchain_installation_batches(integer, text, integer) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION aor_finish_toolchain_installation_batch(uuid, text, smallint, boolean, boolean, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aor_claim_toolchain_installations(integer, text, integer) TO aor_app;
GRANT EXECUTE ON FUNCTION aor_expire_toolchain_installation_leases() TO aor_app;
GRANT EXECUTE ON FUNCTION aor_claimed_toolchain_installation(uuid, text, smallint) TO aor_app;
GRANT EXECUTE ON FUNCTION aor_reconcile_toolchain_installation_batches() TO aor_app;
GRANT EXECUTE ON FUNCTION aor_expire_toolchain_installation_batch_leases() TO aor_app;
GRANT EXECUTE ON FUNCTION aor_claim_ready_toolchain_installation_batches(integer, text, integer) TO aor_app;
GRANT EXECUTE ON FUNCTION aor_finish_toolchain_installation_batch(uuid, text, smallint, boolean, boolean, text, text) TO aor_app;

COMMIT;
