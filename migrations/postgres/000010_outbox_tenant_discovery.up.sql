BEGIN;

CREATE OR REPLACE FUNCTION aor_pending_outbox_tenants(
  requested_at timestamptz,
  requested_limit integer
) RETURNS TABLE (tenant_id uuid)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
  SELECT pending.tenant_id
  FROM public.outbox AS pending
  WHERE pending.published_at IS NULL
    AND pending.next_attempt_at <= requested_at
    AND requested_limit BETWEEN 1 AND 1000
  GROUP BY pending.tenant_id
  ORDER BY min(pending.next_attempt_at), pending.tenant_id
  LIMIT requested_limit
$$;

REVOKE ALL PRIVILEGES ON FUNCTION aor_pending_outbox_tenants(timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aor_pending_outbox_tenants(timestamptz, integer) TO aor_app;

COMMIT;
