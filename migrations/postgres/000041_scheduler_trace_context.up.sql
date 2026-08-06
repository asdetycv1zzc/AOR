BEGIN;

CREATE FUNCTION aor_scheduler_trace_context(
  requested_tenant uuid,
  requested_project uuid,
  requested_task uuid
) RETURNS TABLE (
  traceparent text,
  tracestate text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $$
  SELECT COALESCE(event.metadata_jsonb ->> 'traceparent', ''),
         COALESCE(event.metadata_jsonb ->> 'tracestate', '')
  FROM public.projects AS project
  LEFT JOIN LATERAL (
    SELECT domain.metadata_jsonb
    FROM public.domain_events AS domain
    WHERE domain.tenant_id = requested_tenant
      AND domain.project_id = requested_project
      AND domain.aggregate_type = CASE WHEN requested_task IS NULL THEN 'project' ELSE 'task' END
      AND domain.aggregate_id = COALESCE(requested_task, requested_project)::text
      AND jsonb_typeof(domain.metadata_jsonb -> 'traceparent') = 'string'
    ORDER BY domain.aggregate_version DESC, domain.created_at DESC, domain.event_id DESC
    LIMIT 1
  ) AS event ON true
  WHERE project.tenant_id = requested_tenant
    AND project.id = requested_project;
$$;

REVOKE ALL PRIVILEGES ON FUNCTION aor_scheduler_trace_context(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aor_scheduler_trace_context(uuid, uuid, uuid) TO aor_app;

COMMIT;
