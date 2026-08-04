BEGIN;

-- Runtime commands publish immutable specs and the executable DAG in one
-- serializable transaction. Keep these grants explicit instead of widening
-- the application's table privileges globally.
GRANT SELECT, INSERT, UPDATE ON TABLE public.plan_specs TO aor_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.module_specs TO aor_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.module_tasks TO aor_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.attempt_series TO aor_app;
GRANT SELECT, INSERT ON TABLE public.task_dependencies TO aor_app;

CREATE INDEX relational_spec_artifact_lookup_idx
  ON public.aggregate_projections (
    tenant_id,
    project_id,
    (state_jsonb->>'kind'),
    (state_jsonb->>'version'),
    (state_jsonb->>'contentSha256')
  )
  WHERE aggregate_type = 'spec_artifact';

COMMIT;
