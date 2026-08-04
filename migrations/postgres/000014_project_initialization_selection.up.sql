BEGIN;

ALTER TABLE projects
  ADD COLUMN deployment_targets_jsonb jsonb NOT NULL DEFAULT '[]'::jsonb
  CHECK (jsonb_typeof(deployment_targets_jsonb) = 'array');

GRANT SELECT, INSERT, UPDATE ON TABLE public.projects TO aor_app;

COMMIT;
