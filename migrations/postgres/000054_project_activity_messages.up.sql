BEGIN;

CREATE TABLE IF NOT EXISTS public.project_activity_messages (
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  id text NOT NULL,
  task_id uuid,
  request_id text NOT NULL DEFAULT '',
  claim_request_id text NOT NULL DEFAULT '',
  flow text NOT NULL CHECK (flow IN ('GOAL', 'PLAN', 'EXECUTION', 'AUDIT', 'KNOWLEDGE')),
  agent_instance_id text NOT NULL DEFAULT '',
  role text NOT NULL DEFAULT '',
  sender text NOT NULL CHECK (sender IN ('USER', 'AGENT', 'SYSTEM')),
  state text NOT NULL CHECK (state IN ('QUEUED', 'STREAMING', 'COMPLETED', 'FAILED')),
  content text NOT NULL DEFAULT '',
  error_code text NOT NULL DEFAULT '',
  provider text NOT NULL DEFAULT '',
  model text NOT NULL DEFAULT '',
  input_tokens bigint NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
  output_tokens bigint NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
  latency_ms bigint NOT NULL DEFAULT 0 CHECK (latency_ms >= 0),
  output_sha256 text NOT NULL DEFAULT '',
  principal_id text NOT NULL DEFAULT '',
  idempotency_key text NOT NULL DEFAULT '',
  request_sha256 text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES public.projects (tenant_id, id) ON DELETE CASCADE,
  CHECK (length(id) BETWEEN 1 AND 512),
  CHECK (request_id = '' OR length(request_id) <= 512),
  CHECK (length(content) <= 4194304),
  CHECK (updated_at >= created_at)
);

ALTER TABLE public.project_activity_messages
  ADD COLUMN IF NOT EXISTS claim_request_id text NOT NULL DEFAULT '';
UPDATE public.project_activity_messages
SET request_id = ''
WHERE request_id IS NULL;
ALTER TABLE public.project_activity_messages
  ALTER COLUMN request_id SET DEFAULT '',
  ALTER COLUMN request_id SET NOT NULL;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.project_activity_messages'::regclass
      AND conname = 'project_activity_messages_claim_request_length'
  ) THEN
    ALTER TABLE public.project_activity_messages
      ADD CONSTRAINT project_activity_messages_claim_request_length
      CHECK (claim_request_id = '' OR length(claim_request_id) <= 512);
  END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS project_activity_messages_request_key
  ON public.project_activity_messages (tenant_id, request_id)
  WHERE request_id <> '';

CREATE UNIQUE INDEX IF NOT EXISTS project_activity_messages_idempotency_key
  ON public.project_activity_messages (tenant_id, principal_id, idempotency_key)
  WHERE principal_id <> '' AND idempotency_key <> '';

CREATE INDEX IF NOT EXISTS project_activity_messages_project_order
  ON public.project_activity_messages (tenant_id, project_id, created_at, id);

ALTER TABLE public.project_activity_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.project_activity_messages FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'project_activity_messages'
      AND policyname = 'project_activity_messages_tenant_policy'
  ) THEN
    CREATE POLICY project_activity_messages_tenant_policy ON public.project_activity_messages
      USING (tenant_id = public.aor_current_tenant())
      WITH CHECK (tenant_id = public.aor_current_tenant());
  END IF;
END
$$;

GRANT SELECT, INSERT, UPDATE ON TABLE public.project_activity_messages TO aor_app;

COMMIT;
