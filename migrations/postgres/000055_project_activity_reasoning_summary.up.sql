BEGIN;

ALTER TABLE public.project_activity_messages
  ADD COLUMN IF NOT EXISTS reasoning_summary text NOT NULL DEFAULT '';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.project_activity_messages'::regclass
      AND conname = 'project_activity_messages_reasoning_summary_length'
  ) THEN
    ALTER TABLE public.project_activity_messages
      ADD CONSTRAINT project_activity_messages_reasoning_summary_length
      CHECK (length(reasoning_summary) <= 4194304);
  END IF;
END
$$;

COMMIT;
