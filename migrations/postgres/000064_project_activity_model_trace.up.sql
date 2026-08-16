BEGIN;

ALTER TABLE public.project_activity_messages
  ADD COLUMN IF NOT EXISTS input_prompt text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS reasoning_content text NOT NULL DEFAULT '';

ALTER TABLE public.project_activity_messages
  DROP CONSTRAINT IF EXISTS project_activity_messages_content_check;

ALTER TABLE public.project_activity_messages
  ADD CONSTRAINT project_activity_messages_content_check
  CHECK (length(content) <= 33554432);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.project_activity_messages'::regclass
      AND conname = 'project_activity_messages_input_prompt_length'
  ) THEN
    ALTER TABLE public.project_activity_messages
      ADD CONSTRAINT project_activity_messages_input_prompt_length
      CHECK (length(input_prompt) <= 536870912);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.project_activity_messages'::regclass
      AND conname = 'project_activity_messages_reasoning_content_length'
  ) THEN
    ALTER TABLE public.project_activity_messages
      ADD CONSTRAINT project_activity_messages_reasoning_content_length
      CHECK (length(reasoning_content) <= 33554432);
  END IF;
END
$$;

COMMIT;
