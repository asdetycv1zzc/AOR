ALTER TABLE public.domain_events
  ADD COLUMN replay_state_jsonb jsonb,
  ADD COLUMN replay_state_sha256 aor_sha256,
  ADD CONSTRAINT domain_events_replay_state_pair CHECK (
    (replay_state_jsonb IS NULL) = (replay_state_sha256 IS NULL)
    AND (replay_state_jsonb IS NULL OR jsonb_typeof(replay_state_jsonb) = 'object')
  );

COMMENT ON COLUMN public.domain_events.replay_state_jsonb IS
  'Authoritative aggregate projection state committed atomically with this immutable event';
COMMENT ON COLUMN public.domain_events.replay_state_sha256 IS
  'Canonical SHA-256 digest of replay_state_jsonb';
