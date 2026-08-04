package eventing

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresLegacyReplayLoadsOnlyBoundCommandResult(t *testing.T) {
	dsn := os.Getenv("AOR_TEST_POSTGRES_DSN")
	appDSN := os.Getenv("AOR_TEST_POSTGRES_APP_DSN")
	if dsn == "" || appDSN == "" {
		t.Log("Postgres integration environment is not configured; make postgres-reconciliation enforces it")
		return
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	app, err := sql.Open("pgx", appDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx := context.Background()
	tenantID := uuid.Must(uuid.NewV7()).String()
	projectID := uuid.Must(uuid.NewV7()).String()
	eventID := uuid.Must(uuid.NewV7()).String()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	if _, err := admin.ExecContext(ctx, `INSERT INTO tenants (id, name) VALUES ($1::uuid, $2)`, tenantID, "legacy-replay"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `
INSERT INTO projects
  (id, tenant_id, name, state, state_version, data_classification, deployment_targets_jsonb,
   risk_tolerance, goal_agent_count, created_by, created_at, updated_at)
VALUES ($1::uuid, $2::uuid, 'legacy replay', 'PLANNING', 1, 'INTERNAL', '[]'::jsonb,
        'MEDIUM', 1, 'test', $3, $3)`, projectID, tenantID, now); err != nil {
		t.Fatal(err)
	}
	payload := json.RawMessage(`{"tenantId":"` + tenantID + `","projectId":"` + projectID + `","kind":"PLAN_SPEC","specId":"plan-1","version":1,"contentSha256":"sha256:` + strings.Repeat("1", 64) + `","artifactSha256":"sha256:` + strings.Repeat("2", 64) + `","uri":"artifact://sha256/` + strings.Repeat("2", 64) + `"}`)
	state := json.RawMessage(`{"tenantId":"` + tenantID + `","projectId":"` + projectID + `","kind":"PLAN_SPEC","specId":"plan-1","version":1,"contentSha256":"sha256:` + strings.Repeat("1", 64) + `","artifactSha256":"sha256:` + strings.Repeat("2", 64) + `","uri":"artifact://sha256/` + strings.Repeat("2", 64) + `","mediaType":"application/json","createdBy":"agent-plan"}`)
	payloadDigest, err := canonicaljson.Digest(payload)
	if err != nil {
		t.Fatal(err)
	}
	stateDigest, err := canonicaljson.Digest(state)
	if err != nil {
		t.Fatal(err)
	}
	aggregateID := legacyArtifactAggregateID(projectID, "PLAN_SPEC", "plan-1", 1)
	if _, err := admin.ExecContext(ctx, `
INSERT INTO domain_events
  (event_id, tenant_id, project_id, aggregate_type, aggregate_id, aggregate_version, event_type,
   schema_version, payload_jsonb, payload_sha256, metadata_jsonb, created_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, 'spec_artifact', $4, 1, 'io.aor.spec.artifact-published.v1',
        1, $5::jsonb, $6, '{}'::jsonb, $7)`, eventID, tenantID, projectID, aggregateID, payload, payloadDigest, now); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `
INSERT INTO command_results
  (tenant_id, principal_id, idempotency_key, request_sha256, result_jsonb, result_sha256, event_ids_jsonb)
VALUES
  ($1::uuid, 'agent-plan', 'relevant', $2, $3::jsonb, $4, jsonb_build_array($5::text)),
  ($1::uuid, 'agent-plan', 'irrelevant', $2, '{}'::jsonb, $2, '[]'::jsonb)`,
		tenantID, "sha256:"+strings.Repeat("3", 64), state, stateDigest, eventID); err != nil {
		t.Fatal(err)
	}
	tx, err := app.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenant(ctx, tx, tenantID); err != nil {
		t.Fatal(err)
	}
	events, err := loadReplayEvents(ctx, tx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ReplayStateSHA256 != stateDigest {
		t.Fatalf("legacy replay events=%#v", events)
	}
}
