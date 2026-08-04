package projection

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresDurableReconciliationDetectsOnlineDrift(t *testing.T) {
	dsn := os.Getenv("AOR_TEST_POSTGRES_DSN")
	appDSN := os.Getenv("AOR_TEST_POSTGRES_APP_DSN")
	if dsn == "" || appDSN == "" {
		t.Log("INCONCLUSIVE: Postgres integration environment is not configured; set AOR_TEST_POSTGRES_DSN and AOR_TEST_POSTGRES_APP_DSN to execute this test")
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
	if err := admin.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := app.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	tenantID := uuid.Must(uuid.NewV7()).String()
	projectID := uuid.Must(uuid.NewV7()).String()
	aggregateID := uuid.Must(uuid.NewV7()).String()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	if _, err := admin.ExecContext(ctx, `INSERT INTO tenants (id, name) VALUES ($1::uuid, $2)`, tenantID, "projection-reconciliation"); err != nil {
		t.Fatal(err)
	}
	store := eventing.NewPostgresStore(app)
	projectState := reconciliationProjectState(t, tenantID, projectID)
	projectDigest, err := canonicaljson.Digest(projectState)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Execute(ctx, eventing.TransactionRequest{
		TenantID: tenantID, PrincipalID: "projection-reconciliation", IdempotencyKey: "create-project",
		RequestSHA256: "sha256:" + strings.Repeat("4", 64), Result: projectState, ResultSHA256: projectDigest,
		Updates: []eventing.ProjectionUpdate{{
			TenantID: tenantID, ProjectID: projectID, AggregateType: "project", AggregateID: projectID,
			ExpectedVersion: 0, NextVersion: 1, State: projectState,
		}},
		Events: []eventing.DomainEvent{{
			EventID: uuid.Must(uuid.NewV7()).String(), TenantID: tenantID, ProjectID: projectID,
			AggregateType: "project", AggregateID: projectID, AggregateVersion: 1,
			Type: "io.aor.project.created.v1", Payload: projectState, PayloadSHA256: projectDigest, OccurredAt: now,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	assertReplayStatePairRejected(t, ctx, admin, tenantID, projectID, nil, "sha256:"+strings.Repeat("7", 64), now)
	assertReplayStatePairRejected(t, ctx, admin, tenantID, projectID, []byte(`{}`), nil, now)

	state := reconciliationState(t, tenantID, projectID, aggregateID, "CURRENT")
	digest, err := canonicaljson.Digest(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Execute(ctx, eventing.TransactionRequest{
		TenantID:       tenantID,
		PrincipalID:    "projection-reconciliation",
		IdempotencyKey: "create-fixture",
		RequestSHA256:  "sha256:" + strings.Repeat("8", 64),
		Updates: []eventing.ProjectionUpdate{{
			TenantID: tenantID, ProjectID: projectID, AggregateType: "reconciliation_fixture", AggregateID: aggregateID,
			ExpectedVersion: 0, NextVersion: 1, State: state,
		}},
		Events: []eventing.DomainEvent{{
			EventID: uuid.Must(uuid.NewV7()).String(), TenantID: tenantID, ProjectID: projectID,
			AggregateType: "reconciliation_fixture", AggregateID: aggregateID, AggregateVersion: 1,
			Type: "io.aor.test.reconciliation.v1", Payload: state, PayloadSHA256: digest, OccurredAt: now,
		}},
		Result: state, ResultSHA256: digest,
	}); err != nil {
		t.Fatal(err)
	}

	report, err := VerifyDurable(ctx, store, tenantID)
	if err != nil || !report.Converged || report.EventCount != 2 || report.OnlineCount != 2 {
		t.Fatalf("durable report=%#v error=%v", report, err)
	}
	if _, err := admin.ExecContext(ctx, `UPDATE projects SET state = 'PAUSED' WHERE tenant_id = $1::uuid AND id = $2::uuid`, tenantID, projectID); err != nil {
		t.Fatal(err)
	}
	if report, err = VerifyDurable(ctx, store, tenantID); !errors.Is(err, ErrProjectionDrift) || report.Converged {
		t.Fatalf("relational drift report=%#v error=%v", report, err)
	}
	if _, err := admin.ExecContext(ctx, `UPDATE projects SET state = 'PLANNING' WHERE tenant_id = $1::uuid AND id = $2::uuid`, tenantID, projectID); err != nil {
		t.Fatal(err)
	}
	drifted := reconciliationState(t, tenantID, projectID, aggregateID, "DRIFTED")
	if _, err := admin.ExecContext(ctx, `
UPDATE aggregate_projections
SET state_jsonb = $4::jsonb
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND aggregate_id = $3`, tenantID, projectID, aggregateID, drifted); err != nil {
		t.Fatal(err)
	}
	report, err = VerifyDurable(ctx, store, tenantID)
	if !errors.Is(err, ErrProjectionDrift) || report.Converged || len(report.Drifts) != 1 || report.Drifts[0].Kind != DriftState {
		t.Fatalf("drift report=%#v error=%v", report, err)
	}
}

func assertReplayStatePairRejected(t *testing.T, ctx context.Context, db *sql.DB, tenantID, projectID string, replayState, replayDigest any, occurredAt time.Time) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, execErr := tx.ExecContext(ctx, `
INSERT INTO domain_events
  (event_id, tenant_id, project_id, aggregate_type, aggregate_id, aggregate_version, event_type, schema_version,
   payload_jsonb, payload_sha256, replay_state_jsonb, replay_state_sha256, metadata_jsonb, created_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, 'reconciliation_fixture', $4, 1, 'io.aor.test.reconciliation.v1', 1,
        '{}'::jsonb, $5, $6::jsonb, $7, '{}'::jsonb, $8)`,
		uuid.Must(uuid.NewV7()).String(), tenantID, projectID, uuid.Must(uuid.NewV7()).String(),
		"sha256:"+strings.Repeat("6", 64), replayState, replayDigest, occurredAt)
	if rollbackErr := tx.Rollback(); rollbackErr != nil {
		t.Fatal(rollbackErr)
	}
	if execErr == nil || !strings.Contains(execErr.Error(), "domain_events_replay_state_pair") {
		t.Fatalf("invalid replay state pair error=%v", execErr)
	}
}

func reconciliationState(t *testing.T, tenantID, projectID, aggregateID, state string) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{
		"tenantId": tenantID, "projectId": projectID, "id": aggregateID, "version": 1, "state": state,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func reconciliationProjectState(t *testing.T, tenantID, projectID string) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{
		"tenantId": tenantID, "id": projectID, "state": "PLANNING", "version": 1,
		"name": "projection reconciliation", "goalAgentCount": 1,
		"dataClassification": "INTERNAL", "deploymentTargets": []string{},
		"riskTolerance": "MEDIUM", "createdBy": "projection-reconciliation",
		"budgetCurrency": "USD", "budgetHardLimitMinor": 100, "budgetSoftLimitMinor": 80,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
