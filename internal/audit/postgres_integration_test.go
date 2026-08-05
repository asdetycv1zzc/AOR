package audit

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresAuditRunStorePersistsCompletedRunIdempotently(t *testing.T) {
	adminDSN := os.Getenv("AOR_TEST_POSTGRES_DSN")
	appDSN := os.Getenv("AOR_TEST_POSTGRES_APP_DSN")
	if adminDSN == "" || appDSN == "" {
		t.Log("INCONCLUSIVE: Postgres integration environment is not configured")
		return
	}
	admin, err := sql.Open("pgx", adminDSN)
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
	run := validStoredAuditRun()
	run.TenantID = uuid.Must(uuid.NewV7()).String()
	run.ProjectID = uuid.Must(uuid.NewV7()).String()
	run.SubmissionID = uuid.Must(uuid.NewV7()).String()
	run.ID = uuid.Must(uuid.NewV7()).String()
	goalID := uuid.Must(uuid.NewV7()).String()
	planID := uuid.Must(uuid.NewV7()).String()
	moduleSpecID := uuid.Must(uuid.NewV7()).String()
	taskID := uuid.Must(uuid.NewV7()).String()
	attemptSeriesID := uuid.Must(uuid.NewV7()).String()

	if _, err := admin.ExecContext(ctx, `INSERT INTO tenants (id, name) VALUES ($1::uuid, $2)`, run.TenantID, "audit-store"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `
INSERT INTO projects
  (id, tenant_id, name, state, state_version, data_classification, risk_tolerance,
   goal_agent_count, created_by)
VALUES ($1::uuid, $2::uuid, $3, 'EXECUTING', 1, 'INTERNAL', 'MEDIUM', 1, 'audit-test')`,
		run.ProjectID, run.TenantID, "audit-store"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `
INSERT INTO goal_specs
  (id, tenant_id, project_id, version, status, schema_version, content_jsonb,
   content_sha256, proposer_agent_id, approved_by, approved_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, 1, 'APPROVED', 1, '{}'::jsonb, $4,
        'goal-proposer', 'user', transaction_timestamp())`,
		goalID, run.TenantID, run.ProjectID, digestBytes([]byte("goal"))); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `
INSERT INTO plan_specs
  (id, tenant_id, project_id, goal_spec_id, version, status, schema_version,
   content_jsonb, content_sha256, created_by_agent_id)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, 'PUBLISHED', 1, '{}'::jsonb,
        $5, 'plan-supervisor')`,
		planID, run.TenantID, run.ProjectID, goalID, digestBytes([]byte("plan"))); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `
INSERT INTO module_specs
  (id, tenant_id, project_id, plan_spec_id, module_id, version, risk_level,
   execution_platform, isolation_level, schema_version, content_jsonb, content_sha256)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'audit-module', 1, 'HIGH',
        'LINUX', 'CONTAINER', 1, '{}'::jsonb, $5)`,
		moduleSpecID, run.TenantID, run.ProjectID, planID, digestBytes([]byte("module"))); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `
INSERT INTO module_tasks
  (id, tenant_id, project_id, module_spec_id, state, state_version, attempt_count)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'SUBMITTED', 1, 1)`,
		taskID, run.TenantID, run.ProjectID, moduleSpecID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `
INSERT INTO attempt_series
  (id, tenant_id, module_task_id, module_spec_id, series_number)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1)`,
		attemptSeriesID, run.TenantID, taskID, moduleSpecID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `
INSERT INTO submissions
  (id, tenant_id, project_id, module_task_id, attempt_series_id, attempt,
   base_commit, head_commit, schema_version, manifest_jsonb, manifest_sha256,
   created_by_agent_id, idempotency_key, request_sha256)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, 1,
        '0000000000000000000000000000000000000001',
        '0000000000000000000000000000000000000002', 1, '{}'::jsonb, $6,
        'executor', 'audit-test', $7)`,
		run.SubmissionID, run.TenantID, run.ProjectID, taskID, attemptSeriesID,
		digestBytes([]byte("manifest")), digestBytes([]byte("request"))); err != nil {
		t.Fatal(err)
	}

	store, err := NewPostgresAuditRunStore(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, run); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, run); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	conflict := run
	conflict.Verdict = "PASS"
	if err := store.Put(ctx, conflict); !errors.Is(err, ErrAuditRunConflict) {
		t.Fatalf("conflicting replay error = %v", err)
	}

	canonical, err := canonicalAuditRun(run)
	if err != nil {
		t.Fatal(err)
	}
	var state, verdict, evidenceRef, observed string
	var runCount, findingCount int
	if err := admin.QueryRowContext(ctx, `
SELECT count(*), max(state), max(verdict), max(evidence_bundle_ref)
FROM audit_runs
WHERE tenant_id = $1::uuid AND id = $2::uuid`, run.TenantID, run.ID).Scan(
		&runCount, &state, &verdict, &evidenceRef); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRowContext(ctx, `
SELECT count(*), max(content_jsonb->>'observedBehavior')
FROM audit_findings
WHERE tenant_id = $1::uuid AND audit_run_id = $2::uuid`, run.TenantID, run.ID).Scan(
		&findingCount, &observed); err != nil {
		t.Fatal(err)
	}
	if runCount != 1 || findingCount != 1 || state != auditRunCompleted || verdict != run.Verdict || evidenceRef != run.EvidenceBundleRef || observed != canonical.Findings[0].ObservedBehavior {
		t.Fatalf("stored audit run is incomplete: runs=%d findings=%d state=%s verdict=%s evidence=%s observed=%s", runCount, findingCount, state, verdict, evidenceRef, observed)
	}
}
