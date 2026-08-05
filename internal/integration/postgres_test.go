package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresStoreRequiresDatabase(t *testing.T) {
	if _, err := NewPostgresStore(nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil database error = %v", err)
	}
}

func TestPostgresStoreValidatesDurableMergeShape(t *testing.T) {
	result := MergeResult{
		TenantID:      "11111111-1111-4111-8111-111111111111",
		ProjectID:     "22222222-2222-4222-8222-222222222222",
		IntegrationID: "33333333-3333-4333-8333-333333333333",
		RequestDigest: digest("request"),
		Pending:       true,
		Audit: Audit{
			IntegrationID:  "33333333-3333-4333-8333-333333333333",
			ProjectID:      "22222222-2222-4222-8222-222222222222",
			EvidenceSHA256: digest("audit"),
			Passed:         true,
			CreatedAt:      time.Now().UTC(),
		},
	}
	if !validMergeResult(result, true) {
		t.Fatal("valid pending merge was rejected")
	}
	result.Pending = false
	result.Commit = commit(7)
	if !validMergeResult(result, false) {
		t.Fatal("valid completed merge was rejected")
	}
	result.Audit.Findings = []Finding{{ID: "unexpected"}}
	if validMergeResult(result, false) {
		t.Fatal("passing merge with findings was accepted")
	}
}

func TestPostgresStorePersistsMergeAndImmutableConflict(t *testing.T) {
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
	tenantID := uuid.Must(uuid.NewV7()).String()
	projectID := uuid.Must(uuid.NewV7()).String()
	integrationID := uuid.Must(uuid.NewV7()).String()
	if _, err := admin.ExecContext(ctx, `INSERT INTO tenants (id, name) VALUES ($1::uuid, $2)`, tenantID, "integration-store"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `
INSERT INTO projects
  (id, tenant_id, name, state, state_version, data_classification,
   risk_tolerance, goal_agent_count, created_by)
VALUES ($1::uuid, $2::uuid, $3, 'INTEGRATING', 1, 'INTERNAL', 'MEDIUM', 1, 'integration-test')`, projectID, tenantID, "integration-store"); err != nil {
		t.Fatal(err)
	}
	store, err := NewPostgresStore(app)
	if err != nil {
		t.Fatal(err)
	}
	result := MergeResult{
		TenantID: tenantID, ProjectID: projectID, IntegrationID: integrationID,
		RequestDigest: digest("request"), Pending: true,
		Audit: Audit{IntegrationID: integrationID, ProjectID: projectID, EvidenceSHA256: digest("audit"), Passed: true, CreatedAt: time.Now().UTC()},
	}
	reserved, owner, err := store.Reserve(ctx, result)
	if err != nil || !owner || !reserved.Pending {
		t.Fatalf("reserve = (%#v, %t, %v)", reserved, owner, err)
	}
	replay, owner, err := store.Reserve(ctx, result)
	if err != nil || owner || replay.RequestDigest != result.RequestDigest {
		t.Fatalf("reserve replay = (%#v, %t, %v)", replay, owner, err)
	}
	result.Pending = false
	result.Commit = commit(7)
	if err := store.Complete(ctx, result); err != nil {
		t.Fatal(err)
	}
	if err := store.Complete(ctx, result); err != nil {
		t.Fatalf("complete replay: %v", err)
	}
	stored, found, err := store.Get(ctx, tenantID, integrationID)
	if err != nil || !found || stored.Pending || stored.Commit != result.Commit {
		t.Fatalf("stored result = (%#v, %t, %v)", stored, found, err)
	}

	conflictID := uuid.Must(uuid.NewV7()).String()
	conflict := MergeResult{
		TenantID: tenantID, ProjectID: projectID, IntegrationID: conflictID,
		Audit: Audit{
			IntegrationID: conflictID, ProjectID: projectID, EvidenceSHA256: digest("conflict-audit"), CreatedAt: time.Now().UTC(),
			Findings: []Finding{{ID: "interface-conflict-task-1-task-2", Severity: "BLOCKING", Category: "INTERFACE", Summary: "public interface is owned by multiple modules", Tasks: []string{"task-1", "task-2"}}},
		},
	}
	recorded, created, err := store.RecordConflict(ctx, conflict)
	if err != nil || !created || !sameConflictResult(recorded, conflict) {
		t.Fatalf("record conflict = (%#v, %t, %v)", recorded, created, err)
	}
	replayedConflict := cloneResult(conflict)
	replayedConflict.Audit.CreatedAt = replayedConflict.Audit.CreatedAt.Add(time.Hour)
	replayed, created, err := store.RecordConflict(ctx, replayedConflict)
	if err != nil || created || !sameConflictResult(replayed, conflict) || !replayed.Audit.CreatedAt.Equal(conflict.Audit.CreatedAt) {
		t.Fatalf("record conflict replay = (%#v, %t, %v)", replayed, created, err)
	}
	changedConflict := cloneResult(conflict)
	changedConflict.Audit.Findings[0].Summary = "changed conflict"
	if _, _, err := store.RecordConflict(ctx, changedConflict); !errors.Is(err, ErrImmutable) {
		t.Fatalf("changed conflict error = %v", err)
	}
	storedConflict, found, err := store.Get(ctx, tenantID, conflictID)
	if err != nil || !found || !sameConflictResult(storedConflict, conflict) {
		t.Fatalf("stored conflict = (%#v, %t, %v)", storedConflict, found, err)
	}
	otherTenantID := uuid.Must(uuid.NewV7()).String()
	if _, found, err := store.Get(ctx, otherTenantID, conflictID); err != nil || found {
		t.Fatalf("cross-tenant conflict lookup found=%t error=%v", found, err)
	}
	var state string
	var encodedAudit []byte
	var mergeFieldsNull bool
	if err := admin.QueryRowContext(ctx, `
SELECT state, conflict_jsonb,
       merge_request_sha256 IS NULL AND merge_audit_sha256 IS NULL
       AND merge_result_jsonb IS NULL AND merge_commit IS NULL AND merge_pending IS NULL
FROM integration_tasks
WHERE tenant_id = $1::uuid AND id = $2::uuid`, tenantID, conflictID).Scan(&state, &encodedAudit, &mergeFieldsNull); err != nil {
		t.Fatal(err)
	}
	var persistedAudit Audit
	if err := json.Unmarshal(encodedAudit, &persistedAudit); err != nil {
		t.Fatal(err)
	}
	if state != "REWORK_REQUIRED" || !mergeFieldsNull || persistedAudit.EvidenceSHA256 != conflict.Audit.EvidenceSHA256 || persistedAudit.Findings[0].Summary != conflict.Audit.Findings[0].Summary {
		t.Fatalf("durable conflict state=%q mergeFieldsNull=%t audit=%#v", state, mergeFieldsNull, persistedAudit)
	}
}
