package orchestrator

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/state"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresGoalLifecycleIsAtomicAndRelationallyProjected(t *testing.T) {
	dsn := os.Getenv("AOR_TEST_POSTGRES_DSN")
	appDSN := os.Getenv("AOR_TEST_POSTGRES_APP_DSN")
	if dsn == "" || appDSN == "" {
		t.Log("INCONCLUSIVE: Postgres integration environment is not configured; set AOR_TEST_POSTGRES_DSN and AOR_TEST_POSTGRES_APP_DSN to execute this test")
		return
	}
	adminDatabase, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer adminDatabase.Close()
	database, err := sql.Open("pgx", appDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	if err := adminDatabase.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := database.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	tenantID := uuid.Must(uuid.NewV7()).String()
	projectID := uuid.Must(uuid.NewV7()).String()
	goalID := uuid.Must(uuid.NewV7()).String()
	if _, err := adminDatabase.ExecContext(ctx, `INSERT INTO tenants (id, name) VALUES ($1::uuid, $2)`, tenantID, "goal-integration"); err != nil {
		t.Fatal(err)
	}
	store := eventing.NewPostgresStore(database)
	service := newTestService(store)
	commands := []ProjectRequest{
		{TenantID: tenantID, ProjectID: projectID, PrincipalID: "usr_goal", IdempotencyKey: "create", ExpectedVersion: 0, Command: state.ProjectCommand{Type: state.ProjectCommandCreate, GoalAgentCount: 1}},
		{TenantID: tenantID, ProjectID: projectID, PrincipalID: "usr_goal", IdempotencyKey: "start", ExpectedVersion: 1, Command: state.ProjectCommand{Type: state.ProjectCommandStartGoalNegotiation}},
	}
	for _, command := range commands {
		if _, err := service.HandleProject(ctx, command); err != nil {
			t.Fatal(err)
		}
	}
	draft := testGoalSpec(t, projectID, 1, nil)
	goal := &state.GoalRecord{ID: goalID, Version: 1, SHA256: draft.ContentSHA256}
	if _, err := service.HandleProject(ctx, ProjectRequest{
		TenantID: tenantID, ProjectID: projectID, PrincipalID: "agt_goal", IdempotencyKey: "propose", ExpectedVersion: 2,
		Command: state.ProjectCommand{Type: state.ProjectCommandProposeGoal, Goal: goal, GoalSpec: &draft},
	}); err != nil {
		t.Fatal(err)
	}
	approvalID := uuid.Must(uuid.NewV7()).String()
	if _, err := service.HandleProject(ctx, ProjectRequest{
		TenantID: tenantID, ProjectID: projectID, PrincipalID: "usr_goal", IdempotencyKey: "approve", ExpectedVersion: 3,
		Command: state.ProjectCommand{Type: state.ProjectCommandApproveGoal, Goal: goal, Approval: &state.ApprovalBinding{
			RecordID: approvalID, ApprovalType: "GOAL_APPROVAL", SubjectType: "GOAL_SPEC", SubjectID: goalID, SubjectVersion: 1,
			SubjectSHA256: draft.ContentSHA256, PrincipalID: "usr_goal", Reason: "integration approval", IssuedAt: fixedClock(), Signature: "authenticated",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	var status string
	var approvedBy string
	if err := adminDatabase.QueryRowContext(ctx, `SELECT status, approved_by FROM goal_specs WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND version = 1`, tenantID, projectID).Scan(&status, &approvedBy); err != nil {
		t.Fatal(err)
	}
	if status != "APPROVED" || approvedBy != "usr_goal" {
		t.Fatalf("GoalSpec row status=%q approvedBy=%q", status, approvedBy)
	}
	var eventCount int
	var outboxCount int
	var approvalCount int
	if err := adminDatabase.QueryRowContext(ctx, `SELECT count(*) FROM domain_events WHERE tenant_id = $1::uuid AND project_id = $2::uuid`, tenantID, projectID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if err := adminDatabase.QueryRowContext(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1::uuid`, tenantID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if err := adminDatabase.QueryRowContext(ctx, `SELECT count(*) FROM approvals WHERE tenant_id = $1::uuid AND project_id = $2::uuid`, tenantID, projectID).Scan(&approvalCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 6 || outboxCount != eventCount || approvalCount != 1 {
		t.Fatalf("eventCount=%d outboxCount=%d approvalCount=%d", eventCount, outboxCount, approvalCount)
	}
	var granted bool
	if err := adminDatabase.QueryRowContext(ctx, `SELECT has_table_privilege('aor_app', 'public.goal_specs', 'SELECT') AND has_table_privilege('aor_app', 'public.goal_specs', 'INSERT') AND has_table_privilege('aor_app', 'public.goal_specs', 'UPDATE')`).Scan(&granted); err != nil {
		t.Fatal(err)
	}
	if !granted {
		t.Fatal("aor_app lacks GoalSpec runtime privileges")
	}
}
