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
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresPlanPublicationSynchronizesExecutableRelations(t *testing.T) {
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
	goalID := uuid.Must(uuid.NewV7()).String()
	taskID := uuid.Must(uuid.NewV7()).String()
	seriesID := uuid.Must(uuid.NewV7()).String()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	if _, err := admin.ExecContext(ctx, `INSERT INTO tenants (id, name) VALUES ($1::uuid, $2)`, tenantID, "relational-sync"); err != nil {
		t.Fatal(err)
	}
	goalSHA := "sha256:" + strings.Repeat("1", 64)
	plan, planContent, planSHA := relationalTestPlan(t, projectID, goalSHA)
	_, moduleContent, moduleSHA := relationalTestModule(t, projectID, plan.PlanSpecVersion)
	if _, err := admin.ExecContext(ctx, `
INSERT INTO projects
  (id, tenant_id, name, state, state_version, data_classification, deployment_targets_jsonb,
   risk_tolerance, goal_agent_count, created_by, created_at, updated_at)
VALUES ($1::uuid, $2::uuid, 'relational test', 'PLANNING', 4, 'INTERNAL', '[]'::jsonb,
        'MEDIUM', 1, 'test', $3, $3)`, projectID, tenantID, now); err != nil {
		t.Fatal(err)
	}
	initialProjectState := relationalTestInitialProjectState(tenantID, projectID)
	if _, err := admin.ExecContext(ctx, `
INSERT INTO aggregate_projections
  (tenant_id, project_id, aggregate_type, aggregate_id, aggregate_version, schema_version, state_jsonb, updated_at)
VALUES ($1::uuid, $2::uuid, 'project', $2, 4, 1, $3::jsonb, $4)`, tenantID, projectID, initialProjectState, now); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `
INSERT INTO goal_specs
  (id, tenant_id, project_id, version, status, schema_version, content_jsonb, content_sha256,
   proposer_agent_id, approved_by, approved_at, created_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, 1, 'APPROVED', 1, '{}'::jsonb, $4,
        'agent_goal', 'user', $5, $5)`, goalID, tenantID, projectID, goalSHA, now); err != nil {
		t.Fatal(err)
	}
	projectState := relationalTestProjectState(tenantID, projectID, plan.PlanSpecVersion, planSHA, goalSHA)
	taskState := relationalTestTaskState(tenantID, projectID, taskID, seriesID, moduleSHA)
	if err := insertRelationalTestArtifact(ctx, admin, tenantID, projectID, "plan-artifact", planContent, planSHA, now, "PLAN_SPEC", "plan-1"); err != nil {
		t.Fatal(err)
	}
	if err := insertRelationalTestArtifact(ctx, admin, tenantID, projectID, "module-artifact", moduleContent, moduleSHA, now, "MODULE_SPEC", "module-api"); err != nil {
		t.Fatal(err)
	}
	result, err := json.Marshal(struct {
		Project json.RawMessage   `json:"project"`
		Tasks   []json.RawMessage `json:"tasks"`
	}{Project: projectState, Tasks: []json.RawMessage{taskState}})
	if err != nil {
		t.Fatal(err)
	}
	request := relationalTestTransaction(t, tenantID, projectID, taskID, projectState, taskState, result)
	store := NewPostgresStore(app)
	if _, err := store.Execute(ctx, request); err != nil {
		t.Fatal(err)
	}
	events, err := store.ListEvents(ctx, tenantID)
	if err != nil || len(events) != 2 {
		t.Fatalf("stored event count=%d error=%v", len(events), err)
	}
	snapshot, err := store.LoadReconciliationSnapshot(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Events) != 2 || len(snapshot.Projections) != 4 {
		t.Fatalf("durable reconciliation event count=%d projection count=%d", len(snapshot.Events), len(snapshot.Projections))
	}
	for _, event := range snapshot.Events {
		if len(event.ReplayState) == 0 || event.ReplayStateSHA256 == "" {
			t.Fatalf("event has no immutable replay state: %#v", event)
		}
	}
	var planCount, moduleCount, taskCount, seriesCount, dependencyCount int
	if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM plan_specs WHERE tenant_id = $1::uuid AND project_id = $2::uuid`, tenantID, projectID).Scan(&planCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM module_specs WHERE tenant_id = $1::uuid AND project_id = $2::uuid`, tenantID, projectID).Scan(&moduleCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM module_tasks WHERE tenant_id = $1::uuid AND project_id = $2::uuid`, tenantID, projectID).Scan(&taskCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM attempt_series WHERE tenant_id = $1::uuid AND module_task_id = $2::uuid`, tenantID, taskID).Scan(&seriesCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM task_dependencies WHERE tenant_id = $1::uuid AND task_id = $2::uuid`, tenantID, taskID).Scan(&dependencyCount); err != nil {
		t.Fatal(err)
	}
	if planCount != 1 || moduleCount != 1 || taskCount != 1 || seriesCount != 1 || dependencyCount != 0 {
		t.Fatalf("relational counts plan=%d module=%d task=%d series=%d dependencies=%d", planCount, moduleCount, taskCount, seriesCount, dependencyCount)
	}
	var activePlan, activeGoal, state string
	if err := admin.QueryRowContext(ctx, `SELECT active_plan_spec_id::text, active_goal_spec_id::text, state FROM projects WHERE tenant_id = $1::uuid AND id = $2::uuid`, tenantID, projectID).Scan(&activePlan, &activeGoal, &state); err != nil {
		t.Fatal(err)
	}
	if activePlan == "" || activeGoal != goalID || state != "EXECUTING" {
		t.Fatalf("active bindings plan=%q goal=%q state=%q", activePlan, activeGoal, state)
	}
	var storedState, activeSeries string
	if err := admin.QueryRowContext(ctx, `SELECT state, active_attempt_series_id::text FROM module_tasks WHERE tenant_id = $1::uuid AND id = $2::uuid`, tenantID, taskID).Scan(&storedState, &activeSeries); err != nil {
		t.Fatal(err)
	}
	if storedState != "DEFINED" || activeSeries != seriesID {
		t.Fatalf("task state=%q active series=%q", storedState, activeSeries)
	}
}

func relationalTestTransaction(t *testing.T, tenantID, projectID, taskID string, projectState, taskState, result []byte) TransactionRequest {
	t.Helper()
	projectDigest, err := canonicaljson.Digest(projectState)
	if err != nil {
		t.Fatal(err)
	}
	taskDigest, err := canonicaljson.Digest(taskState)
	if err != nil {
		t.Fatal(err)
	}
	resultDigest, err := canonicaljson.Digest(result)
	if err != nil {
		t.Fatal(err)
	}
	projectEventID := uuid.Must(uuid.NewV7()).String()
	taskEventID := uuid.Must(uuid.NewV7()).String()
	now := time.Date(2030, 1, 2, 3, 4, 6, 0, time.UTC)
	return TransactionRequest{
		TenantID: tenantID, PrincipalID: "agent_plan", IdempotencyKey: "publish-plan", RequestSHA256: "sha256:" + strings.Repeat("9", 64),
		Updates: []ProjectionUpdate{
			{TenantID: tenantID, ProjectID: projectID, AggregateType: "project", AggregateID: projectID, ExpectedVersion: 4, NextVersion: 5, State: projectState},
			{TenantID: tenantID, ProjectID: projectID, AggregateType: "task", AggregateID: taskID, ExpectedVersion: 0, NextVersion: 1, State: taskState},
		},
		Events: []DomainEvent{
			{EventID: projectEventID, TenantID: tenantID, ProjectID: projectID, AggregateType: "project", AggregateID: projectID, AggregateVersion: 5, Type: "io.aor.plan.published.v1", Payload: projectState, PayloadSHA256: projectDigest, OccurredAt: now},
			{EventID: taskEventID, TenantID: tenantID, ProjectID: projectID, AggregateType: "task", AggregateID: taskID, AggregateVersion: 1, Type: "io.aor.module.defined.v1", Payload: taskState, PayloadSHA256: taskDigest, OccurredAt: now},
		},
		Result: result, ResultSHA256: resultDigest,
	}
}

func insertRelationalTestArtifact(ctx context.Context, db *sql.DB, tenantID, projectID, aggregateID string, content []byte, digest string, createdAt time.Time, kind, specID string) error {
	state, err := json.Marshal(struct {
		TenantID       string    `json:"tenantId"`
		ProjectID      string    `json:"projectId"`
		Kind           string    `json:"kind"`
		SpecID         string    `json:"specId"`
		Version        int       `json:"version"`
		ContentSHA256  string    `json:"contentSha256"`
		ArtifactSHA256 string    `json:"artifactSha256"`
		URI            string    `json:"uri"`
		MediaType      string    `json:"mediaType"`
		Content        []byte    `json:"content"`
		CreatedAt      time.Time `json:"createdAt"`
		CreatedBy      string    `json:"createdBy"`
	}{tenantID, projectID, kind, specID, 1, digest, digest, "artifact://sha256/" + digest[len("sha256:"):], "application/json", content, createdAt, "agent_plan"})
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO aggregate_projections
  (tenant_id, project_id, aggregate_type, aggregate_id, aggregate_version, schema_version, state_jsonb, updated_at)
VALUES ($1::uuid, $2::uuid, 'spec_artifact', $3, 1, 1, $4::jsonb, $5)`, tenantID, projectID, aggregateID, state, createdAt)
	return err
}

func relationalTestInitialProjectState(tenantID, projectID string) []byte {
	value := map[string]any{
		"tenantId": tenantID, "id": projectID, "state": "PLANNING", "version": 4,
	}
	encoded, _ := json.Marshal(value)
	return encoded
}

func relationalTestProjectState(tenantID, projectID string, planVersion int, planSHA, goalSHA string) []byte {
	value := map[string]any{
		"tenantId": tenantID, "id": projectID, "state": "EXECUTING", "version": 5,
		"goal": map[string]any{"id": "goal-logical", "version": 1, "sha256": goalSHA, "status": "APPROVED"},
		"plan": map[string]any{"version": planVersion, "sha256": planSHA},
	}
	encoded, _ := json.Marshal(value)
	return encoded
}

func relationalTestTaskState(tenantID, projectID, taskID, seriesID, moduleSHA string) []byte {
	value := map[string]any{
		"tenantId": tenantID, "projectId": projectID, "id": taskID, "state": "DEFINED", "version": 1,
		"moduleSpecRef":   map[string]any{"version": 1, "sha256": moduleSHA},
		"attemptSeriesId": seriesID, "attemptSeriesIds": []string{seriesID}, "attempt": 0, "fencingToken": 0,
		"dependentTaskIds": []string{}, "blockingTaskIds": []string{},
	}
	encoded, _ := json.Marshal(value)
	return encoded
}

func relationalTestPlan(t *testing.T, projectID, goalSHA string) (contracts.PlanSpec, []byte, string) {
	t.Helper()
	plan := contracts.PlanSpec{
		PlanSpecVersion: 1, ProjectID: projectID, GoalSpecRef: contracts.SpecRef{Version: 1, SHA256: goalSHA},
		Architecture:      contracts.Architecture{Style: "service", Components: []string{"api"}, DataFlows: []string{"request"}, TrustBoundaries: []string{"tenant"}, DeploymentUnits: []string{"api"}},
		QualityAttributes: []string{"reliability"}, IntegrationPlan: []string{"merge"}, ReleasePlan: []string{"deploy"}, TestStrategy: []string{"unit"}, RollbackStrategy: []string{"revert"}, OpenDecisions: []string{},
		Modules: []contracts.PlanModule{{ModuleID: "module-api", Name: "API", Responsibility: "serve", ExecutionPlatform: contracts.PlatformLinux, SandboxLevel: contracts.IsolationContainer, OwnedPaths: []string{"internal/api"}, ForbiddenPaths: []string{}, PublicInterfaces: []string{"HTTP"}, Dependencies: []string{}, AcceptanceCriteria: []string{"works"}, Risk: "MEDIUM"}},
	}
	unsigned, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(unsigned, "sha256", "signature")
	if err != nil {
		t.Fatal(err)
	}
	plan.SHA256 = digest
	content, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return plan, content, digest
}

func relationalTestModule(t *testing.T, projectID string, planVersion int) (contracts.ModuleSpec, []byte, string) {
	t.Helper()
	module := contracts.ModuleSpec{
		ModuleSpecVersion: 1, ModuleID: "module-api", ProjectID: projectID, PlanVersion: planVersion,
		Name: "API", Purpose: "serve", Responsibilities: []string{"serve"}, NonResponsibilities: []string{"database"}, Inputs: []string{"request"}, Outputs: []string{"response"}, Interfaces: []string{"HTTP"}, DataOwnership: []string{"api"}, Dependencies: []string{}, AllowedPaths: []string{"internal/api"}, ForbiddenPaths: []string{},
		ExecutionPlatform: contracts.PlatformLinux, SandboxLevel: contracts.IsolationContainer,
		NetworkPolicy: contracts.NetworkPolicy{Mode: contracts.NetworkDenyAll, Destinations: []string{}}, WorkloadProfile: contracts.WorkloadProfile{Trust: contracts.WorkloadUntrusted, HostileMultiTenant: true, RequiresNetworkIsolation: true, RequiresHiddenTestConfidentiality: true},
		ToolCapabilities: []string{}, KnowledgeRefs: []string{}, AcceptanceCriteria: []string{"works"}, TestRequirements: []string{"unit"}, ObservabilityRequirements: []string{}, SecurityRequirements: []string{"isolation"}, Budget: contracts.Budget{MaxInputTokens: 1, MaxOutputTokens: 1, MaxCost: "0", Currency: "USD"},
	}
	unsigned, err := json.Marshal(module)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(unsigned, "sha256", "signature")
	if err != nil {
		t.Fatal(err)
	}
	module.SHA256 = digest
	content, err := json.Marshal(module)
	if err != nil {
		t.Fatal(err)
	}
	return module, content, digest
}
