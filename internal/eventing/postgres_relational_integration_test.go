package eventing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresProjectCreationPersistsPlanningAgents(t *testing.T) {
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
	if _, err := admin.ExecContext(ctx, `INSERT INTO tenants (id, name) VALUES ($1::uuid, $2)`, tenantID, "planning-agents"); err != nil {
		t.Fatal(err)
	}
	projectState, err := json.Marshal(map[string]any{
		"tenantId": tenantID, "id": projectID, "state": "CREATED", "version": 1,
		"name": "planning agents", "goalAgentCount": 2, "dataClassification": "INTERNAL",
		"deploymentTargets": []string{}, "budgetCurrency": "USD", "budgetHardLimitMinor": 100,
		"budgetSoftLimitMinor": 50, "promptBundleVersion": "prompt-v1", "riskTolerance": "MEDIUM",
		"createdBy": "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonicaljson.Digest(projectState)
	if err != nil {
		t.Fatal(err)
	}
	request := TransactionRequest{
		TenantID: tenantID, PrincipalID: "user", IdempotencyKey: "create-project", RequestSHA256: digest,
		Updates: []ProjectionUpdate{{TenantID: tenantID, ProjectID: projectID, AggregateType: "project", AggregateID: projectID, ExpectedVersion: 0, NextVersion: 1, State: projectState}},
		Events:  []DomainEvent{{EventID: uuid.Must(uuid.NewV7()).String(), TenantID: tenantID, ProjectID: projectID, AggregateType: "project", AggregateID: projectID, AggregateVersion: 1, Type: "io.aor.project.created.v1", Payload: projectState, PayloadSHA256: digest, OccurredAt: time.Now().UTC()}},
		Result:  projectState, ResultSHA256: digest,
	}
	if _, err := NewPostgresStore(app).Execute(ctx, request); err != nil {
		t.Fatal(err)
	}
	rows, err := admin.QueryContext(ctx, `
SELECT id, role
FROM agent_instances
WHERE tenant_id = $1::uuid AND project_id = $2::uuid`, tenantID, projectID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	agents := make(map[string]string)
	for rows.Next() {
		var id, role string
		if err := rows.Scan(&id, &role); err != nil {
			t.Fatal(err)
		}
		agents[id] = role
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{
		projectID + ":GOAL_PROPOSER":     "GOAL_PROPOSER",
		projectID + ":GOAL_CHALLENGER":   "GOAL_CHALLENGER",
		projectID + ":KNOWLEDGE_CURATOR": "KNOWLEDGE_CURATOR",
		projectID + ":PLAN_SUPERVISOR":   "PLAN_SUPERVISOR",
	}
	if len(agents) != len(expected) {
		t.Fatalf("agents=%v", agents)
	}
	for id, role := range expected {
		if agents[id] != role {
			t.Fatalf("agent %q role=%q", id, agents[id])
		}
	}
}

func TestPostgresPlanPublicationSynchronizesExecutableRelations(t *testing.T) {
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
	supervisorID := projectID + ":PLAN_SUPERVISOR"
	if _, err := admin.ExecContext(ctx, `
INSERT INTO agent_instances
  (id, tenant_id, project_id, role, provider, logical_model, actual_model_version,
   prompt_bundle_version, state, created_at)
VALUES ($1, $2::uuid, $3::uuid, 'PLAN_SUPERVISOR', 'UNASSIGNED', 'UNASSIGNED', 'UNASSIGNED',
        'prompt-v1', 'DECLARED', $4)`, supervisorID, tenantID, projectID, now); err != nil {
		t.Fatal(err)
	}
	projectState := relationalTestProjectState(tenantID, projectID, plan.PlanSpecVersion, planSHA, goalSHA)
	queuedTaskState := relationalTestStagedTaskState(tenantID, projectID, taskID, seriesID, planSHA, moduleSHA, "QUEUED_PLANNING", 1)
	planningTaskState := relationalTestStagedTaskState(tenantID, projectID, taskID, seriesID, planSHA, moduleSHA, "PLANNING", 2)
	taskState := relationalTestStagedTaskState(tenantID, projectID, taskID, seriesID, planSHA, moduleSHA, "DEFINED", 3)
	if err := insertRelationalTestArtifact(ctx, admin, tenantID, projectID, "plan-artifact", planContent, planSHA, now, "PLAN_SPEC", "plan-1", supervisorID); err != nil {
		t.Fatal(err)
	}
	if err := insertRelationalTestArtifact(ctx, admin, tenantID, projectID, "module-artifact", moduleContent, moduleSHA, now, "MODULE_SPEC", "module-api", projectID+":MODULE_PLANNER:"+taskID); err != nil {
		t.Fatal(err)
	}
	store := NewPostgresStore(app)
	stages := []struct {
		key             string
		eventType       string
		expectedVersion int64
		state           []byte
	}{
		{key: "queue-plan-task", eventType: "io.aor.module.planning-queued.v1", expectedVersion: 0, state: queuedTaskState},
		{key: "start-plan-task", eventType: "io.aor.module.planning-started.v1", expectedVersion: 1, state: planningTaskState},
		{key: "attach-module-spec", eventType: "io.aor.module.spec-attached.v1", expectedVersion: 2, state: taskState},
	}
	for index, stage := range stages {
		if _, err := store.Execute(ctx, relationalTestTaskTransaction(t, tenantID, projectID, taskID, stage.key, stage.eventType, stage.expectedVersion, stage.state)); err != nil {
			t.Fatalf("%s: %v", stage.key, err)
		}
		if _, err := store.LoadReconciliationSnapshot(ctx, tenantID); err != nil {
			t.Fatalf("%s reconciliation: %v", stage.key, err)
		}
		var status, taskStateValue, createdBy, planningAgent string
		var moduleSpecID, moduleCreatedBy, activeSeries sql.NullString
		if err := admin.QueryRowContext(ctx, `
SELECT plan.status, plan.created_by_agent_id, plan.planning_agent_id, task.state, task.module_spec_id::text,
       spec.created_by_agent_id, task.active_attempt_series_id::text
FROM module_tasks task
JOIN plan_specs plan ON plan.tenant_id = task.tenant_id AND plan.id = task.planning_spec_id
LEFT JOIN module_specs spec ON spec.tenant_id = task.tenant_id AND spec.id = task.module_spec_id
WHERE task.tenant_id = $1::uuid AND task.id = $2::uuid`, tenantID, taskID).Scan(
			&status, &createdBy, &planningAgent, &taskStateValue, &moduleSpecID, &moduleCreatedBy, &activeSeries,
		); err != nil {
			t.Fatal(err)
		}
		plannerID := projectID + ":MODULE_PLANNER:" + taskID
		if status != "DRAFT" || createdBy != supervisorID || planningAgent != supervisorID || taskStateValue != []string{"QUEUED_PLANNING", "PLANNING", "DEFINED"}[index] || moduleSpecID.Valid != (index == 2) || moduleCreatedBy.Valid != (index == 2) || index == 2 && moduleCreatedBy.String != plannerID || activeSeries.Valid != (index == 2) {
			t.Fatalf("%s plan=%q creator=%q planning agent=%q task=%q module=%v module creator=%v series=%v", stage.key, status, createdBy, planningAgent, taskStateValue, moduleSpecID, moduleCreatedBy, activeSeries)
		}
		if index == 0 {
			var plannerProjectID, plannerRole string
			if err := admin.QueryRowContext(ctx, `
SELECT project_id::text, role
FROM agent_instances
WHERE tenant_id = $1::uuid AND id = $2`, tenantID, plannerID).Scan(&plannerProjectID, &plannerRole); err != nil {
				t.Fatal(err)
			}
			if plannerProjectID != projectID || plannerRole != "MODULE_PLANNER" {
				t.Fatalf("planner project=%q role=%q", plannerProjectID, plannerRole)
			}
		}
	}
	result, err := json.Marshal(struct {
		Project json.RawMessage   `json:"project"`
		Tasks   []json.RawMessage `json:"tasks"`
	}{Project: projectState, Tasks: []json.RawMessage{taskState}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Execute(ctx, relationalTestPublicationTransaction(t, tenantID, projectID, projectState, result)); err != nil {
		t.Fatal(err)
	}
	events, err := store.ListEvents(ctx, tenantID)
	if err != nil || len(events) != 4 {
		t.Fatalf("stored event count=%d error=%v", len(events), err)
	}
	snapshot, err := store.LoadReconciliationSnapshot(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Events) != 4 || len(snapshot.Projections) != 4 {
		t.Fatalf("durable reconciliation event count=%d projection count=%d", len(snapshot.Events), len(snapshot.Projections))
	}
	for _, event := range snapshot.Events {
		if len(event.ReplayState) == 0 || event.ReplayStateSHA256 == "" {
			t.Fatalf("event has no immutable replay state: %#v", event)
		}
	}
	var legacyTaskState map[string]any
	if err := json.Unmarshal(taskState, &legacyTaskState); err != nil {
		t.Fatal(err)
	}
	legacyTaskState["planningSpecRef"] = map[string]any{"version": 0, "sha256": ""}
	legacyTaskJSON, err := json.Marshal(legacyTaskState)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `
UPDATE module_tasks
SET planning_spec_id = NULL, module_id = NULL
WHERE tenant_id = $1::uuid AND id = $2::uuid`, tenantID, taskID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `
UPDATE aggregate_projections
SET state_jsonb = $3::jsonb
WHERE tenant_id = $1::uuid AND aggregate_type = 'task' AND aggregate_id = $2`, tenantID, taskID, legacyTaskJSON); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadReconciliationSnapshot(ctx, tenantID); err != nil {
		t.Fatalf("legacy task columns reconciliation: %v", err)
	}
	if _, err := admin.ExecContext(ctx, `
UPDATE module_tasks AS task
SET planning_spec_id = spec.plan_spec_id, module_id = spec.module_id
FROM module_specs AS spec
WHERE task.tenant_id = $1::uuid AND task.id = $2::uuid
  AND spec.tenant_id = task.tenant_id AND spec.id = task.module_spec_id`, tenantID, taskID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `
UPDATE aggregate_projections
SET state_jsonb = $3::jsonb
WHERE tenant_id = $1::uuid AND aggregate_type = 'task' AND aggregate_id = $2`, tenantID, taskID, taskState); err != nil {
		t.Fatal(err)
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
	checks := []struct {
		name        string
		driftSQL    string
		driftArgs   []any
		restoreSQL  string
		restoreArgs []any
	}{
		{
			name:        "projects",
			driftSQL:    `UPDATE projects SET state = 'PAUSED' WHERE tenant_id = $1::uuid AND id = $2::uuid`,
			driftArgs:   []any{tenantID, projectID},
			restoreSQL:  `UPDATE projects SET state = 'EXECUTING' WHERE tenant_id = $1::uuid AND id = $2::uuid`,
			restoreArgs: []any{tenantID, projectID},
		},
		{
			name:        "module_tasks",
			driftSQL:    `UPDATE module_tasks SET state = 'READY_EXECUTION' WHERE tenant_id = $1::uuid AND id = $2::uuid`,
			driftArgs:   []any{tenantID, taskID},
			restoreSQL:  `UPDATE module_tasks SET state = 'DEFINED' WHERE tenant_id = $1::uuid AND id = $2::uuid`,
			restoreArgs: []any{tenantID, taskID},
		},
		{
			name:        "plan_specs",
			driftSQL:    `UPDATE plan_specs SET content_jsonb = '{}'::jsonb WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
			driftArgs:   []any{tenantID, projectID},
			restoreSQL:  `UPDATE plan_specs SET content_jsonb = $3::jsonb WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
			restoreArgs: []any{tenantID, projectID, planContent},
		},
		{
			name:        "module_specs",
			driftSQL:    `UPDATE module_specs SET content_jsonb = '{}'::jsonb WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
			driftArgs:   []any{tenantID, projectID},
			restoreSQL:  `UPDATE module_specs SET content_jsonb = $3::jsonb WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
			restoreArgs: []any{tenantID, projectID, moduleContent},
		},
	}
	for _, check := range checks {
		if _, err := admin.ExecContext(ctx, check.driftSQL, check.driftArgs...); err != nil {
			t.Fatalf("drift %s: %v", check.name, err)
		}
		if _, err := store.LoadReconciliationSnapshot(ctx, tenantID); !errors.Is(err, ErrRelationalProjectionDrift) {
			t.Fatalf("%s drift error=%v", check.name, err)
		}
		if _, err := admin.ExecContext(ctx, check.restoreSQL, check.restoreArgs...); err != nil {
			t.Fatalf("restore %s: %v", check.name, err)
		}
	}
	if _, err := store.LoadReconciliationSnapshot(ctx, tenantID); err != nil {
		t.Fatalf("restored relational projection: %v", err)
	}

	secondSeriesID := uuid.Must(uuid.NewV7()).String()
	approvalID := uuid.Must(uuid.NewV7()).String()
	var authorizedState map[string]any
	if err := json.Unmarshal(taskState, &authorizedState); err != nil {
		t.Fatal(err)
	}
	authorizedState["state"] = "READY_EXECUTION"
	authorizedState["version"] = int64(4)
	authorizedState["attemptSeriesId"] = secondSeriesID
	authorizedState["attemptSeriesIds"] = []string{seriesID, secondSeriesID}
	authorizedJSON, err := json.Marshal(authorizedState)
	if err != nil {
		t.Fatal(err)
	}
	authorize := relationalTestTaskTransaction(t, tenantID, projectID, taskID, "authorize-second-series", "io.aor.module.attempt-series-authorized.v1", 3, authorizedJSON)
	authorize.PrincipalID = "user"
	authorize.Approvals = []ApprovalRecord{{
		ID: approvalID, TenantID: tenantID, ProjectID: projectID,
		ApprovalType: "AUTHORIZE_NEW_ATTEMPT_SERIES", SubjectType: "MODULE_TASK", SubjectID: taskID,
		SubjectVersion: 1, SubjectSHA256: moduleSHA, PrincipalID: "user", Reason: "test authorization",
		IssuedAt: now, Signature: "test-signature",
	}}
	if _, err := store.Execute(ctx, authorize); err != nil {
		t.Fatalf("authorize second attempt series: %v", err)
	}

	var executingState map[string]any
	if err := json.Unmarshal(authorizedJSON, &executingState); err != nil {
		t.Fatal(err)
	}
	executingState["state"] = "EXECUTING"
	executingState["version"] = int64(5)
	executingState["fencingToken"] = int64(1)
	executingJSON, err := json.Marshal(executingState)
	if err != nil {
		t.Fatal(err)
	}
	lease := relationalTestTaskTransaction(t, tenantID, projectID, taskID, "lease-second-series", "io.aor.module.execution-leased.v1", 4, executingJSON)
	if _, err := store.Execute(ctx, lease); err != nil {
		t.Fatalf("reuse authorized attempt series without repeated approval: %v", err)
	}

	var storedApprovalID, storedActiveSeries, storedExecutionState string
	if err := admin.QueryRowContext(ctx, `
SELECT series.authorized_by_approval_id::text, task.active_attempt_series_id::text, task.state
FROM module_tasks AS task
JOIN attempt_series AS series ON series.tenant_id = task.tenant_id AND series.id = task.active_attempt_series_id
WHERE task.tenant_id = $1::uuid AND task.id = $2::uuid`, tenantID, taskID).Scan(&storedApprovalID, &storedActiveSeries, &storedExecutionState); err != nil {
		t.Fatal(err)
	}
	if storedApprovalID != approvalID || storedActiveSeries != secondSeriesID || storedExecutionState != "EXECUTING" {
		t.Fatalf("approval=%q active series=%q task state=%q", storedApprovalID, storedActiveSeries, storedExecutionState)
	}
}

func relationalTestTaskTransaction(t *testing.T, tenantID, projectID, taskID, key, eventType string, expectedVersion int64, taskState []byte) TransactionRequest {
	t.Helper()
	payloadDigest, err := canonicaljson.Digest(taskState)
	if err != nil {
		t.Fatal(err)
	}
	requestPayload, err := json.Marshal(map[string]string{"stage": key})
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, err := canonicaljson.Digest(requestPayload)
	if err != nil {
		t.Fatal(err)
	}
	principalID := projectID + ":PLAN_SUPERVISOR"
	if expectedVersion > 0 {
		principalID = projectID + ":MODULE_PLANNER:" + taskID
	}
	nextVersion := expectedVersion + 1
	now := time.Date(2030, 1, 2, 3, 4, 6, 0, time.UTC)
	return TransactionRequest{
		TenantID: tenantID, PrincipalID: principalID, IdempotencyKey: key, RequestSHA256: requestDigest,
		Updates: []ProjectionUpdate{{TenantID: tenantID, ProjectID: projectID, AggregateType: "task", AggregateID: taskID, ExpectedVersion: expectedVersion, NextVersion: nextVersion, State: taskState}},
		Events: []DomainEvent{
			{EventID: uuid.Must(uuid.NewV7()).String(), TenantID: tenantID, ProjectID: projectID, AggregateType: "task", AggregateID: taskID, AggregateVersion: nextVersion, Type: eventType, Payload: taskState, PayloadSHA256: payloadDigest, OccurredAt: now},
		},
		Result: taskState, ResultSHA256: payloadDigest,
	}
}

func relationalTestPublicationTransaction(t *testing.T, tenantID, projectID string, projectState, result []byte) TransactionRequest {
	t.Helper()
	projectDigest, err := canonicaljson.Digest(projectState)
	if err != nil {
		t.Fatal(err)
	}
	resultDigest, err := canonicaljson.Digest(result)
	if err != nil {
		t.Fatal(err)
	}
	requestPayload, err := json.Marshal(map[string]string{"stage": "publish-plan"})
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, err := canonicaljson.Digest(requestPayload)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 1, 2, 3, 4, 6, 0, time.UTC)
	return TransactionRequest{
		TenantID: tenantID, PrincipalID: projectID + ":PLAN_SUPERVISOR", IdempotencyKey: "publish-plan", RequestSHA256: requestDigest,
		Updates: []ProjectionUpdate{{TenantID: tenantID, ProjectID: projectID, AggregateType: "project", AggregateID: projectID, ExpectedVersion: 4, NextVersion: 5, State: projectState}},
		Events:  []DomainEvent{{EventID: uuid.Must(uuid.NewV7()).String(), TenantID: tenantID, ProjectID: projectID, AggregateType: "project", AggregateID: projectID, AggregateVersion: 5, Type: "io.aor.plan.published.v1", Payload: projectState, PayloadSHA256: projectDigest, OccurredAt: now}},
		Result:  result, ResultSHA256: resultDigest,
	}
}

func insertRelationalTestArtifact(ctx context.Context, db *sql.DB, tenantID, projectID, aggregateID string, content []byte, digest string, createdAt time.Time, kind, specID, createdBy string) error {
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
	}{tenantID, projectID, kind, specID, 1, digest, digest, "artifact://sha256/" + digest[len("sha256:"):], "application/json", content, createdAt, createdBy})
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

func relationalTestStagedTaskState(tenantID, projectID, taskID, seriesID, planSHA, moduleSHA, taskState string, version int64) []byte {
	value := map[string]any{
		"tenantId": tenantID, "projectId": projectID, "id": taskID, "moduleId": "module-api", "state": taskState, "version": version,
		"planningSpecRef": map[string]any{"version": 1, "sha256": planSHA},
		"moduleSpecRef":   map[string]any{"version": 0, "sha256": ""},
		"attemptSeriesId": "", "attemptSeriesIds": []string{}, "attempt": 0, "fencingToken": 0,
		"dependentTaskIds": []string{}, "blockingTaskIds": []string{},
	}
	if taskState == "DEFINED" {
		value["moduleSpecRef"] = map[string]any{"version": 1, "sha256": moduleSHA}
		value["attemptSeriesId"] = seriesID
		value["attemptSeriesIds"] = []string{seriesID}
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
