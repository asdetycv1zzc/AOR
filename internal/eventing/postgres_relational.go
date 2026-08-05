package eventing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
	"github.com/google/uuid"
)

const (
	planArtifactKind   = "PLAN_SPEC"
	moduleArtifactKind = "MODULE_SPEC"
)

type relationalSpecArtifact struct {
	TenantID      string          `json:"tenantId"`
	ProjectID     string          `json:"projectId"`
	Kind          string          `json:"kind"`
	SpecID        string          `json:"specId"`
	Version       int             `json:"version"`
	ContentSHA256 string          `json:"contentSha256"`
	Content       json.RawMessage `json:"-"`
	CreatedAt     time.Time       `json:"createdAt"`
	CreatedBy     string          `json:"createdBy"`
}

func (artifact *relationalSpecArtifact) UnmarshalJSON(input []byte) error {
	type artifactAlias relationalSpecArtifact
	var encoded struct {
		artifactAlias
		Content []byte `json:"content"`
	}
	if err := json.Unmarshal(input, &encoded); err != nil {
		return err
	}
	*artifact = relationalSpecArtifact(encoded.artifactAlias)
	artifact.Content = cloneJSON(encoded.Content)
	return nil
}

type relationalProjectProjection struct {
	TenantID string `json:"tenantId"`
	ID       string `json:"id"`
	State    string `json:"state"`
	Version  int64  `json:"version"`
	Goal     *struct {
		Version int    `json:"version"`
		SHA256  string `json:"sha256"`
		Status  string `json:"status"`
	} `json:"goal"`
	Plan *contracts.SpecRef `json:"plan"`
}

type relationalTaskProjection struct {
	TenantID               string                    `json:"tenantId"`
	ProjectID              string                    `json:"projectId"`
	ID                     string                    `json:"id"`
	ModuleID               string                    `json:"moduleId,omitempty"`
	State                  contracts.ModuleTaskState `json:"state"`
	Version                int64                     `json:"version"`
	PlanningSpecRef        contracts.SpecRef         `json:"planningSpecRef,omitempty"`
	ModuleSpecRef          contracts.SpecRef         `json:"moduleSpecRef"`
	AttemptSeriesID        string                    `json:"attemptSeriesId"`
	AttemptSeriesIDs       []string                  `json:"attemptSeriesIds"`
	Attempt                int                       `json:"attempt"`
	FencingToken           int64                     `json:"fencingToken"`
	DependentTaskIDs       []string                  `json:"dependentTaskIds"`
	BlockingTaskIDs        []string                  `json:"blockingTaskIds"`
	ModuleSpecSourceTaskID string                    `json:"moduleSpecSourceTaskId,omitempty"`
}

type relationalModuleSpec struct {
	ID        string
	PlanID    string
	ModuleID  string
	Ref       contracts.SpecRef
	CreatedBy string
}

type relationalPlanSpec struct {
	ID   string
	Plan contracts.PlanSpec
}

type relationalPlanPublication struct {
	ID     string
	Update ProjectionUpdate
	Plan   contracts.PlanSpec
}

func syncPublishedPlan(ctx context.Context, tx *sql.Tx, request TransactionRequest) (*relationalPlanPublication, error) {
	var update *ProjectionUpdate
	for index := range request.Events {
		event := request.Events[index]
		if event.Type != "io.aor.plan.published.v1" {
			continue
		}
		if update != nil || event.AggregateType != "project" {
			return nil, relationalError("plan publication event")
		}
		for updateIndex := range request.Updates {
			candidate := &request.Updates[updateIndex]
			if candidate.AggregateType == event.AggregateType && candidate.AggregateID == event.AggregateID && candidate.NextVersion == event.AggregateVersion {
				update = candidate
				break
			}
		}
	}
	if update == nil {
		return nil, nil
	}
	project, err := decodeRelationalProject(request, *update)
	if err != nil {
		return nil, err
	}
	if project.Plan == nil || project.State != "EXECUTING" {
		return nil, relationalError("published project plan")
	}
	staged, err := ensureRelationalPlanSpec(ctx, tx, request.TenantID, update.ProjectID, *project.Plan)
	if err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE plan_specs
SET status = 'PUBLISHED'
WHERE tenant_id = $1::uuid AND id = $2::uuid AND status IN ('DRAFT', 'PUBLISHED')`, request.TenantID, staged.ID)
	if err != nil {
		return nil, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if rows != 1 {
		return nil, aorerrors.New(aorerrors.CodeSpecSuperseded, "", map[string]any{"scope": "PlanSpec relational projection"})
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE plan_specs
SET status = 'SUPERSEDED'
WHERE tenant_id = $1::uuid AND project_id = $2::uuid
  AND status IN ('DRAFT', 'PUBLISHED') AND id <> $3::uuid`, request.TenantID, update.ProjectID, staged.ID); err != nil {
		return nil, err
	}
	return &relationalPlanPublication{ID: staged.ID, Update: *update, Plan: staged.Plan}, nil
}

func syncTaskRow(ctx context.Context, tx *sql.Tx, request TransactionRequest, update ProjectionUpdate) (relationalTaskProjection, error) {
	task, err := decodeRelationalTask(update.State, request.TenantID, update.ProjectID, update.AggregateID, update.NextVersion)
	if err != nil {
		return relationalTaskProjection{}, err
	}
	var moduleSpecID any
	var planID, moduleID string
	if planningTaskState(task.State) {
		plan, planErr := ensureRelationalPlanSpec(ctx, tx, request.TenantID, update.ProjectID, task.PlanningSpecRef)
		if planErr != nil {
			return relationalTaskProjection{}, planErr
		}
		if _, found := findPlanModule(plan.Plan, task.ModuleID); !found {
			return relationalTaskProjection{}, relationalError("planning task PlanSpec binding")
		}
		planID, moduleID = plan.ID, task.ModuleID
	} else {
		module, moduleErr := ensureRelationalModuleSpec(ctx, tx, request.TenantID, update.ProjectID, task.ModuleSpecRef)
		if moduleErr != nil {
			return relationalTaskProjection{}, moduleErr
		}
		moduleSpecID, planID, moduleID = module.ID, module.PlanID, module.ModuleID
		if task.PlanningSpecRef != (contracts.SpecRef{}) {
			plan, planErr := ensureRelationalPlanSpec(ctx, tx, request.TenantID, update.ProjectID, task.PlanningSpecRef)
			if planErr != nil {
				return relationalTaskProjection{}, planErr
			}
			creatorTaskID := task.ID
			if task.ModuleSpecSourceTaskID != "" {
				creatorTaskID = task.ModuleSpecSourceTaskID
			}
			if plan.ID != module.PlanID || task.ModuleID != module.ModuleID || module.CreatedBy != planningAgentID(update.ProjectID, creatorTaskID) {
				return relationalTaskProjection{}, relationalError("planned ModuleSpec binding")
			}
		}
	}
	blockedReason, err := taskBlockedReason(task.BlockingTaskIDs)
	if err != nil {
		return relationalTaskProjection{}, err
	}
	if update.ExpectedVersion == 0 {
		_, err = tx.ExecContext(ctx, `
INSERT INTO module_tasks
  (id, tenant_id, project_id, planning_spec_id, module_id, module_spec_id, state, state_version,
   attempt_count, active_attempt_series_id, latest_fencing_token, blocked_reason, created_at, updated_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6::uuid, $7, $8, $9, NULL, $10, $11,
        transaction_timestamp(), transaction_timestamp())`, task.ID, request.TenantID, update.ProjectID, planID,
			moduleID, moduleSpecID, string(task.State), task.Version, task.Attempt, task.FencingToken, blockedReason)
		if err != nil {
			return relationalTaskProjection{}, err
		}
		if planningTaskState(task.State) {
			if err := ensureRelationalPlanningAgent(ctx, tx, request.TenantID, update.ProjectID, task.ID); err != nil {
				return relationalTaskProjection{}, err
			}
		}
		return task, nil
	}
	result, err := tx.ExecContext(ctx, `
UPDATE module_tasks
SET planning_spec_id = $4::uuid, module_id = $5, module_spec_id = $6::uuid, state = $7,
    state_version = $8, attempt_count = $9, latest_fencing_token = $10,
    blocked_reason = $11, updated_at = transaction_timestamp()
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3::uuid
  AND state_version = $12 AND latest_fencing_token <= $10`, request.TenantID, update.ProjectID, task.ID,
		planID, moduleID, moduleSpecID, string(task.State), task.Version, task.Attempt, task.FencingToken, blockedReason, update.ExpectedVersion)
	if err != nil {
		return relationalTaskProjection{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return relationalTaskProjection{}, err
	}
	if rows != 1 {
		return relationalTaskProjection{}, aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"scope": "module task relational projection"})
	}
	return task, nil
}

func syncTaskAttemptSeries(ctx context.Context, tx *sql.Tx, request TransactionRequest, task relationalTaskProjection) error {
	var active sql.NullString
	var moduleSpecID string
	if err := tx.QueryRowContext(ctx, `
SELECT active_attempt_series_id::text, module_spec_id::text
FROM module_tasks
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3::uuid
FOR UPDATE`, request.TenantID, task.ProjectID, task.ID).Scan(&active, &moduleSpecID); err != nil {
		return err
	}
	for index, seriesID := range task.AttemptSeriesIDs {
		seriesNumber := index + 1
		if seriesID == task.AttemptSeriesID {
			var approvalID any
			if seriesNumber > 1 {
				approval, err := newAttemptSeriesApproval(request, task.ID)
				if err != nil {
					return err
				}
				approvalID = approval
			}
			if _, err := tx.ExecContext(ctx, `
INSERT INTO attempt_series
  (id, tenant_id, module_task_id, module_spec_id, series_number, authorized_by_approval_id, created_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, transaction_timestamp())
ON CONFLICT DO NOTHING`, seriesID, request.TenantID, task.ID, moduleSpecID, seriesNumber, approvalID); err != nil {
				return err
			}
		}
		var storedTaskID string
		var storedNumber int
		if err := tx.QueryRowContext(ctx, `
SELECT module_task_id::text, series_number
FROM attempt_series
WHERE tenant_id = $1::uuid AND id = $2::uuid
FOR SHARE`, request.TenantID, seriesID).Scan(&storedTaskID, &storedNumber); err != nil {
			return err
		}
		if storedTaskID != task.ID || storedNumber != seriesNumber {
			return relationalError("attempt series relational projection")
		}
	}
	if active.Valid && active.String != task.AttemptSeriesID {
		result, err := tx.ExecContext(ctx, `
UPDATE attempt_series
SET closed_at = COALESCE(closed_at, transaction_timestamp())
WHERE tenant_id = $1::uuid AND id = $2::uuid AND module_task_id = $3::uuid`, request.TenantID, active.String, task.ID)
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 1 {
			return relationalError("previous attempt series")
		}
	}
	result, err := tx.ExecContext(ctx, `
UPDATE module_tasks
SET active_attempt_series_id = $4::uuid
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3::uuid`, request.TenantID, task.ProjectID, task.ID, task.AttemptSeriesID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return relationalError("active attempt series")
	}
	return nil
}

func syncTaskDependencies(ctx context.Context, tx *sql.Tx, tenantID string, task relationalTaskProjection) error {
	for _, dependentID := range task.DependentTaskIDs {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO task_dependencies (tenant_id, task_id, depends_on_task_id, dependency_type)
VALUES ($1::uuid, $2::uuid, $3::uuid, 'PLAN_DAG')
ON CONFLICT DO NOTHING`, tenantID, dependentID, task.ID); err != nil {
			return err
		}
	}
	rows, err := tx.QueryContext(ctx, `
SELECT task_id::text
FROM task_dependencies
WHERE tenant_id = $1::uuid AND depends_on_task_id = $2::uuid
ORDER BY task_id`, tenantID, task.ID)
	if err != nil {
		return err
	}
	actual := make([]string, 0, len(task.DependentTaskIDs))
	for rows.Next() {
		var taskID string
		if err := rows.Scan(&taskID); err != nil {
			_ = rows.Close()
			return err
		}
		actual = append(actual, taskID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	expected := append([]string(nil), task.DependentTaskIDs...)
	sort.Strings(expected)
	if !slices.Equal(actual, expected) {
		return aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "task dependency relational projection"})
	}
	return nil
}

func validatePublishedPlanTasks(ctx context.Context, tx *sql.Tx, request TransactionRequest, publication relationalPlanPublication) error {
	var result struct {
		Project json.RawMessage   `json:"project"`
		Tasks   []json.RawMessage `json:"tasks"`
	}
	if err := json.Unmarshal(request.Result, &result); err != nil || len(result.Project) == 0 || len(result.Tasks) != len(publication.Plan.Modules) {
		return relationalError("plan publication result")
	}
	resultDigest, err := canonicaljson.Digest(result.Project)
	if err != nil {
		return err
	}
	updateDigest, err := canonicaljson.Digest(publication.Update.State)
	if err != nil || resultDigest != updateDigest {
		return relationalError("plan publication project result")
	}
	tasksByModule := make(map[string]relationalTaskProjection, len(result.Tasks))
	taskIDs := make(map[string]bool, len(result.Tasks))
	for _, raw := range result.Tasks {
		var identity struct {
			ID      string `json:"id"`
			Version int64  `json:"version"`
		}
		if err := json.Unmarshal(raw, &identity); err != nil {
			return relationalError("plan publication task identity")
		}
		task, err := decodeRelationalTask(raw, request.TenantID, publication.Update.ProjectID, identity.ID, identity.Version)
		if err != nil || taskIDs[task.ID] {
			return relationalError("plan publication task result")
		}
		taskIDs[task.ID] = true
		var storedVersion int64
		var storedState []byte
		err = tx.QueryRowContext(ctx, `
SELECT aggregate_version, state_jsonb
FROM aggregate_projections
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND aggregate_type = 'task' AND aggregate_id = $3
FOR SHARE`, request.TenantID, publication.Update.ProjectID, task.ID).Scan(&storedVersion, &storedState)
		if err != nil {
			return err
		}
		storedDigest, err := canonicaljson.Digest(storedState)
		if err != nil {
			return err
		}
		taskDigest, err := canonicaljson.Digest(raw)
		if err != nil || storedVersion != task.Version || storedDigest != taskDigest {
			return relationalError("plan task aggregate binding")
		}
		module, err := ensureRelationalModuleSpec(ctx, tx, request.TenantID, task.ProjectID, task.ModuleSpecRef)
		if err != nil || module.ModuleID == "" {
			return relationalError("plan task ModuleSpec binding")
		}
		if module.PlanID == publication.ID && (task.ModuleID != module.ModuleID || task.PlanningSpecRef != (contracts.SpecRef{Version: publication.Plan.PlanSpecVersion, SHA256: publication.Plan.SHA256})) {
			return relationalError("new plan task planning binding")
		}
		if _, duplicate := tasksByModule[module.ModuleID]; duplicate {
			return relationalError("duplicate plan module task")
		}
		tasksByModule[module.ModuleID] = task
	}
	expectedDependents := make(map[string][]string, len(publication.Plan.Modules))
	for _, module := range publication.Plan.Modules {
		task, found := tasksByModule[module.ModuleID]
		if !found {
			return relationalError("missing plan module task")
		}
		for _, dependency := range module.Dependencies {
			_, found := tasksByModule[dependency]
			if !found {
				return relationalError("plan dependency task")
			}
			expectedDependents[dependency] = append(expectedDependents[dependency], task.ID)
		}
	}
	for moduleID, task := range tasksByModule {
		expected := expectedDependents[moduleID]
		sort.Strings(expected)
		actual := append([]string(nil), task.DependentTaskIDs...)
		sort.Strings(actual)
		if !slices.Equal(actual, expected) {
			return relationalError("plan task dependency binding")
		}
		if err := syncTaskDependencies(ctx, tx, request.TenantID, task); err != nil {
			return err
		}
		if err := validateRelationalTaskRow(ctx, tx, request.TenantID, task); err != nil {
			return err
		}
	}
	return nil
}

func syncProjectSpecBindings(ctx context.Context, tx *sql.Tx, request TransactionRequest, update ProjectionUpdate) error {
	project, err := decodeRelationalProject(request, update)
	if err != nil {
		return err
	}
	var goalID any
	if project.Goal != nil && project.Goal.Status == "APPROVED" {
		var resolved string
		err := tx.QueryRowContext(ctx, `
SELECT id::text
FROM goal_specs
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND version = $3
  AND content_sha256 = $4 AND status = 'APPROVED'
FOR SHARE`, request.TenantID, update.ProjectID, project.Goal.Version, project.Goal.SHA256).Scan(&resolved)
		if errors.Is(err, sql.ErrNoRows) {
			return aorerrors.New(aorerrors.CodeGoalNotApproved, "", map[string]any{"scope": "active GoalSpec binding"})
		}
		if err != nil {
			return err
		}
		goalID = resolved
	}
	var planID any
	if project.Plan != nil {
		var resolved string
		err := tx.QueryRowContext(ctx, `
SELECT id::text
FROM plan_specs
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND version = $3
  AND content_sha256 = $4 AND status = 'PUBLISHED'
FOR SHARE`, request.TenantID, update.ProjectID, project.Plan.Version, project.Plan.SHA256).Scan(&resolved)
		if errors.Is(err, sql.ErrNoRows) {
			return aorerrors.New(aorerrors.CodeSpecSuperseded, "", map[string]any{"scope": "active PlanSpec binding"})
		}
		if err != nil {
			return err
		}
		planID = resolved
	} else {
		if _, err := tx.ExecContext(ctx, `
UPDATE plan_specs AS plan
SET status = 'SUPERSEDED'
FROM projects AS project
WHERE project.tenant_id = $1::uuid AND project.id = $2::uuid
	  AND plan.tenant_id = project.tenant_id AND plan.project_id = project.id
	  AND (
	    (plan.id = project.active_plan_spec_id AND plan.status = 'PUBLISHED')
	    OR (plan.status = 'DRAFT' AND project.state NOT IN ('PLANNING', 'PAUSED'))
	  )`, request.TenantID, update.ProjectID); err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, `
UPDATE projects
SET active_goal_spec_id = $3::uuid, active_plan_spec_id = $4::uuid
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state_version = $5`, request.TenantID, update.ProjectID, goalID, planID, update.NextVersion)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"scope": "project spec bindings"})
	}
	return nil
}

func ensureRelationalPlanSpec(ctx context.Context, tx *sql.Tx, tenantID, projectID string, ref contracts.SpecRef) (relationalPlanSpec, error) {
	artifact, err := loadRelationalSpecArtifact(ctx, tx, tenantID, projectID, planArtifactKind, ref)
	if err != nil {
		return relationalPlanSpec{}, err
	}
	plan, err := validatePlanArtifact(artifact, ref, projectID)
	if err != nil {
		return relationalPlanSpec{}, err
	}
	if artifact.CreatedBy != projectID+":PLAN_SUPERVISOR" {
		return relationalPlanSpec{}, relationalError("PlanSpec supervisor binding")
	}
	var supervisorRole string
	if err := tx.QueryRowContext(ctx, `
SELECT role
FROM agent_instances
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3
FOR SHARE`, tenantID, projectID, artifact.CreatedBy).Scan(&supervisorRole); err != nil || supervisorRole != "PLAN_SUPERVISOR" {
		return relationalPlanSpec{}, relationalError("PlanSpec supervisor authority")
	}
	var goalSpecID string
	err = tx.QueryRowContext(ctx, `
SELECT id::text
FROM goal_specs
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND version = $3
  AND content_sha256 = $4 AND status = 'APPROVED'
FOR SHARE`, tenantID, projectID, plan.GoalSpecRef.Version, plan.GoalSpecRef.SHA256).Scan(&goalSpecID)
	if errors.Is(err, sql.ErrNoRows) {
		return relationalPlanSpec{}, aorerrors.New(aorerrors.CodeGoalNotApproved, "", map[string]any{"scope": "PlanSpec GoalSpec"})
	}
	if err != nil {
		return relationalPlanSpec{}, err
	}
	planUUID, err := uuid.NewV7()
	if err != nil {
		return relationalPlanSpec{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO plan_specs
  (id, tenant_id, project_id, goal_spec_id, version, status, schema_version,
   content_jsonb, content_sha256, created_by_agent_id, planning_agent_id, created_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, 'DRAFT', 1, $6::jsonb, $7, $8, $8, $9)
ON CONFLICT DO NOTHING`, planUUID.String(), tenantID, projectID, goalSpecID, plan.PlanSpecVersion,
		[]byte(artifact.Content), plan.SHA256, artifact.CreatedBy, artifact.CreatedAt); err != nil {
		return relationalPlanSpec{}, err
	}
	var planID string
	var storedGoalID string
	var storedVersion int
	var storedStatus string
	var storedSHA string
	var storedCreatedBy string
	var storedPlanningAgent sql.NullString
	err = tx.QueryRowContext(ctx, `
SELECT id::text, goal_spec_id::text, version, status, content_sha256, created_by_agent_id, planning_agent_id
FROM plan_specs
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND version = $3
FOR SHARE`, tenantID, projectID, plan.PlanSpecVersion).Scan(&planID, &storedGoalID, &storedVersion, &storedStatus, &storedSHA, &storedCreatedBy, &storedPlanningAgent)
	if err != nil {
		return relationalPlanSpec{}, err
	}
	if storedGoalID != goalSpecID || storedVersion != plan.PlanSpecVersion || storedSHA != plan.SHA256 || storedCreatedBy != artifact.CreatedBy || !storedPlanningAgent.Valid || storedPlanningAgent.String != artifact.CreatedBy || storedStatus != "DRAFT" && storedStatus != "PUBLISHED" {
		return relationalPlanSpec{}, aorerrors.New(aorerrors.CodeSpecSuperseded, "", map[string]any{"scope": "PlanSpec relational projection"})
	}
	return relationalPlanSpec{ID: planID, Plan: plan}, nil
}

func ensureRelationalModuleSpec(ctx context.Context, tx *sql.Tx, tenantID, projectID string, ref contracts.SpecRef) (relationalModuleSpec, error) {
	artifact, err := loadRelationalSpecArtifact(ctx, tx, tenantID, projectID, moduleArtifactKind, ref)
	if err != nil {
		return relationalModuleSpec{}, err
	}
	module, err := validateModuleArtifact(artifact, ref, projectID)
	if err != nil {
		return relationalModuleSpec{}, err
	}
	var planID string
	var planState []byte
	err = tx.QueryRowContext(ctx, `
SELECT id::text, content_jsonb
FROM plan_specs
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND version = $3
FOR SHARE`, tenantID, projectID, module.PlanVersion).Scan(&planID, &planState)
	if err != nil {
		return relationalModuleSpec{}, err
	}
	var plan contracts.PlanSpec
	if err := json.Unmarshal(planState, &plan); err != nil {
		return relationalModuleSpec{}, fmt.Errorf("decode relational PlanSpec: %w", err)
	}
	planned, found := findPlanModule(plan, module.ModuleID)
	if !found || planned.ExecutionPlatform != module.ExecutionPlatform || planned.SandboxLevel != module.SandboxLevel {
		return relationalModuleSpec{}, relationalError("ModuleSpec PlanSpec binding")
	}
	moduleSpecUUID, err := uuid.NewV7()
	if err != nil {
		return relationalModuleSpec{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO module_specs
  (id, tenant_id, project_id, plan_spec_id, module_id, version, risk_level,
   execution_platform, isolation_level, schema_version, content_jsonb, content_sha256,
   created_by_agent_id, created_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, $8, $9, 1, $10::jsonb, $11, $12, $13)
ON CONFLICT DO NOTHING`, moduleSpecUUID.String(), tenantID, projectID, planID, module.ModuleID, module.ModuleSpecVersion,
		planned.Risk, string(module.ExecutionPlatform), string(module.SandboxLevel), []byte(artifact.Content), module.SHA256, artifact.CreatedBy, artifact.CreatedAt); err != nil {
		return relationalModuleSpec{}, err
	}
	var moduleSpecID string
	var storedPlanID string
	var storedModuleID string
	var storedVersion int
	var storedSHA string
	var storedCreatedBy sql.NullString
	err = tx.QueryRowContext(ctx, `
SELECT id::text, plan_spec_id::text, module_id, version, content_sha256, created_by_agent_id
FROM module_specs
WHERE tenant_id = $1::uuid AND module_id = $2 AND version = $3
FOR SHARE`, tenantID, module.ModuleID, module.ModuleSpecVersion).Scan(&moduleSpecID, &storedPlanID, &storedModuleID, &storedVersion, &storedSHA, &storedCreatedBy)
	if err != nil {
		return relationalModuleSpec{}, err
	}
	if storedPlanID != planID || storedModuleID != module.ModuleID || storedVersion != module.ModuleSpecVersion || storedSHA != module.SHA256 || storedCreatedBy.Valid && storedCreatedBy.String != artifact.CreatedBy {
		return relationalModuleSpec{}, aorerrors.New(aorerrors.CodeSpecSuperseded, "", map[string]any{"scope": "ModuleSpec relational projection"})
	}
	return relationalModuleSpec{ID: moduleSpecID, PlanID: planID, ModuleID: module.ModuleID, Ref: ref, CreatedBy: storedCreatedBy.String}, nil
}

func ensureRelationalPlanningAgent(ctx context.Context, tx *sql.Tx, tenantID, projectID, taskID string) error {
	supervisorID := projectID + ":PLAN_SUPERVISOR"
	plannerID := planningAgentID(projectID, taskID)
	var promptBundleVersion string
	if err := tx.QueryRowContext(ctx, `
SELECT prompt_bundle_version
FROM agent_instances
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3 AND role = 'PLAN_SUPERVISOR'
FOR SHARE`, tenantID, projectID, supervisorID).Scan(&promptBundleVersion); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO agent_instances
  (id, tenant_id, project_id, role, provider, logical_model, actual_model_version,
   prompt_bundle_version, state, created_at)
VALUES ($1, $2::uuid, $3::uuid, 'MODULE_PLANNER', 'UNASSIGNED', 'UNASSIGNED', 'UNASSIGNED',
        $4, 'DECLARED', transaction_timestamp())
ON CONFLICT DO NOTHING`, plannerID, tenantID, projectID, promptBundleVersion); err != nil {
		return err
	}
	var storedProjectID, role, storedPrompt string
	if err := tx.QueryRowContext(ctx, `
SELECT project_id::text, role, prompt_bundle_version
FROM agent_instances
WHERE tenant_id = $1::uuid AND id = $2
FOR SHARE`, tenantID, plannerID).Scan(&storedProjectID, &role, &storedPrompt); err != nil {
		return err
	}
	if storedProjectID != projectID || role != "MODULE_PLANNER" || storedPrompt != promptBundleVersion {
		return relationalError("ModulePlanner agent authority")
	}
	return nil
}

func planningAgentID(projectID, taskID string) string {
	return projectID + ":MODULE_PLANNER:" + taskID
}

func loadRelationalSpecArtifact(ctx context.Context, tx *sql.Tx, tenantID, projectID, kind string, ref contracts.SpecRef) (relationalSpecArtifact, error) {
	if ref.Validate() != nil {
		return relationalSpecArtifact{}, relationalError("spec artifact reference")
	}
	rows, err := tx.QueryContext(ctx, `
SELECT state_jsonb
FROM aggregate_projections
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND aggregate_type = 'spec_artifact'
  AND state_jsonb->>'kind' = $3 AND state_jsonb->>'version' = $4
  AND state_jsonb->>'contentSha256' = $5
ORDER BY aggregate_id
FOR SHARE`, tenantID, projectID, kind, fmt.Sprint(ref.Version), ref.SHA256)
	if err != nil {
		return relationalSpecArtifact{}, err
	}
	defer rows.Close()
	var artifact relationalSpecArtifact
	count := 0
	for rows.Next() {
		var state []byte
		if err := rows.Scan(&state); err != nil {
			return relationalSpecArtifact{}, err
		}
		count++
		if count > 1 {
			return relationalSpecArtifact{}, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "duplicate spec artifact"})
		}
		if err := json.Unmarshal(state, &artifact); err != nil {
			return relationalSpecArtifact{}, fmt.Errorf("decode spec artifact projection: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return relationalSpecArtifact{}, err
	}
	if count == 0 {
		return relationalSpecArtifact{}, aorerrors.New(aorerrors.CodeNotFound, "", map[string]any{"scope": kind + " artifact"})
	}
	if artifact.TenantID != tenantID || artifact.ProjectID != projectID || artifact.Kind != kind || artifact.SpecID == "" || artifact.Version != ref.Version || artifact.ContentSHA256 != ref.SHA256 || len(artifact.Content) == 0 || artifact.CreatedAt.IsZero() || artifact.CreatedBy == "" {
		return relationalSpecArtifact{}, relationalError("spec artifact projection")
	}
	return artifact, nil
}

func validatePlanArtifact(artifact relationalSpecArtifact, ref contracts.SpecRef, projectID string) (contracts.PlanSpec, error) {
	if contracts.ValidatePlanJSON(artifact.Content) != nil {
		return contracts.PlanSpec{}, relationalError("PlanSpec schema")
	}
	var plan contracts.PlanSpec
	if err := json.Unmarshal(artifact.Content, &plan); err != nil {
		return contracts.PlanSpec{}, err
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(artifact.Content, "sha256", "signature")
	if err != nil || digest != ref.SHA256 || plan.SHA256 != ref.SHA256 || plan.PlanSpecVersion != ref.Version || plan.ProjectID != projectID || plan.Validate() != nil {
		return contracts.PlanSpec{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "PlanSpec relational projection"})
	}
	return plan, nil
}

func validateModuleArtifact(artifact relationalSpecArtifact, ref contracts.SpecRef, projectID string) (contracts.ModuleSpec, error) {
	if contracts.ValidateModuleJSON(artifact.Content) != nil {
		return contracts.ModuleSpec{}, relationalError("ModuleSpec schema")
	}
	var module contracts.ModuleSpec
	if err := json.Unmarshal(artifact.Content, &module); err != nil {
		return contracts.ModuleSpec{}, err
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(artifact.Content, "sha256", "signature")
	if err != nil || digest != ref.SHA256 || module.SHA256 != ref.SHA256 || module.ModuleSpecVersion != ref.Version || module.ProjectID != projectID || module.ModuleID == "" || module.PlanVersion < 1 {
		return contracts.ModuleSpec{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "ModuleSpec relational projection"})
	}
	return module, nil
}

func decodeRelationalProject(request TransactionRequest, update ProjectionUpdate) (relationalProjectProjection, error) {
	var project relationalProjectProjection
	if err := json.Unmarshal(update.State, &project); err != nil {
		return relationalProjectProjection{}, fmt.Errorf("decode project spec bindings: %w", err)
	}
	if project.TenantID != request.TenantID || project.ID != update.AggregateID || update.ProjectID != project.ID || project.State == "" || project.Version != update.NextVersion {
		return relationalProjectProjection{}, relationalError("project spec projection")
	}
	if project.Plan != nil && project.Plan.Validate() != nil {
		return relationalProjectProjection{}, relationalError("project PlanSpec reference")
	}
	return project, nil
}

func decodeRelationalTask(input []byte, tenantID, projectID, taskID string, version int64) (relationalTaskProjection, error) {
	var task relationalTaskProjection
	if err := json.Unmarshal(input, &task); err != nil {
		return relationalTaskProjection{}, fmt.Errorf("decode module task relational projection: %w", err)
	}
	if task.TenantID != tenantID || task.ProjectID != projectID || task.ID != taskID || task.Version != version || task.Version < 1 || task.Attempt < 0 || task.Attempt > 3 || task.FencingToken < 0 || !validRelationalTaskState(task.State) {
		return relationalTaskProjection{}, relationalError("module task relational projection")
	}
	if !validUUID(task.ID) {
		return relationalTaskProjection{}, relationalError("module task relational identity")
	}
	if task.ModuleSpecSourceTaskID != "" && (!validUUID(task.ModuleSpecSourceTaskID) || task.ModuleSpecSourceTaskID == task.ID) {
		return relationalTaskProjection{}, relationalError("ModuleSpec source task identity")
	}
	if planningTaskState(task.State) {
		if task.ModuleID == "" || task.PlanningSpecRef.Validate() != nil || task.ModuleSpecRef != (contracts.SpecRef{}) || task.AttemptSeriesID != "" || len(task.AttemptSeriesIDs) != 0 || task.Attempt != 0 || task.FencingToken != 0 {
			return relationalTaskProjection{}, relationalError("planning task relational identity")
		}
	} else if task.ModuleSpecRef.Validate() != nil || len(task.AttemptSeriesIDs) == 0 || task.AttemptSeriesID != task.AttemptSeriesIDs[len(task.AttemptSeriesIDs)-1] || task.PlanningSpecRef != (contracts.SpecRef{}) && task.PlanningSpecRef.Validate() != nil {
		return relationalTaskProjection{}, relationalError("module task relational identity")
	}
	seenSeries := make(map[string]bool, len(task.AttemptSeriesIDs))
	for _, seriesID := range task.AttemptSeriesIDs {
		if !validUUID(seriesID) || seenSeries[seriesID] {
			return relationalTaskProjection{}, relationalError("module task attempt series")
		}
		seenSeries[seriesID] = true
	}
	seenDependents := make(map[string]bool, len(task.DependentTaskIDs))
	for _, dependentID := range task.DependentTaskIDs {
		if !validUUID(dependentID) || dependentID == task.ID || seenDependents[dependentID] {
			return relationalTaskProjection{}, relationalError("module task dependents")
		}
		seenDependents[dependentID] = true
	}
	for _, blockingID := range task.BlockingTaskIDs {
		if !validUUID(blockingID) || blockingID == task.ID {
			return relationalTaskProjection{}, relationalError("module task blockers")
		}
	}
	return task, nil
}

func validateRelationalTaskRow(ctx context.Context, tx *sql.Tx, tenantID string, task relationalTaskProjection) error {
	var state string
	var version int64
	var specVersion sql.NullInt64
	var specSHA sql.NullString
	var planVersion int
	var planSHA string
	var moduleID string
	var activeSeries sql.NullString
	var attempt int
	var fencing int64
	var blocked sql.NullString
	err := tx.QueryRowContext(ctx, `
SELECT task.state, task.state_version, spec.version, spec.content_sha256,
       plan.version, plan.content_sha256, COALESCE(task.module_id, spec.module_id),
       task.active_attempt_series_id::text, task.attempt_count, task.latest_fencing_token, task.blocked_reason
FROM module_tasks AS task
LEFT JOIN module_specs AS spec ON spec.tenant_id = task.tenant_id AND spec.id = task.module_spec_id
JOIN plan_specs AS plan ON plan.tenant_id = task.tenant_id AND plan.id = COALESCE(task.planning_spec_id, spec.plan_spec_id)
WHERE task.tenant_id = $1::uuid AND task.project_id = $2::uuid AND task.id = $3::uuid
FOR SHARE OF task, plan`, tenantID, task.ProjectID, task.ID).Scan(
		&state, &version, &specVersion, &specSHA, &planVersion, &planSHA, &moduleID,
		&activeSeries, &attempt, &fencing, &blocked,
	)
	if err != nil {
		return err
	}
	expectedBlocked, err := taskBlockedReason(task.BlockingTaskIDs)
	if err != nil {
		return err
	}
	if state != string(task.State) || version != task.Version || attempt != task.Attempt || fencing != task.FencingToken || blocked.String != stringValue(expectedBlocked) || blocked.Valid != (expectedBlocked != nil) {
		return relationalError("module task authority row")
	}
	if task.PlanningSpecRef != (contracts.SpecRef{}) && (planVersion != task.PlanningSpecRef.Version || planSHA != task.PlanningSpecRef.SHA256 || moduleID != task.ModuleID) {
		return relationalError("planning task authority row")
	}
	if planningTaskState(task.State) {
		if specVersion.Valid || specSHA.Valid || activeSeries.Valid {
			return relationalError("planning task ModuleSpec authority row")
		}
	} else if !specVersion.Valid || int(specVersion.Int64) != task.ModuleSpecRef.Version || !specSHA.Valid || specSHA.String != task.ModuleSpecRef.SHA256 || !activeSeries.Valid || activeSeries.String != task.AttemptSeriesID {
		return relationalError("module task ModuleSpec authority row")
	}
	return nil
}

func newAttemptSeriesApproval(request TransactionRequest, taskID string) (string, error) {
	approvalID := ""
	for _, approval := range request.Approvals {
		if approval.ApprovalType != "AUTHORIZE_NEW_ATTEMPT_SERIES" || approval.SubjectType != "MODULE_TASK" || approval.SubjectID != taskID {
			continue
		}
		if approvalID != "" || !validUUID(approval.ID) {
			return "", relationalError("new attempt series approval")
		}
		approvalID = approval.ID
	}
	if approvalID == "" {
		return "", aorerrors.New(aorerrors.CodeApprovalRequired, "", map[string]any{"scope": "new attempt series relational projection"})
	}
	return approvalID, nil
}

func taskBlockedReason(blockers []string) (any, error) {
	if len(blockers) == 0 {
		return nil, nil
	}
	values := append([]string(nil), blockers...)
	sort.Strings(values)
	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	return string(encoded), nil
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	text, _ := value.(string)
	return text
}

func findPlanModule(plan contracts.PlanSpec, moduleID string) (contracts.PlanModule, bool) {
	for _, module := range plan.Modules {
		if module.ModuleID == moduleID {
			return module, true
		}
	}
	return contracts.PlanModule{}, false
}

func validRelationalTaskState(state contracts.ModuleTaskState) bool {
	switch state {
	case contracts.TaskDefined, contracts.TaskQueuedPlanning, contracts.TaskPlanning,
		contracts.TaskReadyExecution, contracts.TaskQueuedExecution, contracts.TaskExecuting,
		contracts.TaskSubmitted, contracts.TaskDeterministicAudit, contracts.TaskLLMAudit,
		contracts.TaskReworkRequired, contracts.TaskBlockedDependency, contracts.TaskBlockedUserDecision,
		contracts.TaskPassed, contracts.TaskIntegrated, contracts.TaskCanceled, contracts.TaskSuperseded:
		return true
	default:
		return false
	}
}

func planningTaskState(value contracts.ModuleTaskState) bool {
	return value == contracts.TaskQueuedPlanning || value == contracts.TaskPlanning
}

func validUUID(value string) bool {
	_, err := uuid.Parse(value)
	return err == nil
}

func validateRelationalProjectionSnapshot(ctx context.Context, tx *sql.Tx, tenantID string) error {
	checks := []struct {
		table string
		query string
	}{
		{table: "projects", query: `
WITH online AS (
  SELECT id::text AS id, state, state_version, active_goal_spec_id, active_plan_spec_id
  FROM projects
  WHERE tenant_id = $1::uuid
), authoritative AS (
  SELECT aggregate_id AS id, project_id::text AS project_id, aggregate_version, state_jsonb
  FROM aggregate_projections
  WHERE tenant_id = $1::uuid AND aggregate_type = 'project'
)
SELECT COALESCE(online.id, authoritative.id)
FROM online
FULL OUTER JOIN authoritative USING (id)
WHERE online.id IS NULL OR authoritative.id IS NULL
   OR authoritative.project_id <> online.id
   OR authoritative.aggregate_version <> online.state_version
   OR authoritative.state_jsonb->>'tenantId' <> $1::uuid::text
   OR authoritative.state_jsonb->>'id' <> online.id
   OR authoritative.state_jsonb->>'state' <> online.state
   OR (authoritative.state_jsonb->>'version')::bigint <> online.state_version
   OR COALESCE(jsonb_typeof(authoritative.state_jsonb->'plan') = 'object', false) <> (online.active_plan_spec_id IS NOT NULL)
   OR COALESCE(authoritative.state_jsonb->'goal'->>'status' = 'APPROVED', false) <> (online.active_goal_spec_id IS NOT NULL)
   OR (online.active_plan_spec_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM plan_specs AS plan
        WHERE plan.tenant_id = $1::uuid AND plan.id = online.active_plan_spec_id
          AND plan.project_id::text = online.id AND plan.status = 'PUBLISHED'
          AND plan.version = (authoritative.state_jsonb->'plan'->>'version')::integer
          AND plan.content_sha256 = authoritative.state_jsonb->'plan'->>'sha256'
      ))
   OR (online.active_goal_spec_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM goal_specs AS goal
        WHERE goal.tenant_id = $1::uuid AND goal.id = online.active_goal_spec_id
          AND goal.project_id::text = online.id AND goal.status = 'APPROVED'
          AND goal.version = (authoritative.state_jsonb->'goal'->>'version')::integer
          AND goal.content_sha256 = authoritative.state_jsonb->'goal'->>'sha256'
      ))
LIMIT 1`},
		{table: "module_tasks", query: `
WITH online AS (
	  SELECT task.id::text AS id, task.project_id::text AS project_id, task.state, task.state_version,
	         task.attempt_count, task.active_attempt_series_id::text AS active_attempt_series_id,
	         task.latest_fencing_token, COALESCE(task.module_id, spec.module_id) AS module_id, plan.version AS planning_version,
	         plan.content_sha256 AS planning_sha256, spec.version AS module_version,
	         spec.content_sha256 AS module_sha256, spec.created_by_agent_id AS module_created_by
	  FROM module_tasks AS task
	  LEFT JOIN module_specs AS spec ON spec.tenant_id = task.tenant_id AND spec.id = task.module_spec_id
	  JOIN plan_specs AS plan ON plan.tenant_id = task.tenant_id AND plan.id = COALESCE(task.planning_spec_id, spec.plan_spec_id)
  WHERE task.tenant_id = $1::uuid
), authoritative AS (
  SELECT aggregate_id AS id, project_id::text AS project_id, aggregate_version, state_jsonb
  FROM aggregate_projections
  WHERE tenant_id = $1::uuid AND aggregate_type = 'task'
)
SELECT COALESCE(online.id, authoritative.id)
FROM online
FULL OUTER JOIN authoritative USING (id)
WHERE online.id IS NULL OR authoritative.id IS NULL
   OR online.project_id <> authoritative.project_id
   OR online.state_version <> authoritative.aggregate_version
   OR authoritative.state_jsonb->>'tenantId' <> $1::uuid::text
   OR authoritative.state_jsonb->>'projectId' <> online.project_id
   OR authoritative.state_jsonb->>'id' <> online.id
   OR authoritative.state_jsonb->>'state' <> online.state
   OR (authoritative.state_jsonb->>'version')::bigint <> online.state_version
   OR COALESCE((authoritative.state_jsonb->>'attempt')::integer, 0) <> online.attempt_count
	   OR NULLIF(authoritative.state_jsonb->>'attemptSeriesId', '') IS DISTINCT FROM online.active_attempt_series_id
	   OR COALESCE((authoritative.state_jsonb->>'fencingToken')::bigint, 0) <> online.latest_fencing_token
	   OR (authoritative.state_jsonb ? 'moduleId' AND authoritative.state_jsonb->>'moduleId' <> online.module_id)
	   OR COALESCE(NULLIF((authoritative.state_jsonb->'planningSpecRef'->>'version')::integer, 0), online.planning_version) <> online.planning_version
	   OR COALESCE(NULLIF(authoritative.state_jsonb->'planningSpecRef'->>'sha256', ''), online.planning_sha256) <> online.planning_sha256
	   OR COALESCE((authoritative.state_jsonb->'moduleSpecRef'->>'version')::integer, 0) <> COALESCE(online.module_version, 0)
	   OR COALESCE(authoritative.state_jsonb->'moduleSpecRef'->>'sha256', '') <> COALESCE(online.module_sha256, '')
	   OR (
	     COALESCE((authoritative.state_jsonb->'planningSpecRef'->>'version')::integer, 0) > 0
	     AND
	     COALESCE((authoritative.state_jsonb->'moduleSpecRef'->>'version')::integer, 0) > 0
	     AND online.module_created_by IS DISTINCT FROM online.project_id || ':MODULE_PLANNER:' || online.id
	   )
LIMIT 1`},
		{table: "plan_specs", query: `
SELECT plan.id::text
FROM plan_specs AS plan
JOIN projects AS project ON project.tenant_id = plan.tenant_id AND project.id = plan.project_id
WHERE plan.tenant_id = $1::uuid
  AND (
    plan.schema_version <> 1
    OR plan.project_id::text <> plan.content_jsonb->>'projectId'
    OR plan.version <> (plan.content_jsonb->>'planSpecVersion')::integer
    OR plan.content_sha256 <> plan.content_jsonb->>'sha256'
	    OR plan.status <> CASE
	         WHEN project.active_plan_spec_id = plan.id THEN 'PUBLISHED'
	         WHEN plan.status = 'DRAFT' AND project.state IN ('PLANNING', 'PAUSED') THEN 'DRAFT'
	         ELSE 'SUPERSEDED'
	       END
	    OR (plan.status = 'DRAFT' AND plan.planning_agent_id IS NULL)
	    OR (plan.planning_agent_id IS NOT NULL AND plan.planning_agent_id <> (plan.project_id::text || ':PLAN_SUPERVISOR'))
	    OR (
	      plan.planning_agent_id IS NOT NULL
	      AND NOT EXISTS (
	        SELECT 1
	        FROM agent_instances AS creator
	        WHERE creator.tenant_id = plan.tenant_id AND creator.project_id = plan.project_id
	          AND creator.id = plan.planning_agent_id AND creator.role = 'PLAN_SUPERVISOR'
	      )
	    )
    OR NOT EXISTS (
      SELECT 1
      FROM goal_specs AS goal
      WHERE goal.tenant_id = plan.tenant_id AND goal.id = plan.goal_spec_id
        AND goal.project_id = plan.project_id
        AND goal.version = (plan.content_jsonb->'goalSpecRef'->>'version')::integer
        AND goal.content_sha256 = plan.content_jsonb->'goalSpecRef'->>'sha256'
    )
    OR NOT EXISTS (
      SELECT 1
      FROM aggregate_projections AS artifact
      WHERE artifact.tenant_id = plan.tenant_id AND artifact.project_id = plan.project_id
        AND artifact.aggregate_type = 'spec_artifact'
        AND artifact.state_jsonb->>'kind' = 'PLAN_SPEC'
        AND artifact.state_jsonb->>'version' = plan.version::text
        AND artifact.state_jsonb->>'contentSha256' = plan.content_sha256
        AND artifact.state_jsonb->>'createdBy' = plan.created_by_agent_id
        AND (artifact.state_jsonb->>'createdAt')::timestamptz = plan.created_at
        AND convert_from(decode(artifact.state_jsonb->>'content', 'base64'), 'UTF8')::jsonb = plan.content_jsonb
    )
  )
LIMIT 1`},
		{table: "module_specs", query: `
SELECT module.id::text
FROM module_specs AS module
JOIN plan_specs AS plan ON plan.tenant_id = module.tenant_id AND plan.id = module.plan_spec_id
WHERE module.tenant_id = $1::uuid
  AND (
    module.schema_version <> 1
    OR module.project_id <> plan.project_id
    OR module.project_id::text <> module.content_jsonb->>'projectId'
    OR module.module_id <> module.content_jsonb->>'moduleId'
    OR module.version <> (module.content_jsonb->>'moduleSpecVersion')::integer
    OR module.content_sha256 <> module.content_jsonb->>'sha256'
    OR module.execution_platform <> module.content_jsonb->>'executionPlatform'
    OR module.isolation_level <> module.content_jsonb->>'sandboxLevel'
	    OR plan.version <> (module.content_jsonb->>'planVersion')::integer
	    OR (
	      module.created_by_agent_id IS NOT NULL
	      AND NOT EXISTS (
	        SELECT 1
	        FROM agent_instances AS creator
	        WHERE creator.tenant_id = module.tenant_id AND creator.project_id = module.project_id
	          AND creator.id = module.created_by_agent_id AND creator.role = 'MODULE_PLANNER'
	      )
	    )
    OR NOT EXISTS (
      SELECT 1
      FROM jsonb_array_elements(plan.content_jsonb->'modules') AS planned
      WHERE planned->>'moduleId' = module.module_id
        AND planned->>'risk' = module.risk_level
        AND planned->>'executionPlatform' = module.execution_platform
        AND planned->>'sandboxLevel' = module.isolation_level
    )
    OR NOT EXISTS (
      SELECT 1
      FROM aggregate_projections AS artifact
      WHERE artifact.tenant_id = module.tenant_id AND artifact.project_id = module.project_id
        AND artifact.aggregate_type = 'spec_artifact'
	        AND artifact.state_jsonb->>'kind' = 'MODULE_SPEC'
	        AND artifact.state_jsonb->>'version' = module.version::text
	        AND artifact.state_jsonb->>'contentSha256' = module.content_sha256
	        AND (module.created_by_agent_id IS NULL OR artifact.state_jsonb->>'createdBy' = module.created_by_agent_id)
        AND (artifact.state_jsonb->>'createdAt')::timestamptz = module.created_at
        AND convert_from(decode(artifact.state_jsonb->>'content', 'base64'), 'UTF8')::jsonb = module.content_jsonb
    )
  )
LIMIT 1`},
	}
	for _, check := range checks {
		var rowID string
		err := tx.QueryRowContext(ctx, check.query, tenantID).Scan(&rowID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("validate %s relational projection: %w", check.table, err)
		}
		return fmt.Errorf("%w: %s/%s", ErrRelationalProjectionDrift, check.table, rowID)
	}
	return nil
}

func relationalError(scope string) error {
	return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": scope})
}
