package eventing

import (
	"context"
	"crypto/sha256"
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
	TenantID         string                    `json:"tenantId"`
	ProjectID        string                    `json:"projectId"`
	ID               string                    `json:"id"`
	State            contracts.ModuleTaskState `json:"state"`
	Version          int64                     `json:"version"`
	ModuleSpecRef    contracts.SpecRef         `json:"moduleSpecRef"`
	AttemptSeriesID  string                    `json:"attemptSeriesId"`
	AttemptSeriesIDs []string                  `json:"attemptSeriesIds"`
	Attempt          int                       `json:"attempt"`
	FencingToken     int64                     `json:"fencingToken"`
	DependentTaskIDs []string                  `json:"dependentTaskIds"`
	BlockingTaskIDs  []string                  `json:"blockingTaskIds"`
}

type relationalModuleSpec struct {
	ID       string
	ModuleID string
	Ref      contracts.SpecRef
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
	artifact, err := loadRelationalSpecArtifact(ctx, tx, request.TenantID, update.ProjectID, planArtifactKind, *project.Plan)
	if err != nil {
		return nil, err
	}
	plan, err := validatePlanArtifact(artifact, *project.Plan, update.ProjectID)
	if err != nil {
		return nil, err
	}
	var goalSpecID string
	err = tx.QueryRowContext(ctx, `
SELECT id::text
FROM goal_specs
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND version = $3
  AND content_sha256 = $4 AND status = 'APPROVED'
FOR SHARE`, request.TenantID, update.ProjectID, plan.GoalSpecRef.Version, plan.GoalSpecRef.SHA256).Scan(&goalSpecID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, aorerrors.New(aorerrors.CodeGoalNotApproved, "", map[string]any{"scope": "published plan GoalSpec"})
	}
	if err != nil {
		return nil, err
	}
	planID := relationalUUID(request.TenantID, update.ProjectID, "plan", fmt.Sprint(plan.PlanSpecVersion), plan.SHA256)
	result, err := tx.ExecContext(ctx, `
INSERT INTO plan_specs
  (id, tenant_id, project_id, goal_spec_id, version, status, schema_version,
   content_jsonb, content_sha256, created_by_agent_id, created_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, 'PUBLISHED', 1, $6::jsonb, $7, $8, $9)
ON CONFLICT DO NOTHING`, planID, request.TenantID, update.ProjectID, goalSpecID, plan.PlanSpecVersion,
		[]byte(artifact.Content), plan.SHA256, artifact.CreatedBy, artifact.CreatedAt)
	if err != nil {
		return nil, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	var storedGoalID string
	var storedVersion int
	var storedStatus string
	var storedSHA string
	err = tx.QueryRowContext(ctx, `
SELECT goal_spec_id::text, version, status, content_sha256
FROM plan_specs
WHERE tenant_id = $1::uuid AND id = $2::uuid
FOR SHARE`, request.TenantID, planID).Scan(&storedGoalID, &storedVersion, &storedStatus, &storedSHA)
	if err != nil {
		return nil, err
	}
	if inserted == 0 && storedStatus != "PUBLISHED" || storedGoalID != goalSpecID || storedVersion != plan.PlanSpecVersion || storedSHA != plan.SHA256 {
		return nil, aorerrors.New(aorerrors.CodeSpecSuperseded, "", map[string]any{"scope": "PlanSpec relational projection"})
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE plan_specs
SET status = 'SUPERSEDED'
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND status = 'PUBLISHED' AND id <> $3::uuid`, request.TenantID, update.ProjectID, planID); err != nil {
		return nil, err
	}
	return &relationalPlanPublication{ID: planID, Update: *update, Plan: plan}, nil
}

func syncTaskRow(ctx context.Context, tx *sql.Tx, request TransactionRequest, update ProjectionUpdate) (relationalTaskProjection, error) {
	task, err := decodeRelationalTask(update.State, request.TenantID, update.ProjectID, update.AggregateID, update.NextVersion)
	if err != nil {
		return relationalTaskProjection{}, err
	}
	module, err := ensureRelationalModuleSpec(ctx, tx, request.TenantID, update.ProjectID, task.ModuleSpecRef)
	if err != nil {
		return relationalTaskProjection{}, err
	}
	blockedReason, err := taskBlockedReason(task.BlockingTaskIDs)
	if err != nil {
		return relationalTaskProjection{}, err
	}
	if update.ExpectedVersion == 0 {
		_, err = tx.ExecContext(ctx, `
INSERT INTO module_tasks
  (id, tenant_id, project_id, module_spec_id, state, state_version, attempt_count,
   active_attempt_series_id, latest_fencing_token, blocked_reason, created_at, updated_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, NULL, $8, $9,
        transaction_timestamp(), transaction_timestamp())`, task.ID, request.TenantID, update.ProjectID, module.ID,
			string(task.State), task.Version, task.Attempt, task.FencingToken, blockedReason)
		if err != nil {
			return relationalTaskProjection{}, err
		}
		return task, nil
	}
	result, err := tx.ExecContext(ctx, `
UPDATE module_tasks
SET module_spec_id = $4::uuid, state = $5, state_version = $6, attempt_count = $7,
    latest_fencing_token = $8, blocked_reason = $9, updated_at = transaction_timestamp()
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3::uuid
  AND state_version = $10 AND latest_fencing_token <= $8`, request.TenantID, update.ProjectID, task.ID,
		module.ID, string(task.State), task.Version, task.Attempt, task.FencingToken, blockedReason, update.ExpectedVersion)
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
  AND plan.tenant_id = project.tenant_id AND plan.id = project.active_plan_spec_id
  AND plan.status = 'PUBLISHED'`, request.TenantID, update.ProjectID); err != nil {
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
	moduleSpecID := relationalUUID(tenantID, projectID, "module", module.ModuleID, fmt.Sprint(module.ModuleSpecVersion), module.SHA256)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO module_specs
  (id, tenant_id, project_id, plan_spec_id, module_id, version, risk_level,
   execution_platform, isolation_level, schema_version, content_jsonb, content_sha256, created_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, $8, $9, 1, $10::jsonb, $11, $12)
ON CONFLICT DO NOTHING`, moduleSpecID, tenantID, projectID, planID, module.ModuleID, module.ModuleSpecVersion,
		planned.Risk, string(module.ExecutionPlatform), string(module.SandboxLevel), []byte(artifact.Content), module.SHA256, artifact.CreatedAt); err != nil {
		return relationalModuleSpec{}, err
	}
	var storedPlanID string
	var storedModuleID string
	var storedVersion int
	var storedSHA string
	err = tx.QueryRowContext(ctx, `
SELECT plan_spec_id::text, module_id, version, content_sha256
FROM module_specs
WHERE tenant_id = $1::uuid AND id = $2::uuid
FOR SHARE`, tenantID, moduleSpecID).Scan(&storedPlanID, &storedModuleID, &storedVersion, &storedSHA)
	if err != nil {
		return relationalModuleSpec{}, err
	}
	if storedPlanID != planID || storedModuleID != module.ModuleID || storedVersion != module.ModuleSpecVersion || storedSHA != module.SHA256 {
		return relationalModuleSpec{}, aorerrors.New(aorerrors.CodeSpecSuperseded, "", map[string]any{"scope": "ModuleSpec relational projection"})
	}
	return relationalModuleSpec{ID: moduleSpecID, ModuleID: module.ModuleID, Ref: ref}, nil
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
	if task.TenantID != tenantID || task.ProjectID != projectID || task.ID != taskID || task.Version != version || task.Version < 1 || task.ModuleSpecRef.Validate() != nil || task.Attempt < 0 || task.Attempt > 3 || task.FencingToken < 0 || !validRelationalTaskState(task.State) {
		return relationalTaskProjection{}, relationalError("module task relational projection")
	}
	if !validUUID(task.ID) || len(task.AttemptSeriesIDs) == 0 || task.AttemptSeriesID != task.AttemptSeriesIDs[len(task.AttemptSeriesIDs)-1] {
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
	var specVersion int
	var specSHA string
	var activeSeries string
	var attempt int
	var fencing int64
	var blocked sql.NullString
	err := tx.QueryRowContext(ctx, `
SELECT task.state, task.state_version, spec.version, spec.content_sha256,
       task.active_attempt_series_id::text, task.attempt_count, task.latest_fencing_token, task.blocked_reason
FROM module_tasks AS task
JOIN module_specs AS spec ON spec.tenant_id = task.tenant_id AND spec.id = task.module_spec_id
WHERE task.tenant_id = $1::uuid AND task.project_id = $2::uuid AND task.id = $3::uuid
FOR SHARE OF task, spec`, tenantID, task.ProjectID, task.ID).Scan(&state, &version, &specVersion, &specSHA, &activeSeries, &attempt, &fencing, &blocked)
	if err != nil {
		return err
	}
	expectedBlocked, err := taskBlockedReason(task.BlockingTaskIDs)
	if err != nil {
		return err
	}
	if state != string(task.State) || version != task.Version || specVersion != task.ModuleSpecRef.Version || specSHA != task.ModuleSpecRef.SHA256 || activeSeries != task.AttemptSeriesID || attempt != task.Attempt || fencing != task.FencingToken || blocked.String != stringValue(expectedBlocked) || blocked.Valid != (expectedBlocked != nil) {
		return relationalError("module task authority row")
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

func validUUID(value string) bool {
	_, err := uuid.Parse(value)
	return err == nil
}

func relationalUUID(parts ...string) string {
	value := relationalDigest(parts...)
	value[6] = value[6]&0x0f | 0x50
	value[8] = value[8]&0x3f | 0x80
	id, _ := uuid.FromBytes(value[:16])
	return id.String()
}

func relationalDigest(parts ...string) [32]byte {
	input := make([]byte, 0)
	for index, part := range parts {
		if index != 0 {
			input = append(input, 0)
		}
		input = append(input, part...)
	}
	return sha256.Sum256(input)
}

func relationalError(scope string) error {
	return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": scope})
}
