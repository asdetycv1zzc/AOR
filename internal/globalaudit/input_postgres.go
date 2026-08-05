package globalaudit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/integration"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

type EnvironmentFacts struct {
	ExecutionPlatform  contracts.ExecutionPlatform
	IsolationLevel     contracts.IsolationLevel
	SandboxImageDigest string
}

type PostgresInputSource struct {
	database *sql.DB
}

func NewPostgresInputSource(database *sql.DB) (*PostgresInputSource, error) {
	if database == nil {
		return nil, ErrRuntimeUnavailable
	}
	return &PostgresInputSource{database: database}, nil
}

func (source *PostgresInputSource) Load(ctx context.Context, request Request, project state.Project) (InputSnapshot, error) {
	if source == nil || source.database == nil || ctx == nil || ctx.Err() != nil ||
		!tenantBound(ctx, request.TenantID) || !uuidV7(request.RunID) || !validProject(project, request) {
		return InputSnapshot{}, ErrInvalidRequest
	}
	tx, err := beginGlobalAuditAuthorityTx(ctx, source.database, request.TenantID, true)
	if err != nil {
		return InputSnapshot{}, err
	}
	defer func() { _ = tx.Rollback() }()
	snapshot, modules, err := loadGlobalAuditSnapshot(ctx, tx, request, project)
	if err != nil {
		return InputSnapshot{}, err
	}
	if err := validateReleaseSummary(ctx, tx, request, modules, &snapshot); err != nil {
		return InputSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return InputSnapshot{}, err
	}
	return snapshot, nil
}

type globalAuditModule struct {
	TaskID        string
	ModuleID      string
	State         contracts.ModuleTaskState
	Version       int64
	Attempt       int
	ModuleSpecRef contracts.SpecRef
}

func loadGlobalAuditSnapshot(ctx context.Context, tx *sql.Tx, request Request, project state.Project) (InputSnapshot, []globalAuditModule, error) {
	goalID, planID, err := validateGlobalAuditProjectRows(ctx, tx, request, project)
	if err != nil {
		return InputSnapshot{}, nil, err
	}
	goal, goalURI, err := loadApprovedGoal(ctx, tx, request, project, goalID)
	if err != nil {
		return InputSnapshot{}, nil, err
	}
	plan, planURI, err := loadPublishedPlan(ctx, tx, request, project, goalID, planID)
	if err != nil {
		return InputSnapshot{}, nil, err
	}
	modules, err := loadIntegratedModules(ctx, tx, request, planID, plan)
	if err != nil {
		return InputSnapshot{}, nil, err
	}
	return InputSnapshot{GoalSpec: goal, GoalArtifactURI: goalURI, PlanSpec: plan, PlanArtifactURI: planURI}, modules, nil
}

func validateGlobalAuditProjectRows(ctx context.Context, tx *sql.Tx, request Request, project state.Project) (string, string, error) {
	var stateName, classification string
	var version int64
	var goalID, planID sql.NullString
	err := tx.QueryRowContext(ctx, `
SELECT state, state_version, active_goal_spec_id::text, active_plan_spec_id::text,
       data_classification
FROM projects
WHERE tenant_id = $1::uuid AND id = $2::uuid`, request.TenantID, request.ProjectID).Scan(
		&stateName, &version, &goalID, &planID, &classification,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrProjectNotReady
	}
	if err != nil {
		return "", "", err
	}
	if stateName != string(contracts.ProjectGlobalAudit) || version != project.Version || classification != project.DataClassification ||
		!goalID.Valid || !planID.Valid {
		return "", "", ErrProjectNotReady
	}
	var projectionVersion int64
	var encoded []byte
	err = tx.QueryRowContext(ctx, `
SELECT aggregate_version, state_jsonb
FROM aggregate_projections
WHERE tenant_id = $1::uuid AND project_id = $2::uuid
  AND aggregate_type = 'project' AND aggregate_id = $2::uuid::text`, request.TenantID, request.ProjectID).Scan(&projectionVersion, &encoded)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", ErrProjectNotReady
		}
		return "", "", err
	}
	var stored state.Project
	if projectionVersion != version || decodeStrict(encoded, &stored) != nil || !reflect.DeepEqual(stored, project) {
		return "", "", ErrProjectNotReady
	}
	return goalID.String, planID.String, nil
}

func loadApprovedGoal(ctx context.Context, tx *sql.Tx, request Request, project state.Project, goalID string) (contracts.GoalSpec, string, error) {
	if !canonicalUUID(project.Goal.ApprovalRecordID) {
		return contracts.GoalSpec{}, "", ErrProjectNotReady
	}
	var version, schemaVersion int
	var status, contentSHA, approvedBy string
	var content []byte
	err := tx.QueryRowContext(ctx, `
SELECT version, status, schema_version, content_jsonb, content_sha256, approved_by
FROM goal_specs
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3::uuid`, request.TenantID, request.ProjectID, goalID).Scan(
		&version, &status, &schemaVersion, &content, &contentSHA, &approvedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return contracts.GoalSpec{}, "", ErrProjectNotReady
		}
		return contracts.GoalSpec{}, "", err
	}
	goalRef := projectGoalRef(project)
	if status != string(contracts.GoalApproved) || version != goalRef.Version || contentSHA != goalRef.SHA256 ||
		approvedBy != project.Goal.ApprovedBy {
		return contracts.GoalSpec{}, "", ErrProjectNotReady
	}
	var approvalIssuedAt time.Time
	err = tx.QueryRowContext(ctx, `
SELECT issued_at
FROM approvals
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3::uuid
  AND approval_type = 'GOAL_APPROVAL' AND subject_type = 'GOAL_SPEC'
  AND subject_id = $4 AND subject_version = $5 AND subject_sha256 = $6
  AND principal_id = $7 AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > transaction_timestamp())`, request.TenantID, request.ProjectID,
		project.Goal.ApprovalRecordID, project.Goal.ID, version, contentSHA, approvedBy).Scan(&approvalIssuedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return contracts.GoalSpec{}, "", ErrProjectNotReady
		}
		return contracts.GoalSpec{}, "", err
	}
	artifact, err := loadSpecArtifact(ctx, tx, request, goalplan.ArtifactGoalApproved, goalRef, project.Goal.ID)
	if err != nil {
		return contracts.GoalSpec{}, "", err
	}
	var goal contracts.GoalSpec
	if decodeStrict(artifact.Content, &goal) != nil || contracts.ValidateGoalJSON(artifact.Content) != nil {
		return contracts.GoalSpec{}, "", ErrProjectNotReady
	}
	if goal.ApprovedBy == nil {
		return contracts.GoalSpec{}, "", ErrProjectNotReady
	}
	goalContent, marshalErr := json.Marshal(goal.Content)
	approvedAt, timeErr := time.Parse(time.RFC3339Nano, goal.ApprovedBy.ApprovedAt)
	if marshalErr != nil ||
		goal.Status != contracts.GoalApproved || goal.ApprovedBy.ActorID != approvedBy ||
		timeErr != nil || !approvedAt.Equal(approvalIssuedAt) ||
		goal.Content.ProjectID != project.ID || goal.Content.Version != version || goal.Content.GoalSpecVersion != schemaVersion ||
		goal.ContentSHA256 != contentSHA || !sameCanonicalJSON(goalContent, content) || artifact.CreatedBy != approvedBy {
		return contracts.GoalSpec{}, "", ErrProjectNotReady
	}
	return goal, artifact.URI, nil
}

func loadPublishedPlan(ctx context.Context, tx *sql.Tx, request Request, project state.Project, goalID, planID string) (contracts.PlanSpec, string, error) {
	var version, schemaVersion int
	var status, contentSHA, storedGoalID, createdBy string
	var planningAgent sql.NullString
	var content []byte
	err := tx.QueryRowContext(ctx, `
SELECT goal_spec_id::text, version, status, schema_version, content_jsonb,
       content_sha256, created_by_agent_id, planning_agent_id
FROM plan_specs
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3::uuid`, request.TenantID, request.ProjectID, planID).Scan(
		&storedGoalID, &version, &status, &schemaVersion, &content, &contentSHA, &createdBy, &planningAgent,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return contracts.PlanSpec{}, "", ErrProjectNotReady
		}
		return contracts.PlanSpec{}, "", err
	}
	supervisorID := project.ID + ":PLAN_SUPERVISOR"
	if storedGoalID != goalID || status != "PUBLISHED" || version != project.Plan.Version || contentSHA != project.Plan.SHA256 ||
		schemaVersion != 1 || createdBy != supervisorID || !planningAgent.Valid || planningAgent.String != supervisorID {
		return contracts.PlanSpec{}, "", ErrProjectNotReady
	}
	artifact, err := loadSpecArtifact(ctx, tx, request, goalplan.ArtifactPlanSpec, *project.Plan, "")
	if err != nil {
		return contracts.PlanSpec{}, "", err
	}
	var plan contracts.PlanSpec
	if decodeStrict(content, &plan) != nil || contracts.ValidatePlanJSON(content) != nil || decodeStrict(artifact.Content, &plan) != nil ||
		contracts.ValidatePlanJSON(artifact.Content) != nil || !sameCanonicalJSON(content, artifact.Content) ||
		plan.ProjectID != project.ID || plan.GoalSpecRef != projectGoalRef(project) || plan.PlanSpecVersion != version ||
		plan.SHA256 != contentSHA || artifact.CreatedBy != createdBy {
		return contracts.PlanSpec{}, "", ErrProjectNotReady
	}
	return plan, artifact.URI, nil
}

func loadSpecArtifact(ctx context.Context, tx *sql.Tx, request Request, kind goalplan.ArtifactKind, ref contracts.SpecRef, specID string) (goalplan.SpecArtifact, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT state_jsonb
FROM aggregate_projections
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND aggregate_type = 'spec_artifact'
  AND state_jsonb->>'kind' = $3 AND state_jsonb->>'version' = $4
  AND state_jsonb->>'contentSha256' = $5
ORDER BY aggregate_id`, request.TenantID, request.ProjectID, string(kind), strconv.Itoa(ref.Version), ref.SHA256)
	if err != nil {
		return goalplan.SpecArtifact{}, err
	}
	defer rows.Close()
	var found []goalplan.SpecArtifact
	for rows.Next() {
		var encoded []byte
		var artifact goalplan.SpecArtifact
		if rows.Scan(&encoded) != nil || decodeStrict(encoded, &artifact) != nil {
			return goalplan.SpecArtifact{}, ErrProjectNotReady
		}
		if specID == "" || artifact.SpecID == specID {
			found = append(found, artifact)
		}
	}
	if err := rows.Err(); err != nil {
		return goalplan.SpecArtifact{}, err
	}
	if len(found) != 1 || !validSpecArtifact(found[0], request, kind, ref) {
		return goalplan.SpecArtifact{}, ErrProjectNotReady
	}
	return found[0], nil
}

func validSpecArtifact(artifact goalplan.SpecArtifact, request Request, kind goalplan.ArtifactKind, ref contracts.SpecRef) bool {
	if artifact.TenantID != request.TenantID || artifact.ProjectID != request.ProjectID || artifact.Kind != kind ||
		artifact.SpecID == "" || artifact.Version != ref.Version || artifact.ContentSHA256 != ref.SHA256 ||
		artifact.MediaType != "application/json" || len(artifact.Content) == 0 || artifact.CreatedBy == "" || artifact.CreatedAt.IsZero() {
		return false
	}
	digest, err := canonicaljson.Digest(artifact.Content)
	return err == nil && digest == artifact.ArtifactSHA256 && artifact.URI == "artifact://sha256/"+digest[len("sha256:"):]
}

func loadIntegratedModules(ctx context.Context, tx *sql.Tx, request Request, planID string, plan contracts.PlanSpec) ([]globalAuditModule, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT task.id::text, COALESCE(task.module_id, spec.module_id), task.state,
       task.state_version, task.attempt_count, spec.version, spec.content_sha256,
       spec.content_jsonb
FROM module_tasks AS task
JOIN module_specs AS spec ON spec.tenant_id = task.tenant_id AND spec.id = task.module_spec_id
WHERE task.tenant_id = $1::uuid AND task.project_id = $2::uuid
  AND COALESCE(task.planning_spec_id, spec.plan_spec_id) = $3::uuid
ORDER BY task.id`, request.TenantID, request.ProjectID, planID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	planned := make(map[string]contracts.PlanModule, len(plan.Modules))
	for _, module := range plan.Modules {
		planned[module.ModuleID] = module
	}
	modules := make([]globalAuditModule, 0, len(plan.Modules))
	seen := make(map[string]struct{}, len(plan.Modules))
	for rows.Next() {
		var current globalAuditModule
		var moduleVersion int
		var moduleSHA string
		var encoded []byte
		if err := rows.Scan(&current.TaskID, &current.ModuleID, &current.State, &current.Version, &current.Attempt, &moduleVersion, &moduleSHA, &encoded); err != nil {
			return nil, err
		}
		plannedModule, exists := planned[current.ModuleID]
		_, duplicate := seen[current.ModuleID]
		var module contracts.ModuleSpec
		if !exists || duplicate || current.State != contracts.TaskIntegrated || current.Version < 1 || current.Attempt < 1 ||
			decodeStrict(encoded, &module) != nil || contracts.ValidateModuleJSON(encoded) != nil ||
			module.ProjectID != request.ProjectID || module.ModuleID != current.ModuleID || module.PlanVersion != plan.PlanSpecVersion ||
			module.ModuleSpecVersion != moduleVersion || module.SHA256 != moduleSHA || module.ExecutionPlatform != plannedModule.ExecutionPlatform ||
			module.SandboxLevel != plannedModule.SandboxLevel {
			return nil, ErrProjectNotReady
		}
		current.ModuleSpecRef = contracts.SpecRef{Version: moduleVersion, SHA256: moduleSHA}
		seen[current.ModuleID] = struct{}{}
		modules = append(modules, current)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(modules) != len(plan.Modules) || len(seen) != len(plan.Modules) {
		return nil, ErrProjectNotReady
	}
	return modules, nil
}

func validateReleaseSummary(ctx context.Context, tx *sql.Tx, request Request, modules []globalAuditModule, snapshot *InputSnapshot) error {
	var total, done int
	if err := tx.QueryRowContext(ctx, `
SELECT count(*), count(*) FILTER (WHERE state = 'DONE')
FROM integration_tasks
WHERE tenant_id = $1::uuid AND project_id = $2::uuid`, request.TenantID, request.ProjectID).Scan(&total, &done); err != nil {
		return err
	}
	if total != 1 || done != 1 {
		return ErrProjectNotReady
	}
	var integrationID, stateName, requestSHA, auditSHA, commit string
	var ownerTask sql.NullString
	var version int64
	var attempt int
	var pending bool
	var mergeJSON, summaryJSON []byte
	err := tx.QueryRowContext(ctx, `
SELECT task.id::text, task.state, task.state_version, task.attempt_count,
       task.owner_module_task_id::text, task.merge_request_sha256,
       task.merge_audit_sha256, task.merge_result_jsonb, task.merge_commit,
       task.merge_pending, summary.state_jsonb
FROM integration_tasks AS task
JOIN aggregate_projections AS summary
  ON summary.tenant_id = task.tenant_id AND summary.project_id = task.project_id
 AND summary.aggregate_type = 'integration_summary' AND summary.aggregate_id = task.id::text
WHERE task.tenant_id = $1::uuid AND task.project_id = $2::uuid`, request.TenantID, request.ProjectID).Scan(
		&integrationID, &stateName, &version, &attempt, &ownerTask, &requestSHA,
		&auditSHA, &mergeJSON, &commit, &pending, &summaryJSON,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrProjectNotReady
		}
		return err
	}
	var merged integration.MergeResult
	var summary integration.PlanSupervisorSummary
	if stateName != string(integration.TaskDone) || version < 1 || pending || !commitPattern.MatchString(commit) ||
		decodeStrict(mergeJSON, &merged) != nil || decodeStrict(summaryJSON, &summary) != nil || summary.Validate() != nil ||
		summary.State != integration.SummaryReleaseCandidate || summary.TenantID != request.TenantID || summary.ProjectID != request.ProjectID ||
		summary.IntegrationID != integrationID || summary.IntegrationCommit != commit || summary.RequestSHA256 != requestSHA ||
		summary.OwnerTaskID != ownerTask.String || summary.Attempt != attempt ||
		merged.TenantID != request.TenantID || merged.ProjectID != request.ProjectID || merged.IntegrationID != integrationID ||
		merged.OwnerTaskID != ownerTask.String || merged.Attempt != attempt || merged.Commit != commit || merged.RequestDigest != requestSHA ||
		merged.Pending || !merged.Audit.Passed || merged.Audit.EvidenceSHA256 != auditSHA || len(merged.Audit.Findings) != 0 {
		return ErrProjectNotReady
	}
	checks := merged.Checks
	if len(checks) == 0 {
		checks = merged.Audit.Checks
	}
	if merged.Audit.IntegrationID != integrationID || merged.Audit.ProjectID != request.ProjectID ||
		merged.Audit.BaseCommit != summary.BaseCommit || merged.Audit.CreatedAt.IsZero() ||
		!reflect.DeepEqual(merged.Audit.Candidates, merged.Candidates) || !reflect.DeepEqual(checks, summary.Checks) ||
		!releaseModulesMatch(modules, merged.Candidates, summary.Modules) || !releaseEvidenceComplete(summary, merged, checks) {
		return ErrProjectNotReady
	}
	snapshot.IntegrationEvidence = append(json.RawMessage(nil), summaryJSON...)
	snapshot.IntegrationEvidenceSHA256 = agentruntime.DigestContextContent(string(summaryJSON))
	snapshot.IntegrationEvidenceURI = "aor://integration/" + integrationID + "/summary/" + summary.SummarySHA256[len("sha256:"):]
	snapshot.ReleaseCommit = commit
	snapshot.ArtifactRefs = evidenceArtifactRefs(summary.EvidenceSHA256)
	return nil
}

func releaseModulesMatch(modules []globalAuditModule, candidates []integration.Candidate, outcomes []integration.ModuleOutcome) bool {
	if len(modules) != len(candidates) || len(modules) != len(outcomes) {
		return false
	}
	candidateByTask := make(map[string]integration.Candidate, len(candidates))
	for _, candidate := range candidates {
		if _, duplicate := candidateByTask[candidate.TaskID]; duplicate {
			return false
		}
		candidateByTask[candidate.TaskID] = candidate
	}
	outcomeByTask := make(map[string]integration.ModuleOutcome, len(outcomes))
	for _, outcome := range outcomes {
		if _, duplicate := outcomeByTask[outcome.TaskID]; duplicate {
			return false
		}
		outcomeByTask[outcome.TaskID] = outcome
	}
	for _, module := range modules {
		candidate, candidateFound := candidateByTask[module.TaskID]
		outcome, outcomeFound := outcomeByTask[module.TaskID]
		validVersion := outcome.State == contracts.TaskPassed && module.Version == outcome.Version+1 ||
			outcome.State == contracts.TaskIntegrated && module.Version == outcome.Version
		if !candidateFound || !outcomeFound || candidate.ModuleID != module.ModuleID || candidate.ModuleSpecRef != module.ModuleSpecRef ||
			!candidate.AuditPassed || !commitPattern.MatchString(candidate.SubmissionCommit) || !digestPattern.MatchString(candidate.EvidenceSHA256) ||
			outcome.ModuleID != module.ModuleID || outcome.Attempt != module.Attempt || outcome.SubmissionCommit != candidate.SubmissionCommit ||
			outcome.EvidenceSHA256 != candidate.EvidenceSHA256 || !validVersion {
			return false
		}
	}
	return true
}

func evidenceArtifactRefs(digests []string) []string {
	refs := make([]string, 0, len(digests))
	seen := make(map[string]struct{}, len(digests))
	for _, digest := range digests {
		if !digestPattern.MatchString(digest) {
			continue
		}
		ref := "artifact://sha256/" + digest[len("sha256:"):]
		if _, duplicate := seen[ref]; duplicate {
			continue
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}

func releaseEvidenceComplete(summary integration.PlanSupervisorSummary, merged integration.MergeResult, checks []integration.CheckResult) bool {
	ordered := append([]string(nil), summary.EvidenceSHA256...)
	sort.Strings(ordered)
	if !reflect.DeepEqual(ordered, summary.EvidenceSHA256) {
		return false
	}
	available := make(map[string]struct{}, len(summary.EvidenceSHA256))
	for _, digest := range summary.EvidenceSHA256 {
		if !digestPattern.MatchString(digest) {
			return false
		}
		if _, duplicate := available[digest]; duplicate {
			return false
		}
		available[digest] = struct{}{}
	}
	required := []string{merged.Audit.EvidenceSHA256}
	for _, candidate := range merged.Candidates {
		required = append(required, candidate.EvidenceSHA256)
	}
	for _, check := range checks {
		required = append(required, check.EvidenceSHA256)
	}
	for _, digest := range required {
		if _, found := available[digest]; !found {
			return false
		}
	}
	return true
}

func sameCanonicalJSON(left, right []byte) bool {
	leftCanonical, leftErr := canonicaljson.Canonicalize(left)
	rightCanonical, rightErr := canonicaljson.Canonicalize(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftCanonical, rightCanonical)
}

type PostgresAgentRegistry struct {
	database *sql.DB
}

func NewPostgresAgentRegistry(database *sql.DB) (*PostgresAgentRegistry, error) {
	if database == nil {
		return nil, ErrRuntimeUnavailable
	}
	return &PostgresAgentRegistry{database: database}, nil
}

func (registry *PostgresAgentRegistry) Register(ctx context.Context, registration AgentRegistration) error {
	if registry == nil || registry.database == nil || ctx == nil || ctx.Err() != nil || !tenantBound(ctx, registration.TenantID) ||
		!canonicalUUID(registration.ProjectID) || !uuidV7(registration.RunID) || registration.ProjectVersion < 1 ||
		registration.AgentInstanceID != registration.ProjectID+":"+string(agentruntime.RoleGlobalAuditor)+":"+registration.RunID ||
		!safeText(registration.Provider, 128) || !safeText(registration.Model, 256) || !safeText(registration.PromptBundleVersion, 256) {
		return ErrInvalidRequest
	}
	tx, err := beginGlobalAuditAuthorityTx(ctx, registry.database, registration.TenantID, false)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var stateName, promptVersion string
	var projectVersion, projectionVersion int64
	err = tx.QueryRowContext(ctx, `
SELECT project.state, project.state_version, projection.aggregate_version,
       projection.state_jsonb->>'promptBundleVersion'
FROM projects AS project
JOIN aggregate_projections AS projection
  ON projection.tenant_id = project.tenant_id AND projection.project_id = project.id
 AND projection.aggregate_type = 'project' AND projection.aggregate_id = project.id::text
WHERE project.tenant_id = $1::uuid AND project.id = $2::uuid`, registration.TenantID, registration.ProjectID).Scan(
		&stateName, &projectVersion, &projectionVersion, &promptVersion,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrProjectNotReady
		}
		return err
	}
	if stateName != string(contracts.ProjectGlobalAudit) || projectVersion != registration.ProjectVersion ||
		projectionVersion != projectVersion || promptVersion != registration.PromptBundleVersion {
		return ErrProjectNotReady
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO agent_instances
  (id, tenant_id, project_id, role, provider, logical_model, actual_model_version,
   prompt_bundle_version, state, created_at)
VALUES ($1, $2::uuid, $3::uuid, 'GLOBAL_AUDITOR', $4, $5, $5, $6,
        'DECLARED', transaction_timestamp())
ON CONFLICT (id) DO NOTHING`, registration.AgentInstanceID, registration.TenantID, registration.ProjectID,
		registration.Provider, registration.Model, registration.PromptBundleVersion)
	if err != nil {
		return err
	}
	var tenantID, projectID, role, provider, logicalModel, actualModel, storedPrompt, agentState string
	err = tx.QueryRowContext(ctx, `
SELECT tenant_id::text, project_id::text, role, provider, logical_model,
       actual_model_version, prompt_bundle_version, state
FROM agent_instances
WHERE tenant_id = $1::uuid AND id = $2`, registration.TenantID, registration.AgentInstanceID).Scan(
		&tenantID, &projectID, &role, &provider, &logicalModel, &actualModel, &storedPrompt, &agentState,
	)
	if err != nil {
		return err
	}
	if tenantID != registration.TenantID || projectID != registration.ProjectID || role != string(agentruntime.RoleGlobalAuditor) ||
		provider != registration.Provider || logicalModel != registration.Model || actualModel != registration.Model ||
		storedPrompt != registration.PromptBundleVersion || !activeGlobalAuditorState(agentState) {
		return ErrRuntimeUnavailable
	}
	return tx.Commit()
}

func activeGlobalAuditorState(value string) bool {
	switch value {
	case "DECLARED", "QUEUED", "LEASED", "STARTING", "RUNNING", "WAITING_INPUT", "WAITING_TOOL", "WAITING_DEPENDENCY", "COMPLETED":
		return true
	default:
		return false
	}
}

func beginGlobalAuditAuthorityTx(ctx context.Context, database *sql.DB, tenantID string, readOnly bool) (*sql.Tx, error) {
	if database == nil || ctx == nil || ctx.Err() != nil || !tenantBound(ctx, tenantID) {
		return nil, ErrRuntimeUnavailable
	}
	tx, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: readOnly})
	if err != nil {
		return nil, err
	}
	var superuser, bypassRLS bool
	if err := tx.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if superuser || bypassRLS {
		_ = tx.Rollback()
		return nil, ErrRuntimeUnavailable
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

var _ InputSource = (*PostgresInputSource)(nil)
var _ AgentRegistry = (*PostgresAgentRegistry)(nil)
