package globalaudit

import (
	"context"
	"database/sql"
	"errors"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/integration"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/google/uuid"
)

var (
	ErrFollowupUnavailable = errors.New("global audit follow-up service unavailable")
	ErrFollowupConflict    = errors.New("global audit follow-up conflicts with authoritative state")
)

type FollowupResult struct {
	ModuleTaskIDs      []string `json:"moduleTaskIds"`
	IntegrationTaskIDs []string `json:"integrationTaskIds"`
}

type PostgresFollowupCreator struct {
	database       *sql.DB
	orchestrator   *orchestrator.Service
	integrations   integration.Store
	conflictReader integrationConflictReader
	conflicts      integrationConflictCreator
	principal      authn.Principal
}

type integrationConflictCreator interface {
	CreateGlobalAuditConflict(context.Context, integration.MergeResult) (integration.MergeResult, bool, error)
}

type integrationConflictReader interface {
	FindConflictByEvidence(context.Context, string, string, string) (integration.IntegrationTask, bool, error)
}

func conflictReader(store integration.Store) integrationConflictReader {
	reader, _ := store.(integrationConflictReader)
	return reader
}

func NewPostgresFollowupCreator(database *sql.DB, events eventing.Store, integrations integration.Store, principal authn.Principal, clock func() time.Time) (*PostgresFollowupCreator, error) {
	if database == nil || events == nil || integrations == nil || !validFollowupPrincipal(principal) {
		return nil, ErrFollowupUnavailable
	}
	if clock == nil {
		clock = time.Now
	}
	boundary := &followupCommitBoundary{principalID: principal.ID}
	commandOrchestrator := orchestrator.NewWithBoundary(events, clock, boundary)
	conflicts, err := integration.NewGlobalAuditConflictAuthority(integrations, commandOrchestrator, principal)
	if err != nil {
		return nil, err
	}
	return &PostgresFollowupCreator{
		database: database, orchestrator: commandOrchestrator, integrations: integrations,
		conflictReader: conflictReader(integrations), conflicts: conflicts, principal: cloneFollowupPrincipal(principal),
	}, nil
}

func (creator *PostgresFollowupCreator) Create(ctx context.Context, report Report, evidenceSHA256 string) (FollowupResult, error) {
	if creator == nil || creator.database == nil || creator.orchestrator == nil || creator.integrations == nil || creator.conflicts == nil ||
		ctx == nil || ctx.Err() != nil || report.Validate() != nil || !digestPattern.MatchString(evidenceSHA256) {
		return FollowupResult{}, ErrFollowupUnavailable
	}
	if report.PassesGate() {
		return FollowupResult{ModuleTaskIDs: []string{}, IntegrationTaskIDs: []string{}}, nil
	}
	open := openFindings(report.Findings)
	if len(open) == 0 {
		return FollowupResult{ModuleTaskIDs: []string{}, IntegrationTaskIDs: []string{}}, nil
	}
	principal := cloneFollowupPrincipal(creator.principal)
	if principal.TenantID != "" && principal.TenantID != report.TenantID || principal.ProjectID != "" && principal.ProjectID != report.ProjectID {
		return FollowupResult{}, ErrFollowupConflict
	}
	principal.TenantID = report.TenantID
	principal.ProjectID = report.ProjectID
	bound, err := authn.ContextWithPrincipal(ctx, principal)
	if err != nil {
		return FollowupResult{}, ErrFollowupUnavailable
	}
	project, found, err := creator.orchestrator.Project(bound, report.TenantID, report.ProjectID)
	if err != nil {
		return FollowupResult{}, err
	}
	if !found || !reportMatchesProject(report, project) {
		return FollowupResult{}, ErrFollowupConflict
	}
	plan, err := creator.loadPlan(bound, report)
	if err != nil {
		return FollowupResult{}, err
	}
	tasks, err := creator.orchestrator.Tasks(bound, report.TenantID, report.ProjectID)
	if err != nil {
		return FollowupResult{}, err
	}

	moduleFindings, integrationFindings, integrationModules := classifyFollowupFindings(open, plan.Modules)
	moduleIDs := sortedFindingModules(moduleFindings)
	existing, complete, progressed, err := creator.inspectExistingFollowups(bound, report, evidenceSHA256, moduleIDs, len(integrationFindings) != 0)
	if err != nil {
		return FollowupResult{}, err
	}
	if project.State != contracts.ProjectGlobalAudit {
		if !complete {
			return FollowupResult{}, ErrFollowupConflict
		}
		return existing, nil
	}
	if progressed {
		if !complete {
			return FollowupResult{}, ErrFollowupConflict
		}
		return existing, nil
	}
	currentTasks := currentIntegratedTasks(plan.Modules, tasks)
	replacements := make(map[string]state.ModuleTask, len(moduleIDs))
	result := FollowupResult{ModuleTaskIDs: make([]string, 0, len(moduleIDs)), IntegrationTaskIDs: []string{}}
	for _, moduleID := range moduleIDs {
		task, createErr := creator.createModuleTask(bound, report, evidenceSHA256, moduleID, currentTasks[moduleID])
		if createErr != nil {
			return FollowupResult{}, createErr
		}
		replacements[moduleID] = task
		result.ModuleTaskIDs = append(result.ModuleTaskIDs, task.ID)
	}
	if len(integrationFindings) != 0 {
		integrationID, createErr := creator.createIntegrationTask(bound, report, evidenceSHA256, integrationFindings, integrationModules, plan.Modules, currentTasks, replacements)
		if createErr != nil {
			return FollowupResult{}, createErr
		}
		result.IntegrationTaskIDs = append(result.IntegrationTaskIDs, integrationID)
	}

	reopen := state.ProjectCommandReopenIntegration
	if len(result.ModuleTaskIDs) != 0 {
		reopen = state.ProjectCommandReopenExecution
	}
	_, err = creator.orchestrator.HandleProject(bound, orchestrator.ProjectRequest{
		TenantID: report.TenantID, ProjectID: report.ProjectID, PrincipalID: principal.ID,
		IdempotencyKey: "global-audit:" + report.RunID + ":reopen", ExpectedVersion: project.Version,
		Command: state.ProjectCommand{Type: reopen, Guard: &state.ProjectGuardFacts{EvidenceSHA256: evidenceSHA256}},
	})
	if err != nil {
		return FollowupResult{}, err
	}
	sort.Strings(result.ModuleTaskIDs)
	sort.Strings(result.IntegrationTaskIDs)
	return result, nil
}

func (creator *PostgresFollowupCreator) inspectExistingFollowups(ctx context.Context, report Report, evidenceSHA256 string, moduleIDs []string, integrationExpected bool) (FollowupResult, bool, bool, error) {
	result := FollowupResult{ModuleTaskIDs: make([]string, 0, len(moduleIDs)), IntegrationTaskIDs: []string{}}
	complete := true
	progressed := false
	for _, moduleID := range moduleIDs {
		defined, found, err := creator.loadFollowupTaskMapping(ctx, report, moduleID)
		if err != nil {
			return FollowupResult{}, false, false, err
		}
		if !found {
			complete = false
			continue
		}
		task, taskFound, err := creator.orchestrator.Task(ctx, report.TenantID, report.ProjectID, defined.ID)
		if err != nil {
			return FollowupResult{}, false, false, err
		}
		if !taskFound || !validMappedFollowupTask(report, moduleID, defined, task) {
			return FollowupResult{}, false, false, ErrFollowupConflict
		}
		result.ModuleTaskIDs = append(result.ModuleTaskIDs, task.ID)
		if task.State == contracts.TaskDefined {
			complete = false
		} else if task.State != contracts.TaskReadyExecution {
			progressed = true
		}
	}
	if integrationExpected {
		if creator.conflictReader == nil {
			return FollowupResult{}, false, false, ErrFollowupUnavailable
		}
		task, found, err := creator.conflictReader.FindConflictByEvidence(ctx, report.TenantID, report.ProjectID, evidenceSHA256)
		if err != nil {
			return FollowupResult{}, false, false, err
		}
		if !found {
			complete = false
		} else {
			if task.TenantID != report.TenantID || task.ProjectID != report.ProjectID || !uuidV7(task.ID) || task.OwnerTaskID == "" ||
				task.Conflict.IntegrationID != task.ID || task.Conflict.ProjectID != report.ProjectID || task.Conflict.EvidenceSHA256 != evidenceSHA256 {
				return FollowupResult{}, false, false, ErrFollowupConflict
			}
			result.IntegrationTaskIDs = append(result.IntegrationTaskIDs, task.ID)
			if task.State != integration.TaskReworkRequired || task.Attempt != 0 || task.Version != 1 {
				progressed = true
			}
		}
	}
	sort.Strings(result.ModuleTaskIDs)
	return result, complete, progressed, nil
}

func (creator *PostgresFollowupCreator) createModuleTask(ctx context.Context, report Report, evidenceSHA256, moduleID string, original state.ModuleTask) (state.ModuleTask, error) {
	key := followupModuleKey(report.RunID, moduleID)
	defined, exists, err := creator.loadFollowupTaskMapping(ctx, report, moduleID)
	if err != nil {
		return state.ModuleTask{}, err
	}
	var existing state.ModuleTask
	if exists {
		existing, exists, err = creator.orchestrator.Task(ctx, report.TenantID, report.ProjectID, defined.ID)
		if err != nil {
			return state.ModuleTask{}, err
		}
		if !exists || !validMappedFollowupTask(report, moduleID, defined, existing) {
			return state.ModuleTask{}, ErrFollowupConflict
		}
		if original.ID == existing.ID {
			original = state.ModuleTask{}
		} else if original.ID != "" && (original.ModuleSpecRef != defined.ModuleSpecRef || !sameTaskPlanMetadata(original, defined)) {
			return state.ModuleTask{}, ErrFollowupConflict
		}
	} else {
		if original.ID == "" || original.State != contracts.TaskIntegrated || original.ModuleID != moduleID ||
			original.PlanningSpecRef != report.PlanSpecRef || original.ModuleSpecRef.Validate() != nil {
			return state.ModuleTask{}, ErrFollowupConflict
		}
		taskID, idErr := newFollowupUUID()
		if idErr != nil {
			return state.ModuleTask{}, idErr
		}
		seriesID, idErr := newFollowupUUID()
		if idErr != nil {
			return state.ModuleTask{}, idErr
		}
		outcome, handleErr := creator.orchestrator.HandleTask(ctx, orchestrator.TaskRequest{
			TenantID: report.TenantID, ProjectID: report.ProjectID, TaskID: taskID, PrincipalID: creator.principal.ID,
			IdempotencyKey: key + ":define", ExpectedVersion: 0,
			Command: state.TaskCommand{
				Type: state.TaskCommandDefine, ModuleID: moduleID, PlanningSpecRef: original.PlanningSpecRef,
				ModuleSpecRef: original.ModuleSpecRef, AttemptSeriesID: seriesID,
				DependentTaskIDs:   append([]string(nil), original.DependentTaskIDs...),
				FrozenDependentIDs: append([]string(nil), original.FrozenDependentIDs...),
				BlockingTaskIDs:    append([]string(nil), original.BlockingTaskIDs...), BlockedFromState: original.BlockedFromState,
				ModuleSpecSourceTaskID: moduleSpecSourceTaskID(original),
				AuditEvidenceSHA256:    evidenceSHA256,
			},
		})
		if handleErr != nil {
			defined, mapped, lookupErr := creator.loadFollowupTaskMapping(ctx, report, moduleID)
			if lookupErr != nil {
				return state.ModuleTask{}, lookupErr
			}
			if !mapped {
				return state.ModuleTask{}, handleErr
			}
			existing, exists, lookupErr = creator.orchestrator.Task(ctx, report.TenantID, report.ProjectID, defined.ID)
			if lookupErr != nil {
				return state.ModuleTask{}, lookupErr
			}
			if !exists || !validMappedFollowupTask(report, moduleID, defined, existing) || original.ModuleSpecRef != defined.ModuleSpecRef || !sameTaskPlanMetadata(original, defined) {
				return state.ModuleTask{}, ErrFollowupConflict
			}
		} else {
			existing = outcome.Task
		}
	}
	if existing.State == contracts.TaskDefined {
		outcome, err := creator.orchestrator.HandleTask(ctx, orchestrator.TaskRequest{
			TenantID: report.TenantID, ProjectID: report.ProjectID, TaskID: existing.ID, PrincipalID: creator.principal.ID,
			IdempotencyKey: key + ":ready", ExpectedVersion: existing.Version,
			Command: state.TaskCommand{Type: state.TaskCommandReadyExecution, AuditEvidenceSHA256: evidenceSHA256},
		})
		if err != nil {
			return state.ModuleTask{}, err
		}
		existing = outcome.Task
	}
	if !validFollowupTaskState(existing.State) {
		return state.ModuleTask{}, ErrFollowupConflict
	}
	if original.ID != "" && original.State == contracts.TaskIntegrated {
		_, err := creator.orchestrator.HandleTask(ctx, orchestrator.TaskRequest{
			TenantID: report.TenantID, ProjectID: report.ProjectID, TaskID: original.ID, PrincipalID: creator.principal.ID,
			IdempotencyKey: key + ":supersede", ExpectedVersion: original.Version,
			Command: state.TaskCommand{Type: state.TaskCommandSupersede, AuditEvidenceSHA256: evidenceSHA256},
		})
		if err != nil {
			return state.ModuleTask{}, err
		}
	}
	return existing, nil
}

func (creator *PostgresFollowupCreator) createIntegrationTask(ctx context.Context, report Report, evidenceSHA256 string, findings []contracts.AuditFinding, affectedModules []string, modules []contracts.PlanModule, current, replacements map[string]state.ModuleTask) (string, error) {
	taskIDs := affectedTaskIDs(affectedModules, modules, current, replacements)
	if len(taskIDs) == 0 {
		return "", ErrFollowupConflict
	}
	ownerTaskID := taskIDs[0]
	if creator.conflictReader == nil {
		return "", ErrFollowupUnavailable
	}
	existing, found, err := creator.conflictReader.FindConflictByEvidence(ctx, report.TenantID, report.ProjectID, evidenceSHA256)
	if err != nil {
		return "", err
	}
	integrationID := existing.ID
	if !found {
		integrationID, err = newFollowupUUID()
		if err != nil {
			return "", err
		}
	} else if !uuidV7(integrationID) || existing.Conflict.EvidenceSHA256 != evidenceSHA256 {
		return "", ErrFollowupConflict
	}
	integrationFindings := make([]integration.Finding, 0, len(findings))
	for _, finding := range findings {
		severity := string(finding.Severity)
		if finding.Severity == contracts.FindingHigh || finding.Severity == contracts.FindingCritical {
			severity = "BLOCKING"
		}
		integrationFindings = append(integrationFindings, integration.Finding{
			ID: finding.FindingID, Severity: severity, Category: finding.Category,
			Summary: finding.ObservedBehavior, Tasks: append([]string(nil), taskIDs...),
		})
	}
	sort.Slice(integrationFindings, func(left, right int) bool { return integrationFindings[left].ID < integrationFindings[right].ID })
	audit := integration.Audit{
		IntegrationID: integrationID, ProjectID: report.ProjectID, BaseCommit: report.ReleaseCommit,
		Findings: integrationFindings,
		Checks: []integration.CheckResult{{
			Kind: integration.CheckIntegration, Status: integration.CheckError, EvidenceSHA256: evidenceSHA256,
			Summary: "global audit requires integration remediation", OwnerTaskID: ownerTaskID,
			Tasks: append([]string(nil), taskIDs...), StartedAt: report.StartedAt, CompletedAt: report.CompletedAt,
		}},
		EvidenceSHA256: evidenceSHA256, Passed: false, CreatedAt: report.CompletedAt,
	}
	stored, _, err := creator.conflicts.CreateGlobalAuditConflict(ctx, integration.MergeResult{
		TenantID: report.TenantID, ProjectID: report.ProjectID, IntegrationID: integrationID,
		OwnerTaskID: ownerTaskID, Attempt: 0, Audit: audit,
	})
	if err != nil {
		recovered, recoveredFound, lookupErr := creator.conflictReader.FindConflictByEvidence(ctx, report.TenantID, report.ProjectID, evidenceSHA256)
		if lookupErr != nil {
			return "", lookupErr
		}
		if !recoveredFound || !uuidV7(recovered.ID) {
			return "", err
		}
		stored = integration.MergeResult{
			TenantID: recovered.TenantID, ProjectID: recovered.ProjectID, IntegrationID: recovered.ID,
			OwnerTaskID: recovered.OwnerTaskID, Attempt: recovered.Attempt, Audit: recovered.Conflict,
		}
		integrationID = recovered.ID
	}
	if stored.IntegrationID != integrationID || stored.ProjectID != report.ProjectID || stored.OwnerTaskID != ownerTaskID || stored.Audit.EvidenceSHA256 != evidenceSHA256 {
		return "", ErrFollowupConflict
	}
	return integrationID, nil
}

func (creator *PostgresFollowupCreator) loadFollowupTaskMapping(ctx context.Context, report Report, moduleID string) (state.ModuleTask, bool, error) {
	if creator == nil || creator.database == nil || !tenantBound(ctx, report.TenantID) {
		return state.ModuleTask{}, false, ErrFollowupUnavailable
	}
	tx, err := creator.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return state.ModuleTask{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, report.TenantID); err != nil {
		return state.ModuleTask{}, false, err
	}
	var encoded []byte
	err = tx.QueryRowContext(ctx, `
SELECT result_jsonb
FROM command_results
WHERE tenant_id = $1::uuid AND principal_id = $2 AND idempotency_key = $3`,
		report.TenantID, creator.principal.ID, followupModuleKey(report.RunID, moduleID)+":define").Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return state.ModuleTask{}, false, nil
	}
	if err != nil {
		return state.ModuleTask{}, false, err
	}
	var task state.ModuleTask
	if decodeStrict(encoded, &task) != nil || !validDefinedFollowupMapping(report, moduleID, task) {
		return state.ModuleTask{}, false, ErrFollowupConflict
	}
	if err := tx.Commit(); err != nil {
		return state.ModuleTask{}, false, err
	}
	return task, true, nil
}

func (creator *PostgresFollowupCreator) loadPlan(ctx context.Context, report Report) (contracts.PlanSpec, error) {
	if !tenantBound(ctx, report.TenantID) {
		return contracts.PlanSpec{}, ErrFollowupUnavailable
	}
	tx, err := creator.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return contracts.PlanSpec{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, report.TenantID); err != nil {
		return contracts.PlanSpec{}, err
	}
	var version int
	var digest string
	var encoded []byte
	err = tx.QueryRowContext(ctx, `
SELECT plan.version, plan.content_sha256, plan.content_jsonb
FROM projects AS project
JOIN plan_specs AS plan
  ON plan.tenant_id = project.tenant_id AND plan.id = project.active_plan_spec_id
WHERE project.tenant_id = $1::uuid AND project.id = $2::uuid
  AND plan.status = 'PUBLISHED'`, report.TenantID, report.ProjectID).Scan(&version, &digest, &encoded)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return contracts.PlanSpec{}, ErrFollowupConflict
		}
		return contracts.PlanSpec{}, err
	}
	var plan contracts.PlanSpec
	if version != report.PlanSpecRef.Version || digest != report.PlanSpecRef.SHA256 || decodeStrict(encoded, &plan) != nil ||
		contracts.ValidatePlanJSON(encoded) != nil || plan.Validate() != nil || plan.ProjectID != report.ProjectID || plan.SHA256 != digest {
		return contracts.PlanSpec{}, ErrFollowupConflict
	}
	if err := tx.Commit(); err != nil {
		return contracts.PlanSpec{}, err
	}
	return plan, nil
}

type followupCommitBoundary struct {
	principalID string
}

func (boundary *followupCommitBoundary) Validate(ctx context.Context, validation orchestrator.CommitValidation) error {
	principal, found := authn.PrincipalFromContext(ctx)
	if boundary == nil || !found || !validFollowupPrincipal(principal) || principal.ID != boundary.principalID ||
		principal.ID != validation.PrincipalID || principal.TenantID != validation.TenantID ||
		principal.ProjectID != "" && principal.ProjectID != validation.ProjectID || !validFollowupCommit(validation) {
		return orchestrator.ErrCommitBoundary
	}
	return nil
}

func validFollowupCommit(validation orchestrator.CommitValidation) bool {
	if validation.TenantID == "" || validation.ProjectID == "" || validation.Project.State != contracts.ProjectGlobalAudit ||
		validation.Project.Plan == nil || !digestPattern.MatchString(validation.ParameterDigest) ||
		len(validation.EvidenceSHA256) != 1 || !digestPattern.MatchString(validation.EvidenceSHA256[0]) {
		return false
	}
	for _, claim := range validation.Claims {
		if claim {
			return false
		}
	}
	switch state.ProjectCommandType(validation.Action) {
	case state.ProjectCommandReopenExecution, state.ProjectCommandReopenIntegration:
		return validation.TaskID == "" && validation.ExpectedVersion == validation.Project.Version
	}
	if validation.TaskID == "" || validation.ExpectedVersion != validation.Task.Version {
		return false
	}
	switch state.TaskCommandType(validation.Action) {
	case state.TaskCommandDefine:
		return validation.ExpectedVersion == 0 && emptyFollowupTask(validation.Task) && validation.ModuleSpecRef.Validate() == nil
	case state.TaskCommandReadyExecution:
		return validation.Task.State == contracts.TaskDefined && validation.ModuleSpecRef == validation.Task.ModuleSpecRef
	case state.TaskCommandSupersede:
		return validation.Task.State == contracts.TaskIntegrated && validation.ModuleSpecRef == validation.Task.ModuleSpecRef
	default:
		return false
	}
}

func openFindings(findings []contracts.AuditFinding) []contracts.AuditFinding {
	result := make([]contracts.AuditFinding, 0, len(findings))
	for _, finding := range findings {
		if finding.Status == contracts.FindingOpen {
			result = append(result, finding)
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].StableFingerprint < result[right].StableFingerprint })
	return result
}

func classifyFollowupFindings(findings []contracts.AuditFinding, modules []contracts.PlanModule) (map[string][]contracts.AuditFinding, []contracts.AuditFinding, []string) {
	moduleFindings := make(map[string][]contracts.AuditFinding)
	integrationFindings := make([]contracts.AuditFinding, 0)
	integrationModules := make(map[string]struct{})
	for _, finding := range findings {
		owners := ownedModules(finding.File, modules)
		if len(owners) == 1 {
			moduleFindings[owners[0]] = append(moduleFindings[owners[0]], finding)
			continue
		}
		integrationFindings = append(integrationFindings, finding)
		for _, moduleID := range owners {
			integrationModules[moduleID] = struct{}{}
		}
	}
	moduleIDs := make([]string, 0, len(integrationModules))
	for moduleID := range integrationModules {
		moduleIDs = append(moduleIDs, moduleID)
	}
	sort.Strings(moduleIDs)
	return moduleFindings, integrationFindings, moduleIDs
}

func ownedModules(file string, modules []contracts.PlanModule) []string {
	if file == "" {
		return nil
	}
	owners := make([]string, 0, 1)
	for _, module := range modules {
		for _, owned := range module.OwnedPaths {
			if followupPathMatch(file, owned) {
				owners = append(owners, module.ModuleID)
				break
			}
		}
	}
	sort.Strings(owners)
	return owners
}

func followupPathMatch(candidate, pattern string) bool {
	candidate = strings.ReplaceAll(candidate, "\\", "/")
	pattern = strings.ReplaceAll(pattern, "\\", "/")
	if candidate == pattern {
		return true
	}
	if strings.HasSuffix(pattern, "/...") {
		root := strings.TrimSuffix(pattern, "/...")
		return candidate == root || strings.HasPrefix(candidate, root+"/")
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return strings.HasPrefix(candidate, strings.TrimSuffix(pattern, "/")+"/")
	}
	return followupGlobParts(strings.Split(candidate, "/"), strings.Split(pattern, "/"))
}

func followupGlobParts(candidate, patternParts []string) bool {
	for len(patternParts) != 0 {
		if patternParts[0] == "**" {
			patternParts = patternParts[1:]
			if len(patternParts) == 0 {
				return true
			}
			for index := 0; index <= len(candidate); index++ {
				if followupGlobParts(candidate[index:], patternParts) {
					return true
				}
			}
			return false
		}
		if len(candidate) == 0 {
			return false
		}
		matched, err := path.Match(patternParts[0], candidate[0])
		if err != nil || !matched {
			return false
		}
		candidate = candidate[1:]
		patternParts = patternParts[1:]
	}
	return len(candidate) == 0
}

func currentIntegratedTasks(modules []contracts.PlanModule, tasks []state.ModuleTask) map[string]state.ModuleTask {
	known := make(map[string]struct{}, len(modules))
	for _, module := range modules {
		known[module.ModuleID] = struct{}{}
	}
	result := make(map[string]state.ModuleTask, len(modules))
	for _, task := range tasks {
		if _, found := known[task.ModuleID]; !found || task.State != contracts.TaskIntegrated || task.ModuleSpecRef.Validate() != nil {
			continue
		}
		if _, duplicate := result[task.ModuleID]; duplicate {
			result[task.ModuleID] = state.ModuleTask{}
			continue
		}
		result[task.ModuleID] = task
	}
	return result
}

func affectedTaskIDs(affectedModules []string, modules []contracts.PlanModule, current, replacements map[string]state.ModuleTask) []string {
	moduleIDs := append([]string(nil), affectedModules...)
	if len(moduleIDs) == 0 {
		for moduleID := range replacements {
			moduleIDs = append(moduleIDs, moduleID)
		}
	}
	if len(moduleIDs) == 0 {
		for _, module := range modules {
			moduleIDs = append(moduleIDs, module.ModuleID)
		}
	}
	sort.Strings(moduleIDs)
	seen := make(map[string]struct{}, len(moduleIDs))
	result := make([]string, 0, len(moduleIDs))
	for _, moduleID := range moduleIDs {
		task := replacements[moduleID]
		if task.ID == "" {
			task = current[moduleID]
		}
		if task.ID == "" {
			continue
		}
		if _, duplicate := seen[task.ID]; duplicate {
			continue
		}
		seen[task.ID] = struct{}{}
		result = append(result, task.ID)
	}
	sort.Strings(result)
	return result
}

func sortedFindingModules(findings map[string][]contracts.AuditFinding) []string {
	result := make([]string, 0, len(findings))
	for moduleID := range findings {
		result = append(result, moduleID)
	}
	sort.Strings(result)
	return result
}

func sameTaskPlanMetadata(original, replacement state.ModuleTask) bool {
	return original.PlanningSpecRef == replacement.PlanningSpecRef &&
		moduleSpecSourceTaskID(original) == replacement.ModuleSpecSourceTaskID &&
		original.BlockedFromState == replacement.BlockedFromState &&
		sameStrings(original.DependentTaskIDs, replacement.DependentTaskIDs) &&
		sameStrings(original.FrozenDependentIDs, replacement.FrozenDependentIDs) &&
		sameStrings(original.BlockingTaskIDs, replacement.BlockingTaskIDs)
}

func moduleSpecSourceTaskID(task state.ModuleTask) string {
	if task.ModuleSpecSourceTaskID != "" {
		return task.ModuleSpecSourceTaskID
	}
	return task.ID
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func hasString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func validDefinedFollowupMapping(report Report, moduleID string, task state.ModuleTask) bool {
	return task.TenantID == report.TenantID && task.ProjectID == report.ProjectID && task.ModuleID == moduleID &&
		uuidV7(task.ID) && uuidV7(task.AttemptSeriesID) && uuidV7(task.ModuleSpecSourceTaskID) && task.State == contracts.TaskDefined && task.Version == 1 &&
		task.PlanningSpecRef == report.PlanSpecRef && task.ModuleSpecRef.Validate() == nil &&
		len(task.AttemptSeriesIDs) == 1 && task.AttemptSeriesIDs[0] == task.AttemptSeriesID
}

func validMappedFollowupTask(report Report, moduleID string, defined, current state.ModuleTask) bool {
	return validDefinedFollowupMapping(report, moduleID, defined) && current.TenantID == defined.TenantID &&
		current.ProjectID == defined.ProjectID && current.ID == defined.ID && current.ModuleID == defined.ModuleID &&
		current.ModuleSpecSourceTaskID == defined.ModuleSpecSourceTaskID &&
		current.PlanningSpecRef == defined.PlanningSpecRef && current.ModuleSpecRef == defined.ModuleSpecRef &&
		sameStrings(current.DependentTaskIDs, defined.DependentTaskIDs) &&
		hasString(current.AttemptSeriesIDs, defined.AttemptSeriesID) && validFollowupTaskState(current.State)
}

func validFollowupTaskState(value contracts.ModuleTaskState) bool {
	switch value {
	case contracts.TaskReadyExecution, contracts.TaskQueuedExecution, contracts.TaskExecuting, contracts.TaskSubmitted,
		contracts.TaskDeterministicAudit, contracts.TaskLLMAudit, contracts.TaskReworkRequired,
		contracts.TaskBlockedDependency, contracts.TaskBlockedUserDecision, contracts.TaskPassed, contracts.TaskIntegrated:
		return true
	case contracts.TaskSuperseded:
		return true
	default:
		return false
	}
}

func emptyFollowupTask(task state.ModuleTask) bool {
	return task.TenantID == "" && task.ProjectID == "" && task.ID == "" && task.ModuleID == "" && task.State == "" && task.Version == 0 &&
		task.PlanningSpecRef == (contracts.SpecRef{}) && task.ModuleSpecRef == (contracts.SpecRef{}) && task.AttemptSeriesID == "" &&
		len(task.AttemptSeriesIDs) == 0 && task.Attempt == 0 && task.FencingToken == 0 && len(task.DependentTaskIDs) == 0 &&
		len(task.FrozenDependentIDs) == 0 && len(task.BlockingTaskIDs) == 0 && task.BlockedFromState == "" && task.ModuleSpecSourceTaskID == ""
}

func followupModuleKey(runID, moduleID string) string {
	return "global-audit:" + runID + ":module:" + moduleID
}

func newFollowupUUID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", ErrFollowupUnavailable
	}
	return id.String(), nil
}

func validFollowupPrincipal(principal authn.Principal) bool {
	return principal.Validate() == nil && principal.Type == authn.PrincipalService && principal.Role == authn.RoleService
}

func cloneFollowupPrincipal(principal authn.Principal) authn.Principal {
	clone := principal
	clone.Attributes = make(map[string]string, len(principal.Attributes))
	for key, value := range principal.Attributes {
		clone.Attributes[key] = value
	}
	return clone
}

var _ FollowupCreator = (*PostgresFollowupCreator)(nil)
var _ orchestrator.CommitBoundary = (*followupCommitBoundary)(nil)
