package integration

import (
	"context"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
)

type OrchestratorAuthority struct {
	service   *orchestrator.Service
	principal authn.Principal
}

// ProjectSource is the read side of the Orchestrator authority used by the
// narrow global-audit IntegrationTask creation boundary below.
type ProjectSource interface {
	Project(context.Context, string, string) (state.Project, bool, error)
}

// GlobalAuditConflictAuthority is the smallest authoritative write entrypoint
// for a conflict discovered outside the integration merge queue. It keeps the
// durable Store behind the Orchestrator-owned service principal and verifies
// that the project is still in GLOBAL_AUDIT before creating the task.
type GlobalAuditConflictAuthority struct {
	store     Store
	projects  ProjectSource
	principal authn.Principal
}

func NewGlobalAuditConflictAuthority(store Store, projects ProjectSource, principal authn.Principal) (*GlobalAuditConflictAuthority, error) {
	if store == nil || projects == nil || !validIntegrationServicePrincipal(principal) {
		return nil, ErrWorkflowUnavailable
	}
	return &GlobalAuditConflictAuthority{store: store, projects: projects, principal: cloneIntegrationPrincipal(principal)}, nil
}

func (authority *GlobalAuditConflictAuthority) CreateGlobalAuditConflict(ctx context.Context, result MergeResult) (MergeResult, bool, error) {
	if authority == nil || authority.store == nil || authority.projects == nil || ctx == nil || ctx.Err() != nil ||
		!canonicalUUID(result.TenantID) || !canonicalUUID(result.ProjectID) || !canonicalUUID(result.IntegrationID) ||
		!canonicalUUID(result.OwnerTaskID) || result.Attempt != 0 || !validConflictResult(result) ||
		!globalAuditConflictEvidence(result) {
		return MergeResult{}, false, ErrInvalidRequest
	}
	principal, found := authn.PrincipalFromContext(ctx)
	if !found || !validIntegrationServicePrincipal(principal) || principal.ID != authority.principal.ID ||
		authority.principal.TenantID != "" && authority.principal.TenantID != result.TenantID ||
		authority.principal.ProjectID != "" && authority.principal.ProjectID != result.ProjectID ||
		principal.TenantID != "" && principal.TenantID != result.TenantID || principal.ProjectID != "" && principal.ProjectID != result.ProjectID {
		return MergeResult{}, false, ErrNotAudited
	}
	principal.TenantID = result.TenantID
	principal.ProjectID = result.ProjectID
	bound, err := authn.ContextWithPrincipal(ctx, principal)
	if err != nil {
		return MergeResult{}, false, ErrNotAudited
	}
	project, found, err := authority.projects.Project(bound, result.TenantID, result.ProjectID)
	if err != nil {
		return MergeResult{}, false, err
	}
	if !found || project.TenantID != result.TenantID || project.ID != result.ProjectID || project.State != contracts.ProjectGlobalAudit {
		return MergeResult{}, false, ErrNotAudited
	}
	return authority.store.RecordConflict(bound, result)
}

func globalAuditConflictEvidence(result MergeResult) bool {
	if len(result.Audit.Checks) != 1 {
		return false
	}
	check := result.Audit.Checks[0]
	return check.Kind == CheckIntegration && check.Status == CheckError && check.EvidenceSHA256 == result.Audit.EvidenceSHA256 &&
		check.OwnerTaskID == result.OwnerTaskID && containsString(check.Tasks, result.OwnerTaskID) &&
		allConflictFindingsOwned(result.Audit.Findings, result.OwnerTaskID)
}

func allConflictFindingsOwned(findings []Finding, ownerTaskID string) bool {
	if len(findings) == 0 {
		return false
	}
	for _, finding := range findings {
		if !containsString(finding.Tasks, ownerTaskID) {
			return false
		}
	}
	return true
}

func NewOrchestratorAuthority(store eventing.Store, policy authz.PolicyEvaluator, principal authn.Principal, clock func() time.Time) (*OrchestratorAuthority, error) {
	if store == nil || policy == nil || !validIntegrationServicePrincipal(principal) {
		return nil, ErrWorkflowUnavailable
	}
	boundary, err := NewServiceCommitBoundary(policy)
	if err != nil {
		return nil, err
	}
	if clock == nil {
		clock = time.Now
	}
	return &OrchestratorAuthority{
		service:   orchestrator.NewWithBoundary(store, clock, boundary),
		principal: cloneIntegrationPrincipal(principal),
	}, nil
}

func (authority *OrchestratorAuthority) Project(ctx context.Context, tenantID, projectID string) (state.Project, bool, error) {
	if authority == nil || authority.service == nil {
		return state.Project{}, false, ErrWorkflowUnavailable
	}
	return authority.service.Project(ctx, tenantID, projectID)
}

func (authority *OrchestratorAuthority) Task(ctx context.Context, tenantID, projectID, taskID string) (state.ModuleTask, bool, error) {
	if authority == nil || authority.service == nil {
		return state.ModuleTask{}, false, ErrWorkflowUnavailable
	}
	return authority.service.Task(ctx, tenantID, projectID, taskID)
}

func (authority *OrchestratorAuthority) Tasks(ctx context.Context, tenantID, projectID string) ([]state.ModuleTask, error) {
	if authority == nil || authority.service == nil {
		return nil, ErrWorkflowUnavailable
	}
	return authority.service.Tasks(ctx, tenantID, projectID)
}

func (authority *OrchestratorAuthority) BeginIntegration(ctx context.Context, integrationID, tenantID, projectID string, expectedVersion int64, policyDigest, evidenceSHA256 string) (state.Project, bool, error) {
	if !validAuthorityRequest(integrationID, tenantID, projectID, expectedVersion, policyDigest, evidenceSHA256) {
		return state.Project{}, false, ErrInvalidRequest
	}
	return authority.commitProject(ctx, integrationID, tenantID, projectID, expectedVersion, policyDigest, "begin", state.ProjectCommand{
		Type:  state.ProjectCommandBeginIntegration,
		Guard: &state.ProjectGuardFacts{AllTasksPassed: true, EvidenceSHA256: evidenceSHA256},
	})
}

func (authority *OrchestratorAuthority) IntegrateTask(ctx context.Context, integrationID, tenantID, projectID, taskID string, expectedVersion int64, policyDigest, evidenceSHA256 string) (state.ModuleTask, bool, error) {
	if authority == nil || authority.service == nil || ctx == nil || ctx.Err() != nil || !safeIntegrationID(integrationID) || tenantID == "" || projectID == "" || taskID == "" || expectedVersion < 1 || !digestPattern(policyDigest) || !digestPattern(evidenceSHA256) {
		return state.ModuleTask{}, false, ErrInvalidRequest
	}
	tasks, err := authority.service.Tasks(ctx, tenantID, projectID)
	if err != nil || !taskDependenciesIntegrated(tasks, taskID) {
		if err != nil {
			return state.ModuleTask{}, false, err
		}
		return state.ModuleTask{}, false, ErrModulesNotReady
	}
	principal, bound, err := authority.boundContext(ctx, tenantID, projectID)
	if err != nil {
		return state.ModuleTask{}, false, err
	}
	outcome, err := authority.service.HandleTask(bound, orchestrator.TaskRequest{
		TenantID: tenantID, ProjectID: projectID, TaskID: taskID,
		PrincipalID: principal.ID, IdempotencyKey: integrationCommandKey(integrationID, "integrate:"+taskID),
		ExpectedVersion: expectedVersion,
		Command: state.TaskCommand{
			Type: state.TaskCommandIntegrate, DependenciesSatisfied: true,
			MergeGatePassed: true, AuditEvidenceSHA256: evidenceSHA256,
		},
		Authorization: orchestrator.CommitAuthorization{Capability: orchestrator.CommitCapability{PolicyVersion: policyDigest}},
	})
	return outcome.Task, outcome.Duplicate, err
}

func (authority *OrchestratorAuthority) BeginGlobalAudit(ctx context.Context, integrationID, tenantID, projectID string, expectedVersion int64, policyDigest, evidenceSHA256 string) (state.Project, bool, error) {
	if !validAuthorityRequest(integrationID, tenantID, projectID, expectedVersion, policyDigest, evidenceSHA256) {
		return state.Project{}, false, ErrInvalidRequest
	}
	tasks, err := authority.service.Tasks(ctx, tenantID, projectID)
	if err != nil || !allTasksIntegrated(tasks) {
		if err != nil {
			return state.Project{}, false, err
		}
		return state.Project{}, false, ErrModulesNotReady
	}
	return authority.commitProject(ctx, integrationID, tenantID, projectID, expectedVersion, policyDigest, "global-audit", state.ProjectCommand{
		Type:  state.ProjectCommandBeginGlobalAudit,
		Guard: &state.ProjectGuardFacts{AllTasksIntegrated: true, IntegrationAuditPassed: true, EvidenceSHA256: evidenceSHA256},
	})
}

func (authority *OrchestratorAuthority) commitProject(ctx context.Context, integrationID, tenantID, projectID string, expectedVersion int64, policyDigest, suffix string, command state.ProjectCommand) (state.Project, bool, error) {
	if authority == nil || authority.service == nil || ctx == nil || ctx.Err() != nil {
		return state.Project{}, false, ErrWorkflowUnavailable
	}
	principal, bound, err := authority.boundContext(ctx, tenantID, projectID)
	if err != nil {
		return state.Project{}, false, err
	}
	outcome, err := authority.service.HandleProject(bound, orchestrator.ProjectRequest{
		TenantID: tenantID, ProjectID: projectID, PrincipalID: principal.ID,
		IdempotencyKey: integrationCommandKey(integrationID, suffix), ExpectedVersion: expectedVersion,
		Command:       command,
		Authorization: orchestrator.CommitAuthorization{Capability: orchestrator.CommitCapability{PolicyVersion: policyDigest}},
	})
	return outcome.Project, outcome.Duplicate, err
}

func (authority *OrchestratorAuthority) boundContext(ctx context.Context, tenantID, projectID string) (authn.Principal, context.Context, error) {
	principal := cloneIntegrationPrincipal(authority.principal)
	if principal.TenantID != "" && principal.TenantID != tenantID || principal.ProjectID != "" && principal.ProjectID != projectID {
		return authn.Principal{}, nil, ErrNotAudited
	}
	principal.TenantID = tenantID
	principal.ProjectID = projectID
	bound, err := authn.ContextWithPrincipal(ctx, principal)
	if err != nil {
		return authn.Principal{}, nil, ErrNotAudited
	}
	return principal, bound, nil
}

type ServiceCommitBoundary struct {
	policy authz.PolicyEvaluator
}

func NewServiceCommitBoundary(policy authz.PolicyEvaluator) (*ServiceCommitBoundary, error) {
	if policy == nil {
		return nil, ErrWorkflowUnavailable
	}
	return &ServiceCommitBoundary{policy: policy}, nil
}

func (boundary *ServiceCommitBoundary) Validate(ctx context.Context, validation orchestrator.CommitValidation) error {
	principal, found := authn.PrincipalFromContext(ctx)
	if boundary == nil || boundary.policy == nil || !found || !validIntegrationServicePrincipal(principal) || principal.ID != validation.PrincipalID || principal.TenantID != validation.TenantID || principal.ProjectID != validation.ProjectID || !validIntegrationCommitValidation(validation) {
		return orchestrator.ErrCommitBoundary
	}
	policyDigest := validation.Authorization.Capability.PolicyVersion
	input := authz.PolicyInput{
		Principal: principal,
		Project: authz.ProjectScope{
			TenantID: validation.TenantID, ID: validation.ProjectID,
			State: string(validation.Project.State), StateVersion: validation.Project.Version,
			Classification: integrationClassification(validation.Project.DataClassification),
		},
		Action: authz.ActionProjectCommand,
		Resource: authz.Resource{Type: "project", ID: validation.ProjectID, Attributes: map[string]string{
			"command": validation.Action, "policy_digest": policyDigest,
		}},
		ParameterDigest: validation.ParameterDigest,
		Budget:          authz.BudgetScope{AccountID: "integration-control-plane", Available: true},
	}
	if validation.TaskID != "" {
		input.Action = authz.ActionTaskCommand
		input.Resource.Type = "task"
		input.Resource.ID = validation.TaskID
		input.Task = authz.TaskScope{
			TenantID: validation.TenantID, ProjectID: validation.ProjectID, ID: validation.TaskID,
			State: string(validation.Task.State), StateVersion: validation.Task.Version,
			SpecDigest: validation.Task.ModuleSpecRef.SHA256,
		}
	}
	decision, err := boundary.policy.Evaluate(ctx, input)
	if err != nil || !decision.Decision.Allowed() || decision.PolicyVersion != policyDigest {
		return orchestrator.ErrCommitBoundary
	}
	return nil
}

func validIntegrationCommitValidation(validation orchestrator.CommitValidation) bool {
	if validation.TenantID == "" || validation.ProjectID == "" || validation.Project.TenantID != validation.TenantID || validation.Project.ID != validation.ProjectID || !digestPattern(validation.ParameterDigest) || !digestPattern(validation.Authorization.Capability.PolicyVersion) || len(validation.EvidenceSHA256) != 1 || !digestPattern(validation.EvidenceSHA256[0]) {
		return false
	}
	switch state.ProjectCommandType(validation.Action) {
	case state.ProjectCommandBeginIntegration:
		return validation.TaskID == "" && validation.ExpectedVersion == validation.Project.Version && validation.Project.State == contracts.ProjectExecuting && integrationProjectClaims(validation.Claims, true, false, false)
	case state.ProjectCommandBeginGlobalAudit:
		return validation.TaskID == "" && validation.ExpectedVersion == validation.Project.Version && validation.Project.State == contracts.ProjectIntegrating && integrationProjectClaims(validation.Claims, false, true, true)
	}
	return state.TaskCommandType(validation.Action) == state.TaskCommandIntegrate && validation.Project.State == contracts.ProjectIntegrating && validation.TaskID != "" && validation.Task.TenantID == validation.TenantID && validation.Task.ProjectID == validation.ProjectID && validation.Task.ID == validation.TaskID && validation.Task.Version == validation.ExpectedVersion && validation.Task.State == contracts.TaskPassed && validation.ModuleSpecRef == validation.Task.ModuleSpecRef && validation.Task.ModuleSpecRef.Validate() == nil && len(validation.Claims) == 2 && validation.Claims["dependencies_satisfied"] && validation.Claims["merge_gate_passed"]
}

func integrationProjectClaims(claims map[string]bool, passed, integrated, audited bool) bool {
	return len(claims) == 3 && claims["all_tasks_passed"] == passed && claims["all_tasks_integrated"] == integrated && claims["integration_audit_passed"] == audited
}

func taskDependenciesIntegrated(tasks []state.ModuleTask, taskID string) bool {
	found := false
	for _, task := range tasks {
		if task.ID == taskID {
			found = task.State == contracts.TaskPassed
		}
		if task.State == contracts.TaskCanceled || task.State == contracts.TaskSuperseded || !containsTaskID(task.DependentTaskIDs, taskID) {
			continue
		}
		if task.State != contracts.TaskIntegrated {
			return false
		}
	}
	return found
}

func allTasksIntegrated(tasks []state.ModuleTask) bool {
	if len(tasks) == 0 {
		return false
	}
	for _, task := range tasks {
		if task.State != contracts.TaskIntegrated && task.State != contracts.TaskCanceled && task.State != contracts.TaskSuperseded {
			return false
		}
	}
	return true
}

func containsTaskID(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func validAuthorityRequest(integrationID, tenantID, projectID string, expectedVersion int64, policyDigest, evidenceSHA256 string) bool {
	return safeIntegrationID(integrationID) && tenantID != "" && projectID != "" && expectedVersion >= 1 && digestPattern(policyDigest) && digestPattern(evidenceSHA256)
}

func validIntegrationServicePrincipal(principal authn.Principal) bool {
	return principal.Validate() == nil && principal.Type == authn.PrincipalService && principal.Role == authn.RoleService
}

func cloneIntegrationPrincipal(principal authn.Principal) authn.Principal {
	attributes := make(map[string]string, len(principal.Attributes))
	for key, value := range principal.Attributes {
		attributes[key] = value
	}
	principal.Attributes = attributes
	return principal
}

func integrationCommandKey(integrationID, suffix string) string {
	return "integration:" + integrationID + ":" + strings.ToLower(suffix)
}

func integrationClassification(value string) string {
	if value == "" {
		return "INTERNAL"
	}
	return value
}

var _ TaskLister = (*OrchestratorAuthority)(nil)
var _ orchestrator.CommitBoundary = (*ServiceCommitBoundary)(nil)
