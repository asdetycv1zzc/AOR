package audit

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

type TaskCommitRequest struct {
	AuditRunID      string
	TenantID        string
	ProjectID       string
	TaskID          string
	ExpectedVersion int64
	PolicyDigest    string
	Command         state.TaskCommand
}

type TaskAuthority interface {
	Project(context.Context, string, string) (state.Project, bool, error)
	Task(context.Context, string, string, string) (state.ModuleTask, bool, error)
	Commit(context.Context, TaskCommitRequest) (state.ModuleTask, bool, error)
}

// OrchestratorTaskAuthority is the production state boundary for Module Audit.
// It binds every command to one authenticated service principal and delegates
// optimistic concurrency and durable idempotency to Orchestrator.
type OrchestratorTaskAuthority struct {
	service   *orchestrator.Service
	principal authn.Principal
}

func NewOrchestratorTaskAuthority(store eventing.Store, policy authz.PolicyEvaluator, principal authn.Principal, clock func() time.Time, classroomCore bool) (*OrchestratorTaskAuthority, error) {
	if store == nil || policy == nil || !validAuditServicePrincipal(principal) {
		return nil, ErrAuditServiceUnavailable
	}
	boundary, err := NewServiceCommitBoundary(policy)
	if err != nil {
		return nil, err
	}
	if clock == nil {
		clock = time.Now
	}
	return &OrchestratorTaskAuthority{
		service:   orchestrator.NewWithBoundaryAndMode(store, clock, boundary, classroomCore),
		principal: cloneAuditPrincipal(principal),
	}, nil
}

func (authority *OrchestratorTaskAuthority) Project(ctx context.Context, tenantID, projectID string) (state.Project, bool, error) {
	if authority == nil || authority.service == nil {
		return state.Project{}, false, ErrAuditServiceUnavailable
	}
	return authority.service.Project(ctx, tenantID, projectID)
}

func (authority *OrchestratorTaskAuthority) Task(ctx context.Context, tenantID, projectID, taskID string) (state.ModuleTask, bool, error) {
	if authority == nil || authority.service == nil {
		return state.ModuleTask{}, false, ErrAuditServiceUnavailable
	}
	return authority.service.Task(ctx, tenantID, projectID, taskID)
}

func (authority *OrchestratorTaskAuthority) Commit(ctx context.Context, request TaskCommitRequest) (state.ModuleTask, bool, error) {
	if authority == nil || authority.service == nil || ctx == nil || ctx.Err() != nil ||
		!validAuditRunID(request.AuditRunID) || !validCoordinatorID(request.TenantID) ||
		!validCoordinatorID(request.ProjectID) || !validCoordinatorID(request.TaskID) ||
		request.ExpectedVersion < 1 || !digestPattern.MatchString(request.PolicyDigest) ||
		!validAuditStateCommand(request.Command) {
		return state.ModuleTask{}, false, ErrInvalidAuditRequest
	}
	principal := cloneAuditPrincipal(authority.principal)
	if principal.TenantID != "" && principal.TenantID != request.TenantID || principal.ProjectID != "" && principal.ProjectID != request.ProjectID {
		return state.ModuleTask{}, false, ErrAuditAuthorization
	}
	principal.TenantID = request.TenantID
	principal.ProjectID = request.ProjectID
	bound, err := authn.ContextWithPrincipal(ctx, principal)
	if err != nil {
		return state.ModuleTask{}, false, ErrAuditAuthorization
	}
	command := request.Command
	command.At = time.Time{}
	outcome, err := authority.service.HandleTask(bound, orchestrator.TaskRequest{
		TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		PrincipalID: principal.ID, IdempotencyKey: auditCommandKey(request.AuditRunID, command.Type),
		ExpectedVersion: request.ExpectedVersion, Command: command,
		Authorization: orchestrator.CommitAuthorization{Capability: orchestrator.CommitCapability{PolicyVersion: request.PolicyDigest}},
	})
	if err != nil {
		return state.ModuleTask{}, false, err
	}
	return outcome.Task, outcome.Duplicate, nil
}

type ServiceCommitBoundary struct {
	policy authz.PolicyEvaluator
}

func NewServiceCommitBoundary(policy authz.PolicyEvaluator) (*ServiceCommitBoundary, error) {
	if policy == nil {
		return nil, ErrAuditServiceUnavailable
	}
	return &ServiceCommitBoundary{policy: policy}, nil
}

// Validate accepts only Module Audit transitions from an authenticated service
// principal and requires the same current policy digest used by the audit run.
func (boundary *ServiceCommitBoundary) Validate(ctx context.Context, validation orchestrator.CommitValidation) error {
	principal, found := authn.PrincipalFromContext(ctx)
	if boundary == nil || boundary.policy == nil || !found || !validAuditServicePrincipal(principal) ||
		principal.ID != validation.PrincipalID || principal.TenantID != validation.TenantID ||
		principal.ProjectID != "" && principal.ProjectID != validation.ProjectID ||
		!validAuditCommitValidation(validation) {
		return orchestrator.ErrCommitBoundary
	}
	policyDigest := validation.Authorization.Capability.PolicyVersion
	input := authz.PolicyInput{
		Principal: principal,
		Project: authz.ProjectScope{
			TenantID: validation.TenantID, ID: validation.ProjectID,
			State: string(validation.Project.State), StateVersion: validation.Project.Version,
			Classification: auditClassification(validation.Project.DataClassification),
		},
		Task: authz.TaskScope{
			TenantID: validation.TenantID, ProjectID: validation.ProjectID,
			ID: validation.TaskID, State: string(validation.Task.State),
			StateVersion: validation.Task.Version, SpecDigest: validation.Task.ModuleSpecRef.SHA256,
		},
		Action: authz.ActionTaskCommand,
		Resource: authz.Resource{Type: "task", ID: validation.TaskID, Attributes: map[string]string{
			"command":       validation.Action,
			"policy_digest": policyDigest,
		}},
		ParameterDigest: validation.ParameterDigest,
		Budget:          authz.BudgetScope{AccountID: "audit-control-plane", Available: true},
	}
	decision, err := boundary.policy.Evaluate(ctx, input)
	if err != nil || !decision.Decision.Allowed() || decision.PolicyVersion != policyDigest {
		return orchestrator.ErrCommitBoundary
	}
	return nil
}

func validAuditCommitValidation(validation orchestrator.CommitValidation) bool {
	if validation.TenantID == "" || validation.ProjectID == "" || validation.TaskID == "" ||
		validation.ExpectedVersion != validation.Task.Version || validation.Task.TenantID != validation.TenantID ||
		validation.Task.ProjectID != validation.ProjectID || validation.Task.ID != validation.TaskID ||
		validation.ModuleSpecRef != validation.Task.ModuleSpecRef || validation.Task.ModuleSpecRef.Validate() != nil ||
		!digestPattern.MatchString(validation.ParameterDigest) ||
		!digestPattern.MatchString(validation.Authorization.Capability.PolicyVersion) || len(validation.EvidenceSHA256) != 1 ||
		!digestPattern.MatchString(validation.EvidenceSHA256[0]) {
		return false
	}
	switch state.TaskCommandType(validation.Action) {
	case state.TaskCommandStartAudit:
		return validation.Task.State == contracts.TaskSubmitted && exactClaims(validation.Claims, "submission_validated")
	case state.TaskCommandDeterministicSuccess, state.TaskCommandDeterministicFailure:
		return validation.Task.State == contracts.TaskDeterministicAudit && len(validation.Claims) == 0
	case state.TaskCommandLLMSuccess:
		return validation.Task.State == contracts.TaskLLMAudit && exactClaims(validation.Claims, "fresh_auditor", "blind_audit_context", "no_blocking_findings")
	case state.TaskCommandLLMFailure:
		return validation.Task.State == contracts.TaskLLMAudit && exactClaims(validation.Claims, "fresh_auditor", "blind_audit_context")
	case state.TaskCommandQueueRework:
		return validation.Task.State == contracts.TaskReworkRequired && len(validation.Claims) == 0
	default:
		return false
	}
}

func validAuditStateCommand(command state.TaskCommand) bool {
	if !digestPattern.MatchString(command.AuditEvidenceSHA256) {
		return false
	}
	switch command.Type {
	case state.TaskCommandStartAudit:
		return command.SubmissionValidated && !command.FreshAuditor && !command.BlindAuditContext && !command.NoBlockingFindings
	case state.TaskCommandDeterministicSuccess, state.TaskCommandDeterministicFailure:
		return !command.SubmissionValidated && !command.FreshAuditor && !command.BlindAuditContext && !command.NoBlockingFindings
	case state.TaskCommandLLMSuccess:
		return !command.SubmissionValidated && command.FreshAuditor && command.BlindAuditContext && command.NoBlockingFindings
	case state.TaskCommandLLMFailure:
		return !command.SubmissionValidated && command.FreshAuditor && command.BlindAuditContext && !command.NoBlockingFindings
	case state.TaskCommandQueueRework:
		return !command.SubmissionValidated && !command.FreshAuditor && !command.BlindAuditContext && !command.NoBlockingFindings
	default:
		return false
	}
}

func exactClaims(claims map[string]bool, names ...string) bool {
	if len(claims) != len(names) {
		return false
	}
	for _, name := range names {
		if !claims[name] {
			return false
		}
	}
	return true
}

func validAuditServicePrincipal(principal authn.Principal) bool {
	return principal.Validate() == nil && principal.Type == authn.PrincipalService && principal.Role == authn.RoleService
}

func cloneAuditPrincipal(principal authn.Principal) authn.Principal {
	principal.Attributes = make(map[string]string, len(principal.Attributes))
	for key, value := range principal.Attributes {
		principal.Attributes[key] = value
	}
	return principal
}

func auditCommandKey(runID string, command state.TaskCommandType) string {
	return "module-audit:" + runID + ":" + strings.ToLower(string(command))
}

func auditClassification(value string) string {
	if value == "" {
		return "INTERNAL"
	}
	return value
}

var _ TaskAuthority = (*OrchestratorTaskAuthority)(nil)
var _ orchestrator.CommitBoundary = (*ServiceCommitBoundary)(nil)
