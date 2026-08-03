package authz

import (
	"context"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

// PolicyEvaluator is the interface consumed by future Tool Broker, Model
// Gateway, and repository commit boundaries.
type PolicyEvaluator interface {
	Evaluate(context.Context, PolicyInput) (PolicyDecision, error)
}

// ApprovalVerifier verifies the immutable Approval Record signature and its
// current revocation state. Implementations normally read the WP-02 authority.
type ApprovalVerifier interface {
	Verify(context.Context, Approval) error
}

type EngineConfig struct {
	Bundle           PolicyBundle
	LeaseManager     *LeaseManager
	ApprovalVerifier ApprovalVerifier
	Clock            func() time.Time
	MaxWriteBytes    int64
}

// Engine is a deterministic policy evaluator. The bundle is immutable for the
// life of an Engine; a policy reload creates a new Engine and therefore a new
// policy version for newly issued leases.
type Engine struct {
	bundle        PolicyBundle
	leases        *LeaseManager
	approvals     ApprovalVerifier
	clock         func() time.Time
	maxWriteBytes int64
}

func NewEngine(config EngineConfig) *Engine {
	maxBytes := config.MaxWriteBytes
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	config.Bundle.Rules = append([]Rule(nil), config.Bundle.Rules...)
	return &Engine{bundle: config.Bundle, leases: config.LeaseManager, approvals: config.ApprovalVerifier, clock: config.Clock, maxWriteBytes: maxBytes}
}

func (e *Engine) now() time.Time {
	if e != nil && e.clock != nil {
		return e.clock().UTC()
	}
	return time.Now().UTC()
}

// Evaluate checks request shape and current security facts before running
// bundle rules. Even a custom allow cannot bypass lease or tenant validation.
func (e *Engine) Evaluate(ctx context.Context, input PolicyInput) (PolicyDecision, error) {
	if !bundleUsable(e) {
		decision := denyDecision(policyVersion(e), "POLICY_UNAVAILABLE")
		return decision, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"policyVersion": decision.PolicyVersion})
	}
	if err := ctx.Err(); err != nil {
		decision := denyDecision(e.bundle.Version, "REQUEST_CANCELED")
		return decision, aorerrors.Wrap(aorerrors.CodePolicyDenied, "", err, map[string]any{"policyVersion": e.bundle.Version})
	}
	now := e.now()
	if err := input.Validate(now); err != nil {
		decision := denyDecision(e.bundle.Version, reasonForError(err))
		return decision, err
	}
	if err := e.validateApprovalProof(ctx, input); err != nil {
		return denyDecision(e.bundle.Version, reasonForError(err)), err
	}
	if err := e.validateExecutionBoundary(input); err != nil {
		return denyDecision(e.bundle.Version, "EXECUTION_BOUNDARY_DENIED"), err
	}
	lease, err := e.validateLease(ctx, input, now)
	if err != nil {
		return denyDecision(e.bundle.Version, reasonForError(err)), err
	}
	baseline := e.defaultDecision(input, lease, now)
	if baseline.Decision != DecisionAllow {
		if err := baseline.Validate(now); err != nil {
			return denyDecision(e.bundle.Version, "INVALID_POLICY_RESULT"), err
		}
		return baseline, nil
	}

	for _, rule := range e.bundle.Rules {
		if rule == nil {
			return denyDecision(e.bundle.Version, "INVALID_POLICY_RULE"), aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": e.bundle.Version})
		}
		result, applies := rule.Evaluate(input)
		if !applies {
			continue
		}
		if result.PolicyVersion == "" {
			result.PolicyVersion = e.bundle.Version
		}
		if result.PolicyVersion != e.bundle.Version {
			return denyDecision(e.bundle.Version, "POLICY_VERSION_MISMATCH"), aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": e.bundle.Version})
		}
		if err := result.Validate(now); err != nil {
			return denyDecision(e.bundle.Version, "INVALID_POLICY_RESULT"), err
		}
		if result.Decision == DecisionAllow {
			result = e.intersectAllow(baseline, result, input, lease)
		}
		return result, nil
	}
	if err := baseline.Validate(now); err != nil {
		return denyDecision(e.bundle.Version, "INVALID_POLICY_RESULT"), err
	}
	return baseline, nil
}

// Authorize is the commit-boundary spelling of Evaluate. Callers must invoke it
// immediately before a permanent side effect, not only at task start.
func (e *Engine) Authorize(ctx context.Context, input PolicyInput) (PolicyDecision, error) {
	return e.Evaluate(ctx, input)
}

// EvaluateLeaseGrant performs the policy step that precedes capability lease
// issuance. It applies the same role, state, approval, ownership, and execution
// checks as Evaluate, but intentionally does not require a lease that has not
// yet been issued. The allow result is bound to the normalized request facts.
func (e *Engine) EvaluateLeaseGrant(ctx context.Context, input PolicyInput) (PolicyDecision, error) {
	if !bundleUsable(e) {
		decision := denyDecision(policyVersion(e), "POLICY_UNAVAILABLE")
		return decision, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"policyVersion": decision.PolicyVersion})
	}
	if err := ctx.Err(); err != nil {
		return denyDecision(e.bundle.Version, "REQUEST_CANCELED"), aorerrors.Wrap(aorerrors.CodePolicyDenied, "", err, map[string]any{"policyVersion": e.bundle.Version})
	}
	now := e.now()
	if err := input.Validate(now); err != nil {
		return denyDecision(e.bundle.Version, reasonForError(err)), err
	}
	if err := e.validateApprovalProof(ctx, input); err != nil {
		return denyDecision(e.bundle.Version, reasonForError(err)), err
	}
	if !IsSideEffect(input.Action) || input.Lease != nil || input.ParameterDigest == "" || input.Budget.AccountID == "" || !input.Budget.Available || input.Task.SpecDigest == "" {
		return denyDecision(e.bundle.Version, "INVALID_LEASE_GRANT_INPUT"), aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "lease grant"})
	}
	if err := e.validateExecutionBoundary(input); err != nil {
		return denyDecision(e.bundle.Version, "EXECUTION_BOUNDARY_DENIED"), err
	}
	baseline := e.defaultDecision(input, CapabilityLease{}, now)
	baseline = bindGrant(baseline, input, now)
	if baseline.Decision != DecisionAllow {
		if err := baseline.Validate(now); err != nil {
			return denyDecision(e.bundle.Version, "INVALID_POLICY_RESULT"), err
		}
		return baseline, nil
	}
	for _, rule := range e.bundle.Rules {
		if rule == nil {
			return denyDecision(e.bundle.Version, "INVALID_POLICY_RULE"), aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": e.bundle.Version})
		}
		result, applies := rule.Evaluate(input)
		if !applies {
			continue
		}
		if result.PolicyVersion == "" {
			result.PolicyVersion = e.bundle.Version
		}
		if result.PolicyVersion != e.bundle.Version {
			return denyDecision(e.bundle.Version, "POLICY_VERSION_MISMATCH"), aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": e.bundle.Version})
		}
		result = bindGrant(result, input, now)
		if result.Decision == DecisionAllow {
			result = e.intersectAllow(baseline, result, input, CapabilityLease{})
			result.Binding = baseline.Binding
		}
		if err := result.Validate(now); err != nil {
			return denyDecision(e.bundle.Version, "INVALID_POLICY_RESULT"), err
		}
		return result, nil
	}
	if err := baseline.Validate(now); err != nil {
		return denyDecision(e.bundle.Version, "INVALID_POLICY_RESULT"), err
	}
	return baseline, nil
}

func bundleUsable(engine *Engine) bool {
	return engine != nil && engine.bundle.Available && engine.bundle.Version != "" && (engine.bundle.Digest == "" || engine.bundle.Digest == engine.bundle.Version)
}

func policyVersion(engine *Engine) string {
	if engine != nil && engine.bundle.Version != "" {
		return engine.bundle.Version
	}
	return "unavailable"
}

func denyDecision(version, reason string) PolicyDecision {
	return PolicyDecision{Decision: DecisionDeny, PolicyVersion: version, ReasonCodes: []string{reason}, RuleID: "aor.default.deny"}
}

func approvalDecision(version, reason string) PolicyDecision {
	return PolicyDecision{Decision: DecisionApprovalRequired, PolicyVersion: version, ReasonCodes: []string{reason}, RuleID: "aor.approval.required"}
}

func allowDecision(version, rule string, reasons ...string) PolicyDecision {
	return PolicyDecision{Decision: DecisionAllow, PolicyVersion: version, ReasonCodes: append([]string(nil), reasons...), RuleID: rule}
}

func bindGrant(result PolicyDecision, input PolicyInput, now time.Time) PolicyDecision {
	if result.Decision != DecisionAllow {
		return result
	}
	if result.Constraints.ExpiresAt.IsZero() {
		result.Constraints.ExpiresAt = now.Add(5 * time.Minute)
	}
	result.Binding = &DecisionBinding{PrincipalID: input.Principal.ID, TenantID: input.Project.TenantID, ProjectID: input.Project.ID, ProjectVersion: input.Project.StateVersion, TaskID: input.Task.ID, TaskVersion: input.Task.StateVersion, SpecDigest: input.Task.SpecDigest, Role: input.Principal.Role, Action: input.Action, Resource: cloneResource(input.Resource), ParameterDigest: input.ParameterDigest, BudgetAccountID: input.Budget.AccountID}
	return result
}

func reasonForError(err error) string {
	typed, ok := err.(*aorerrors.Error)
	if !ok {
		return "POLICY_CHECK_FAILED"
	}
	switch typed.Code {
	case aorerrors.CodeLeaseExpired:
		return "LEASE_EXPIRED"
	case aorerrors.CodeApprovalRequired:
		return "APPROVAL_REQUIRED"
	case aorerrors.CodeUnauthorizedPath:
		return "UNAUTHORIZED_PATH"
	case aorerrors.CodeDependencyUnavailable:
		return "DEPENDENCY_UNAVAILABLE"
	case aorerrors.CodeForbidden, aorerrors.CodeUnauthorized:
		return "IDENTITY_SCOPE_DENIED"
	default:
		return "INVALID_POLICY_INPUT"
	}
}

func (e *Engine) validateExecutionBoundary(input PolicyInput) error {
	if !RequiresTask(input.Action) {
		return nil
	}
	task := input.Task
	if IsSideEffect(input.Action) && !validTaskExecutionScope(task) {
		return aorerrors.New(aorerrors.CodeSandboxLevelInsufficient, "", map[string]any{"scope": "trusted task execution profile"})
	}
	if input.Context.Platform != "" && input.Context.Platform != task.ExecutionPlatform || input.Context.SandboxLevel != "" && input.Context.SandboxLevel != task.SandboxLevel {
		return aorerrors.New(aorerrors.CodeSandboxLevelInsufficient, "", map[string]any{"scope": "execution context mismatch"})
	}
	production := task.DeploymentProfile == "PRODUCTION"
	untrusted := task.WorkloadTrust == "UNTRUSTED" || task.HostileMultiTenant || task.RequiresNetworkIsolation || task.RequiresHiddenConfidentiality
	if production && untrusted && (task.ExecutionPlatform != "LINUX" || task.SandboxLevel != "CONTAINER") {
		return aorerrors.New(aorerrors.CodeSandboxLevelInsufficient, "", map[string]any{"scope": "production untrusted workload"})
	}
	if task.ExecutionPlatform == "WINDOWS" && task.SandboxLevel != "NONE" {
		return aorerrors.New(aorerrors.CodeSandboxLevelInsufficient, "", map[string]any{"scope": "windows isolation"})
	}
	if task.ExecutionPlatform == "LINUX" && task.SandboxLevel != "CONTAINER" {
		return aorerrors.New(aorerrors.CodeSandboxLevelInsufficient, "", map[string]any{"scope": "linux isolation"})
	}
	return nil
}

func (e *Engine) validateApprovalProof(ctx context.Context, input PolicyInput) error {
	if input.Approval == nil {
		return nil
	}
	if e.approvals == nil {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "approval verifier"})
	}
	if err := e.approvals.Verify(ctx, *input.Approval); err != nil {
		return aorerrors.New(aorerrors.CodeApprovalRequired, "", nil)
	}
	return nil
}

func (e *Engine) validateLease(ctx context.Context, input PolicyInput, now time.Time) (CapabilityLease, error) {
	if !IsSideEffect(input.Action) {
		return CapabilityLease{}, nil
	}
	if input.Lease == nil {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "lease required"})
	}
	if input.Lease.PolicyVersion != e.bundle.Version {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": e.bundle.Version})
	}
	if input.ParameterDigest == "" || input.Budget.AccountID == "" || !input.Budget.Available || input.Task.SpecDigest == "" {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "commit facts"})
	}
	if e.leases == nil {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "lease store"})
	}
	lease, err := e.leases.Validate(ctx, LeaseCheck{LeaseID: input.Lease.ID, AgentInstanceID: input.Principal.ID, PrincipalID: input.Principal.ID, PrincipalType: input.Principal.Type, TenantID: input.Project.TenantID, ProjectID: input.Project.ID, ProjectVersion: input.Project.StateVersion, TaskID: input.Task.ID, TaskVersion: input.Task.StateVersion, SpecDigest: input.Task.SpecDigest, Role: input.Principal.Role, Action: input.Action, Resource: input.Resource, ParameterDigest: input.ParameterDigest, PolicyVersion: e.bundle.Version, BudgetAccountID: input.Budget.AccountID, Capability: input.Action, FencingToken: input.Lease.FencingToken, At: now})
	if err != nil {
		return CapabilityLease{}, err
	}
	if !lease.ExpiresAt.Equal(input.Lease.ExpiresAt) || lease.BudgetAccountID != input.Budget.AccountID {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "lease binding"})
	}
	return lease, nil
}

func (e *Engine) defaultDecision(input PolicyInput, lease CapabilityLease, now time.Time) PolicyDecision {
	switch input.Action {
	case ActionGoalRead, ActionPlanRead, ActionTaskRead, ActionKnowledgeRead:
		return allowDecision(e.bundle.Version, "aor.read", "ROLE_ALLOWED", "PROJECT_SCOPE_VALID")
	case ActionRepoRead:
		if roleIn(input.Principal.Role, authn.RoleExecutor, authn.RoleAuditor, authn.RoleModulePlanner, authn.RolePlanSupervisor, authn.RoleService) {
			return allowDecision(e.bundle.Version, "aor.repo.read", "ROLE_ALLOWED", "PROJECT_SCOPE_VALID")
		}
		return denyDecision(e.bundle.Version, "ROLE_DENIED")
	case ActionRepoWrite, ActionRepoApplyPatch:
		return e.repoWriteDecision(input, lease)
	case ActionToolInvoke:
		if roleIn(input.Principal.Role, authn.RoleGoalProposer, authn.RoleGoalChallenger, authn.RolePlanSupervisor, authn.RoleModulePlanner, authn.RoleExecutor, authn.RoleAuditor, authn.RoleKnowledgeCurator, authn.RoleService) {
			return e.constrainAllow(allowDecision(e.bundle.Version, "aor.tool.invoke", "ROLE_ALLOWED", "LEASE_VALID"), input, lease)
		}
		return denyDecision(e.bundle.Version, "ROLE_DENIED")
	case ActionKnowledgeWrite:
		if input.Principal.Type != authn.PrincipalKnowledgeCurator && input.Principal.Role != authn.RoleKnowledgeCurator {
			return denyDecision(e.bundle.Version, "CURATOR_REQUIRED")
		}
		if !approvalMatches(input, now) {
			return approvalDecision(e.bundle.Version, "CURATOR_APPROVAL_REQUIRED")
		}
		return e.constrainAllow(allowDecision(e.bundle.Version, "aor.knowledge.write", "CURATOR_ALLOWED", "APPROVAL_VALID", "LEASE_VALID"), input, lease)
	case ActionArtifactPublish:
		if input.Principal.Type != authn.PrincipalService && input.Principal.Role != authn.RoleService {
			return denyDecision(e.bundle.Version, "TRUSTED_SERVICE_REQUIRED")
		}
		if !approvalMatches(input, now) {
			return approvalDecision(e.bundle.Version, "PUBLISH_APPROVAL_REQUIRED")
		}
		return e.constrainAllow(allowDecision(e.bundle.Version, "aor.artifact.publish", "TRUSTED_SERVICE_ALLOWED", "APPROVAL_VALID", "LEASE_VALID"), input, lease)
	case ActionPolicyTest:
		if input.Principal.Type == authn.PrincipalService || input.Principal.Type == authn.PrincipalBreakGlassAdmin || input.Principal.Role == authn.RoleBreakGlassAdmin {
			return allowDecision(e.bundle.Version, "aor.policy.test", "ADMIN_ROLE_ALLOWED")
		}
		return denyDecision(e.bundle.Version, "ADMIN_ROLE_REQUIRED")
	case ActionPolicyWrite, ActionDeploy:
		if input.Principal.Type != authn.PrincipalBreakGlassAdmin && input.Principal.Role != authn.RoleBreakGlassAdmin {
			return denyDecision(e.bundle.Version, "BREAK_GLASS_REQUIRED")
		}
		if !approvalMatches(input, now) || input.Approval.CoApproverID == "" {
			return approvalDecision(e.bundle.Version, "BREAK_GLASS_APPROVAL_REQUIRED")
		}
		return e.constrainAllow(allowDecision(e.bundle.Version, "aor.break_glass", "BREAK_GLASS_ALLOWED", "APPROVAL_VALID", "LEASE_VALID"), input, lease)
	default:
		return denyDecision(e.bundle.Version, "UNKNOWN_ACTION")
	}
}

func (e *Engine) repoWriteDecision(input PolicyInput, lease CapabilityLease) PolicyDecision {
	if input.Principal.Type != authn.PrincipalAgentInstance || input.Principal.Role != authn.RoleExecutor {
		return denyDecision(e.bundle.Version, "EXECUTOR_REQUIRED")
	}
	if input.Project.State != "EXECUTING" || input.Task.State != "EXECUTING" {
		return denyDecision(e.bundle.Version, "TASK_NOT_EXECUTING")
	}
	if input.Resource.Path == "" {
		return denyDecision(e.bundle.Version, "RESOURCE_PATH_REQUIRED")
	}
	for _, owned := range input.Task.OwnedPaths {
		if pathMatchesGlob(input.Resource.Path, owned) {
			result := allowDecision(e.bundle.Version, "aor.repo.owned_path", "ROLE_ALLOWED", "TASK_OWNS_PATH", "LEASE_VALID")
			result.Constraints = Constraints{PathGlob: owned, MaxBytes: e.maxWriteBytes, ExpiresAt: lease.ExpiresAt}
			return result
		}
	}
	return denyDecision(e.bundle.Version, "TASK_DOES_NOT_OWN_PATH")
}

func (e *Engine) constrainAllow(result PolicyDecision, input PolicyInput, lease CapabilityLease) PolicyDecision {
	if IsSideEffect(input.Action) {
		if !lease.ExpiresAt.IsZero() && (result.Constraints.ExpiresAt.IsZero() || lease.ExpiresAt.Before(result.Constraints.ExpiresAt)) {
			result.Constraints.ExpiresAt = lease.ExpiresAt
		}
		if result.Constraints.MaxBytes == 0 && (input.Action == ActionRepoWrite || input.Action == ActionRepoApplyPatch || input.Action == ActionToolInvoke) {
			result.Constraints.MaxBytes = e.maxWriteBytes
		}
	}
	return result
}

func (e *Engine) intersectAllow(baseline, narrowed PolicyDecision, input PolicyInput, lease CapabilityLease) PolicyDecision {
	result := narrowed
	if baseline.Constraints.PathGlob != "" {
		if result.Constraints.PathGlob != "" && result.Constraints.PathGlob != baseline.Constraints.PathGlob {
			return denyDecision(e.bundle.Version, "POLICY_CONSTRAINT_CONFLICT")
		}
		result.Constraints.PathGlob = baseline.Constraints.PathGlob
	}
	if baseline.Constraints.MaxBytes > 0 && (result.Constraints.MaxBytes == 0 || result.Constraints.MaxBytes > baseline.Constraints.MaxBytes) {
		result.Constraints.MaxBytes = baseline.Constraints.MaxBytes
	}
	if !baseline.Constraints.ExpiresAt.IsZero() && (result.Constraints.ExpiresAt.IsZero() || baseline.Constraints.ExpiresAt.Before(result.Constraints.ExpiresAt)) {
		result.Constraints.ExpiresAt = baseline.Constraints.ExpiresAt
	}
	return e.constrainAllow(result, input, lease)
}

func approvalMatches(input PolicyInput, now time.Time) bool {
	if input.Approval == nil || validateApproval(*input.Approval, now) != nil {
		return false
	}
	expected := input.Resource.ID
	if expected == "" {
		expected = input.Resource.Path
	}
	if expected == "" || input.Approval.SubjectID != expected {
		return false
	}
	if input.Approval.TenantID != input.Project.TenantID || input.Approval.ProjectID != input.Project.ID || input.Approval.SubjectVersion != input.Task.StateVersion || input.Approval.SubjectDigest != input.ParameterDigest {
		return false
	}
	return input.Approval.SubjectType == input.Action || input.Approval.SubjectType == input.Resource.Type
}

func roleIn(role string, roles ...string) bool {
	for _, allowed := range roles {
		if role == allowed {
			return true
		}
	}
	return false
}
