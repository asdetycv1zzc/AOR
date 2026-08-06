// Package authz provides typed, fail-closed policy evaluation and capability
// leases for AOR side effects.
package authz

import (
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

// Decision is the only policy result vocabulary exposed to callers.
type Decision string

const (
	DecisionAllow            Decision = "ALLOW"
	DecisionDeny             Decision = "DENY"
	DecisionApprovalRequired Decision = "APPROVAL_REQUIRED"
)

func (d Decision) Valid() bool {
	return d == DecisionAllow || d == DecisionDeny || d == DecisionApprovalRequired
}

func (d Decision) Allowed() bool { return d == DecisionAllow }

// Action names used by the reference policy. Deployments may add action names
// in a signed bundle, but unknown actions remain denied by the default rules.
const (
	ActionProjectCreate     = "project.create"
	ActionProjectRead       = "project.read"
	ActionProjectCommand    = "project.command"
	ActionGoalRead          = "goal.read"
	ActionPlanRead          = "plan.read"
	ActionTaskRead          = "task.read"
	ActionTaskCommand       = "task.command"
	ActionRepoRead          = "repo.read"
	ActionRepoWrite         = "repo.write"
	ActionRepoApplyPatch    = "repo.apply_patch"
	ActionToolInvoke        = "tool.invoke"
	ActionKnowledgeRead     = "knowledge.read"
	ActionKnowledgeWrite    = "knowledge.write"
	ActionArtifactPublish   = "artifact.publish"
	ActionPolicyTest        = "policy.test"
	ActionPolicyWrite       = "policy.write"
	ActionDeploy            = "deploy"
	ActionModelGenerate     = "model.generate"
	ActionModelStream       = "model.stream"
	ActionModelCancel       = "model.cancel"
	ActionModelReconcile    = "model.reconcile"
	ActionModelCapabilities = "model.capabilities"
	ActionSandboxExec       = "sandbox.exec"
	ActionIntegrationMerge  = "integration.merge"
)

var (
	actionPattern = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	ruleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
)

// ProjectScope is the current trusted project projection needed by policy.
type ProjectScope struct {
	TenantID       string `json:"tenantId"`
	ID             string `json:"id"`
	State          string `json:"state"`
	StateVersion   int64  `json:"stateVersion"`
	Classification string `json:"classification"`
}

// TaskScope is intentionally a narrow projection. OwnedPaths are policy data,
// not a path authorization result supplied by the caller.
type TaskScope struct {
	TenantID                      string   `json:"tenantId"`
	ProjectID                     string   `json:"projectId"`
	ID                            string   `json:"id"`
	State                         string   `json:"state"`
	StateVersion                  int64    `json:"stateVersion"`
	SpecDigest                    string   `json:"specDigest"`
	OwnedPaths                    []string `json:"ownedPaths"`
	ExecutionPlatform             string   `json:"executionPlatform"`
	SandboxLevel                  string   `json:"sandboxLevel"`
	WorkloadTrust                 string   `json:"workloadTrust"`
	DeploymentProfile             string   `json:"deploymentProfile"`
	HostileMultiTenant            bool     `json:"hostileMultiTenant"`
	RequiresNetworkIsolation      bool     `json:"requiresNetworkIsolation"`
	RequiresHiddenConfidentiality bool     `json:"requiresHiddenConfidentiality"`
}

type Resource struct {
	Type       string            `json:"type,omitempty"`
	ID         string            `json:"id,omitempty"`
	Path       string            `json:"path,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// LeaseReference is the untrusted request-side view of a capability lease.
// The manager rehydrates and verifies the complete signed record.
type LeaseReference struct {
	ID            string    `json:"id"`
	ExpiresAt     time.Time `json:"expiresAt"`
	PolicyVersion string    `json:"policyVersion"`
	FencingToken  int64     `json:"fencingToken"`
}

type Approval struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenantId"`
	ProjectID      string     `json:"projectId"`
	PrincipalID    string     `json:"principalId"`
	CoApproverID   string     `json:"coApproverId,omitempty"`
	SubjectType    string     `json:"subjectType"`
	SubjectID      string     `json:"subjectId"`
	SubjectVersion int64      `json:"subjectVersion"`
	SubjectDigest  string     `json:"subjectDigest"`
	IssuedAt       time.Time  `json:"issuedAt"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	RevokedAt      *time.Time `json:"revokedAt,omitempty"`
	Signature      string     `json:"signature"`
}

type ExecutionContext struct {
	IP                string `json:"ip,omitempty"`
	Platform          string `json:"platform,omitempty"`
	SandboxLevel      string `json:"sandboxLevel,omitempty"`
	AuthorizationTime string `json:"authorizationTime,omitempty"`
}

type BudgetScope struct {
	AccountID string `json:"accountId"`
	Available bool   `json:"available"`
}

// PolicyInput is the complete authorization input. Callers must fill scope
// explicitly; the engine does not consult ambient context or infer IDs.
type PolicyInput struct {
	Principal       authn.Principal  `json:"principal"`
	Project         ProjectScope     `json:"project"`
	Task            TaskScope        `json:"task"`
	Action          string           `json:"action"`
	Resource        Resource         `json:"resource"`
	ParameterDigest string           `json:"parameterDigest,omitempty"`
	Budget          BudgetScope      `json:"budget"`
	Lease           *LeaseReference  `json:"lease,omitempty"`
	Approval        *Approval        `json:"approval,omitempty"`
	Context         ExecutionContext `json:"context"`
}

func (input PolicyInput) Validate(now time.Time) *aorerrors.Error {
	var timeErr *aorerrors.Error
	now, timeErr = policyAuthorizationTime(input, now)
	if timeErr != nil {
		return timeErr
	}
	if err := input.Principal.Validate(); err != nil {
		return err
	}
	if !safeID(input.Project.TenantID) || !safeID(input.Project.ID) || input.Project.State == "" || input.Project.StateVersion < 0 || input.Project.Classification == "" {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "project"})
	}
	hasTask := input.Task.ID != "" || input.Task.TenantID != "" || input.Task.ProjectID != "" || input.Task.State != "" || input.Task.SpecDigest != "" || len(input.Task.OwnedPaths) > 0
	if (RequiresTask(input.Action) && !globalAuditorProjectReadTool(input)) || hasTask {
		if !safeID(input.Task.TenantID) || !safeID(input.Task.ProjectID) || !safeID(input.Task.ID) || input.Task.State == "" || input.Task.StateVersion < 0 {
			return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "task"})
		}
		if input.Project.TenantID != input.Task.TenantID || input.Project.ID != input.Task.ProjectID {
			return aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "task project"})
		}
		if IsSideEffect(input.Action) && !validTaskExecutionScope(input.Task) {
			return aorerrors.New(aorerrors.CodeSandboxLevelInsufficient, "", map[string]any{"scope": "trusted task execution profile"})
		}
	}
	if input.Principal.TenantID != "" && input.Principal.TenantID != input.Project.TenantID {
		return aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "tenant"})
	}
	if input.Principal.ProjectID != "" && input.Principal.ProjectID != input.Project.ID {
		return aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "project"})
	}
	if !actionPattern.MatchString(input.Action) {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "action"})
	}
	if input.Resource.Type != "" && !safeOpaque(input.Resource.Type, 128) || input.Resource.ID != "" && !safeOpaque(input.Resource.ID, 512) {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "resource"})
	}
	if len(input.Resource.Attributes) > 32 {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "resource attributes"})
	}
	for key, value := range input.Resource.Attributes {
		if !safeOpaque(key, 128) || sensitiveAttributeName(key) || !safeOpaque(value, 1024) {
			return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "resource attributes"})
		}
	}
	if input.Resource.Path != "" {
		if _, err := normalizeRelativePath(input.Resource.Path); err != nil {
			return aorerrors.New(aorerrors.CodeUnauthorizedPath, "", nil)
		}
	}
	for _, owned := range input.Task.OwnedPaths {
		if _, err := normalizeGlob(owned); err != nil {
			return aorerrors.New(aorerrors.CodeUnauthorizedPath, "", nil)
		}
	}
	if input.Lease != nil {
		if input.Lease.ID == "" || input.Lease.FencingToken < 1 || input.Lease.ExpiresAt.IsZero() || input.Lease.PolicyVersion == "" {
			return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "lease"})
		}
		if !now.Before(input.Lease.ExpiresAt) {
			return aorerrors.New(aorerrors.CodeLeaseExpired, "", nil)
		}
	}
	if input.Approval != nil {
		if err := validateApproval(*input.Approval, now); err != nil {
			return err
		}
	}
	return nil
}

func policyAuthorizationTime(input PolicyInput, fallback time.Time) (time.Time, *aorerrors.Error) {
	if input.Context.AuthorizationTime == "" {
		return fallback.UTC(), nil
	}
	value, err := time.Parse(time.RFC3339Nano, input.Context.AuthorizationTime)
	if err != nil || value.Location() != time.UTC || value.Format(time.RFC3339Nano) != input.Context.AuthorizationTime {
		return time.Time{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "authorization time"})
	}
	return value, nil
}

func validTaskExecutionScope(task TaskScope) bool {
	if task.DeploymentProfile != "LOCAL" && task.DeploymentProfile != "TEST" && task.DeploymentProfile != "PREPRODUCTION" && task.DeploymentProfile != "PRODUCTION" {
		return false
	}
	if task.WorkloadTrust != "TRUSTED" && task.WorkloadTrust != "UNTRUSTED" {
		return false
	}
	return (task.ExecutionPlatform == "LINUX" && task.SandboxLevel == "CONTAINER") ||
		(task.ExecutionPlatform == "WINDOWS" && task.SandboxLevel == "NONE")
}

func sensitiveAttributeName(value string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(value, "_", ""), "-", ""))
	for _, fragment := range []string{"secret", "password", "passwd", "token", "credential", "privatekey", "apikey", "refreshtoken"} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func safeID(value string) bool {
	if value == "" || len(value) > 256 || strings.ContainsAny(value, "\r\n\x00/\\") {
		return false
	}
	for _, runeValue := range value {
		if runeValue < 0x20 || runeValue == 0x7f {
			return false
		}
	}
	return true
}

func safeOpaque(value string, max int) bool {
	if value == "" || len(value) > max || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, runeValue := range value {
		if runeValue < 0x20 || runeValue == 0x7f {
			return false
		}
	}
	return true
}

func normalizeRelativePath(value string) (string, error) {
	if value == "" || strings.ContainsRune(value, '\x00') || strings.ContainsRune(value, '\\') || strings.HasPrefix(value, "/") {
		return "", aorerrors.New(aorerrors.CodeUnauthorizedPath, "", nil)
	}
	clean := path.Clean(value)
	if clean != value || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", aorerrors.New(aorerrors.CodeUnauthorizedPath, "", nil)
	}
	return clean, nil
}

func normalizeGlob(value string) (string, error) {
	if value == "" || strings.ContainsRune(value, '\x00') || strings.ContainsRune(value, '\\') || strings.HasPrefix(value, "/") {
		return "", aorerrors.New(aorerrors.CodeUnauthorizedPath, "", nil)
	}
	clean := path.Clean(value)
	if clean != value || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", aorerrors.New(aorerrors.CodeUnauthorizedPath, "", nil)
	}
	return clean, nil
}

func validateApproval(approval Approval, now time.Time) *aorerrors.Error {
	if !safeID(approval.ID) || !safeID(approval.TenantID) || !safeID(approval.ProjectID) || !safeID(approval.PrincipalID) || !safeOpaque(approval.SubjectType, 128) || !safeOpaque(approval.SubjectID, 512) || approval.SubjectVersion < 0 || !digestPattern.MatchString(approval.SubjectDigest) || !safeOpaque(approval.Signature, 2048) || approval.IssuedAt.IsZero() {
		return aorerrors.New(aorerrors.CodeApprovalRequired, "", nil)
	}
	if approval.CoApproverID != "" && (!safeID(approval.CoApproverID) || approval.CoApproverID == approval.PrincipalID) {
		return aorerrors.New(aorerrors.CodeApprovalRequired, "", nil)
	}
	if approval.ExpiresAt.IsZero() || !approval.IssuedAt.Before(approval.ExpiresAt) || !now.Before(approval.ExpiresAt) || now.Before(approval.IssuedAt) {
		return aorerrors.New(aorerrors.CodeApprovalRequired, "", nil)
	}
	if approval.RevokedAt != nil && !approval.RevokedAt.After(now) {
		return aorerrors.New(aorerrors.CodeApprovalRequired, "", nil)
	}
	return nil
}

// Constraints are returned with an allow and must be enforced by the caller at
// execution time. A zero MaxBytes means no additional byte constraint.
type Constraints struct {
	PathGlob       string    `json:"pathGlob,omitempty"`
	MaxBytes       int64     `json:"maxBytes,omitempty"`
	ExpiresAt      time.Time `json:"expiresAt,omitempty"`
	AllowedMethods []string  `json:"allowedMethods,omitempty"`
}

func (c Constraints) Validate(now time.Time) bool {
	if c.PathGlob != "" {
		if _, err := normalizeGlob(c.PathGlob); err != nil {
			return false
		}
	}
	if c.MaxBytes < 0 || (!c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt)) {
		return false
	}
	if len(c.AllowedMethods) > 32 {
		return false
	}
	for _, method := range c.AllowedMethods {
		if !safeOpaque(method, 32) {
			return false
		}
	}
	return true
}

type PolicyDecision struct {
	Decision      Decision         `json:"decision"`
	PolicyVersion string           `json:"policyVersion"`
	Constraints   Constraints      `json:"constraints,omitempty"`
	ReasonCodes   []string         `json:"reasonCodes"`
	RuleID        string           `json:"ruleId,omitempty"`
	Binding       *DecisionBinding `json:"binding,omitempty"`
}

// DecisionBinding makes a lease grant single-use for one normalized security
// context. It contains hashes and identifiers, never raw parameters.
type DecisionBinding struct {
	PrincipalID     string   `json:"principalId"`
	TenantID        string   `json:"tenantId"`
	ProjectID       string   `json:"projectId"`
	ProjectVersion  int64    `json:"projectVersion"`
	TaskID          string   `json:"taskId"`
	TaskVersion     int64    `json:"taskVersion"`
	SpecDigest      string   `json:"specDigest"`
	Role            string   `json:"role"`
	Action          string   `json:"action"`
	Resource        Resource `json:"resource"`
	ParameterDigest string   `json:"parameterDigest"`
	BudgetAccountID string   `json:"budgetAccountId"`
}

func (d PolicyDecision) Validate(now time.Time) *aorerrors.Error {
	if !d.Decision.Valid() || !safeOpaque(d.PolicyVersion, 256) || (d.RuleID != "" && !ruleIDPattern.MatchString(d.RuleID)) || !d.Constraints.Validate(now) {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": d.PolicyVersion})
	}
	if len(d.ReasonCodes) == 0 {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": d.PolicyVersion})
	}
	for _, reason := range d.ReasonCodes {
		if !safeReason(reason) {
			return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": d.PolicyVersion})
		}
	}
	if d.Binding != nil {
		binding := d.Binding
		if !safeID(binding.PrincipalID) || !safeID(binding.TenantID) || !safeID(binding.ProjectID) || binding.ProjectVersion < 0 || binding.TaskID != "" && !safeID(binding.TaskID) || !validLeaseScopeBinding(binding.Action, binding.Role, binding.TaskID, binding.TaskVersion, binding.SpecDigest) || !safeOpaque(binding.Role, 128) || !leaseActionAllowed(binding.Action, binding.Role, binding.TaskID) || !digestPattern.MatchString(binding.ParameterDigest) || !safeID(binding.BudgetAccountID) {
			return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": d.PolicyVersion})
		}
		if binding.Resource.Path != "" {
			if _, err := normalizeRelativePath(binding.Resource.Path); err != nil {
				return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": d.PolicyVersion})
			}
		}
		if resourceEmpty(binding.Resource) || binding.Resource.Type != "" && !safeOpaque(binding.Resource.Type, 128) || binding.Resource.ID != "" && !safeOpaque(binding.Resource.ID, 512) || len(binding.Resource.Attributes) > 32 {
			return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": d.PolicyVersion})
		}
		for key, value := range binding.Resource.Attributes {
			if !safeOpaque(key, 128) || sensitiveAttributeName(key) || !safeOpaque(value, 1024) {
				return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": d.PolicyVersion})
			}
		}
	}
	return nil
}

func safeReason(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, runeValue := range value {
		if !(runeValue == '_' || runeValue == '-' || runeValue >= 'A' && runeValue <= 'Z' || runeValue >= '0' && runeValue <= '9') {
			return false
		}
	}
	return true
}

// PolicyBundle is an immutable in-process view of a signed policy bundle.
type PolicyBundle struct {
	Version   string
	Digest    string
	Available bool
	Rules     []Rule
}

// Rule can return a decision and whether it applies. A rule must not turn an
// invalid input into an allow; Engine validates input before invoking rules.
type Rule interface {
	Evaluate(PolicyInput) (PolicyDecision, bool)
}

type RuleFunc func(PolicyInput) (PolicyDecision, bool)

func (f RuleFunc) Evaluate(input PolicyInput) (PolicyDecision, bool) { return f(input) }

func IsSideEffect(action string) bool {
	switch action {
	case ActionRepoWrite, ActionRepoApplyPatch, ActionToolInvoke, ActionKnowledgeWrite,
		ActionArtifactPublish, ActionPolicyWrite, ActionDeploy, ActionSandboxExec, ActionIntegrationMerge:
		return true
	default:
		return false
	}
}

func RequiresTask(action string) bool {
	switch action {
	case ActionProjectCreate, ActionProjectRead, ActionProjectCommand, ActionGoalRead, ActionPlanRead,
		ActionKnowledgeRead, ActionKnowledgeWrite, ActionArtifactPublish, ActionPolicyTest, ActionModelCapabilities, ActionModelGenerate,
		ActionModelStream, ActionModelCancel, ActionModelReconcile, ActionIntegrationMerge:
		return false
	default:
		return true
	}
}

// LeaseRoleRequiresTask keeps project-level Goal and Plan agents usable before
// a ModuleTask exists. Unknown and task-level roles remain fail-closed.
func LeaseRoleRequiresTask(role string) bool {
	switch role {
	case authn.RoleGoalProposer, authn.RoleGoalChallenger, authn.RolePlanSupervisor, authn.RoleGlobalAuditor, authn.RoleKnowledgeCurator, authn.RoleService:
		return false
	default:
		return true
	}
}

func globalAuditorProjectReadTool(input PolicyInput) bool {
	return input.Action == ActionToolInvoke && input.Principal.Role == authn.RoleGlobalAuditor && input.Task.ID == "" && globalAuditorReadToolResource(input.Resource)
}

func globalAuditorReadToolResource(resource Resource) bool {
	if resource.Type != "tool" || resource.Path == "" || !strings.HasPrefix(resource.ID, "tool://") {
		return false
	}
	for _, toolID := range []string{"artifact.read", "knowledge.read_range", "knowledge.search", "repository.file.read"} {
		marker := "/" + toolID + "@"
		index := strings.LastIndex(resource.ID, marker)
		if index > len("tool://") && index+len(marker) < len(resource.ID) && !strings.ContainsAny(resource.ID[index+len(marker):], "/@") {
			return true
		}
	}
	return false
}

func taskModelLeaseRole(role string) bool {
	switch role {
	case authn.RoleModulePlanner, authn.RoleExecutor, authn.RoleAuditor, "MODULE_AUDITOR":
		return true
	default:
		return false
	}
}

func validLeaseTaskBinding(role, taskID string, taskVersion int64, specDigest string) bool {
	if taskID == "" {
		return !LeaseRoleRequiresTask(role) && taskVersion == 0 && specDigest == ""
	}
	return taskVersion >= 0 && digestPattern.MatchString(specDigest)
}

func validLeaseScopeBinding(action, role, taskID string, taskVersion int64, specDigest string) bool {
	if action == ActionKnowledgeWrite {
		return role == authn.RoleKnowledgeCurator && taskID == "" && taskVersion == 0 && specDigest == ""
	}
	return validLeaseTaskBinding(role, taskID, taskVersion, specDigest)
}

func IsHighRisk(action string) bool {
	return action == ActionKnowledgeWrite || action == ActionPolicyWrite || action == ActionArtifactPublish || action == ActionDeploy
}

func pathMatchesGlob(candidate, pattern string) bool {
	candidate, candidateErr := normalizeRelativePath(candidate)
	pattern, patternErr := normalizeGlob(pattern)
	if candidateErr != nil || patternErr != nil {
		return false
	}
	return globMatch(candidate, pattern)
}

// globMatch supports the policy's recursive ** segment while keeping ordinary
// * and ? confined to one path segment.
func globMatch(candidate, pattern string) bool {
	if pattern == "**" {
		return true
	}
	patternParts := strings.Split(pattern, "/")
	candidateParts := strings.Split(candidate, "/")
	return globPartsMatch(candidateParts, patternParts)
}

func globPartsMatch(candidate, pattern []string) bool {
	for len(pattern) > 0 {
		if pattern[0] == "**" {
			pattern = pattern[1:]
			if len(pattern) == 0 {
				return true
			}
			for index := range candidate {
				if globPartsMatch(candidate[index:], pattern) {
					return true
				}
			}
			return false
		}
		if len(candidate) == 0 || !segmentMatch(candidate[0], pattern[0]) {
			return false
		}
		candidate, pattern = candidate[1:], pattern[1:]
	}
	return len(candidate) == 0
}

func segmentMatch(candidate, pattern string) bool {
	matched, err := path.Match(pattern, candidate)
	return err == nil && matched
}
