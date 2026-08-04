package controlapi

import (
	"context"
	"errors"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/orchestrator"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func contextWithPrincipal(ctx context.Context, principal authn.Principal) context.Context {
	bound, err := authn.ContextWithPrincipal(ctx, principal)
	if err != nil {
		return ctx
	}
	return bound
}

func principalFromContext(ctx context.Context) (authn.Principal, bool) {
	return authn.PrincipalFromContext(ctx)
}

// PolicyCommitBoundary re-evaluates the authenticated human principal against
// current aggregate facts immediately before the orchestrator transaction.
type PolicyCommitBoundary struct {
	authorizer authz.PolicyEvaluator
}

func NewPolicyCommitBoundary(authorizer authz.PolicyEvaluator) (*PolicyCommitBoundary, error) {
	if authorizer == nil {
		return nil, orchestrator.ErrCommitBoundary
	}
	return &PolicyCommitBoundary{authorizer: authorizer}, nil
}

func (boundary *PolicyCommitBoundary) Validate(ctx context.Context, validation orchestrator.CommitValidation) error {
	principal, ok := principalFromContext(ctx)
	if boundary == nil || boundary.authorizer == nil || !ok || principal.ID != validation.PrincipalID || principal.TenantID != validation.TenantID {
		return orchestrator.ErrCommitBoundary
	}
	if principal.Type != authn.PrincipalUser && principal.Type != authn.PrincipalBreakGlassAdmin {
		return orchestrator.ErrCommitBoundary
	}
	input := policyInput(principal, validation)
	decision, err := boundary.authorizer.Evaluate(ctx, input)
	if err != nil || !decision.Decision.Allowed() {
		return orchestrator.ErrCommitBoundary
	}
	return nil
}

func policyInput(principal authn.Principal, validation orchestrator.CommitValidation) authz.PolicyInput {
	stateValue := string(validation.Project.State)
	classification := validation.Project.DataClassification
	if stateValue == "" {
		stateValue = "CREATED"
	}
	if classification == "" {
		classification = "INTERNAL"
	}
	input := authz.PolicyInput{
		Principal: principal,
		Project: authz.ProjectScope{
			TenantID:       validation.TenantID,
			ID:             validation.ProjectID,
			State:          stateValue,
			StateVersion:   validation.Project.Version,
			Classification: classification,
		},
		Action:          policyAction(validation),
		Resource:        authz.Resource{Type: aggregateResourceType(validation), ID: aggregateResourceID(validation)},
		ParameterDigest: validation.ParameterDigest,
		Budget:          authz.BudgetScope{AccountID: "control-plane", Available: true},
	}
	if validation.TaskID != "" {
		input.Task = authz.TaskScope{
			TenantID:     validation.TenantID,
			ProjectID:    validation.ProjectID,
			ID:           validation.TaskID,
			State:        string(validation.Task.State),
			StateVersion: validation.Task.Version,
			SpecDigest:   validation.Task.ModuleSpecRef.SHA256,
		}
		if input.Task.State == "" {
			input.Task.State = "DEFINED"
		}
	}
	return input
}

func policyAction(validation orchestrator.CommitValidation) string {
	if validation.TaskID != "" {
		return "task.command"
	}
	if validation.Project.Version == 0 {
		return "project.create"
	}
	return "project.command"
}

func aggregateResourceType(validation orchestrator.CommitValidation) string {
	if validation.TaskID != "" {
		return "task"
	}
	return "project"
}

func aggregateResourceID(validation orchestrator.CommitValidation) string {
	if validation.TaskID != "" {
		return validation.TaskID
	}
	return validation.ProjectID
}

func authorizeRead(ctx context.Context, authorizer authz.PolicyEvaluator, principal authn.Principal, projectID, action, resourceType, resourceID string, projectState string, version int64, classification string) error {
	if authorizer == nil || principal.TenantID == "" || projectID == "" {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", nil)
	}
	input := authz.PolicyInput{
		Principal: principal,
		Project:   authz.ProjectScope{TenantID: principal.TenantID, ID: projectID, State: projectState, StateVersion: version, Classification: classification},
		Action:    action,
		Resource:  authz.Resource{Type: resourceType, ID: resourceID},
		Budget:    authz.BudgetScope{AccountID: "control-plane", Available: true},
	}
	decision, err := authorizer.Evaluate(ctx, input)
	if err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	if !decision.Decision.Allowed() {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": decision.PolicyVersion, "ruleId": decision.RuleID})
	}
	return nil
}

func isCommitBoundaryError(err error) bool {
	return errors.Is(err, orchestrator.ErrCommitBoundary)
}

var _ orchestrator.CommitBoundary = (*PolicyCommitBoundary)(nil)
