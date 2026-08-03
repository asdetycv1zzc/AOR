package toolbroker

import (
	"context"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
)

type ExecutionScope struct {
	ProjectVersion int64
	TaskVersion    int64
	SpecDigest     string
}

// ExecutionScopeResolver returns the current control-plane projection. The
// request is deliberately not allowed to supply versions or specification
// digests used in the lease binding.
type ExecutionScopeResolver interface {
	ResolveExecutionScope(context.Context, string, string, string) (ExecutionScope, error)
}

type AuthzLeaseValidator interface {
	Validate(context.Context, authz.LeaseCheck) (authz.CapabilityLease, error)
}

type AuthzLeaseChecker struct {
	Manager AuthzLeaseValidator
	Scopes  ExecutionScopeResolver
}

func (checker AuthzLeaseChecker) Validate(ctx context.Context, validation LeaseValidation) error {
	if checker.Manager == nil || checker.Scopes == nil {
		return ErrLeaseInvalid
	}
	expectedResource := authorizationResourceID(validation.MCPServerID, validation.ToolID, validation.ToolVersion)
	if validation.Action != authz.ActionToolInvoke || validation.Resource != expectedResource || validation.BudgetAccountID == "" {
		return ErrLeaseInvalid
	}
	expiresAt, err := time.Parse(time.RFC3339, validation.Lease.ExpiresAt)
	if err != nil {
		return ErrLeaseInvalid
	}
	scope, err := checker.Scopes.ResolveExecutionScope(ctx, validation.TenantID, validation.ProjectID, validation.TaskID)
	if err != nil {
		return err
	}
	lease, err := checker.Manager.Validate(ctx, authz.LeaseCheck{
		LeaseID:         validation.Lease.ID,
		AgentInstanceID: validation.Principal.ID,
		PrincipalID:     validation.Principal.ID,
		PrincipalType:   authn.PrincipalType(validation.Principal.Type),
		TenantID:        validation.TenantID,
		ProjectID:       validation.ProjectID,
		ProjectVersion:  scope.ProjectVersion,
		TaskID:          validation.TaskID,
		TaskVersion:     scope.TaskVersion,
		SpecDigest:      scope.SpecDigest,
		Role:            validation.Principal.Role,
		Action:          validation.Action,
		Resource:        AuthorizationResource(validation.MCPServerID, validation.ToolID, validation.ToolVersion),
		ParameterDigest: validation.ParameterSHA256,
		PolicyVersion:   validation.PolicyVersion,
		BudgetAccountID: validation.BudgetAccountID,
		Capability:      validation.Action,
		FencingToken:    validation.Lease.FencingToken,
		At:              validation.At,
	})
	if err != nil {
		return err
	}
	if !lease.ExpiresAt.Equal(expiresAt) {
		return ErrLeaseInvalid
	}
	return nil
}

// AuthorizationResource is the canonical authz resource used both when a
// tool capability lease is issued and when the Tool Broker commits it.
func AuthorizationResource(mcpServerID, toolID, version string) authz.Resource {
	return authz.Resource{Type: "tool", ID: authorizationResourceID(mcpServerID, toolID, version)}
}

func authorizationResourceID(mcpServerID, toolID, version string) string {
	return "tool://" + mcpServerID + "/" + toolID + "@" + version
}
