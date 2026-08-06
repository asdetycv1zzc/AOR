package leaseauthority

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/toolbroker"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

const defaultRuntimeRenewalTTL = 5 * time.Minute

type runtimeLeaseManager interface {
	GetForTenant(context.Context, string, string) (authz.CapabilityLease, bool, error)
	Validate(context.Context, authz.LeaseCheck) (authz.CapabilityLease, error)
}

type runtimeAuthority struct {
	service    *Service
	manager    runtimeLeaseManager
	renewalTTL time.Duration
}

type runtimeOperationAuthority struct {
	*runtimeAuthority
	tools RuntimeToolResolver
}

type RuntimeToolResolver interface {
	MCPServerID(context.Context, string, string) (string, error)
}

// NewRuntimeAuthority adapts signed capability leases to Agent Runtime's
// lifecycle interface. Every operation is checked against the authoritative
// signed lease rather than the caller-provided transport view.
func NewRuntimeAuthority(service *Service, renewalTTL time.Duration) (agentruntime.LeaseAuthority, error) {
	return newRuntimeAuthority(service, renewalTTL)
}

func NewRuntimeOperationAuthority(service *Service, renewalTTL time.Duration, tools RuntimeToolResolver) (agentruntime.OperationLeaseAuthority, error) {
	if tools == nil {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "runtime tool resolver"})
	}
	authority, err := newRuntimeAuthority(service, renewalTTL)
	if err != nil {
		return nil, err
	}
	return &runtimeOperationAuthority{runtimeAuthority: authority, tools: tools}, nil
}

func newRuntimeAuthority(service *Service, renewalTTL time.Duration) (*runtimeAuthority, error) {
	if service == nil {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "runtime lease authority"})
	}
	manager, ok := service.manager.(runtimeLeaseManager)
	if !ok {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "runtime lease manager"})
	}
	if renewalTTL == 0 {
		renewalTTL = defaultRuntimeRenewalTTL
	}
	if renewalTTL < time.Duration(agentruntime.DefaultHeartbeatSeconds*agentruntime.MissedHeartbeatLimit)*time.Second || renewalTTL > 15*time.Minute {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "runtime lease ttl"})
	}
	return &runtimeAuthority{service: service, manager: manager, renewalTTL: renewalTTL}, nil
}

func (authority *runtimeOperationAuthority) AcquireOperationLease(ctx context.Context, execution agentruntime.AgentLease, request agentruntime.OperationLeaseRequest) (agentruntime.AgentLease, error) {
	current, err := authority.current(ctx, execution, agentruntime.LeaseOperationAssign)
	if err != nil {
		return agentruntime.AgentLease{}, err
	}
	if _, err := authority.manager.Validate(ctx, leaseCheck(current)); err != nil {
		return agentruntime.AgentLease{}, runtimeLeaseError(err)
	}
	var action string
	var resource authz.Resource
	var parameterDigest string
	switch request.Operation {
	case agentruntime.LeaseOperationModel:
		resourceID, digest, bindingErr := agentruntime.ModelOperationBinding(request.ModelCall)
		if bindingErr != nil || request.RequestID != request.ModelCall.RequestID || request.Provider != request.ModelCall.Provider || request.Model != request.ModelCall.Model {
			return agentruntime.AgentLease{}, agentruntime.ErrLeaseInvalid
		}
		action = authz.ActionModelGenerate
		resource = authz.Resource{Type: "model", ID: resourceID, Path: current.ID}
		parameterDigest = digest
		if current.Action == action && current.Resource.Type == resource.Type && current.Resource.ID == resource.ID && current.Resource.Path == "" && current.ParameterDigest == parameterDigest {
			return execution, nil
		}
	case agentruntime.LeaseOperationTool:
		if authority.tools == nil {
			return agentruntime.AgentLease{}, agentruntime.ErrLeaseInvalid
		}
		serverID, resolveErr := authority.tools.MCPServerID(ctx, request.ToolID, request.ToolVersion)
		digest, digestErr := toolbroker.AuthorizationParameterDigest(request.Parameters)
		if resolveErr != nil || digestErr != nil || strings.TrimSpace(serverID) == "" {
			return agentruntime.AgentLease{}, agentruntime.ErrLeaseInvalid
		}
		action = authz.ActionToolInvoke
		resource = toolbroker.AuthorizationResource(serverID, request.ToolID, request.ToolVersion, current.ID)
		parameterDigest = digest
	default:
		return agentruntime.AgentLease{}, agentruntime.ErrLeaseInvalid
	}
	principal, principalCtx, err := runtimeLeasePrincipal(ctx, current)
	if err != nil {
		return agentruntime.AgentLease{}, err
	}
	issued, err := authority.service.issueAtFencing(principalCtx, principal, GrantRequest{
		TenantID: current.TenantID, ProjectID: current.ProjectID, TaskID: current.TaskID,
		Action: action, Resource: resource, ParameterDigest: parameterDigest,
		BudgetAccountID: current.BudgetAccountID,
		IdempotencyKey:  runtimeOperationKey(current.ID, current.FencingToken, request.RequestID, action, parameterDigest),
		TTL:             authority.renewalTTL,
		NotAfter:        current.ExpiresAt,
	}, current.FencingToken)
	if err != nil {
		return agentruntime.AgentLease{}, runtimeLeaseError(err)
	}
	if issued.AgentInstanceID != current.AgentInstanceID || issued.TenantID != current.TenantID || issued.ProjectID != current.ProjectID || issued.TaskID != current.TaskID || issued.Role != current.Role || issued.Action != action || issued.Resource.Type != resource.Type || issued.Resource.ID != resource.ID || issued.Resource.Path != resource.Path || len(issued.Resource.Attributes) != 0 || issued.ParameterDigest != parameterDigest || issued.FencingToken != current.FencingToken || issued.BudgetAccountID != current.BudgetAccountID {
		return agentruntime.AgentLease{}, agentruntime.ErrLeaseInvalid
	}
	return toRuntimeLease(issued), nil
}

func runtimeOperationKey(executionLeaseID string, fencingToken int64, requestID, action, parameterDigest string) string {
	digest := sha256.Sum256([]byte(executionLeaseID + "\x00" + strconv.FormatInt(fencingToken, 10) + "\x00" + requestID + "\x00" + action + "\x00" + parameterDigest))
	return "runtime-operation-" + hex.EncodeToString(digest[:])
}

func (authority *runtimeAuthority) Validate(ctx context.Context, lease agentruntime.AgentLease, operation agentruntime.LeaseOperation) error {
	current, err := authority.current(ctx, lease, operation)
	if err != nil {
		return err
	}
	_, err = authority.manager.Validate(ctx, leaseCheck(current))
	return runtimeLeaseError(err)
}

func (authority *runtimeAuthority) Heartbeat(ctx context.Context, lease agentruntime.AgentLease) (agentruntime.AgentLease, error) {
	current, err := authority.current(ctx, lease, agentruntime.LeaseOperationHeartbeat)
	if err != nil {
		return agentruntime.AgentLease{}, err
	}
	if _, err := authority.manager.Validate(ctx, leaseCheck(current)); err != nil {
		return agentruntime.AgentLease{}, runtimeLeaseError(err)
	}
	principal, principalCtx, err := runtimeLeasePrincipal(ctx, current)
	if err != nil {
		return agentruntime.AgentLease{}, err
	}
	updated, err := authority.service.Heartbeat(principalCtx, principal, HeartbeatRequest{
		TenantID: current.TenantID, ProjectID: current.ProjectID, TaskID: current.TaskID,
		LeaseID: current.ID, FencingToken: current.FencingToken,
	})
	if err != nil {
		return agentruntime.AgentLease{}, runtimeLeaseError(err)
	}
	return toRuntimeLease(updated), nil
}

func (authority *runtimeAuthority) Renew(ctx context.Context, lease agentruntime.AgentLease) (agentruntime.AgentLease, error) {
	current, err := authority.current(ctx, lease, agentruntime.LeaseOperationRenew)
	if err != nil {
		return agentruntime.AgentLease{}, err
	}
	if _, err := authority.manager.Validate(ctx, leaseCheck(current)); err != nil {
		return agentruntime.AgentLease{}, runtimeLeaseError(err)
	}
	principal, principalCtx, err := runtimeLeasePrincipal(ctx, current)
	if err != nil {
		return agentruntime.AgentLease{}, err
	}
	updated, err := authority.service.Renew(principalCtx, principal, RenewRequest{
		GrantRequest: GrantRequest{
			TenantID: current.TenantID, ProjectID: current.ProjectID, TaskID: current.TaskID,
			Action: current.Action, Resource: current.Resource, ParameterDigest: current.ParameterDigest,
			BudgetAccountID: current.BudgetAccountID,
			IdempotencyKey:  "runtime-renew:" + current.ID + ":" + strconv.FormatInt(current.FencingToken, 10),
			TTL:             authority.renewalTTL,
		},
		LeaseID: current.ID, FencingToken: current.FencingToken, PolicyVersion: current.PolicyVersion,
	})
	if err != nil {
		return agentruntime.AgentLease{}, runtimeLeaseError(err)
	}
	return toRuntimeLease(updated), nil
}

func (authority *runtimeAuthority) current(ctx context.Context, lease agentruntime.AgentLease, operation agentruntime.LeaseOperation) (authz.CapabilityLease, error) {
	if authority == nil || authority.service == nil || authority.manager == nil || ctx == nil || lease.TenantID == "" || lease.LeaseID == "" {
		return authz.CapabilityLease{}, agentruntime.ErrLeaseInvalid
	}
	current, found, err := authority.manager.GetForTenant(ctx, lease.TenantID, lease.LeaseID)
	if err != nil {
		return authz.CapabilityLease{}, runtimeLeaseError(err)
	}
	if !found || current.State != authz.LeaseActive {
		return authz.CapabilityLease{}, agentruntime.ErrLeaseExpired
	}
	if !runtimeLeaseMatches(lease, current) {
		return authz.CapabilityLease{}, agentruntime.ErrLeaseInvalid
	}
	switch operation {
	case agentruntime.LeaseOperationAssign, agentruntime.LeaseOperationHeartbeat, agentruntime.LeaseOperationRenew, agentruntime.LeaseOperationResult:
	case agentruntime.LeaseOperationModel:
		if current.Action != authz.ActionModelGenerate {
			return authz.CapabilityLease{}, agentruntime.ErrLeaseInvalid
		}
	case agentruntime.LeaseOperationTool:
		if current.Action != authz.ActionToolInvoke {
			return authz.CapabilityLease{}, agentruntime.ErrLeaseInvalid
		}
	default:
		return authz.CapabilityLease{}, agentruntime.ErrLeaseInvalid
	}
	return current, nil
}

func runtimeLeasePrincipal(ctx context.Context, lease authz.CapabilityLease) (authn.Principal, context.Context, error) {
	principal := authn.Principal{
		ID: lease.PrincipalID, Type: lease.PrincipalType, Role: lease.Role,
		TenantID: lease.TenantID, ProjectID: lease.ProjectID,
	}
	principalCtx, err := authn.ContextWithPrincipal(ctx, principal)
	if err != nil {
		return authn.Principal{}, nil, agentruntime.ErrLeaseInvalid
	}
	return principal, principalCtx, nil
}

func leaseCheck(lease authz.CapabilityLease) authz.LeaseCheck {
	return authz.LeaseCheck{
		LeaseID: lease.ID, AgentInstanceID: lease.AgentInstanceID,
		PrincipalID: lease.PrincipalID, PrincipalType: lease.PrincipalType,
		TenantID: lease.TenantID, ProjectID: lease.ProjectID, ProjectVersion: lease.ProjectVersion,
		TaskID: lease.TaskID, TaskVersion: lease.TaskVersion, SpecDigest: lease.SpecDigest,
		Role: lease.Role, Action: lease.Action, Resource: lease.Resource, ParameterDigest: lease.ParameterDigest,
		PolicyVersion: lease.PolicyVersion, BudgetAccountID: lease.BudgetAccountID,
		Capability: lease.Action, FencingToken: lease.FencingToken,
	}
}

func runtimeLeaseMatches(view agentruntime.AgentLease, lease authz.CapabilityLease) bool {
	return view.LeaseID == lease.ID && view.AgentInstanceID == lease.AgentInstanceID &&
		view.TenantID == lease.TenantID && view.ProjectID == lease.ProjectID && view.TaskID == lease.TaskID &&
		string(view.Role) == lease.Role && view.IssuedAt.Equal(lease.IssuedAt) && view.ExpiresAt.Equal(lease.ExpiresAt) &&
		view.LastHeartbeatAt.Equal(lease.LastHeartbeatAt) && view.HeartbeatIntervalSeconds == int(lease.HeartbeatIntervalSeconds) &&
		slices.Equal(view.Capabilities, lease.Capabilities) && view.PolicyVersion == lease.PolicyVersion &&
		view.BudgetAccountID == lease.BudgetAccountID && view.Nonce == lease.Nonce &&
		view.FencingToken == lease.FencingToken && view.Signature == lease.Signature
}

func toRuntimeLease(lease authz.CapabilityLease) agentruntime.AgentLease {
	return agentruntime.AgentLease{
		LeaseID: lease.ID, AgentInstanceID: lease.AgentInstanceID,
		TenantID: lease.TenantID, ProjectID: lease.ProjectID, TaskID: lease.TaskID,
		Role: agentruntime.Role(lease.Role), IssuedAt: lease.IssuedAt, ExpiresAt: lease.ExpiresAt,
		LastHeartbeatAt: lease.LastHeartbeatAt, HeartbeatIntervalSeconds: int(lease.HeartbeatIntervalSeconds),
		Capabilities: append([]string(nil), lease.Capabilities...), PolicyVersion: lease.PolicyVersion,
		BudgetAccountID: lease.BudgetAccountID, Nonce: lease.Nonce,
		FencingToken: lease.FencingToken, Signature: lease.Signature,
	}
}

func runtimeLeaseError(err error) error {
	if err == nil {
		return nil
	}
	var typed *aorerrors.Error
	if errors.As(err, &typed) && (typed.Code == aorerrors.CodeLeaseExpired || typed.Code == aorerrors.CodeNotFound) {
		return agentruntime.ErrLeaseExpired
	}
	return agentruntime.ErrLeaseInvalid
}

var _ agentruntime.LeaseAuthority = (*runtimeAuthority)(nil)
var _ agentruntime.OperationLeaseAuthority = (*runtimeOperationAuthority)(nil)
