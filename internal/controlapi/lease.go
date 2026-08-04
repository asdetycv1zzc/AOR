package controlapi

import (
	"context"
	"net/http"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/leaseauthority"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

const maximumLeaseTTLSeconds = 15 * 60

type LeaseAuthority interface {
	Issue(context.Context, authn.Principal, leaseauthority.GrantRequest) (authz.CapabilityLease, error)
	Renew(context.Context, authn.Principal, leaseauthority.RenewRequest) (authz.CapabilityLease, error)
	Heartbeat(context.Context, authn.Principal, leaseauthority.HeartbeatRequest) (authz.CapabilityLease, error)
	Revoke(context.Context, authn.Principal, leaseauthority.RevokeRequest) error
}

type leaseGrantBody struct {
	Action          string         `json:"action"`
	Resource        authz.Resource `json:"resource"`
	ParameterDigest string         `json:"parameterDigest"`
	BudgetAccountID string         `json:"budgetAccountId"`
	ApprovalID      string         `json:"approvalId,omitempty"`
	TTLSeconds      int64          `json:"ttlSeconds,omitempty"`
}

type leaseRenewBody struct {
	leaseGrantBody
	LeaseID       string `json:"leaseId"`
	FencingToken  int64  `json:"fencingToken"`
	PolicyVersion string `json:"policyVersion"`
}

type leaseHeartbeatBody struct {
	LeaseID      string `json:"leaseId"`
	FencingToken int64  `json:"fencingToken"`
}

type leaseRevokeBody struct {
	LeaseID string `json:"leaseId"`
	Reason  string `json:"reason"`
}

func (handler *Handler) manageTaskLease(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID, taskID, command string) {
	if handler == nil || handler.leases == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "lease authority"}))
		return
	}
	if request.Method != http.MethodPost {
		writeMethodNotAllowed(response, request)
		return
	}
	switch command {
	case "leases":
		handler.issueTaskLease(response, request, principal, projectID, taskID)
	case "leases:renew":
		handler.renewTaskLease(response, request, principal, projectID, taskID)
	case "leases:heartbeat":
		handler.heartbeatTaskLease(response, request, principal, projectID, taskID)
	case "leases:revoke":
		handler.revokeTaskLease(response, request, principal, projectID, taskID)
	default:
		writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
	}
}

func (handler *Handler) issueTaskLease(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID, taskID string) {
	if principal.Type != authn.PrincipalAgentInstance {
		writeError(response, request, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "lease principal"}))
		return
	}
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	var body leaseGrantBody
	if err := decodeJSON(request, &body); err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "lease issue"}))
		return
	}
	ttl, err := leaseTTL(body.TTLSeconds)
	if err != nil {
		writeError(response, request, err)
		return
	}
	lease, err := handler.leases.Issue(request.Context(), principal, leaseauthority.GrantRequest{
		TenantID: principal.TenantID, ProjectID: projectID, TaskID: taskID,
		Action: body.Action, Resource: body.Resource, ParameterDigest: body.ParameterDigest,
		BudgetAccountID: body.BudgetAccountID, ApprovalID: body.ApprovalID,
		IdempotencyKey: idempotencyKey, TTL: ttl,
	})
	if err != nil {
		writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusCreated, lease)
}

func (handler *Handler) renewTaskLease(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID, taskID string) {
	if principal.Type != authn.PrincipalAgentInstance {
		writeError(response, request, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "lease principal"}))
		return
	}
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	var body leaseRenewBody
	if err := decodeJSON(request, &body); err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "lease renewal"}))
		return
	}
	ttl, err := leaseTTL(body.TTLSeconds)
	if err != nil {
		writeError(response, request, err)
		return
	}
	lease, err := handler.leases.Renew(request.Context(), principal, leaseauthority.RenewRequest{
		GrantRequest: leaseauthority.GrantRequest{
			TenantID: principal.TenantID, ProjectID: projectID, TaskID: taskID,
			Action: body.Action, Resource: body.Resource, ParameterDigest: body.ParameterDigest,
			BudgetAccountID: body.BudgetAccountID, ApprovalID: body.ApprovalID,
			IdempotencyKey: idempotencyKey, TTL: ttl,
		},
		LeaseID: body.LeaseID, FencingToken: body.FencingToken, PolicyVersion: body.PolicyVersion,
	})
	if err != nil {
		writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, lease)
}

func (handler *Handler) heartbeatTaskLease(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID, taskID string) {
	if principal.Type != authn.PrincipalAgentInstance {
		writeError(response, request, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "lease principal"}))
		return
	}
	var body leaseHeartbeatBody
	if err := decodeJSON(request, &body); err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "lease heartbeat"}))
		return
	}
	lease, err := handler.leases.Heartbeat(request.Context(), principal, leaseauthority.HeartbeatRequest{
		TenantID: principal.TenantID, ProjectID: projectID, TaskID: taskID,
		LeaseID: body.LeaseID, FencingToken: body.FencingToken,
	})
	if err != nil {
		writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, lease)
}

func (handler *Handler) revokeTaskLease(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID, taskID string) {
	if principal.Type != authn.PrincipalAgentInstance && principal.Type != authn.PrincipalBreakGlassAdmin {
		writeError(response, request, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "lease principal"}))
		return
	}
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	var body leaseRevokeBody
	if err := decodeJSON(request, &body); err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "lease revoke"}))
		return
	}
	if err := handler.leases.Revoke(request.Context(), principal, leaseauthority.RevokeRequest{
		TenantID: principal.TenantID, ProjectID: projectID, TaskID: taskID,
		LeaseID: body.LeaseID, Reason: body.Reason, IdempotencyKey: idempotencyKey,
	}); err != nil {
		writeError(response, request, err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func leaseTTL(seconds int64) (time.Duration, error) {
	if seconds < 0 || seconds > maximumLeaseTTLSeconds {
		return 0, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "lease ttl"})
	}
	return time.Duration(seconds) * time.Second, nil
}

var _ LeaseAuthority = (*leaseauthority.Service)(nil)
