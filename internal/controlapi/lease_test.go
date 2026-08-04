package controlapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/leaseauthority"
)

type recordingLeaseAuthority struct {
	issueRequest     leaseauthority.GrantRequest
	renewRequest     leaseauthority.RenewRequest
	heartbeatRequest leaseauthority.HeartbeatRequest
	revokeRequest    leaseauthority.RevokeRequest
	principal        authn.Principal
	err              error
}

func (authority *recordingLeaseAuthority) Issue(_ context.Context, principal authn.Principal, request leaseauthority.GrantRequest) (authz.CapabilityLease, error) {
	authority.principal, authority.issueRequest = principal, request
	return authz.CapabilityLease{ID: "lease_issue", FencingToken: 1}, authority.err
}

func (authority *recordingLeaseAuthority) Renew(_ context.Context, principal authn.Principal, request leaseauthority.RenewRequest) (authz.CapabilityLease, error) {
	authority.principal, authority.renewRequest = principal, request
	return authz.CapabilityLease{ID: request.LeaseID, FencingToken: request.FencingToken + 1}, authority.err
}

func (authority *recordingLeaseAuthority) Heartbeat(_ context.Context, principal authn.Principal, request leaseauthority.HeartbeatRequest) (authz.CapabilityLease, error) {
	authority.principal, authority.heartbeatRequest = principal, request
	return authz.CapabilityLease{ID: request.LeaseID, FencingToken: request.FencingToken}, authority.err
}

func (authority *recordingLeaseAuthority) Revoke(_ context.Context, principal authn.Principal, request leaseauthority.RevokeRequest) error {
	authority.principal, authority.revokeRequest = principal, request
	return authority.err
}

func TestTaskLeaseHTTPWorkflowBindsAuthenticatedAgentAndPathScope(t *testing.T) {
	handler, _, _ := newTestHandler(t)
	authority := &recordingLeaseAuthority{}
	agent := authn.Principal{ID: "agent_1", Type: authn.PrincipalAgentInstance, Role: authn.RoleExecutor, TenantID: testTenantID, ProjectID: "22222222-2222-4222-8222-222222222222"}
	handler.authenticator = fixedAuthenticator{principal: agent}
	handler.leases = authority
	base := "/v1/projects/" + agent.ProjectID + "/tasks/task_1/"
	digest := "sha256:" + strings.Repeat("1", 64)
	grant := []byte(`{"action":"tool.invoke","resource":{"type":"tool","id":"tool://repository/repo.read@1.0.0"},"parameterDigest":"` + digest + `","budgetAccountId":"budget_1","ttlSeconds":300}`)
	headers := map[string]string{"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "lease-http-1"}

	issued := performRequest(handler, http.MethodPost, base+"leases", grant, headers)
	if issued.Code != http.StatusCreated || authority.issueRequest.ProjectID != agent.ProjectID || authority.issueRequest.TaskID != "task_1" || authority.issueRequest.TenantID != testTenantID || authority.issueRequest.IdempotencyKey != "lease-http-1" || authority.issueRequest.TTL.Seconds() != 300 || authority.principal.ID != agent.ID {
		t.Fatalf("issue status=%d body=%s request=%#v principal=%#v", issued.Code, issued.Body.String(), authority.issueRequest, authority.principal)
	}

	renew := []byte(`{"leaseId":"lease_issue","fencingToken":1,"policyVersion":"policy_1","action":"tool.invoke","resource":{"type":"tool","id":"tool://repository/repo.read@1.0.0"},"parameterDigest":"` + digest + `","budgetAccountId":"budget_1","ttlSeconds":300}`)
	renewed := performRequest(handler, http.MethodPost, base+"leases:renew", renew, map[string]string{"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "lease-renew-1"})
	if renewed.Code != http.StatusOK || authority.renewRequest.LeaseID != "lease_issue" || authority.renewRequest.FencingToken != 1 || authority.renewRequest.PolicyVersion != "policy_1" || authority.renewRequest.Action != authz.ActionToolInvoke || authority.renewRequest.IdempotencyKey != "lease-renew-1" {
		t.Fatalf("renew status=%d body=%s request=%#v", renewed.Code, renewed.Body.String(), authority.renewRequest)
	}

	heartbeat := performRequest(handler, http.MethodPost, base+"leases:heartbeat", []byte(`{"leaseId":"lease_issue","fencingToken":2}`), map[string]string{"Authorization": "Bearer " + testBearer, "Content-Type": "application/json"})
	if heartbeat.Code != http.StatusOK || authority.heartbeatRequest.TenantID != testTenantID || authority.heartbeatRequest.ProjectID != agent.ProjectID || authority.heartbeatRequest.TaskID != "task_1" || authority.heartbeatRequest.LeaseID != "lease_issue" || authority.heartbeatRequest.FencingToken != 2 {
		t.Fatalf("heartbeat status=%d body=%s request=%#v", heartbeat.Code, heartbeat.Body.String(), authority.heartbeatRequest)
	}

	revoked := performRequest(handler, http.MethodPost, base+"leases:revoke", []byte(`{"leaseId":"lease_issue","reason":"task canceled"}`), map[string]string{"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "lease-revoke-1"})
	if revoked.Code != http.StatusNoContent || authority.revokeRequest.TenantID != testTenantID || authority.revokeRequest.ProjectID != agent.ProjectID || authority.revokeRequest.TaskID != "task_1" || authority.revokeRequest.LeaseID != "lease_issue" || authority.revokeRequest.Reason != "task canceled" || authority.revokeRequest.IdempotencyKey != "lease-revoke-1" {
		t.Fatalf("revoke status=%d body=%s request=%#v", revoked.Code, revoked.Body.String(), authority.revokeRequest)
	}
}

func TestTaskLeaseHTTPFailsClosedForInvalidCallerRequestAndMethod(t *testing.T) {
	handler, _, _ := newTestHandler(t)
	authority := &recordingLeaseAuthority{}
	handler.leases = authority
	projectID := "22222222-2222-4222-8222-222222222222"
	route := "/v1/projects/" + projectID + "/tasks/task_1/leases"
	digest := "sha256:" + strings.Repeat("1", 64)
	body := []byte(`{"action":"tool.invoke","resource":{"type":"tool","id":"tool://repository/repo.read@1.0.0"},"parameterDigest":"` + digest + `","budgetAccountId":"budget_1","ttlSeconds":901}`)

	denied := performRequest(handler, http.MethodPost, route, body, map[string]string{"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "denied"})
	if denied.Code != http.StatusForbidden || authority.issueRequest.Action != "" {
		t.Fatalf("user issue status=%d body=%s", denied.Code, denied.Body.String())
	}

	agent := authn.Principal{ID: "agent_1", Type: authn.PrincipalAgentInstance, Role: authn.RoleExecutor, TenantID: testTenantID, ProjectID: projectID}
	handler.authenticator = fixedAuthenticator{principal: agent}
	invalidTTL := performRequest(handler, http.MethodPost, route, body, map[string]string{"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "invalid-ttl"})
	if invalidTTL.Code != http.StatusBadRequest || authority.issueRequest.Action != "" {
		t.Fatalf("invalid ttl status=%d body=%s", invalidTTL.Code, invalidTTL.Body.String())
	}

	missingKey := performRequest(handler, http.MethodPost, route, []byte(`{}`), map[string]string{"Authorization": "Bearer " + testBearer, "Content-Type": "application/json"})
	if missingKey.Code != http.StatusBadRequest {
		t.Fatalf("missing key status=%d body=%s", missingKey.Code, missingKey.Body.String())
	}

	method := performRequest(handler, http.MethodGet, route, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method status=%d body=%s", method.Code, method.Body.String())
	}
}

var _ LeaseAuthority = (*recordingLeaseAuthority)(nil)
