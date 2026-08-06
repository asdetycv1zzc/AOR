package controlapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/eventing"
)

func TestAdminEndpointsRequireBreakGlassAndRunChecks(t *testing.T) {
	store := eventing.NewMemoryStore()
	authorizer := &recordingAuthorizer{}
	handler, err := New(Config{
		Store: store,
		Authenticator: fixedAuthenticator{principal: authn.Principal{
			ID: "admin-1", Type: authn.PrincipalBreakGlassAdmin, Role: authn.RoleBreakGlassAdmin, TenantID: testTenantID,
		}},
		Authorizer: authorizer,
		Clock:      func() time.Time { return controlAPITestTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	response := performRequest(handler, http.MethodPost, "/v1/admin/doctor", []byte(`{}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "doctor-1",
	})
	if response.Code != http.StatusOK {
		t.Fatalf("doctor status=%d body=%s", response.Code, response.Body.String())
	}
	var report adminReport
	if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil || report.Operation != "doctor" || len(report.Checks) == 0 {
		t.Fatalf("doctor report=%#v err=%v", report, err)
	}

	policyBody := []byte(`{"project":{"tenantId":"` + testTenantID + `","id":"project-1","state":"GOAL_NEGOTIATING","stateVersion":1,"classification":"INTERNAL"},"action":"project.read","resource":{"type":"project","id":"project-1"}}`)
	response = performRequest(handler, http.MethodPost, "/v1/admin/policies:test", policyBody, map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "policy-1",
	})
	if response.Code != http.StatusOK {
		t.Fatalf("policy status=%d body=%s", response.Code, response.Body.String())
	}
	var decision authz.PolicyDecision
	if err := json.Unmarshal(response.Body.Bytes(), &decision); err != nil || decision.Decision != authz.DecisionAllow {
		t.Fatalf("policy decision=%#v err=%v", decision, err)
	}

	probeBody := []byte(`{"platform":"WINDOWS","isolationLevel":"NONE","workloadTrust":"UNTRUSTED"}`)
	response = performRequest(handler, http.MethodPost, "/v1/admin/sandboxes:probe", probeBody, map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "probe-1",
	})
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "FAIL") {
		t.Fatalf("probe status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAdminEndpointsRejectRegularUser(t *testing.T) {
	store := eventing.NewMemoryStore()
	handler, err := New(Config{
		Store: store,
		Authenticator: fixedAuthenticator{principal: authn.Principal{
			ID: "user-1", Type: authn.PrincipalUser, Role: authn.RoleUser, TenantID: testTenantID,
		}},
		Authorizer: &recordingAuthorizer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := performRequest(handler, http.MethodPost, "/v1/admin/doctor", []byte(`{}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "doctor-user",
	})
	if response.Code != http.StatusForbidden {
		t.Fatalf("user status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestBackupVerificationEndpointRequiresRestoreDependencies(t *testing.T) {
	handler, err := New(Config{
		Store: eventing.NewMemoryStore(),
		Authenticator: fixedAuthenticator{principal: authn.Principal{
			ID: "admin-1", Type: authn.PrincipalBreakGlassAdmin, Role: authn.RoleBreakGlassAdmin, TenantID: testTenantID,
		}},
		Authorizer: &recordingAuthorizer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := performRequest(handler, http.MethodPost, "/v1/admin/backup:verify", []byte(`{}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "backup-verify-1",
	})
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("backup verification status=%d body=%s", response.Code, response.Body.String())
	}
}
