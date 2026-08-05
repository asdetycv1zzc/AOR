package controlapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/knowledgecurator"
)

func TestKnowledgeCuratorHandlerRejectsControlAndAdminRoutes(t *testing.T) {
	handler, err := NewKnowledgeCuratorHandler(Config{
		Store: eventing.NewMemoryStore(),
		Authenticator: fixedAuthenticator{principal: authn.Principal{
			ID: "admin-1", Type: authn.PrincipalUser, Role: authn.RoleBreakGlassAdmin, TenantID: testTenantID,
		}},
		Authorizer:       &recordingAuthorizer{},
		KnowledgeCurator: &recordingKnowledgeCurator{record: knowledgecurator.Record{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/admin/doctor", "/v1/projects", "/v1/projects/22222222-2222-4222-8222-222222222222/knowledge:search"} {
		response := performRequest(handler, http.MethodGet, path, nil, map[string]string{"Authorization": "Bearer " + testBearer})
		if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "AOR_NOT_FOUND") {
			t.Fatalf("path=%s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
}
