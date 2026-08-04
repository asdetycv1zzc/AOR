package controlapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/state"
)

const (
	testTenantID = "11111111-1111-4111-8111-111111111111"
	testBearer   = "verified-test-token"
)

var controlAPITestTime = time.Date(2026, 8, 4, 4, 0, 0, 0, time.UTC)

type fixedAuthenticator struct {
	principal authn.Principal
	err       error
}

func (authenticator fixedAuthenticator) Authenticate(_ context.Context, credential authn.Credential) (authn.Principal, error) {
	if credential.BearerToken != testBearer || authenticator.err != nil {
		return authn.Principal{}, authenticator.err
	}
	return authenticator.principal, nil
}

type recordingAuthorizer struct {
	inputs []authz.PolicyInput
	deny   bool
	err    error
}

func (authorizer *recordingAuthorizer) Evaluate(_ context.Context, input authz.PolicyInput) (authz.PolicyDecision, error) {
	authorizer.inputs = append(authorizer.inputs, input)
	if authorizer.err != nil {
		return authz.PolicyDecision{}, authorizer.err
	}
	decision := authz.DecisionAllow
	if authorizer.deny {
		decision = authz.DecisionDeny
	}
	return authz.PolicyDecision{Decision: decision, PolicyVersion: "policy-test", ReasonCodes: []string{"TEST"}, RuleID: "aor.test"}, nil
}

func TestCreateProjectIsAuthenticatedAuthorizedAndIdempotent(t *testing.T) {
	handler, store, authorizer := newTestHandler(t)
	body := []byte(`{"name":"AOR integration","goalAgentCount":2,"dataClassification":"INTERNAL"}`)

	first := performRequest(handler, http.MethodPost, "/v1/projects", body, map[string]string{
		"Authorization":   "Bearer " + testBearer,
		"Content-Type":    "application/json",
		"Idempotency-Key": "project-create-1",
	})
	if first.Code != http.StatusCreated {
		t.Fatalf("first status = %d body=%s", first.Code, first.Body.String())
	}
	var project state.Project
	if err := json.Unmarshal(first.Body.Bytes(), &project); err != nil {
		t.Fatal(err)
	}
	if project.ID != projectIDFor(testTenantID, "user-1", "project-create-1") || project.Version != 1 || first.Header().Get("ETag") != `"v1"` {
		t.Fatalf("unexpected project response: %#v etag=%q", project, first.Header().Get("ETag"))
	}

	second := performRequest(handler, http.MethodPost, "/v1/projects", body, map[string]string{
		"Authorization":   "Bearer " + testBearer,
		"Content-Type":    "application/json",
		"Idempotency-Key": "project-create-1",
	})
	if second.Code != http.StatusCreated {
		t.Fatalf("duplicate status = %d body=%s", second.Code, second.Body.String())
	}
	events, err := store.ListEvents(context.Background(), testTenantID)
	if err != nil || len(events) != 1 {
		t.Fatalf("events = %d err=%v", len(events), err)
	}
	if len(authorizer.inputs) != 3 || authorizer.inputs[0].Action != "project.create" || authorizer.inputs[1].Action != "project.create" {
		t.Fatalf("policy inputs = %#v", authorizer.inputs)
	}

	conflictBody := []byte(`{"name":"different","goalAgentCount":1,"dataClassification":"INTERNAL"}`)
	conflict := performRequest(handler, http.MethodPost, "/v1/projects", conflictBody, map[string]string{
		"Authorization":   "Bearer " + testBearer,
		"Content-Type":    "application/json",
		"Idempotency-Key": "project-create-1",
	})
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflict status = %d body=%s", conflict.Code, conflict.Body.String())
	}
}

func TestProjectReadAndCommandRequirePolicyAndVersion(t *testing.T) {
	handler, _, authorizer := newTestHandler(t)
	project := createTestProject(t, handler)

	read := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if read.Code != http.StatusOK || read.Header().Get("ETag") != `"v1"` {
		t.Fatalf("read status=%d etag=%q body=%s", read.Code, read.Header().Get("ETag"), read.Body.String())
	}

	missingVersion := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+":pause", []byte(`{"expectedVersion":1}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "pause-1",
	})
	if missingVersion.Code != http.StatusConflict {
		t.Fatalf("missing If-Match status=%d body=%s", missingVersion.Code, missingVersion.Body.String())
	}

	paused := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+":pause", []byte(`{"expectedVersion":1}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "pause-1", "If-Match": `"v1"`,
	})
	if paused.Code != http.StatusAccepted {
		t.Fatalf("pause status=%d body=%s", paused.Code, paused.Body.String())
	}
	var result state.Project
	if err := json.Unmarshal(paused.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.State != "PAUSED" || result.Version != 2 {
		t.Fatalf("paused project = %#v", result)
	}
	if authorizer.inputs[len(authorizer.inputs)-1].Action != "project.command" {
		t.Fatalf("last policy action = %q", authorizer.inputs[len(authorizer.inputs)-1].Action)
	}
}

func TestProjectArchiveRequiresAbortedOrCompletedState(t *testing.T) {
	handler, _, _ := newTestHandler(t)
	project := createTestProject(t, handler)
	headers := func(key, etag string) map[string]string {
		return map[string]string{
			"Authorization": "Bearer " + testBearer, "Content-Type": "application/json",
			"Idempotency-Key": key, "If-Match": etag,
		}
	}
	active := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+":archive", []byte(`{"expectedVersion":1}`), headers("archive-active", `"v1"`))
	if active.Code != http.StatusConflict {
		t.Fatalf("active archive status=%d body=%s", active.Code, active.Body.String())
	}
	aborted := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+":abort", []byte(`{"expectedVersion":1}`), headers("abort-before-archive", `"v1"`))
	if aborted.Code != http.StatusAccepted {
		t.Fatalf("abort status=%d body=%s", aborted.Code, aborted.Body.String())
	}
	archived := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+":archive", []byte(`{"expectedVersion":2}`), headers("archive-aborted", `"v2"`))
	if archived.Code != http.StatusAccepted || archived.Header().Get("ETag") != `"v3"` {
		t.Fatalf("archive status=%d etag=%q body=%s", archived.Code, archived.Header().Get("ETag"), archived.Body.String())
	}
	var result state.Project
	if err := json.Unmarshal(archived.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.State != "ARCHIVED" || result.Version != 3 {
		t.Fatalf("archived project = %#v", result)
	}
}

func TestAuthenticationAndPolicyFailuresAreFailClosed(t *testing.T) {
	handler, _, authorizer := newTestHandler(t)
	unauthenticated := performRequest(handler, http.MethodPost, "/v1/projects", []byte(`{}`), map[string]string{"Content-Type": "application/json", "Idempotency-Key": "key"})
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticated.Code)
	}

	authorizer.deny = true
	denied := performRequest(handler, http.MethodPost, "/v1/projects", []byte(`{"name":"denied","goalAgentCount":1,"dataClassification":"INTERNAL"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "denied",
	})
	if denied.Code != http.StatusForbidden {
		t.Fatalf("denied status = %d body=%s", denied.Code, denied.Body.String())
	}

	authorizer.deny = false
	authorizer.err = errors.New("opa unavailable with secret detail")
	unavailable := performRequest(handler, http.MethodPost, "/v1/projects", []byte(`{"name":"unavailable","goalAgentCount":1,"dataClassification":"INTERNAL"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "unavailable",
	})
	if unavailable.Code != http.StatusServiceUnavailable || bytes.Contains(unavailable.Body.Bytes(), []byte("secret detail")) {
		t.Fatalf("unavailable status=%d body=%s", unavailable.Code, unavailable.Body.String())
	}
}

func TestProjectEventsResumeFromCursorAndRejectInvalidRoutes(t *testing.T) {
	handler, store, _ := newTestHandler(t)
	project := createTestProject(t, handler)
	paused := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+":pause", []byte(`{"expectedVersion":1}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "pause-for-events", "If-Match": `"v1"`,
	})
	if paused.Code != http.StatusAccepted {
		t.Fatalf("pause status=%d body=%s", paused.Code, paused.Body.String())
	}
	events, err := store.ListEvents(context.Background(), testTenantID)
	if err != nil || len(events) != 2 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	stream := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/events?after="+events[0].EventID, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if stream.Code != http.StatusOK || !strings.Contains(stream.Body.String(), events[1].EventID) || strings.Contains(stream.Body.String(), events[0].EventID) {
		t.Fatalf("resumed stream status=%d body=%s", stream.Code, stream.Body.String())
	}
	unknownCursor := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/events?after=missing", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if unknownCursor.Code != http.StatusBadRequest {
		t.Fatalf("unknown cursor status=%d body=%s", unknownCursor.Code, unknownCursor.Body.String())
	}
	invalidRoute := performRequest(handler, http.MethodGet, "/v1/projects/not-a-uuid", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if invalidRoute.Code != http.StatusNotFound {
		t.Fatalf("invalid route status=%d body=%s", invalidRoute.Code, invalidRoute.Body.String())
	}
	method := performRequest(handler, http.MethodDelete, "/v1/projects/"+project.ID, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if method.Code != http.StatusMethodNotAllowed || method.Header().Get("Allow") == "" {
		t.Fatalf("method status=%d allow=%q body=%s", method.Code, method.Header().Get("Allow"), method.Body.String())
	}
}

func newTestHandler(t *testing.T) (*Handler, *eventing.MemoryStore, *recordingAuthorizer) {
	t.Helper()
	store := eventing.NewMemoryStore()
	authorizer := &recordingAuthorizer{}
	handler, err := New(Config{
		Store: store,
		Authenticator: fixedAuthenticator{principal: authn.Principal{
			ID: "user-1", Type: authn.PrincipalUser, Role: authn.RoleUser, TenantID: testTenantID,
		}},
		Authorizer: authorizer,
		Clock:      func() time.Time { return controlAPITestTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, store, authorizer
}

func createTestProject(t *testing.T, handler http.Handler) state.Project {
	t.Helper()
	response := performRequest(handler, http.MethodPost, "/v1/projects", []byte(`{"name":"project","goalAgentCount":1,"dataClassification":"INTERNAL"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "create-for-read",
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var project state.Project
	if err := json.Unmarshal(response.Body.Bytes(), &project); err != nil {
		t.Fatal(err)
	}
	return project
}

func performRequest(handler http.Handler, method, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

var _ authn.Authenticator = fixedAuthenticator{}
var _ authz.PolicyEvaluator = (*recordingAuthorizer)(nil)
