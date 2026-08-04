package controlapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/knowledge"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
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

type testArtifactCatalog struct {
	record  artifact.Record
	content string
	err     error
}

func (catalog *testArtifactCatalog) List(context.Context, string, string, string, int) (artifact.Page, error) {
	if catalog.err != nil {
		return artifact.Page{}, catalog.err
	}
	return artifact.Page{Items: []artifact.Record{catalog.record}, NextCursor: "next-artifact"}, nil
}

func (catalog *testArtifactCatalog) Get(context.Context, string, string, string) (artifact.Record, error) {
	if catalog.err != nil {
		return artifact.Record{}, catalog.err
	}
	return catalog.record, nil
}

func (catalog *testArtifactCatalog) Open(context.Context, string, string, string) (artifact.Record, io.ReadCloser, error) {
	if catalog.err != nil {
		return artifact.Record{}, nil, catalog.err
	}
	return catalog.record, io.NopCloser(strings.NewReader(catalog.content)), nil
}

type testKnowledgeReader struct {
	searchRequest knowledge.SearchRequest
	readRequest   knowledge.ReadRangeRequest
	manifest      knowledge.Manifest
	reference     knowledge.Reference
	err           error
}

func (reader *testKnowledgeReader) Search(_ context.Context, request knowledge.SearchRequest) (knowledge.SearchResponse, error) {
	reader.searchRequest = request
	if reader.err != nil {
		return knowledge.SearchResponse{}, reader.err
	}
	return knowledge.SearchResponse{Revision: reader.reference.ScopeRevision, References: []knowledge.Reference{reader.reference}}, nil
}

func (reader *testKnowledgeReader) ReadRange(_ context.Context, request knowledge.ReadRangeRequest) (knowledge.ReadRangeResponse, error) {
	reader.readRequest = request
	if reader.err != nil {
		return knowledge.ReadRangeResponse{}, reader.err
	}
	return knowledge.ReadRangeResponse{Reference: reader.reference, Content: "selected knowledge\n"}, nil
}

func (reader *testKnowledgeReader) Manifest(context.Context, knowledge.Access, string) (knowledge.Manifest, error) {
	if reader.err != nil {
		return knowledge.Manifest{}, reader.err
	}
	return reader.manifest, nil
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
	if !validProjectID(project.ID) || project.Version != 1 || first.Header().Get("ETag") != `"v1"` {
		t.Fatalf("unexpected project response: %#v etag=%q", project, first.Header().Get("ETag"))
	}
	accounts, err := handler.budgets.ListAccounts(context.Background(), testTenantID, project.ID)
	if err != nil || len(accounts) != 1 || accounts[0].ID != project.ID || accounts[0].Version != 1 {
		t.Fatalf("default project budget = %#v err=%v", accounts, err)
	}

	second := performRequest(handler, http.MethodPost, "/v1/projects", body, map[string]string{
		"Authorization":   "Bearer " + testBearer,
		"Content-Type":    "application/json",
		"Idempotency-Key": "project-create-1",
	})
	if second.Code != http.StatusCreated {
		t.Fatalf("duplicate status = %d body=%s", second.Code, second.Body.String())
	}
	var duplicate state.Project
	if err := json.Unmarshal(second.Body.Bytes(), &duplicate); err != nil || duplicate.ID != project.ID {
		t.Fatalf("duplicate project = %#v err=%v", duplicate, err)
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

func TestWriteRequestsRejectDuplicateJSONMembers(t *testing.T) {
	handler, _, _ := newTestHandler(t)
	duplicate := performRequest(handler, http.MethodPost, "/v1/projects", []byte(`{"name":"first","name":"second","goalAgentCount":1,"dataClassification":"INTERNAL"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "duplicate-json",
	})
	if duplicate.Code != http.StatusBadRequest {
		t.Fatalf("duplicate member status=%d body=%s", duplicate.Code, duplicate.Body.String())
	}
	nested := []byte(`{"name":"project","goalAgentCount":1,"dataClassification":"INTERNAL","unknown":{"key":1,"key":2}}`)
	duplicate = performRequest(handler, http.MethodPost, "/v1/projects", nested, map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "duplicate-nested-json",
	})
	if duplicate.Code != http.StatusBadRequest {
		t.Fatalf("nested duplicate status=%d body=%s", duplicate.Code, duplicate.Body.String())
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

func TestTaskListUsesStableOpaqueCursor(t *testing.T) {
	handler, store, _ := newTestHandler(t)
	project := createTestProject(t, handler)
	for index := 0; index < 101; index++ {
		seedTaskProjection(t, store, project.ID, fmt.Sprintf("task_%03d", index))
	}
	first := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/tasks", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if first.Code != http.StatusOK {
		t.Fatalf("first page status=%d body=%s", first.Code, first.Body.String())
	}
	var firstPage struct {
		Items      []state.ModuleTask `json:"items"`
		NextCursor string             `json:"nextCursor"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstPage); err != nil {
		t.Fatal(err)
	}
	if len(firstPage.Items) != 100 || firstPage.Items[0].ID != "task_000" || firstPage.Items[99].ID != "task_099" || len(firstPage.NextCursor) != 64 {
		t.Fatalf("first page = %#v", firstPage)
	}
	second := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/tasks?cursor="+firstPage.NextCursor, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	var secondPage struct {
		Items []state.ModuleTask `json:"items"`
	}
	if second.Code != http.StatusOK || json.Unmarshal(second.Body.Bytes(), &secondPage) != nil || len(secondPage.Items) != 1 || secondPage.Items[0].ID != "task_100" {
		t.Fatalf("second page status=%d body=%s", second.Code, second.Body.String())
	}
	unknown := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/tasks?cursor=unknown", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown cursor status=%d body=%s", unknown.Code, unknown.Body.String())
	}
}

func TestGoalAPIMessageSpecApprovalChangeAndRejectionLifecycle(t *testing.T) {
	handler, store, authorizer := newTestHandler(t)
	project := createTestProject(t, handler)
	messageRoute := "/v1/projects/" + project.ID + "/goal/messages"
	messageBody := []byte(`{"expectedVersion":1,"message":"build a production API"}`)
	messageHeaders := map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json",
		"Idempotency-Key": "goal-message-1", "If-Match": `"v1"`,
	}
	submitted := performRequest(handler, http.MethodPost, messageRoute, messageBody, messageHeaders)
	if submitted.Code != http.StatusAccepted || submitted.Header().Get("ETag") != `"v2"` {
		t.Fatalf("message status=%d etag=%q body=%s", submitted.Code, submitted.Header().Get("ETag"), submitted.Body.String())
	}
	replayedMessage := performRequest(handler, http.MethodPost, messageRoute, messageBody, messageHeaders)
	if replayedMessage.Code != http.StatusAccepted || replayedMessage.Body.String() != submitted.Body.String() {
		t.Fatalf("message replay status=%d body=%s", replayedMessage.Code, replayedMessage.Body.String())
	}
	messages := performRequest(handler, http.MethodGet, messageRoute, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if messages.Code != http.StatusOK || messages.Header().Get("ETag") != `"v2"` || !strings.Contains(messages.Body.String(), "build a production API") || !strings.Contains(messages.Body.String(), `"kind":"USER"`) {
		t.Fatalf("messages status=%d etag=%q body=%s", messages.Code, messages.Header().Get("ETag"), messages.Body.String())
	}

	draft := controlGoalSpec(t, project.ID, 1, nil)
	seedGoalSpec(t, handler, project.ID, 2, state.ProjectCommandProposeGoal, draft)
	specRoute := "/v1/projects/" + project.ID + "/goal/specs/1"
	gotDraft := performRequest(handler, http.MethodGet, specRoute, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if gotDraft.Code != http.StatusOK || gotDraft.Header().Get("ETag") != `"goal-v1-r1"` || !strings.Contains(gotDraft.Body.String(), `"status":"DRAFT"`) {
		t.Fatalf("draft status=%d etag=%q body=%s", gotDraft.Code, gotDraft.Header().Get("ETag"), gotDraft.Body.String())
	}
	listed := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/goal/specs", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if listed.Code != http.StatusOK || listed.Header().Get("ETag") != `"v3"` || !strings.Contains(listed.Body.String(), draft.ContentSHA256) {
		t.Fatalf("listed status=%d etag=%q body=%s", listed.Code, listed.Header().Get("ETag"), listed.Body.String())
	}

	approveBody := []byte(`{"expectedVersion":3,"sha256":"` + draft.ContentSHA256 + `","decision":"APPROVE","comment":"requirements are correct","idempotencyKey":"approve-goal-1"}`)
	approveHeaders := map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json",
		"Idempotency-Key": "approve-goal-1", "If-Match": `"v3"`,
	}
	approved := performRequest(handler, http.MethodPost, specRoute+":approve", approveBody, approveHeaders)
	if approved.Code != http.StatusAccepted || approved.Header().Get("ETag") != `"v4"` || !strings.Contains(approved.Body.String(), `"state":"PLANNING"`) {
		t.Fatalf("approve status=%d etag=%q body=%s", approved.Code, approved.Header().Get("ETag"), approved.Body.String())
	}
	statsAfterApproval := store.Stats()
	approvedAgain := performRequest(handler, http.MethodPost, specRoute+":approve", approveBody, approveHeaders)
	if approvedAgain.Code != http.StatusAccepted || approvedAgain.Body.String() != approved.Body.String() || store.Stats() != statsAfterApproval {
		t.Fatalf("approve replay status=%d body=%s stats=%#v", approvedAgain.Code, approvedAgain.Body.String(), store.Stats())
	}
	gotApproved := performRequest(handler, http.MethodGet, specRoute, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if gotApproved.Code != http.StatusOK || gotApproved.Header().Get("ETag") != `"goal-v1-r2"` || !strings.Contains(gotApproved.Body.String(), `"status":"APPROVED"`) || !strings.Contains(gotApproved.Body.String(), `"actorId":"user-1"`) {
		t.Fatalf("approved spec status=%d etag=%q body=%s", gotApproved.Code, gotApproved.Header().Get("ETag"), gotApproved.Body.String())
	}
	if statsAfterApproval.Approvals != 1 || statsAfterApproval.Events != statsAfterApproval.Outbox {
		t.Fatalf("approval stats=%#v", statsAfterApproval)
	}

	changeBody := []byte(`{"expectedVersion":4,"version":1,"sha256":"` + draft.ContentSHA256 + `","message":"add a second deployment target","impactedTaskIds":[]}`)
	changeHeaders := map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json",
		"Idempotency-Key": "change-goal-1", "If-Match": `"v4"`,
	}
	changed := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+"/goal:change", changeBody, changeHeaders)
	if changed.Code != http.StatusAccepted || changed.Header().Get("ETag") != `"v5"` || !strings.Contains(changed.Body.String(), `"state":"GOAL_NEGOTIATING"`) {
		t.Fatalf("change status=%d etag=%q body=%s", changed.Code, changed.Header().Get("ETag"), changed.Body.String())
	}
	gotSuperseded := performRequest(handler, http.MethodGet, specRoute, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if gotSuperseded.Code != http.StatusOK || gotSuperseded.Header().Get("ETag") != `"goal-v1-r3"` || !strings.Contains(gotSuperseded.Body.String(), `"status":"SUPERSEDED"`) {
		t.Fatalf("superseded status=%d etag=%q body=%s", gotSuperseded.Code, gotSuperseded.Header().Get("ETag"), gotSuperseded.Body.String())
	}

	draftTwo := controlGoalSpec(t, project.ID, 2, nil)
	seedGoalSpec(t, handler, project.ID, 5, state.ProjectCommandSupersedeGoal, draftTwo)
	rejectRoute := "/v1/projects/" + project.ID + "/goal/specs/2:reject"
	rejectBody := []byte(`{"expectedVersion":6,"sha256":"` + draftTwo.ContentSHA256 + `","decision":"REJECT","comment":"deployment target is incomplete"}`)
	rejected := performRequest(handler, http.MethodPost, rejectRoute, rejectBody, map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json",
		"Idempotency-Key": "reject-goal-2", "If-Match": `"v6"`,
	})
	if rejected.Code != http.StatusAccepted || rejected.Header().Get("ETag") != `"v7"` {
		t.Fatalf("reject status=%d etag=%q body=%s", rejected.Code, rejected.Header().Get("ETag"), rejected.Body.String())
	}
	gotRejected := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/goal/specs/2", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if gotRejected.Code != http.StatusOK || !strings.Contains(gotRejected.Body.String(), `"status":"REJECTED"`) {
		t.Fatalf("rejected spec status=%d body=%s", gotRejected.Code, gotRejected.Body.String())
	}
	if last := authorizer.inputs[len(authorizer.inputs)-1]; last.Action != authz.ActionGoalRead || last.Resource.Type != "goal-spec" {
		t.Fatalf("last goal policy input=%#v", last)
	}
}

func TestGoalAPIRejectsUnsafeHeadersBodiesHashesAndUnresolvedApproval(t *testing.T) {
	handler, _, authorizer := newTestHandler(t)
	project := createTestProject(t, handler)
	route := "/v1/projects/" + project.ID + "/goal/messages"
	missingMatch := performRequest(handler, http.MethodPost, route, []byte(`{"expectedVersion":1,"message":"goal"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "goal-no-match",
	})
	if missingMatch.Code != http.StatusConflict {
		t.Fatalf("missing match status=%d body=%s", missingMatch.Code, missingMatch.Body.String())
	}
	duplicate := performRequest(handler, http.MethodPost, route, []byte(`{"expectedVersion":1,"message":"one","message":"two"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "goal-duplicate", "If-Match": `"v1"`,
	})
	if duplicate.Code != http.StatusBadRequest {
		t.Fatalf("duplicate status=%d body=%s", duplicate.Code, duplicate.Body.String())
	}
	authorizer.deny = true
	denied := performRequest(handler, http.MethodPost, route, []byte(`{"expectedVersion":1,"message":"denied"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "goal-denied", "If-Match": `"v1"`,
	})
	if denied.Code != http.StatusForbidden {
		t.Fatalf("denied status=%d body=%s", denied.Code, denied.Body.String())
	}
	authorizer.deny = false
	accepted := performRequest(handler, http.MethodPost, route, []byte(`{"expectedVersion":1,"message":"accepted"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "goal-accepted", "If-Match": `"v1"`,
	})
	if accepted.Code != http.StatusAccepted {
		t.Fatalf("accepted status=%d body=%s", accepted.Code, accepted.Body.String())
	}
	draft := controlGoalSpec(t, project.ID, 1, []string{"choose a region"})
	seedGoalSpec(t, handler, project.ID, 2, state.ProjectCommandProposeGoal, draft)
	approveRoute := "/v1/projects/" + project.ID + "/goal/specs/1:approve"
	unresolved := performRequest(handler, http.MethodPost, approveRoute, []byte(`{"expectedVersion":3,"sha256":"`+draft.ContentSHA256+`"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "approve-unresolved", "If-Match": `"v3"`,
	})
	if unresolved.Code != http.StatusConflict || !strings.Contains(unresolved.Body.String(), string(aorerrors.CodeGoalNotApproved)) {
		t.Fatalf("unresolved status=%d body=%s", unresolved.Code, unresolved.Body.String())
	}
	wrongHash := performRequest(handler, http.MethodPost, approveRoute, []byte(`{"expectedVersion":3,"sha256":"sha256:`+strings.Repeat("f", 64)+`"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "approve-wrong-hash", "If-Match": `"v3"`,
	})
	if wrongHash.Code != http.StatusConflict || !strings.Contains(wrongHash.Body.String(), string(aorerrors.CodeGoalHashMismatch)) {
		t.Fatalf("wrong hash status=%d body=%s", wrongHash.Code, wrongHash.Body.String())
	}
}

func TestArtifactEndpointsListMetadataDownloadAndMapFailures(t *testing.T) {
	handler, _, authorizer := newTestHandler(t)
	project := createTestProject(t, handler)
	content := `{"artifact":true}`
	digest, err := canonicaljson.Digest([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	record := artifact.Record{
		ID: "22222222-2222-4222-8222-222222222222", ProjectID: project.ID,
		URI: "artifact://sha256/" + strings.TrimPrefix(digest, "sha256:"), SHA256: digest,
		SizeBytes: int64(len(content)), ContentType: "application/json", Classification: "INTERNAL",
		CreatedByPrincipal: "agent-1", Metadata: map[string]any{"taskId": "task-1"}, CreatedAt: controlAPITestTime,
	}
	catalog := &testArtifactCatalog{record: record, content: content}
	handler.artifacts = catalog

	listed := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/artifacts", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if listed.Code != http.StatusOK || listed.Header().Get("ETag") == "" || !strings.Contains(listed.Body.String(), record.ID) || !strings.Contains(listed.Body.String(), "next-artifact") {
		t.Fatalf("list status=%d body=%s", listed.Code, listed.Body.String())
	}
	metadata := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/artifacts/"+record.ID, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if metadata.Code != http.StatusOK || metadata.Header().Get("ETag") != `"`+digest+`"` || !strings.Contains(metadata.Body.String(), record.URI) {
		t.Fatalf("metadata status=%d etag=%q body=%s", metadata.Code, metadata.Header().Get("ETag"), metadata.Body.String())
	}
	download := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/artifacts/"+record.ID+"?download=true", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if download.Code != http.StatusOK || download.Body.String() != content || download.Header().Get("Content-Type") != "application/json" || download.Header().Get("X-AOR-Artifact-URI") != record.URI {
		t.Fatalf("download status=%d headers=%v body=%s", download.Code, download.Header(), download.Body.String())
	}
	if last := authorizer.inputs[len(authorizer.inputs)-1]; last.Action != authz.ActionProjectRead || last.Resource.Type != "artifact" || last.Resource.ID != record.ID {
		t.Fatalf("artifact policy input=%#v", last)
	}

	catalog.err = artifact.ErrNotFound
	missing := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/artifacts/"+record.ID, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if missing.Code != http.StatusNotFound || !strings.Contains(missing.Body.String(), string(aorerrors.CodeArtifactNotAvailable)) {
		t.Fatalf("missing status=%d body=%s", missing.Code, missing.Body.String())
	}
	catalog.err = artifact.ErrIntegrity
	corrupt := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/artifacts/"+record.ID, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if corrupt.Code != http.StatusConflict || !strings.Contains(corrupt.Body.String(), string(aorerrors.CodeArtifactHashMismatch)) {
		t.Fatalf("corrupt status=%d body=%s", corrupt.Code, corrupt.Body.String())
	}
	invalidQuery := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/artifacts/"+record.ID+"?download=1", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if invalidQuery.Code != http.StatusBadRequest {
		t.Fatalf("invalid download status=%d body=%s", invalidQuery.Code, invalidQuery.Body.String())
	}
}

func TestKnowledgeEndpointsReturnReferencesAndPreserveRevisionBinding(t *testing.T) {
	handler, _, authorizer := newTestHandler(t)
	project := createTestProject(t, handler)
	revision := "sha256:" + strings.Repeat("1", 64)
	documentDigest := "sha256:" + strings.Repeat("2", 64)
	reference := knowledge.Reference{
		ResourceURI: "file:///var/lib/aor/knowledge/document.md", LocalPath: "/var/lib/aor/knowledge/document.md",
		ScopeRevision: revision, SourceProjectID: project.ID, Path: "architecture/document.md", Revision: revision,
		SHA256: documentDigest, LineStart: 1, LineEnd: 2, Encoding: "utf-8", LineEnding: "LF",
		ContentType: "text/markdown", Title: "Document", Tags: []string{"architecture"}, TrustLevel: knowledge.TrustCurated,
	}
	reader := &testKnowledgeReader{reference: reference, manifest: knowledge.Manifest{Version: 1, TenantID: testTenantID, ProjectID: project.ID, Revision: revision, CreatedAt: controlAPITestTime, Documents: []knowledge.DocumentMetadata{{Path: reference.Path, SHA256: reference.SHA256, LineCount: 2, TrustLevel: reference.TrustLevel, ContentType: reference.ContentType}}}}
	handler.knowledge = reader

	search := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+"/knowledge:search", []byte(`{"text":"document","limit":5}`), map[string]string{"Authorization": "Bearer " + testBearer, "Content-Type": "application/json"})
	if search.Code != http.StatusOK || search.Header().Get("ETag") != `"`+revision+`"` || !strings.Contains(search.Body.String(), documentDigest) || reader.searchRequest.Access.ProjectID != project.ID || reader.searchRequest.Text != "document" {
		t.Fatalf("search status=%d request=%#v body=%s", search.Code, reader.searchRequest, search.Body.String())
	}
	readBody, err := json.Marshal(knowledgeReadRangeBody{Reference: reference, LineStart: 1, LineEnd: 2})
	if err != nil {
		t.Fatal(err)
	}
	read := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+"/knowledge:read-range", readBody, map[string]string{"Authorization": "Bearer " + testBearer, "Content-Type": "application/json"})
	if read.Code != http.StatusOK || read.Header().Get("ETag") != `"`+documentDigest+`"` || reader.readRequest.Reference.Revision != revision || reader.readRequest.Reference.SHA256 != documentDigest {
		t.Fatalf("read status=%d request=%#v body=%s", read.Code, reader.readRequest, read.Body.String())
	}
	manifest := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/knowledge/manifest?revision="+revision, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if manifest.Code != http.StatusOK || manifest.Header().Get("ETag") != `"`+revision+`"` || !strings.Contains(manifest.Body.String(), reference.Path) {
		t.Fatalf("manifest status=%d etag=%q body=%s", manifest.Code, manifest.Header().Get("ETag"), manifest.Body.String())
	}
	for _, input := range authorizer.inputs[len(authorizer.inputs)-3:] {
		if input.Action != authz.ActionKnowledgeRead {
			t.Fatalf("knowledge policy input=%#v", input)
		}
	}
}

func TestBudgetEndpointsReadAdjustAndReplayIdempotently(t *testing.T) {
	handler, ledger, authorizer := newBudgetTestHandler(t)
	project := createTestProject(t, handler)
	if err := ledger.CreateAccount(context.Background(), modelgateway.BudgetAccount{
		ID: "budget-account-1", TenantID: testTenantID, ScopeType: "PROJECT", ScopeID: project.ID, Currency: "USD",
		LimitMicros: 100, SoftLimitMicros: 80, SpentMicros: 10, ReservedMicros: 5,
		PeriodStart: controlAPITestTime, Version: 1,
	}); err != nil {
		t.Fatal(err)
	}

	budgets := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/budgets", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if budgets.Code != http.StatusOK || budgets.Header().Get("ETag") != `"v1"` {
		t.Fatalf("budgets status=%d etag=%q body=%s", budgets.Code, budgets.Header().Get("ETag"), budgets.Body.String())
	}
	var collection budgetCollection
	if err := json.Unmarshal(budgets.Body.Bytes(), &collection); err != nil {
		t.Fatal(err)
	}
	if collection.ProjectID != project.ID || collection.Version != 1 || len(collection.Items) != 1 || collection.Items[0].RemainingMinor != 85 || strings.Contains(budgets.Body.String(), "tenantId") {
		t.Fatalf("budget collection = %#v body=%s", collection, budgets.Body.String())
	}

	for _, route := range []string{"/usage", "/budgets/usage"} {
		usage := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+route, nil, map[string]string{"Authorization": "Bearer " + testBearer})
		if usage.Code != http.StatusOK || usage.Header().Get("ETag") != `"v1"` {
			t.Fatalf("usage route=%s status=%d etag=%q body=%s", route, usage.Code, usage.Header().Get("ETag"), usage.Body.String())
		}
		var snapshot budgetUsageResource
		if err := json.Unmarshal(usage.Body.Bytes(), &snapshot); err != nil || snapshot.ProjectID != project.ID || snapshot.SpentMinor != 10 || snapshot.ReservedMinor != 5 || snapshot.RemainingMinor != 85 {
			t.Fatalf("usage route=%s snapshot=%#v error=%v", route, snapshot, err)
		}
	}

	body := []byte(`{"expectedVersion":1,"hardLimitMinor":250,"softLimitMinor":200,"currency":"USD","reason":"approved project capacity increase"}`)
	headers := map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json",
		"Idempotency-Key": "budget-adjust-1", "If-Match": `"v1"`,
	}
	adjusted := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+"/budgets:adjust", body, headers)
	if adjusted.Code != http.StatusAccepted || adjusted.Header().Get("ETag") != `"v2"` {
		t.Fatalf("adjust status=%d etag=%q body=%s", adjusted.Code, adjusted.Header().Get("ETag"), adjusted.Body.String())
	}
	var adjustment budgetAdjustmentResource
	if err := json.Unmarshal(adjusted.Body.Bytes(), &adjustment); err != nil {
		t.Fatal(err)
	}
	if adjustment.Account.HardLimitMinor != 250 || adjustment.Account.SoftLimitMinor != 200 || adjustment.Account.Version != 2 || adjustment.Usage.RemainingMinor != 235 {
		t.Fatalf("adjustment = %#v", adjustment)
	}
	lastInput := authorizer.inputs[len(authorizer.inputs)-1]
	if lastInput.Action != authz.ActionProjectCommand || lastInput.Resource.Type != "budget" || lastInput.Budget.AccountID != "budget-account-1" || !strings.HasPrefix(lastInput.ParameterDigest, "sha256:") {
		t.Fatalf("budget policy input = %#v", lastInput)
	}

	replayed := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+"/budgets:adjust", body, headers)
	if replayed.Code != http.StatusAccepted || replayed.Header().Get("ETag") != `"v2"` || replayed.Body.String() != adjusted.Body.String() {
		t.Fatalf("replay status=%d etag=%q body=%s", replayed.Code, replayed.Header().Get("ETag"), replayed.Body.String())
	}
	account, found := ledger.Account(testTenantID, "budget-account-1")
	if !found || account.Version != 2 || account.LimitMicros != 250 {
		t.Fatalf("replayed account = %#v found=%v", account, found)
	}
}

func TestBudgetAdjustmentRejectsUnsafeOrConflictingCommands(t *testing.T) {
	handler, ledger, authorizer := newBudgetTestHandler(t)
	project := createTestProject(t, handler)
	if err := ledger.CreateAccount(context.Background(), modelgateway.BudgetAccount{
		ID: project.ID, TenantID: testTenantID, ScopeType: "PROJECT", ScopeID: project.ID, Currency: "USD",
		LimitMicros: 100, SoftLimitMicros: 80, SpentMicros: 30, ReservedMicros: 20,
		PeriodStart: controlAPITestTime, Version: 1,
	}); err != nil {
		t.Fatal(err)
	}
	route := "/v1/projects/" + project.ID + "/budgets:adjust"
	body := []byte(`{"expectedVersion":1,"hardLimitMinor":120,"softLimitMinor":90,"currency":"USD","reason":"capacity review"}`)
	baseHeaders := map[string]string{"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "budget-safe"}

	missingMatch := performRequest(handler, http.MethodPost, route, body, baseHeaders)
	if missingMatch.Code != http.StatusConflict {
		t.Fatalf("missing If-Match status=%d body=%s", missingMatch.Code, missingMatch.Body.String())
	}
	invalid := performRequest(handler, http.MethodPost, route, []byte(`{"expectedVersion":1,"hardLimitMinor":49,"softLimitMinor":40,"currency":"USD","reason":"too low"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "budget-low", "If-Match": `"v1"`,
	})
	if invalid.Code != http.StatusConflict {
		t.Fatalf("unsafe limit status=%d body=%s", invalid.Code, invalid.Body.String())
	}

	authorizer.deny = true
	denied := performRequest(handler, http.MethodPost, route, body, map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "budget-denied", "If-Match": `"v1"`,
	})
	if denied.Code != http.StatusForbidden {
		t.Fatalf("denied adjustment status=%d body=%s", denied.Code, denied.Body.String())
	}
	account, _ := ledger.Account(testTenantID, project.ID)
	if account.Version != 1 || account.LimitMicros != 100 {
		t.Fatalf("denied adjustment mutated account: %#v", account)
	}
	authorizer.deny = false

	accepted := performRequest(handler, http.MethodPost, route, body, map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "budget-safe", "If-Match": `"v1"`,
	})
	if accepted.Code != http.StatusAccepted {
		t.Fatalf("accepted adjustment status=%d body=%s", accepted.Code, accepted.Body.String())
	}
	collision := performRequest(handler, http.MethodPost, route, []byte(`{"expectedVersion":2,"hardLimitMinor":130,"softLimitMinor":100,"currency":"USD","reason":"different body"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "budget-safe", "If-Match": `"v2"`,
	})
	if collision.Code != http.StatusConflict || !strings.Contains(collision.Body.String(), string(aorerrors.CodeIdempotencyConflict)) {
		t.Fatalf("idempotency collision status=%d body=%s", collision.Code, collision.Body.String())
	}
}

func newBudgetTestHandler(t *testing.T) (*Handler, *modelgateway.BudgetLedger, *recordingAuthorizer) {
	t.Helper()
	store := eventing.NewMemoryStore()
	ledger := modelgateway.NewBudgetLedger(func() time.Time { return controlAPITestTime })
	authorizer := &recordingAuthorizer{}
	handler, err := New(Config{
		Store: store,
		Authenticator: fixedAuthenticator{principal: authn.Principal{
			ID: "user-1", Type: authn.PrincipalUser, Role: authn.RoleUser, TenantID: testTenantID,
		}},
		Authorizer: authorizer,
		Budgets:    ledger,
		Clock:      func() time.Time { return controlAPITestTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, ledger, authorizer
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

func seedGoalSpec(t *testing.T, handler *Handler, projectID string, expectedVersion int64, commandType state.ProjectCommandType, spec contracts.GoalSpec) {
	t.Helper()
	principal := authn.Principal{ID: "user-1", Type: authn.PrincipalUser, Role: authn.RoleUser, TenantID: testTenantID}
	goal := &state.GoalRecord{ID: "22222222-2222-4222-8222-222222222222", Version: spec.Content.Version, SHA256: spec.ContentSHA256, UnresolvedItems: append([]string(nil), spec.Content.UnresolvedItems...)}
	_, err := handler.orchestrator.HandleProject(contextWithPrincipal(context.Background(), principal), orchestrator.ProjectRequest{
		TenantID: testTenantID, ProjectID: projectID, PrincipalID: principal.ID,
		IdempotencyKey: fmt.Sprintf("seed-goal-%d", spec.Content.Version), ExpectedVersion: expectedVersion,
		Command: state.ProjectCommand{Type: commandType, Goal: goal, GoalSpec: &spec},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func controlGoalSpec(t *testing.T, projectID string, version int, unresolved []string) contracts.GoalSpec {
	t.Helper()
	content := contracts.GoalContent{
		GoalSpecVersion: 1, ProjectID: projectID, Version: version, Title: "Goal", Summary: "Summary", ProblemStatement: "Problem",
		BusinessOutcomes: []contracts.Outcome{{ID: "outcome-1", Statement: "Outcome"}}, Scope: contracts.Scope{Included: []string{"api"}, Excluded: []string{}},
		UserPersonas: []string{}, FunctionalRequirements: []string{"serve requests"},
		NonFunctionalRequirements: contracts.NonFunctionalRequirements{Security: []string{}, Privacy: []string{}, Performance: []string{}, Reliability: []string{}, Operability: []string{}},
		Constraints:               []string{}, Assumptions: []contracts.Assumption{}, Decisions: []string{}, UnresolvedItems: append([]string(nil), unresolved...),
		AcceptanceCriteria: []contracts.AcceptanceCriterion{{ID: "criterion-1", Statement: "passes", EvidenceType: "AUTOMATED"}},
		RiskTolerance:      contracts.RiskLow, HumanApprovalPoints: []string{}, DataClassification: contracts.DataInternal,
		DeploymentTargets: []string{"test"}, SourceReferences: []string{}, CreatedAt: controlAPITestTime.Format(time.RFC3339),
		CreatedBy: contracts.AgentIdentity{AgentInstanceID: "agent-goal", Role: "GOAL_PROPOSER"},
	}
	encoded, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonicaljson.Digest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return contracts.GoalSpec{Content: content, Status: contracts.GoalDraft, ContentSHA256: digest}
}

func seedTaskProjection(t *testing.T, store *eventing.MemoryStore, projectID, taskID string) {
	t.Helper()
	task := state.ModuleTask{
		TenantID: testTenantID, ProjectID: projectID, ID: taskID, State: contracts.TaskDefined, Version: 1,
		ModuleSpecRef:   contracts.SpecRef{Version: 1, SHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		AttemptSeriesID: "series_1", AttemptSeriesIDs: []string{"series_1"},
	}
	content, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonicaljson.Digest(content)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Execute(context.Background(), eventing.TransactionRequest{
		TenantID: testTenantID, PrincipalID: "test-seed", IdempotencyKey: taskID, RequestSHA256: digest,
		Result: content, ResultSHA256: digest,
		Updates: []eventing.ProjectionUpdate{{TenantID: testTenantID, ProjectID: projectID, AggregateType: "task", AggregateID: taskID, ExpectedVersion: 0, NextVersion: 1, State: content}},
		Events:  []eventing.DomainEvent{{EventID: "event-" + taskID, TenantID: testTenantID, ProjectID: projectID, AggregateType: "task", AggregateID: taskID, AggregateVersion: 1, Type: "io.aor.module.defined.v1", Payload: content, PayloadSHA256: digest, OccurredAt: controlAPITestTime}},
	})
	if err != nil {
		t.Fatal(err)
	}
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
