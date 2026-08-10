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
	"slices"
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
	"github.com/akimisaka/aor/internal/toolchain"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/cloudevents"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type testToolchainSource struct{}

func (testToolchainSource) Snapshot(context.Context) (toolchain.Inventory, error) {
	return toolchain.Inventory{Tools: []toolchain.InstalledTool{{
		SchemaVersion: 1, ID: "go-1.26.5-linux-amd64", Kind: contracts.ToolchainCompiler, Name: "Go", Version: "1.26.5",
		Platform: contracts.PlatformLinux, Architecture: "amd64", Languages: []string{"Go"}, BinDirs: []string{"bin"}, Executables: []toolchain.Executable{{Name: "go", Path: "bin/go"}},
	}}}, nil
}

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
	record       artifact.Record
	content      string
	publications []artifact.Publication
	err          error
}

type testProjectEraser struct {
	projectID  string
	deletionID string
	report     ErasureReport
	err        error
}

func (eraser *testProjectEraser) EraseProject(_ context.Context, _, projectID, deletionID string) (ErasureReport, error) {
	eraser.projectID, eraser.deletionID = projectID, deletionID
	if eraser.err != nil {
		return ErasureReport{}, eraser.err
	}
	return eraser.report, nil
}

func (catalog *testArtifactCatalog) Publish(_ context.Context, publication artifact.Publication) (artifact.Record, error) {
	if catalog.err != nil {
		return artifact.Record{}, catalog.err
	}
	publication.Data = append([]byte(nil), publication.Data...)
	catalog.publications = append(catalog.publications, publication)
	digest, err := canonicaljson.Digest(publication.Data)
	if err != nil {
		return artifact.Record{}, err
	}
	return artifact.Record{
		ID: "33333333-3333-4333-8333-333333333333", ProjectID: publication.ProjectID,
		URI: "artifact://sha256/" + strings.TrimPrefix(digest, "sha256:"), SHA256: digest,
		SizeBytes: int64(len(publication.Data)), ContentType: publication.ContentType,
		Classification: "INTERNAL", CreatedByPrincipal: publication.CreatedByPrincipal,
		Metadata: publication.Metadata, CreatedAt: controlAPITestTime,
	}, nil
}

func (catalog *testArtifactCatalog) List(_ context.Context, _, _, cursor string, _ int) (artifact.Page, error) {
	if catalog.err != nil {
		return artifact.Page{}, catalog.err
	}
	if cursor != "" {
		return artifact.Page{}, nil
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
	initialized   []knowledge.Manifest
	err           error
}

type testTaskHistoryReader struct {
	submissions TaskSubmissionPage
	audits      TaskAuditPage
	tenantID    string
	projectID   string
	taskID      string
	cursor      string
	err         error
}

func (reader *testTaskHistoryReader) ListSubmissions(_ context.Context, tenantID, projectID, taskID, cursor string) (TaskSubmissionPage, error) {
	reader.tenantID, reader.projectID, reader.taskID, reader.cursor = tenantID, projectID, taskID, cursor
	return reader.submissions, reader.err
}

func (reader *testTaskHistoryReader) ListAudits(_ context.Context, tenantID, projectID, taskID, cursor string) (TaskAuditPage, error) {
	reader.tenantID, reader.projectID, reader.taskID, reader.cursor = tenantID, projectID, taskID, cursor
	return reader.audits, reader.err
}

func (reader *testKnowledgeReader) Initialize(_ context.Context, tenantID, projectID string, createdAt time.Time) (knowledge.Manifest, error) {
	if reader.err != nil {
		return knowledge.Manifest{}, reader.err
	}
	manifest := knowledge.Manifest{Version: 1, TenantID: tenantID, ProjectID: projectID, Revision: "sha256:" + strings.Repeat("1", 64), CreatedAt: createdAt, Parents: []knowledge.ParentSnapshot{}, Overrides: []string{}, Documents: []knowledge.DocumentMetadata{}}
	reader.initialized = append(reader.initialized, manifest)
	return manifest, nil
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
	body := []byte(`{"name":"AOR integration","goalAgentCount":2,"dataClassification":"INTERNAL","deploymentTargets":["test"],"budget":{"hardLimitMinor":100000,"softLimitMinor":80000,"currency":"USD"}}`)

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

	conflictBody := []byte(`{"name":"different","goalAgentCount":1,"dataClassification":"INTERNAL","deploymentTargets":["test"],"budget":{"hardLimitMinor":100000,"softLimitMinor":80000,"currency":"USD"}}`)
	conflict := performRequest(handler, http.MethodPost, "/v1/projects", conflictBody, map[string]string{
		"Authorization":   "Bearer " + testBearer,
		"Content-Type":    "application/json",
		"Idempotency-Key": "project-create-1",
	})
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflict status = %d body=%s", conflict.Code, conflict.Body.String())
	}
}

func TestCreateProjectInitializesSelectedBudgetKnowledgePromptsAndGoalAgents(t *testing.T) {
	store := eventing.NewMemoryStore()
	authorizer := &recordingAuthorizer{}
	catalog := &testArtifactCatalog{}
	knowledgeReader := &testKnowledgeReader{}
	handler, err := New(Config{
		Store: store,
		Authenticator: fixedAuthenticator{principal: authn.Principal{
			ID: "user-1", Type: authn.PrincipalUser, Role: authn.RoleUser, TenantID: testTenantID,
		}},
		Authorizer: authorizer, Artifacts: catalog, Knowledge: knowledgeReader,
		DefaultModelRoutes: testControlModelRoutes(), ModelProviders: testControlModelProviders(),
		Clock: func() time.Time { return controlAPITestTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"name":"initialized","goalAgentCount":2,"dataClassification":"CONFIDENTIAL","deploymentTargets":["test-linux","pre-production"],"budget":{"hardLimitMinor":100000,"softLimitMinor":80000,"currency":"USD"}}`)
	response := performRequest(handler, http.MethodPost, "/v1/projects", body, map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "project-initialize-1",
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var project state.Project
	if err := json.Unmarshal(response.Body.Bytes(), &project); err != nil {
		t.Fatal(err)
	}
	if project.State != contracts.ProjectGoalNegotiating || project.Version != 1 || project.PromptBundleVersion != "1.0.0" || !slices.Equal(project.DeploymentTargets, []string{"test-linux", "pre-production"}) || project.BudgetCurrency != "USD" || project.BudgetHardLimitMinor != 100000 || project.BudgetSoftLimitMinor != 80000 {
		t.Fatalf("initialized project = %#v", project)
	}
	accounts, err := handler.budgets.ListAccounts(context.Background(), testTenantID, project.ID)
	if err != nil || len(accounts) != 1 || accounts[0].LimitMicros != 1_000_000_000 || accounts[0].SoftLimitMicros != 800_000_000 || accounts[0].Currency != "USD" {
		t.Fatalf("budget accounts=%#v err=%v", accounts, err)
	}
	if len(knowledgeReader.initialized) != 1 || knowledgeReader.initialized[0].ProjectID != project.ID || knowledgeReader.initialized[0].CreatedAt != controlAPITestTime {
		t.Fatalf("knowledge initialization = %#v", knowledgeReader.initialized)
	}
	if len(catalog.publications) != 2 {
		t.Fatalf("prompt publications = %#v", catalog.publications)
	}
	roles := make(map[string]bool, 2)
	for _, publication := range catalog.publications {
		if publication.ProjectID != project.ID || publication.CreatedByPrincipal != "user-1" || publication.ContentType != "application/json" || publication.Metadata["artifactKind"] != "PROMPT_BUNDLE" || publication.Metadata["promptBundleVersion"] != "1.0.0" {
			t.Fatalf("prompt publication = %#v", publication)
		}
		role, _ := publication.Metadata["role"].(string)
		roles[role] = true
	}
	if !roles["GOAL_PROPOSER"] || !roles["GOAL_CHALLENGER"] {
		t.Fatalf("prompt roles = %#v", roles)
	}
	events, err := store.ListEvents(context.Background(), testTenantID)
	if err != nil || len(events) != 1 || events[0].Type != "io.aor.goal.negotiation-started.v1" {
		t.Fatalf("initialization events=%#v err=%v", events, err)
	}
}

func TestCreateProjectRejectsIncompleteInitializationSelection(t *testing.T) {
	handler, store, _ := newTestHandler(t)
	response := performRequest(handler, http.MethodPost, "/v1/projects", []byte(`{"name":"partial","goalAgentCount":1,"dataClassification":"INTERNAL","deploymentTargets":["test"]}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "project-partial",
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("partial selection status=%d body=%s", response.Code, response.Body.String())
	}
	if stats := store.Stats(); stats.Projections != 0 || stats.Events != 0 {
		t.Fatalf("partial selection committed state: %#v", stats)
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
	if result.State != contracts.ProjectGoalSuspended || result.Version != 2 {
		t.Fatalf("paused project = %#v", result)
	}
	if authorizer.inputs[len(authorizer.inputs)-1].Action != "project.command" {
		t.Fatalf("last policy action = %q", authorizer.inputs[len(authorizer.inputs)-1].Action)
	}
}

func TestProjectDeletionAndLegalHoldAPIsAreVersionedAndAudited(t *testing.T) {
	handler, _, _ := newTestHandler(t)
	project := createTestProject(t, handler)
	holdResponse := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+"/legal-holds", []byte(`{"expectedVersion":1,"reason":"active litigation"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "hold-project", "If-Match": `"v1"`,
	})
	if holdResponse.Code != http.StatusAccepted {
		t.Fatalf("hold status=%d body=%s", holdResponse.Code, holdResponse.Body.String())
	}
	var held state.Project
	if err := json.Unmarshal(holdResponse.Body.Bytes(), &held); err != nil || len(held.LegalHolds) != 1 || held.LegalHolds[0].ID == "" {
		t.Fatalf("held project=%#v err=%v", held, err)
	}
	holdID := held.LegalHolds[0].ID
	listed := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/legal-holds", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if listed.Code != http.StatusOK || listed.Header().Get("ETag") != `"v2"` || !strings.Contains(listed.Body.String(), holdID) {
		t.Fatalf("hold list status=%d etag=%q body=%s", listed.Code, listed.Header().Get("ETag"), listed.Body.String())
	}
	deletionResponse := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+":request-deletion", []byte(`{"expectedVersion":2}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "delete-project", "If-Match": `"v2"`,
	})
	if deletionResponse.Code != http.StatusAccepted {
		t.Fatalf("deletion status=%d body=%s", deletionResponse.Code, deletionResponse.Body.String())
	}
	var deleting state.Project
	if err := json.Unmarshal(deletionResponse.Body.Bytes(), &deleting); err != nil || deleting.State != contracts.ProjectPaused || deleting.Deletion == nil || deleting.Deletion.Status != state.ProjectDeletionBlocked || deleting.Deletion.RequestedBy != "user-1" || !deleting.Deletion.RequestedAt.Equal(controlAPITestTime) {
		t.Fatalf("deleting project=%#v err=%v", deleting, err)
	}
	releaseResponse := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+"/legal-holds/"+holdID+":release", []byte(`{"expectedVersion":3,"reason":"matter closed"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "release-hold", "If-Match": `"v3"`,
	})
	if releaseResponse.Code != http.StatusAccepted {
		t.Fatalf("release status=%d body=%s", releaseResponse.Code, releaseResponse.Body.String())
	}
	var released state.Project
	if err := json.Unmarshal(releaseResponse.Body.Bytes(), &released); err != nil || released.Deletion.Status != state.ProjectDeletionReady || released.LegalHolds[0].ReleasedAt == nil || released.LegalHolds[0].ReleasedBy != "user-1" {
		t.Fatalf("released project=%#v err=%v", released, err)
	}
	missingVersion := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+"/legal-holds", []byte(`{"expectedVersion":4,"reason":"new matter"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "hold-without-version",
	})
	if missingVersion.Code != http.StatusConflict {
		t.Fatalf("missing version status=%d body=%s", missingVersion.Code, missingVersion.Body.String())
	}
}

func TestProjectExportPublishesStableContentAddressedManifest(t *testing.T) {
	store := eventing.NewMemoryStore()
	authorizer := &recordingAuthorizer{}
	catalog := &testArtifactCatalog{}
	handler, err := New(Config{
		Store:         store,
		Authenticator: fixedAuthenticator{principal: authn.Principal{ID: "user-1", Type: authn.PrincipalUser, Role: authn.RoleUser, TenantID: testTenantID}},
		Authorizer:    authorizer, Artifacts: catalog, Knowledge: &testKnowledgeReader{}, Clock: func() time.Time { return controlAPITestTime },
		DefaultModelRoutes: testControlModelRoutes(), ModelProviders: testControlModelProviders(),
	})
	if err != nil {
		t.Fatal(err)
	}
	project := createTestProject(t, handler)
	catalog.publications = nil
	catalog.record = artifact.Record{
		ID: "22222222-2222-4222-8222-222222222222", ProjectID: project.ID,
		URI: "artifact://sha256/" + strings.Repeat("a", 64), SHA256: "sha256:" + strings.Repeat("a", 64),
		SizeBytes: 7, ContentType: "application/json", Classification: "INTERNAL", CreatedByPrincipal: "agent-1",
		Metadata: map[string]any{"kind": "evidence"}, CreatedAt: controlAPITestTime,
	}
	first := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/export", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if first.Code != http.StatusOK || first.Header().Get("ETag") == "" || len(catalog.publications) != 1 {
		t.Fatalf("first export status=%d etag=%q body=%s publications=%d", first.Code, first.Header().Get("ETag"), first.Body.String(), len(catalog.publications))
	}
	var manifest projectExportManifest
	if err := json.Unmarshal(catalog.publications[0].Data, &manifest); err != nil || manifest.Project.ID != project.ID || manifest.Project.Version != project.Version || len(manifest.Events) != 1 || len(manifest.Artifacts) != 1 || manifest.Artifacts[0].ID != catalog.record.ID {
		t.Fatalf("manifest=%#v err=%v", manifest, err)
	}
	firstContent := append([]byte(nil), catalog.publications[0].Data...)
	second := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/export", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if second.Code != http.StatusOK || second.Header().Get("ETag") != first.Header().Get("ETag") || len(catalog.publications) != 2 || !bytes.Equal(firstContent, catalog.publications[1].Data) {
		t.Fatalf("second export status=%d etag=%q body=%s", second.Code, second.Header().Get("ETag"), second.Body.String())
	}
}

func TestProjectDeletionExecutionRequiresEraserAndPublishesContentFreeProof(t *testing.T) {
	handler, _, _ := newTestHandler(t)
	eraser := &testProjectEraser{report: ErasureReport{Scopes: []string{"artifacts", "indexes", "cache", "keys"}, Records: 4, Objects: 3, CacheEntries: 2}}
	handler.eraser = eraser
	project := createTestProject(t, handler)
	requested := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+":request-deletion", []byte(`{"expectedVersion":1}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "request-delete", "If-Match": `"v1"`,
	})
	if requested.Code != http.StatusAccepted {
		t.Fatalf("request deletion status=%d body=%s", requested.Code, requested.Body.String())
	}
	executed := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+":execute-deletion", []byte(`{"expectedVersion":2}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "execute-delete", "If-Match": `"v2"`,
	})
	if executed.Code != http.StatusAccepted {
		t.Fatalf("execute deletion status=%d body=%s", executed.Code, executed.Body.String())
	}
	var completed state.Project
	if err := json.Unmarshal(executed.Body.Bytes(), &completed); err != nil || completed.State != contracts.ProjectArchived || completed.Deletion == nil || completed.Deletion.Status != state.ProjectDeletionCompleted || completed.Deletion.ProofSHA256 == "" || eraser.projectID != project.ID || eraser.deletionID == "" {
		t.Fatalf("completed deletion=%#v eraser=%#v err=%v", completed, eraser, err)
	}
	if len(handler.publisher.(*testArtifactCatalog).publications) == 0 {
		t.Fatal("deletion proof was not published")
	}
	publication := handler.publisher.(*testArtifactCatalog).publications[len(handler.publisher.(*testArtifactCatalog).publications)-1]
	if publication.ContentType != "application/vnd.aor.deletion-proof.v1+json" || strings.Contains(string(publication.Data), "active") {
		t.Fatalf("proof publication=%#v", publication)
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

func TestApproveReleaseBindsCurrentProjectVersionAndPlan(t *testing.T) {
	handler, store, _ := newTestHandler(t)
	projectID := "22222222-2222-4222-8222-222222222222"
	planDigest := "sha256:" + strings.Repeat("a", 64)
	project := state.Project{
		TenantID: testTenantID, ID: projectID, Name: "release", CreatedBy: "user-1", DataClassification: "INTERNAL",
		RiskTolerance: "MEDIUM", State: contracts.ProjectGlobalAudit, Version: 1, GoalAgentCount: 1,
		Plan: &contracts.SpecRef{Version: 1, SHA256: planDigest},
	}
	content, err := json.Marshal(project)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonicaljson.Digest(content)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Execute(context.Background(), eventing.TransactionRequest{
		TenantID: testTenantID, PrincipalID: "test-seed", IdempotencyKey: "release-ready", RequestSHA256: digest,
		Result: content, ResultSHA256: digest,
		Updates: []eventing.ProjectionUpdate{{TenantID: testTenantID, ProjectID: projectID, AggregateType: "project", AggregateID: projectID, ExpectedVersion: 0, NextVersion: 1, State: content}},
		Events: []eventing.DomainEvent{{EventID: "event-release-ready", TenantID: testTenantID, ProjectID: projectID, AggregateType: "project", AggregateID: projectID,
			AggregateVersion: 1, Type: "io.aor.project.global-audit-started.v1", Payload: content, PayloadSHA256: digest, OccurredAt: controlAPITestTime}},
	})
	if err != nil {
		t.Fatal(err)
	}

	wrong := performRequest(handler, http.MethodPost, "/v1/projects/"+projectID+":approve-release", []byte(`{"expectedVersion":1,"sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "approve-wrong", "If-Match": `"v1"`,
	})
	if wrong.Code != http.StatusConflict {
		t.Fatalf("wrong digest status=%d body=%s", wrong.Code, wrong.Body.String())
	}
	approved := performRequest(handler, http.MethodPost, "/v1/projects/"+projectID+":approve-release", []byte(`{"expectedVersion":1,"sha256":"`+planDigest+`"}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "approve-release", "If-Match": `"v1"`,
	})
	if approved.Code != http.StatusAccepted || approved.Header().Get("ETag") != `"v2"` {
		t.Fatalf("approve status=%d etag=%q body=%s", approved.Code, approved.Header().Get("ETag"), approved.Body.String())
	}
	var result state.Project
	if err := json.Unmarshal(approved.Body.Bytes(), &result); err != nil || result.ReleaseApprovalRecordID == "" || result.State != contracts.ProjectGlobalAudit {
		t.Fatalf("approved project=%#v err=%v", result, err)
	}
	if stats := store.Stats(); stats.Approvals != 1 {
		t.Fatalf("approval stats=%#v", stats)
	}
}

func TestAuthenticationAndPolicyFailuresAreFailClosed(t *testing.T) {
	handler, _, authorizer := newTestHandler(t)
	unauthenticated := performRequest(handler, http.MethodPost, "/v1/projects", []byte(`{}`), map[string]string{"Content-Type": "application/json", "Idempotency-Key": "key"})
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticated.Code)
	}

	authorizer.deny = true
	denied := performRequest(handler, http.MethodPost, "/v1/projects", []byte(`{"name":"denied","goalAgentCount":1,"dataClassification":"INTERNAL","deploymentTargets":["test"],"budget":{"hardLimitMinor":100000,"softLimitMinor":80000,"currency":"USD"}}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "denied",
	})
	if denied.Code != http.StatusForbidden {
		t.Fatalf("denied status = %d body=%s", denied.Code, denied.Body.String())
	}

	authorizer.deny = false
	authorizer.err = errors.New("opa unavailable with secret detail")
	unavailable := performRequest(handler, http.MethodPost, "/v1/projects", []byte(`{"name":"unavailable","goalAgentCount":1,"dataClassification":"INTERNAL","deploymentTargets":["test"],"budget":{"hardLimitMinor":100000,"softLimitMinor":80000,"currency":"USD"}}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "unavailable",
	})
	if unavailable.Code != http.StatusServiceUnavailable || bytes.Contains(unavailable.Body.Bytes(), []byte("secret detail")) {
		t.Fatalf("unavailable status=%d body=%s", unavailable.Code, unavailable.Body.String())
	}
}

func TestWriteRequestsRejectDuplicateJSONMembers(t *testing.T) {
	handler, _, _ := newTestHandler(t)
	duplicate := performRequest(handler, http.MethodPost, "/v1/projects", []byte(`{"name":"first","name":"second","goalAgentCount":1,"dataClassification":"INTERNAL","deploymentTargets":["test"],"budget":{"hardLimitMinor":100000,"softLimitMinor":80000,"currency":"USD"}}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "duplicate-json",
	})
	if duplicate.Code != http.StatusBadRequest {
		t.Fatalf("duplicate member status=%d body=%s", duplicate.Code, duplicate.Body.String())
	}
	nested := []byte(`{"name":"project","goalAgentCount":1,"dataClassification":"INTERNAL","deploymentTargets":["test"],"budget":{"hardLimitMinor":100000,"softLimitMinor":80000,"currency":"USD"},"unknown":{"key":1,"key":2}}`)
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

func TestProjectEventsEmitCloudEventEnvelopeAndLastEventID(t *testing.T) {
	handler, store, _ := newTestHandler(t)
	project := createTestProject(t, handler)
	paused := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+":pause", []byte(`{"expectedVersion":1}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "pause-cloud-event", "If-Match": `"v1"`,
	})
	if paused.Code != http.StatusAccepted {
		t.Fatalf("pause status=%d body=%s", paused.Code, paused.Body.String())
	}
	events, err := store.ListEvents(context.Background(), testTenantID)
	if err != nil || len(events) != 2 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	stream := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/events", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if stream.Code != http.StatusOK || stream.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream status=%d content-type=%q body=%s", stream.Code, stream.Header().Get("Content-Type"), stream.Body.String())
	}
	var envelope cloudevents.Event
	lines := strings.Split(stream.Body.String(), "\n")
	data := ""
	for _, line := range lines {
		if strings.HasPrefix(line, "data: ") {
			data = strings.TrimPrefix(line, "data: ")
			break
		}
	}
	if data == "" || json.Unmarshal([]byte(data), &envelope) != nil || envelope.SpecVersion != "1.0" || envelope.Source == "" || envelope.ProjectID != project.ID || envelope.Traceparent == "" {
		t.Fatalf("invalid CloudEvent envelope: %s", data)
	}
	resumed := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/events", nil, map[string]string{
		"Authorization": "Bearer " + testBearer, "Last-Event-ID": events[0].EventID,
	})
	if resumed.Code != http.StatusOK || !strings.Contains(resumed.Body.String(), events[1].EventID) || strings.Contains(resumed.Body.String(), events[0].EventID) {
		t.Fatalf("Last-Event-ID resume status=%d body=%s", resumed.Code, resumed.Body.String())
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

func TestPlanEndpointsReadImmutableSpecArtifacts(t *testing.T) {
	handler, store, authorizer := newTestHandler(t)
	project := createTestProject(t, handler)
	plan := seedPlanProjection(t, store, project.ID, 1)

	listed := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/plans", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if listed.Code != http.StatusOK || listed.Header().Get("ETag") != `"v1"` || !strings.Contains(listed.Body.String(), plan.SHA256) || !strings.Contains(listed.Body.String(), `"planSpecVersion":1`) {
		t.Fatalf("plan list status=%d etag=%q body=%s", listed.Code, listed.Header().Get("ETag"), listed.Body.String())
	}
	got := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/plans/1", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if got.Code != http.StatusOK || got.Header().Get("ETag") != `"`+plan.SHA256+`"` || !strings.Contains(got.Body.String(), `"moduleId":"module-api"`) {
		t.Fatalf("get plan status=%d etag=%q body=%s", got.Code, got.Header().Get("ETag"), got.Body.String())
	}
	missing := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/plans/2", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing plan status=%d body=%s", missing.Code, missing.Body.String())
	}
	invalidCursor := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/plans?cursor=unknown", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if invalidCursor.Code != http.StatusBadRequest {
		t.Fatalf("invalid plan cursor status=%d body=%s", invalidCursor.Code, invalidCursor.Body.String())
	}
	if last := authorizer.inputs[len(authorizer.inputs)-1]; last.Action != authz.ActionProjectRead || last.Resource.Type != "plan-list" {
		t.Fatalf("plan policy input=%#v", last)
	}
}

func TestTaskHistoryEndpointsAreScopedAuthorizedAndVersioned(t *testing.T) {
	handler, store, authorizer := newTestHandler(t)
	project := createTestProject(t, handler)
	seedTaskProjection(t, store, project.ID, "task_history")
	reader := &testTaskHistoryReader{
		submissions: TaskSubmissionPage{Items: []json.RawMessage{json.RawMessage(`{"submissionVersion":1,"sha256":"sha256:` + strings.Repeat("2", 64) + `"}`)}, NextCursor: "next-submission"},
		audits: TaskAuditPage{Items: []TaskAuditRun{{
			ID: "22222222-2222-4222-8222-222222222222", ProjectID: project.ID, TaskID: "task_history",
			SubmissionID: "33333333-3333-4333-8333-333333333333", Phase: "DETERMINISTIC", State: "COMPLETED",
			PipelineVersion: "pipeline-1", ExecutionPlatform: "LINUX", IsolationLevel: "CONTAINER", StartedAt: controlAPITestTime,
			Verdict: "PASS", Findings: []TaskAuditFinding{},
		}}},
	}
	handler.taskHistory = reader

	submissions := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/tasks/task_history/submissions?cursor=resume", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if submissions.Code != http.StatusOK || submissions.Header().Get("ETag") == "" || !strings.Contains(submissions.Body.String(), "next-submission") || reader.cursor != "resume" || reader.tenantID != testTenantID || reader.projectID != project.ID || reader.taskID != "task_history" {
		t.Fatalf("submissions status=%d etag=%q reader=%#v body=%s", submissions.Code, submissions.Header().Get("ETag"), reader, submissions.Body.String())
	}
	audits := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/tasks/task_history/audits", nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if audits.Code != http.StatusOK || audits.Header().Get("ETag") == "" || !strings.Contains(audits.Body.String(), `"pipelineVersion":"pipeline-1"`) {
		t.Fatalf("audits status=%d etag=%q body=%s", audits.Code, audits.Header().Get("ETag"), audits.Body.String())
	}
	if last := authorizer.inputs[len(authorizer.inputs)-1]; last.Action != authz.ActionTaskRead || last.Resource.Type != "task-audits" || last.Resource.ID != "task_history" {
		t.Fatalf("task history policy input=%#v", last)
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
		LimitMicros: 1_000_000, SoftLimitMicros: 800_000, SpentMicros: 100_000, ReservedMicros: 50_000,
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
	if !found || account.Version != 2 || account.LimitMicros != 2_500_000 {
		t.Fatalf("replayed account = %#v found=%v", account, found)
	}
}

func TestBudgetAdjustmentRejectsUnsafeOrConflictingCommands(t *testing.T) {
	handler, ledger, authorizer := newBudgetTestHandler(t)
	project := createTestProject(t, handler)
	if err := ledger.CreateAccount(context.Background(), modelgateway.BudgetAccount{
		ID: project.ID, TenantID: testTenantID, ScopeType: "PROJECT", ScopeID: project.ID, Currency: "USD",
		LimitMicros: 1_000_000, SoftLimitMicros: 800_000, SpentMicros: 300_000, ReservedMicros: 200_000,
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
	if account.Version != 1 || account.LimitMicros != 1_000_000 {
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
		Authorizer:         authorizer,
		Budgets:            ledger,
		Artifacts:          &testArtifactCatalog{},
		Knowledge:          &testKnowledgeReader{},
		Toolchains:         testToolchainSource{},
		DefaultModelRoutes: testControlModelRoutes(),
		ModelProviders:     testControlModelProviders(),
		Clock:              func() time.Time { return controlAPITestTime },
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
		Authorizer:         authorizer,
		Artifacts:          &testArtifactCatalog{},
		Knowledge:          &testKnowledgeReader{},
		Toolchains:         testToolchainSource{},
		DefaultModelRoutes: testControlModelRoutes(),
		ModelProviders:     testControlModelProviders(),
		Clock:              func() time.Time { return controlAPITestTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, store, authorizer
}

func createTestProject(t *testing.T, handler http.Handler) state.Project {
	t.Helper()
	response := performRequest(handler, http.MethodPost, "/v1/projects", []byte(`{"name":"project","goalAgentCount":1,"dataClassification":"INTERNAL","deploymentTargets":["test"],"budget":{"hardLimitMinor":100000,"softLimitMinor":80000,"currency":"USD"}}`), map[string]string{
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

func testControlModelRoutes() map[string]state.ProjectModelRoute {
	route := state.ProjectModelRoute{Provider: "provider", Model: "model", ReasoningEffort: "medium", MaxOutputTokens: 4096, ProviderPolicy: "default", CachePolicy: "NO_STORE", MaxAttempts: 3}
	return map[string]state.ProjectModelRoute{
		"GOAL_PROPOSER": route, "GOAL_CHALLENGER": route, "PLAN_SUPERVISOR": route, "MODULE_PLANNER": route,
		"EXECUTOR": route, "MODULE_AUDITOR": route, "GLOBAL_AUDITOR": route, "KNOWLEDGE_CURATOR": route,
	}
}

func testControlModelProviders() []ModelProvider {
	return []ModelProvider{{
		ID: "provider", Provider: "provider-family", Models: []string{"model"},
		MaxInputTokens: 8192, MaxOutputTokens: 4096, SupportsSeed: true, SupportsJSONSchema: true, SupportsToolCalls: true,
		AllowedDataClassifications: []string{"PUBLIC", "INTERNAL"}, DataResidency: []string{"test"},
		RetentionPolicy: "test", Modalities: []string{"text"},
	}}
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
		GoalSpecVersion: 2, ProjectID: projectID, Version: version, Title: "Goal", Summary: "Summary", ProblemStatement: "Problem",
		BusinessOutcomes: []contracts.Outcome{{ID: "outcome-1", Statement: "Outcome"}}, Scope: contracts.Scope{Included: []string{"api"}, Excluded: []string{}},
		UserPersonas: []string{}, FunctionalRequirements: []string{"serve requests"},
		NonFunctionalRequirements: contracts.NonFunctionalRequirements{Security: []string{}, Privacy: []string{}, Performance: []string{}, Reliability: []string{}, Operability: []string{}},
		Constraints:               []string{}, Assumptions: []contracts.Assumption{}, Decisions: []string{}, UnresolvedItems: append([]string(nil), unresolved...),
		AcceptanceCriteria: []contracts.AcceptanceCriterion{{ID: "criterion-1", Statement: "passes", EvidenceType: "AUTOMATED"}},
		RiskTolerance:      contracts.RiskLow, HumanApprovalPoints: []string{}, DataClassification: contracts.DataInternal,
		DeploymentTargets: []string{"test"}, SourceReferences: []string{}, CreatedAt: controlAPITestTime.Format(time.RFC3339),
		CreatedBy: contracts.AgentIdentity{AgentInstanceID: "agent-goal", Role: "GOAL_PROPOSER"},
		Toolchain: &contracts.GoalToolchain{
			Languages: []contracts.LanguageRequirement{{Name: "Go", Version: "1.26"}},
			Tools:     []contracts.VersionedTool{{InventoryID: "go-1.26.5-linux-amd64", Kind: contracts.ToolchainCompiler, Name: "Go", Version: "1.26.5", Platform: contracts.PlatformLinux, Architecture: "amd64", Source: contracts.ToolchainInstalled}},
		},
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

func seedPlanProjection(t *testing.T, store *eventing.MemoryStore, projectID string, version int) contracts.PlanSpec {
	t.Helper()
	plan := contracts.PlanSpec{
		PlanSpecVersion: version, ProjectID: projectID,
		GoalSpecRef:       contracts.SpecRef{Version: 1, SHA256: "sha256:" + strings.Repeat("1", 64)},
		Architecture:      contracts.Architecture{Style: "modular service", Components: []string{"api"}, DataFlows: []string{}, TrustBoundaries: []string{}, DeploymentUnits: []string{"api"}},
		QualityAttributes: []string{"reliability"}, IntegrationPlan: []string{"merge module"}, ReleasePlan: []string{"deploy test"},
		TestStrategy: []string{"unit"}, RollbackStrategy: []string{"revert"}, OpenDecisions: []string{},
		Modules: []contracts.PlanModule{{
			ModuleID: "module-api", Name: "API", Responsibility: "serve requests", ExecutionPlatform: contracts.PlatformLinux,
			SandboxLevel: contracts.IsolationContainer, OwnedPaths: []string{"internal/api/**"}, ForbiddenPaths: []string{}, PublicInterfaces: []string{"HTTP"},
			Dependencies: []string{}, AcceptanceCriteria: []string{"requests succeed"}, Risk: "MEDIUM",
		}},
	}
	unsigned, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.SHA256, err = canonicaljson.DigestObjectWithoutFields(unsigned, "sha256", "signature")
	if err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(plan)
	if err != nil || contracts.ValidatePlanJSON(content) != nil {
		t.Fatalf("plan content error=%v content=%s", err, content)
	}
	projection, err := json.Marshal(struct {
		TenantID      string `json:"tenantId"`
		ProjectID     string `json:"projectId"`
		Kind          string `json:"kind"`
		SpecID        string `json:"specId"`
		Version       int    `json:"version"`
		ContentSHA256 string `json:"contentSha256"`
		Content       []byte `json:"content"`
	}{testTenantID, projectID, "PLAN_SPEC", "plan-1", version, plan.SHA256, content})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonicaljson.Digest(projection)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Execute(context.Background(), eventing.TransactionRequest{
		TenantID: testTenantID, PrincipalID: "test-seed", IdempotencyKey: fmt.Sprintf("plan-%d", version), RequestSHA256: digest,
		Result: projection, ResultSHA256: digest,
		Updates: []eventing.ProjectionUpdate{{TenantID: testTenantID, ProjectID: projectID, AggregateType: "spec_artifact", AggregateID: fmt.Sprintf("plan-%d", version), ExpectedVersion: 0, NextVersion: 1, State: projection}},
		Events:  []eventing.DomainEvent{{EventID: fmt.Sprintf("event-plan-%d", version), TenantID: testTenantID, ProjectID: projectID, AggregateType: "spec_artifact", AggregateID: fmt.Sprintf("plan-%d", version), AggregateVersion: 1, Type: "io.aor.artifact.spec-stored.v1", Payload: projection, PayloadSHA256: digest, OccurredAt: controlAPITestTime}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
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

func TestValidAPIIdentifierAcceptsUUIDRecordsAndLegacyIdentifiers(t *testing.T) {
	for _, identifier := range []string{
		"01989f4d-0000-7000-8000-000000000001",
		"task_1",
	} {
		if !validAPIIdentifier(identifier) {
			t.Fatalf("expected %q to be a valid API identifier", identifier)
		}
	}

	for _, identifier := range []string{
		"1task",
		"01989f4d-0000-7000-8000-00000000000z",
	} {
		if validAPIIdentifier(identifier) {
			t.Fatalf("expected %q to be rejected", identifier)
		}
	}
}

var _ authn.Authenticator = fixedAuthenticator{}
var _ authz.PolicyEvaluator = (*recordingAuthorizer)(nil)
