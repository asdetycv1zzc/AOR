package knowledge

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

var knowledgeTestNow = time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)

type testAuthorizer struct {
	mu          sync.Mutex
	denyReads   bool
	denyWrites  bool
	evaluations []authz.PolicyInput
}

type acceptingApprovalVerifier struct{}

func (acceptingApprovalVerifier) Verify(context.Context, authz.Approval) error { return nil }

func (authorizer *testAuthorizer) Evaluate(_ context.Context, input authz.PolicyInput) (authz.PolicyDecision, error) {
	authorizer.mu.Lock()
	authorizer.evaluations = append(authorizer.evaluations, input)
	authorizer.mu.Unlock()
	denied := authorizer.denyReads
	if input.Action == authz.ActionKnowledgeWrite {
		denied = authorizer.denyWrites
	}
	decision := authz.DecisionAllow
	reason := "TEST_ALLOW"
	if denied {
		decision = authz.DecisionDeny
		reason = "TEST_DENY"
	}
	return authz.PolicyDecision{Decision: decision, PolicyVersion: "policy-v1", ReasonCodes: []string{reason}, RuleID: "test.knowledge"}, nil
}

type testScopes struct {
	projects map[string]authz.ProjectScope
	tasks    map[string]authz.TaskScope
}

func (scopes *testScopes) ResolveProject(_ context.Context, tenantID, projectID string) (authz.ProjectScope, error) {
	project, exists := scopes.projects[tenantID+"/"+projectID]
	if !exists {
		return authz.ProjectScope{}, errors.New("project scope unavailable")
	}
	return project, nil
}

func (scopes *testScopes) ResolveTask(_ context.Context, tenantID, projectID, taskID string) (authz.TaskScope, error) {
	task, exists := scopes.tasks[tenantID+"/"+projectID+"/"+taskID]
	if !exists {
		return authz.TaskScope{}, errors.New("task scope unavailable")
	}
	return task, nil
}

type knowledgeFixture struct {
	service    *Service
	repository *FileRepository
	authorizer *testAuthorizer
	scopes     *testScopes
}

func newKnowledgeFixture(t *testing.T, projects ...string) knowledgeFixture {
	t.Helper()
	repository, err := NewFileRepository(filepath.Join(t.TempDir(), "knowledge"))
	if err != nil {
		t.Fatal(err)
	}
	scopes := &testScopes{projects: make(map[string]authz.ProjectScope), tasks: make(map[string]authz.TaskScope)}
	for _, projectID := range projects {
		scopes.projects["tenant-1/"+projectID] = authz.ProjectScope{
			TenantID: "tenant-1", ID: projectID, State: "EXECUTING", StateVersion: 7, Classification: "INTERNAL",
		}
		scopes.tasks["tenant-1/"+projectID+"/task-curate"] = authz.TaskScope{
			TenantID: "tenant-1", ProjectID: projectID, ID: "task-curate", State: "EXECUTING",
			StateVersion: 3, SpecDigest: "sha256:" + strings.Repeat("1", 64),
		}
	}
	authorizer := &testAuthorizer{}
	service, err := NewService(ServiceConfig{Repository: repository, Authorizer: authorizer, Scopes: scopes, Clock: func() time.Time { return knowledgeTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	return knowledgeFixture{service: service, repository: repository, authorizer: authorizer, scopes: scopes}
}

func readAccess(projectID string) Access {
	return Access{
		Principal: authn.Principal{ID: "agent-reader", Type: authn.PrincipalAgentInstance, Role: authn.RoleExecutor, TenantID: "tenant-1", ProjectID: projectID},
		TenantID:  "tenant-1", ProjectID: projectID, PolicyVersion: "policy-v1",
	}
}

func curatorAccess(projectID string, proposal UpdateProposal) Access {
	digest, err := ProposalDigest(proposal)
	if err != nil {
		panic(err)
	}
	return Access{
		Principal: authn.Principal{ID: "curator-1", Type: authn.PrincipalKnowledgeCurator, Role: authn.RoleKnowledgeCurator, TenantID: "tenant-1", ProjectID: projectID},
		TenantID:  "tenant-1", ProjectID: projectID, TaskID: "task-curate",
		Lease: &authz.LeaseReference{ID: "lease-1", ExpiresAt: knowledgeTestNow.Add(time.Hour), PolicyVersion: "policy-v1", FencingToken: 1},
		Approval: &authz.Approval{
			ID: "approval-1", TenantID: "tenant-1", ProjectID: projectID, PrincipalID: "user-1",
			SubjectType: authz.ActionKnowledgeWrite, SubjectID: projectID, SubjectVersion: 3,
			SubjectDigest: digest, IssuedAt: knowledgeTestNow.Add(-time.Minute), ExpiresAt: knowledgeTestNow.Add(time.Hour), Signature: "test-signature",
		},
		ParameterDigest: digest, BudgetAccountID: "knowledge-budget", PolicyVersion: "policy-v1",
	}
}

func commitProposal(t *testing.T, service *Service, projectID string, proposal UpdateProposal) UpdateResult {
	t.Helper()
	result, err := service.Update(context.Background(), curatorAccess(projectID, proposal), proposal)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestImmutableReferencesAndPaginatedReads(t *testing.T) {
	fixture := newKnowledgeFixture(t, "project-a")
	lines := make([]string, 205)
	for index := range lines {
		lines[index] = fmt.Sprintf("rule-%03d", index+1)
	}
	proposal1 := UpdateProposal{Parents: []ParentSnapshot{}, Overrides: []string{}, Documents: []DocumentInput{{
		Path: "architecture/auth.md", Title: "Authentication architecture", Tags: []string{"auth", "security"},
		TrustLevel: TrustCurated, Content: []byte(strings.Join(lines, "\r\n") + "\r\n"),
	}}}
	result1 := commitProposal(t, fixture.service, "project-a", proposal1)
	search, err := fixture.service.Search(context.Background(), SearchRequest{Access: readAccess("project-a"), Path: "architecture/auth.md"})
	if err != nil {
		t.Fatal(err)
	}
	if len(search.References) != 1 {
		t.Fatalf("got %d references", len(search.References))
	}
	oldReference := search.References[0]
	if oldReference.Revision != result1.Manifest.Revision || oldReference.ScopeRevision != result1.Manifest.Revision || oldReference.LineStart != 1 || oldReference.LineEnd != 205 || oldReference.Encoding != "utf-8" || oldReference.LineEnding != "LF" {
		t.Fatalf("unexpected reference: %#v", oldReference)
	}
	page1, err := fixture.service.ReadRange(context.Background(), ReadRangeRequest{Access: readAccess("project-a"), Reference: oldReference, LineStart: 1, LineEnd: 205})
	if err != nil {
		t.Fatal(err)
	}
	if page1.Reference.LineEnd != 200 || page1.NextLine != 201 || strings.Contains(page1.Content, "\r") {
		t.Fatalf("unexpected first page: %#v", page1)
	}
	page2, err := fixture.service.ReadRange(context.Background(), ReadRangeRequest{Access: readAccess("project-a"), Reference: oldReference, LineStart: page1.NextLine, LineEnd: 205})
	if err != nil {
		t.Fatal(err)
	}
	if page2.Reference.LineStart != 201 || page2.Reference.LineEnd != 205 || page2.NextLine != 0 || !strings.Contains(page2.Content, "rule-205") {
		t.Fatalf("unexpected second page: %#v", page2)
	}

	proposal2 := UpdateProposal{BaseRevision: result1.Manifest.Revision, Documents: []DocumentInput{{
		Path: "architecture/auth.md", Title: "Authentication architecture", Tags: []string{"auth", "security"},
		TrustLevel: TrustCurated, Content: []byte("replacement\n"),
	}}}
	result2 := commitProposal(t, fixture.service, "project-a", proposal2)
	if result2.Manifest.Revision == result1.Manifest.Revision {
		t.Fatal("content change did not create a revision")
	}
	oldPage, err := fixture.service.ReadRange(context.Background(), ReadRangeRequest{Access: readAccess("project-a"), Reference: oldReference, LineStart: 1, LineEnd: 1})
	if err != nil || oldPage.Content != "rule-001\n" {
		t.Fatalf("old reference was not immutable: content=%q err=%v", oldPage.Content, err)
	}
	forged := oldReference
	forged.ScopeRevision = result2.Manifest.Revision
	_, err = fixture.service.ReadRange(context.Background(), ReadRangeRequest{Access: readAccess("project-a"), Reference: forged, LineStart: 1, LineEnd: 1})
	assertErrorCode(t, err, aorerrors.CodeNotFound)
	missing := oldReference
	missing.ScopeRevision = "sha256:" + strings.Repeat("0", 64)
	_, err = fixture.service.ReadRange(context.Background(), ReadRangeRequest{Access: readAccess("project-a"), Reference: missing, LineStart: 1, LineEnd: 1})
	assertErrorCode(t, err, aorerrors.CodeKnowledgeRevisionUnavailable)
}

func TestReadRangeAppliesByteLimit(t *testing.T) {
	fixture := newKnowledgeFixture(t, "project-a")
	lines := make([]string, 100)
	for index := range lines {
		lines[index] = strings.Repeat("x", 400)
	}
	result := commitProposal(t, fixture.service, "project-a", UpdateProposal{Documents: []DocumentInput{{
		Path: "operations/large.md", Title: "Large", TrustLevel: TrustCurated, Content: []byte(strings.Join(lines, "\n")),
	}}})
	search, err := fixture.service.Search(context.Background(), SearchRequest{Access: readAccess("project-a"), Path: "operations/large.md"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := fixture.service.ReadRange(context.Background(), ReadRangeRequest{Access: readAccess("project-a"), Reference: search.References[0], LineStart: 1, LineEnd: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Content) > MaxReadBytes || page.NextLine == 0 || page.Reference.Revision != result.Manifest.Revision {
		t.Fatalf("byte pagination failed: bytes=%d next=%d", len(page.Content), page.NextLine)
	}
}

func TestSearchExactIndexesFullTextAndCaps(t *testing.T) {
	fixture := newKnowledgeFixture(t, "project-a")
	documents := make([]DocumentInput, 25)
	for index := range documents {
		documents[index] = DocumentInput{
			Path: fmt.Sprintf("lessons/doc-%02d.md", index), Title: fmt.Sprintf("Lesson %02d", index),
			Tags: []string{"shared", fmt.Sprintf("tag-%02d", index)}, TrustLevel: TrustProjectApproved,
			Content: []byte(fmt.Sprintf("heading\nneedle-%02d common-search\n", index)),
		}
	}
	commitProposal(t, fixture.service, "project-a", UpdateProposal{Documents: documents})
	defaultResults, err := fixture.service.Search(context.Background(), SearchRequest{Access: readAccess("project-a"), Text: "common-search"})
	if err != nil {
		t.Fatal(err)
	}
	if len(defaultResults.References) != DefaultSearchLimit {
		t.Fatalf("default limit = %d", len(defaultResults.References))
	}
	maxResults, err := fixture.service.Search(context.Background(), SearchRequest{Access: readAccess("project-a"), Tags: []string{"shared"}, Limit: MaxSearchLimit})
	if err != nil {
		t.Fatal(err)
	}
	if len(maxResults.References) != MaxSearchLimit {
		t.Fatalf("max limit = %d", len(maxResults.References))
	}
	exact, err := fixture.service.Search(context.Background(), SearchRequest{Access: readAccess("project-a"), Title: "Lesson 07", Tags: []string{"tag-07"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(exact.References) != 1 || exact.References[0].Path != "lessons/doc-07.md" {
		t.Fatalf("exact index mismatch: %#v", exact.References)
	}
	fullText, err := fixture.service.Search(context.Background(), SearchRequest{Access: readAccess("project-a"), Text: "needle-03"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fullText.References) != 1 || fullText.References[0].LineStart != 2 || fullText.References[0].LineEnd != 2 {
		t.Fatalf("full text line mismatch: %#v", fullText.References)
	}
	_, err = fixture.service.Search(context.Background(), SearchRequest{Access: readAccess("project-a"), Text: "common-search", Limit: 21})
	assertErrorCode(t, err, aorerrors.CodeInvalidArgument)
}

func TestProjectIsolationAndPinnedInheritance(t *testing.T) {
	fixture := newKnowledgeFixture(t, "parent", "other", "child")
	parent1 := commitProposal(t, fixture.service, "parent", UpdateProposal{Documents: []DocumentInput{{
		Path: "architecture/base.md", Title: "Parent", TrustLevel: TrustCurated, Content: []byte("parent-v1\n"),
	}}})
	commitProposal(t, fixture.service, "other", UpdateProposal{Documents: []DocumentInput{{
		Path: "architecture/other.md", Title: "Other", TrustLevel: TrustCurated, Content: []byte("other-only\n"),
	}}})
	child := commitProposal(t, fixture.service, "child", UpdateProposal{Parents: []ParentSnapshot{{ProjectID: "parent", Revision: parent1.Manifest.Revision, Order: 0}}})
	parent2 := commitProposal(t, fixture.service, "parent", UpdateProposal{BaseRevision: parent1.Manifest.Revision, Documents: []DocumentInput{{
		Path: "architecture/base.md", Title: "Parent", TrustLevel: TrustCurated, Content: []byte("parent-v2\n"),
	}}})
	if parent2.Manifest.Revision == parent1.Manifest.Revision {
		t.Fatal("parent revision did not change")
	}
	oldSearch, err := fixture.service.Search(context.Background(), SearchRequest{Access: readAccess("child"), Text: "parent-v1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(oldSearch.References) != 1 || oldSearch.References[0].ScopeRevision != child.Manifest.Revision || oldSearch.References[0].Revision != parent1.Manifest.Revision || oldSearch.References[0].SourceProjectID != "parent" {
		t.Fatalf("inheritance was not pinned: %#v", oldSearch.References)
	}
	newSearch, err := fixture.service.Search(context.Background(), SearchRequest{Access: readAccess("child"), Text: "parent-v2"})
	if err != nil || len(newSearch.References) != 0 {
		t.Fatalf("child observed later parent change: %#v err=%v", newSearch.References, err)
	}
	otherSearch, err := fixture.service.Search(context.Background(), SearchRequest{Access: readAccess("other"), Text: "parent-v1"})
	if err != nil || len(otherSearch.References) != 0 {
		t.Fatalf("unrelated project discovered parent: %#v err=%v", otherSearch.References, err)
	}
	crossProject := readAccess("other")
	crossProject.ProjectID = "parent"
	_, err = fixture.service.Search(context.Background(), SearchRequest{Access: crossProject, Text: "parent"})
	assertErrorCode(t, err, aorerrors.CodeForbidden)
}

func TestOrderedParentConflictAndTrustResolution(t *testing.T) {
	fixture := newKnowledgeFixture(t, "parent-a", "parent-b", "child")
	parentA := commitProposal(t, fixture.service, "parent-a", UpdateProposal{Documents: []DocumentInput{{
		Path: "policies/rule.md", Title: "Rule A", TrustLevel: TrustCurated, Content: []byte("allow-a\n"),
	}}})
	downgradeOwn := UpdateProposal{BaseRevision: parentA.Manifest.Revision, Documents: []DocumentInput{{
		Path: "policies/rule.md", Title: "Rule A", TrustLevel: TrustExternalUntrusted, Content: []byte("allow-a-low-trust\n"),
	}}}
	_, err := fixture.service.Update(context.Background(), curatorAccess("parent-a", downgradeOwn), downgradeOwn)
	assertErrorCode(t, err, aorerrors.CodeConflict)
	parentB := commitProposal(t, fixture.service, "parent-b", UpdateProposal{Documents: []DocumentInput{{
		Path: "policies/rule.md", Title: "Rule B", TrustLevel: TrustProjectApproved, Content: []byte("allow-b\n"),
	}}})
	parents := []ParentSnapshot{{ProjectID: "parent-a", Revision: parentA.Manifest.Revision, Order: 0}, {ProjectID: "parent-b", Revision: parentB.Manifest.Revision, Order: 1}}
	implicit := UpdateProposal{Parents: parents}
	_, err = ProposalDigest(implicit)
	assertErrorCode(t, err, aorerrors.CodeInvalidArgument)
	conflicting := UpdateProposal{Parents: parents, ParentOrderExplicit: true}
	_, err = fixture.service.Update(context.Background(), curatorAccess("child", conflicting), conflicting)
	assertErrorCode(t, err, aorerrors.CodeConflict)
	lowTrust := UpdateProposal{Parents: parents, ParentOrderExplicit: true, Overrides: []string{"policies/rule.md"}, Documents: []DocumentInput{{
		Path: "policies/rule.md", Title: "Resolved", TrustLevel: TrustExternalUntrusted, Content: []byte("resolved\n"),
	}}}
	_, err = fixture.service.Update(context.Background(), curatorAccess("child", lowTrust), lowTrust)
	assertErrorCode(t, err, aorerrors.CodeConflict)
	resolved := UpdateProposal{Parents: parents, ParentOrderExplicit: true, Overrides: []string{"policies/rule.md"}, Documents: []DocumentInput{{
		Path: "policies/rule.md", Title: "Resolved", TrustLevel: TrustCurated, Content: []byte("resolved\n"),
	}}}
	commitProposal(t, fixture.service, "child", resolved)
	results, err := fixture.service.Search(context.Background(), SearchRequest{Access: readAccess("child"), Path: "policies/rule.md"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results.References) != 1 || results.References[0].SourceProjectID != "child" || results.References[0].TrustLevel != TrustCurated {
		t.Fatalf("resolution mismatch: %#v", results.References)
	}
}

func TestAuthorizationAndPathChecksFailClosed(t *testing.T) {
	fixture := newKnowledgeFixture(t, "project-a")
	_, err := NewService(ServiceConfig{Repository: fixture.repository, Scopes: fixture.scopes})
	assertErrorCode(t, err, aorerrors.CodeDependencyUnavailable)
	proposal := UpdateProposal{Documents: []DocumentInput{{Path: "safe.md", Title: "Safe", TrustLevel: TrustCurated, Content: []byte("safe\n")}}}
	nonCurator := curatorAccess("project-a", proposal)
	nonCurator.Principal = authn.Principal{ID: "executor", Type: authn.PrincipalAgentInstance, Role: authn.RoleExecutor, TenantID: "tenant-1", ProjectID: "project-a"}
	_, err = fixture.service.Update(context.Background(), nonCurator, proposal)
	assertErrorCode(t, err, aorerrors.CodeKnowledgeWriteForbidden)
	missingApproval := curatorAccess("project-a", proposal)
	missingApproval.Approval = nil
	_, err = fixture.service.Update(context.Background(), missingApproval, proposal)
	assertErrorCode(t, err, aorerrors.CodeKnowledgeWriteForbidden)
	fixture.authorizer.denyWrites = true
	_, err = fixture.service.Update(context.Background(), curatorAccess("project-a", proposal), proposal)
	assertErrorCode(t, err, aorerrors.CodeKnowledgeWriteForbidden)
	fixture.authorizer.denyWrites = false
	commitProposal(t, fixture.service, "project-a", proposal)
	fixture.authorizer.denyReads = true
	_, err = fixture.service.Search(context.Background(), SearchRequest{Access: readAccess("project-a"), Path: "safe.md"})
	assertErrorCode(t, err, aorerrors.CodeForbidden)

	for _, candidate := range []string{"../escape.md", "/absolute.md", "a\\..\\escape.md", "C:/escape.md", "CON/file.md"} {
		badProposal := UpdateProposal{BaseRevision: proposalRevision(t, fixture.service, "project-a"), Documents: []DocumentInput{{Path: candidate, Title: "Bad", TrustLevel: TrustCurated, Content: []byte("bad\n")}}}
		_, digestErr := ProposalDigest(badProposal)
		assertErrorCode(t, digestErr, aorerrors.CodeUnauthorizedPath)
	}
}

func TestFileRepositoryRejectsSymlinkRootsAndTampering(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}
	linkedRoot := filepath.Join(base, "linked")
	if err := os.Symlink(target, linkedRoot); err != nil {
		t.Fatal(err)
	}
	_, err := NewFileRepository(linkedRoot)
	assertErrorCode(t, err, aorerrors.CodeUnauthorizedPath)

	symlinkFixture := newKnowledgeFixture(t, "project-a")
	projectDirectory, err := symlinkFixture.repository.projectDirectory("tenant-1", "project-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(projectDirectory), 0o750); err != nil {
		t.Fatal(err)
	}
	externalProject := filepath.Join(t.TempDir(), "external-project")
	if err := os.Mkdir(externalProject, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(externalProject, projectDirectory); err != nil {
		t.Fatal(err)
	}
	symlinkProposal := UpdateProposal{Documents: []DocumentInput{{Path: "escape.md", Title: "Escape", TrustLevel: TrustCurated, Content: []byte("escape\n")}}}
	_, err = symlinkFixture.service.Update(context.Background(), curatorAccess("project-a", symlinkProposal), symlinkProposal)
	assertErrorCode(t, err, aorerrors.CodeUnauthorizedPath)
	entries, err := os.ReadDir(externalProject)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("symlink target was modified: %#v", entries)
	}

	fixture := newKnowledgeFixture(t, "project-a")
	result := commitProposal(t, fixture.service, "project-a", UpdateProposal{Documents: []DocumentInput{{
		Path: "safe.md", Title: "Safe", TrustLevel: TrustCurated, Content: []byte("original\n"),
	}}})
	localPath, err := fixture.repository.LocalPath("tenant-1", "project-a", result.Manifest.Revision, "safe.md")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(localPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(localPath); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.md")
	if err := os.WriteFile(outside, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, localPath); err != nil {
		t.Fatal(err)
	}
	_, err = fixture.repository.Load(context.Background(), "tenant-1", "project-a", result.Manifest.Revision)
	assertErrorCode(t, err, aorerrors.CodeArtifactHashMismatch)
}

func TestIndexRebuildFromImmutableSource(t *testing.T) {
	fixture := newKnowledgeFixture(t, "project-a")
	result := commitProposal(t, fixture.service, "project-a", UpdateProposal{Documents: []DocumentInput{{
		Path: "decisions/one.md", Title: "One", Tags: []string{"adr"}, TrustLevel: TrustSignedPolicy, Content: []byte("decision\n"),
	}}})
	service, err := NewService(ServiceConfig{Repository: fixture.repository, Authorizer: fixture.authorizer, Scopes: fixture.scopes, Clock: func() time.Time { return knowledgeTestNow.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	index, err := service.RebuildIndex(context.Background(), readAccess("project-a"), result.Manifest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if index.Documents != 1 || index.Revision != result.Manifest.Revision {
		t.Fatalf("unexpected index: %#v", index)
	}
	results, err := service.Search(context.Background(), SearchRequest{Access: readAccess("project-a"), Tags: []string{"adr"}})
	if err != nil || len(results.References) != 1 || results.References[0].TrustLevel != TrustSignedPolicy {
		t.Fatalf("rebuilt search failed: %#v err=%v", results, err)
	}
}

func TestServiceUsesWP03LeaseAndApprovalBindings(t *testing.T) {
	repository, err := NewFileRepository(filepath.Join(t.TempDir(), "knowledge"))
	if err != nil {
		t.Fatal(err)
	}
	scopes := &testScopes{
		projects: map[string]authz.ProjectScope{"tenant-1/project-a": {TenantID: "tenant-1", ID: "project-a", State: "EXECUTING", StateVersion: 7, Classification: "INTERNAL"}},
		tasks: map[string]authz.TaskScope{"tenant-1/project-a/task-curate": {
			TenantID: "tenant-1", ProjectID: "project-a", ID: "task-curate", State: "EXECUTING", StateVersion: 3,
			SpecDigest: "sha256:" + strings.Repeat("1", 64),
		}},
	}
	signer, err := authz.NewHMACSigner([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := authz.NewLeaseManager(authz.LeaseManagerConfig{
		Store: authz.NewMemoryLeaseStore(), Signer: signer, Clock: func() time.Time { return knowledgeTestNow },
		DefaultTTL: 5 * time.Minute, MaxTTL: 10 * time.Minute, HeartbeatInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	engine := authz.NewEngine(authz.EngineConfig{
		Bundle:       authz.PolicyBundle{Version: "policy-v1", Digest: "policy-v1", Available: true},
		LeaseManager: manager, ApprovalVerifier: acceptingApprovalVerifier{}, Clock: func() time.Time { return knowledgeTestNow },
	})
	service, err := NewService(ServiceConfig{Repository: repository, Authorizer: engine, Scopes: scopes, Clock: func() time.Time { return knowledgeTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	proposal := UpdateProposal{Documents: []DocumentInput{{Path: "security/policy.md", Title: "Policy", TrustLevel: TrustSignedPolicy, Content: []byte("deny by default\n")}}}
	digest, err := ProposalDigest(proposal)
	if err != nil {
		t.Fatal(err)
	}
	principal := authn.Principal{ID: "curator-1", Type: authn.PrincipalKnowledgeCurator, Role: authn.RoleKnowledgeCurator, TenantID: "tenant-1", ProjectID: "project-a"}
	project := scopes.projects["tenant-1/project-a"]
	task := scopes.tasks["tenant-1/project-a/task-curate"]
	approval := &authz.Approval{
		ID: "approval-1", TenantID: "tenant-1", ProjectID: "project-a", PrincipalID: "user-1",
		SubjectType: authz.ActionKnowledgeWrite, SubjectID: "project-a", SubjectVersion: task.StateVersion,
		SubjectDigest: digest, IssuedAt: knowledgeTestNow.Add(-time.Minute), ExpiresAt: knowledgeTestNow.Add(time.Hour), Signature: "verified-test-signature",
	}
	resource := authz.Resource{Type: "knowledge.snapshot", ID: "project-a"}
	policyInput := authz.PolicyInput{
		Principal: principal, Project: project, Task: task, Action: authz.ActionKnowledgeWrite,
		Resource: resource, ParameterDigest: digest, Budget: authz.BudgetScope{AccountID: "knowledge-budget", Available: true}, Approval: approval,
	}
	grant, err := engine.EvaluateLeaseGrant(context.Background(), policyInput)
	if err != nil || grant.Decision != authz.DecisionAllow {
		t.Fatalf("lease grant failed: %#v err=%v", grant, err)
	}
	lease, err := manager.Issue(context.Background(), authz.LeaseRequest{
		ID: "lease-knowledge", AgentInstanceID: principal.ID, Principal: principal,
		TenantID: "tenant-1", ProjectID: "project-a", ProjectVersion: project.StateVersion,
		TaskID: task.ID, TaskVersion: task.StateVersion, SpecDigest: task.SpecDigest,
		Role: principal.Role, Action: authz.ActionKnowledgeWrite, Resource: resource,
		ParameterDigest: digest, Capabilities: []string{authz.ActionKnowledgeWrite}, PolicyVersion: "policy-v1",
		BudgetAccountID: "knowledge-budget", TTL: 5 * time.Minute, HeartbeatInterval: 10 * time.Second,
		Grant: grant, Now: knowledgeTestNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	access := Access{
		Principal: principal, TenantID: "tenant-1", ProjectID: "project-a", TaskID: task.ID,
		Lease:    &authz.LeaseReference{ID: lease.ID, ExpiresAt: lease.ExpiresAt, PolicyVersion: lease.PolicyVersion, FencingToken: lease.FencingToken},
		Approval: approval, ParameterDigest: digest, BudgetAccountID: "knowledge-budget", PolicyVersion: "policy-v1",
	}
	result, err := service.Update(context.Background(), access, proposal)
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Revision == "" {
		t.Fatal("authorized update did not commit")
	}
	results, err := service.Search(context.Background(), SearchRequest{Access: readAccess("project-a"), Path: "security/policy.md"})
	if err != nil || len(results.References) != 1 {
		t.Fatalf("authorized read failed: %#v err=%v", results, err)
	}
}

func proposalRevision(t *testing.T, service *Service, projectID string) string {
	t.Helper()
	revision, err := service.repository.Head(context.Background(), "tenant-1", projectID)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func assertErrorCode(t *testing.T, err error, expected aorerrors.Code) {
	t.Helper()
	var typed *aorerrors.Error
	if !errors.As(err, &typed) {
		t.Fatalf("expected %s, got %v", expected, err)
	}
	if typed.Code != expected {
		t.Fatalf("expected %s, got %s", expected, typed.Code)
	}
}
