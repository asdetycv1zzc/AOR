package repository

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/google/uuid"
)

type testLeaseValidator struct{}

type testSubmissionSigner struct{}

type revokingLeaseValidator struct {
	mu     sync.Mutex
	calls  int
	failAt int
}

func TestNewWorkspaceIDReturnsDistinctTenantScopedUUIDv7Values(t *testing.T) {
	first, firstErr := newWorkspaceID("tenant-1")
	second, secondErr := newWorkspaceID("tenant-1")
	if firstErr != nil || secondErr != nil || first == second || !validWorkspaceID(first) || !validWorkspaceID(second) {
		t.Fatalf("workspace ids = %q, %q errors=%v,%v", first, second, firstErr, secondErr)
	}
	for _, value := range []string{first, second} {
		raw := strings.TrimPrefix(value, "tenant-1:")
		parsed, err := uuid.Parse(raw)
		if err != nil || parsed.Version() != uuid.Version(7) || parsed.String() != raw {
			t.Fatalf("workspace id %q is not tenant-scoped UUIDv7", value)
		}
	}
}

func (testLeaseValidator) Validate(_ context.Context, validation LeaseValidation) error {
	if validation.Proof.ID == "" || validation.Proof.FencingToken < 1 || !time.Now().Before(validation.Proof.ExpiresAt) || validation.TenantID == "" || validation.ProjectID == "" || validation.TaskID == "" || validation.AttemptSeriesID == "" || validation.ModuleSpecRef.Validate() != nil || validation.AgentInstanceID == "" || validation.Role != "EXECUTOR" || validation.Action == "" || validation.ResourcePath == "" || !strings.HasPrefix(validation.ParameterDigest, "sha256:") {
		return ErrLeaseStale
	}
	return nil
}

func (validator *revokingLeaseValidator) Validate(ctx context.Context, validation LeaseValidation) error {
	if err := (testLeaseValidator{}).Validate(ctx, validation); err != nil {
		return err
	}
	validator.mu.Lock()
	defer validator.mu.Unlock()
	validator.calls++
	if validator.failAt > 0 && validator.calls >= validator.failAt {
		return ErrLeaseStale
	}
	return nil
}

func (validator *revokingLeaseValidator) arm(failAt int) {
	validator.mu.Lock()
	validator.calls = 0
	validator.failAt = failAt
	validator.mu.Unlock()
}

func TestServiceDefersLeaseExpiryToAuthoritativeValidator(t *testing.T) {
	module := testModule()
	service := &Service{leases: testLeaseValidator{}, clock: func() time.Time { return time.Now().Add(48 * time.Hour) }}
	validation := LeaseValidation{
		Proof:            LeaseProof{ID: "lease-1", FencingToken: 1, ExpiresAt: time.Now().Add(24 * time.Hour)},
		ExecutionLeaseID: "lease-1", Action: LeaseActionWriteFile,
		TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1",
		AttemptSeriesID: "series-1", Attempt: 1,
		ModuleSpecRef:   contracts.SpecRef{Version: module.ModuleSpecVersion, SHA256: module.SHA256},
		AgentInstanceID: "agent-1", Role: "EXECUTOR", ResourcePath: "owned/file.go",
		ParameterDigest: DigestBytes([]byte("parameters")),
	}
	if err := service.validateLease(context.Background(), validation); err != nil {
		t.Fatalf("valid authoritative lease rejected by local clock skew: %v", err)
	}
}

func (testSubmissionSigner) Sign(_ context.Context, payload []byte) (*contracts.Signature, error) {
	return &contracts.Signature{Type: "TEST-SHA256", KID: "repository-test", JWS: DigestBytes(payload)}, nil
}

func (testSubmissionSigner) Verify(_ context.Context, payload []byte, signature *contracts.Signature) error {
	if signature == nil || signature.Type != "TEST-SHA256" || signature.KID != "repository-test" || signature.JWS != DigestBytes(payload) {
		return ErrInvalidRequest
	}
	return nil
}

func TestServiceEnforcesOwnedPathsAndCreatesImmutableSubmission(t *testing.T) {
	source := t.TempDir()
	if _, err := runGit(source, "init", "-b", "main"); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, source, "owned/readme.txt", "base\n")
	if _, err := runGit(source, "add", "."); err != nil {
		t.Fatal(err)
	}
	if _, err := runGit(source, "commit", "-m", "initial"); err != nil {
		t.Fatal(err)
	}
	base, err := runGit(source, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(t.TempDir(), testLeaseValidator{}, nil, testSubmissionSigner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	lease := LeaseProof{ID: "lease-1", FencingToken: 1, ExpiresAt: time.Now().Add(time.Hour)}
	module := testModule()
	workspace, err := service.CreateWorkspace(context.Background(), WorkspaceRequest{RepositoryPath: source, TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", Attempt: 1, AttemptSeriesID: "series-1", BaseCommit: strings.TrimSpace(base), ModuleSpec: module, AgentIdentity: contracts.AgentIdentity{AgentInstanceID: "agent-1", Role: "EXECUTOR", LeaseID: lease.ID}, Lease: lease})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.WriteFile(context.Background(), WriteRequest{WorkspaceID: workspace.ID, Path: "owned/changed.txt", Content: []byte("changed\n"), Lease: lease}); err != nil {
		t.Fatal(err)
	}
	if err := service.WriteFile(context.Background(), WriteRequest{WorkspaceID: workspace.ID, Path: "secret.txt", Content: []byte("denied"), Lease: lease}); err != ErrPathDenied {
		t.Fatalf("unowned write error = %v", err)
	}
	if _, err := service.Submit(context.Background(), SubmissionRequest{WorkspaceID: workspace.ID, Attempt: 1, ClaimedCriteria: []string{"unknown-criterion"}, IdempotencyKey: "invalid-criterion", Lease: lease}); err != ErrInvalidRequest {
		t.Fatalf("unknown criterion error = %v", err)
	}
	if _, err := service.Submit(context.Background(), SubmissionRequest{WorkspaceID: workspace.ID, Attempt: 1, ClaimedCriteria: []string{"criterion-1"}, LocalTestEvidenceRefs: []string{"file://local/test.log"}, IdempotencyKey: "invalid-evidence", Lease: lease}); err != ErrInvalidRequest {
		t.Fatalf("mutable evidence reference error = %v", err)
	}
	evidenceRef := "artifact://sha256/1111111111111111111111111111111111111111111111111111111111111111"
	submission, err := service.Submit(context.Background(), SubmissionRequest{WorkspaceID: workspace.ID, Attempt: 1, ClaimedCriteria: []string{"criterion-1"}, LocalTestEvidenceRefs: []string{evidenceRef}, IdempotencyKey: "submit-1", Lease: lease})
	if err != nil {
		t.Fatal(err)
	}
	if submission.Manifest.BaseCommit != strings.TrimSpace(base) || submission.Manifest.HeadCommit == submission.Manifest.BaseCommit || len(submission.Manifest.CreatedFiles) != 1 || submission.Manifest.Signature == nil {
		t.Fatalf("unexpected manifest: %#v", submission.Manifest)
	}
	replay, err := service.Submit(context.Background(), SubmissionRequest{WorkspaceID: workspace.ID, Attempt: 1, ClaimedCriteria: []string{"criterion-1"}, LocalTestEvidenceRefs: []string{evidenceRef}, IdempotencyKey: "submit-1", Lease: lease})
	if err != nil || replay.Manifest.SHA256 != submission.Manifest.SHA256 {
		t.Fatalf("submission replay changed immutable result: %v %#v", err, replay.Manifest)
	}
	if _, err := service.Submit(context.Background(), SubmissionRequest{WorkspaceID: workspace.ID, Attempt: 1, ClaimedCriteria: []string{"criterion-1"}, LocalTestEvidenceRefs: []string{"artifact://sha256/2222222222222222222222222222222222222222222222222222222222222222"}, IdempotencyKey: "submit-1", Lease: lease}); err != ErrSubmissionConflict {
		t.Fatalf("changed idempotent submission error = %v", err)
	}
	if workspace.Branch != "agent/project-1/task-1/attempt-1" {
		t.Fatalf("workspace branch = %s", workspace.Branch)
	}
	message, err := runGit(workspace.Path, "log", "-1", "--format=%B")
	if err != nil || !strings.Contains(message, "AOR-Module-Spec: v1 "+module.SHA256) || !strings.Contains(message, "AOR-Agent: agent-1") {
		t.Fatalf("commit provenance = %q error=%v", message, err)
	}
}

func TestServiceRejectsStaleLeaseAndSymlinkEscape(t *testing.T) {
	source := t.TempDir()
	if _, err := runGit(source, "init", "-b", "main"); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, source, "owned/base.txt", "base\n")
	if _, err := runGit(source, "add", "."); err != nil {
		t.Fatal(err)
	}
	if _, err := runGit(source, "commit", "-m", "initial"); err != nil {
		t.Fatal(err)
	}
	base, _ := runGit(source, "rev-parse", "HEAD")
	service, _ := NewService(t.TempDir(), testLeaseValidator{}, nil, testSubmissionSigner{}, nil)
	lease := LeaseProof{ID: "lease-1", FencingToken: 1, ExpiresAt: time.Now().Add(time.Hour)}
	workspace, err := service.CreateWorkspace(context.Background(), WorkspaceRequest{RepositoryPath: source, TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", Attempt: 1, AttemptSeriesID: "series-1", BaseCommit: strings.TrimSpace(base), ModuleSpec: testModule(), AgentIdentity: contracts.AgentIdentity{AgentInstanceID: "agent-1", Role: "EXECUTOR", LeaseID: lease.ID}, Lease: lease})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.WriteFile(context.Background(), WriteRequest{WorkspaceID: workspace.ID, Path: "owned/x.txt", Content: []byte("x"), Lease: LeaseProof{ID: lease.ID, FencingToken: 1, ExpiresAt: time.Now().Add(-time.Second)}}); !errors.Is(err, ErrLeaseStale) {
		t.Fatalf("expired lease error = %v", err)
	}
	if err := service.WriteFile(context.Background(), WriteRequest{WorkspaceID: workspace.ID, Path: "owned/x.txt", Content: []byte("x"), Lease: LeaseProof{ID: "other-lease", FencingToken: 1, ExpiresAt: time.Now().Add(time.Hour)}}); !errors.Is(err, ErrLeaseStale) {
		t.Fatalf("cross-lease write error = %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	writeTestFile(t, filepath.Dir(outside), filepath.Base(outside), "outside")
	if err := os.Symlink(outside, filepath.Join(workspace.Path, "owned", "link.txt")); err == nil {
		if err := service.WriteFile(context.Background(), WriteRequest{WorkspaceID: workspace.ID, Path: "owned/link.txt", Content: []byte("escape"), Lease: lease}); err != ErrPathDenied {
			t.Fatalf("symlink write error = %v", err)
		}
	}
	hardLink := filepath.Join(workspace.Path, "owned", "hard.txt")
	if err := os.Link(outside, hardLink); err == nil {
		if err := service.WriteFile(context.Background(), WriteRequest{WorkspaceID: workspace.ID, Path: "owned/hard.txt", Content: []byte("escape"), Lease: lease}); err != ErrPathDenied {
			t.Fatalf("hard-link write error = %v", err)
		}
		content, readErr := os.ReadFile(outside)
		if readErr != nil || string(content) != "outside" {
			t.Fatalf("hard-link target changed: %q error=%v", content, readErr)
		}
	}
	caseAlias := filepath.Join(workspace.Path, "OWNED")
	if err := os.Mkdir(caseAlias, 0o700); err == nil {
		if err := service.WriteFile(context.Background(), WriteRequest{WorkspaceID: workspace.ID, Path: "owned/case.txt", Content: []byte("denied"), Lease: lease}); err != ErrPathDenied {
			t.Fatalf("case-folded alias error = %v", err)
		}
	}
}

func TestWorkspaceHidesForbiddenFilesAndKeepsGitMetadataOutsideMount(t *testing.T) {
	source := t.TempDir()
	if _, err := runGit(source, "init", "-b", "main"); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, source, "owned/main.go", "package owned\n")
	writeTestFile(t, source, "hidden-tests/exploit_test.go", "package hidden\n")
	writeTestFile(t, source, "audit/private-policy.rego", "package private\n")
	if _, err := runGit(source, "add", "."); err != nil {
		t.Fatal(err)
	}
	if _, err := runGit(source, "commit", "-m", "initial"); err != nil {
		t.Fatal(err)
	}
	base, err := runGit(source, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(t.TempDir(), testLeaseValidator{}, nil, testSubmissionSigner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	module := testModule()
	module.ForbiddenPaths = []string{".git/...", "hidden-tests/...", "audit/..."}
	lease := LeaseProof{ID: "lease-private", FencingToken: 1, ExpiresAt: time.Now().Add(time.Hour)}
	request := WorkspaceRequest{RepositoryPath: source, TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-private", Attempt: 1, AttemptSeriesID: "series-private", BaseCommit: strings.TrimSpace(base), ModuleSpec: module, AgentIdentity: contracts.AgentIdentity{AgentInstanceID: "agent-private", Role: "EXECUTOR", LeaseID: lease.ID}, Lease: lease}
	workspace, err := service.CreateWorkspace(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := service.CreateWorkspace(context.Background(), request)
	if err != nil || replay.ID != workspace.ID {
		t.Fatalf("workspace replay id = %q want %q error=%v", replay.ID, workspace.ID, err)
	}
	for _, forbidden := range []string{"hidden-tests/exploit_test.go", "audit/private-policy.rego"} {
		if _, err := os.Stat(filepath.Join(workspace.Path, filepath.FromSlash(forbidden))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("forbidden file %s is visible: %v", forbidden, err)
		}
		if _, err := service.ReadFile(context.Background(), workspace.ID, forbidden); !errors.Is(err, ErrPathDenied) {
			t.Fatalf("forbidden service read %s = %v", forbidden, err)
		}
	}
	registered, found := service.Workspace(workspace.ID)
	if !found || registered.gitDir == "" {
		t.Fatal("service-owned git directory was not registered")
	}
	relative, err := filepath.Rel(workspace.Path, registered.gitDir)
	if err != nil || relative == "." || !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		t.Fatalf("git directory %q is inside workspace %q", registered.gitDir, workspace.Path)
	}
	gitMarker, err := os.ReadFile(filepath.Join(workspace.Path, ".git"))
	if err != nil || !strings.HasPrefix(string(gitMarker), "gitdir: ") {
		t.Fatalf("external git marker = %q error=%v", gitMarker, err)
	}
	if _, err := os.Stat(filepath.Join(workspace.Path, "owned", "main.go")); err != nil {
		t.Fatalf("owned file is unavailable: %v", err)
	}
}

func TestServiceRevalidatesLeaseAtEveryRepositoryCommitBoundary(t *testing.T) {
	source := t.TempDir()
	if _, err := runGit(source, "init", "-b", "main"); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, source, "owned/base.txt", "base\n")
	writeTestFile(t, source, "owned/delete.txt", "delete\n")
	if _, err := runGit(source, "add", "."); err != nil {
		t.Fatal(err)
	}
	if _, err := runGit(source, "commit", "-m", "initial"); err != nil {
		t.Fatal(err)
	}
	base, err := runGit(source, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	base = strings.TrimSpace(base)
	validator := &revokingLeaseValidator{}
	store := NewMemorySubmissionStore()
	service, err := NewService(t.TempDir(), validator, store, testSubmissionSigner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	lease := LeaseProof{ID: "lease-1", FencingToken: 7, ExpiresAt: time.Now().Add(time.Hour)}
	workspace, err := service.CreateWorkspace(context.Background(), WorkspaceRequest{RepositoryPath: source, TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", Attempt: 1, AttemptSeriesID: "series-1", BaseCommit: base, ModuleSpec: testModule(), AgentIdentity: contracts.AgentIdentity{AgentInstanceID: "agent-1", Role: "EXECUTOR", LeaseID: lease.ID}, Lease: lease})
	if err != nil {
		t.Fatal(err)
	}

	validator.arm(2)
	if err := service.WriteFile(context.Background(), WriteRequest{WorkspaceID: workspace.ID, Path: "owned/base.txt", Content: []byte("revoked\n"), Lease: lease}); !errors.Is(err, ErrLeaseStale) {
		t.Fatalf("revoked write error = %v", err)
	}
	content, err := os.ReadFile(filepath.Join(workspace.Path, "owned", "base.txt"))
	if err != nil || string(content) != "base\n" {
		t.Fatalf("revoked write changed file: %q error=%v", content, err)
	}

	validator.arm(2)
	deletePath := filepath.Join(workspace.Path, "owned", "delete.txt")
	if err := service.DeleteFile(context.Background(), DeleteRequest{WorkspaceID: workspace.ID, Path: "owned/delete.txt", Lease: lease}); !errors.Is(err, ErrLeaseStale) {
		t.Fatalf("revoked delete error = %v", err)
	}
	if _, err := os.Stat(deletePath); err != nil {
		t.Fatalf("revoked delete removed file: %v", err)
	}

	validator.arm(0)
	if err := service.WriteFile(context.Background(), WriteRequest{WorkspaceID: workspace.ID, Path: "owned/changed.txt", Content: []byte("changed\n"), Lease: lease}); err != nil {
		t.Fatal(err)
	}
	submit := SubmissionRequest{WorkspaceID: workspace.ID, Attempt: 1, ClaimedCriteria: []string{"criterion-1"}, IdempotencyKey: "submit-race", Lease: lease}
	validator.arm(2)
	if _, err := service.Submit(context.Background(), submit); !errors.Is(err, ErrLeaseStale) {
		t.Fatalf("lease revoked before git commit error = %v", err)
	}
	head, err := runGit(workspace.Path, "rev-parse", "HEAD")
	if err != nil || strings.TrimSpace(head) != base {
		t.Fatalf("revoked submission created commit %q error=%v", head, err)
	}

	validator.arm(4)
	if _, err := service.Submit(context.Background(), submit); !errors.Is(err, ErrLeaseStale) {
		t.Fatalf("lease revoked before submission publication error = %v", err)
	}
	if _, found, err := store.Get(context.Background(), workspace.TenantID, workspace.TaskID, workspace.AttemptSeriesID, workspace.Attempt); err != nil || found {
		t.Fatalf("revoked submission was accepted: found=%t error=%v", found, err)
	}
}

func TestServiceRevalidatesLeaseBeforeWorkspaceRegistration(t *testing.T) {
	source := t.TempDir()
	if _, err := runGit(source, "init", "-b", "main"); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, source, "owned/base.txt", "base\n")
	if _, err := runGit(source, "add", "."); err != nil {
		t.Fatal(err)
	}
	if _, err := runGit(source, "commit", "-m", "initial"); err != nil {
		t.Fatal(err)
	}
	base, err := runGit(source, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	validator := &revokingLeaseValidator{failAt: 2}
	service, err := NewService(t.TempDir(), validator, nil, testSubmissionSigner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	lease := LeaseProof{ID: "lease-1", FencingToken: 7, ExpiresAt: time.Now().Add(time.Hour)}
	request := WorkspaceRequest{RepositoryPath: source, TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", Attempt: 1, AttemptSeriesID: "series-1", BaseCommit: strings.TrimSpace(base), ModuleSpec: testModule(), AgentIdentity: contracts.AgentIdentity{AgentInstanceID: "agent-1", Role: "EXECUTOR", LeaseID: lease.ID}, Lease: lease}
	if _, err := service.CreateWorkspace(context.Background(), request); !errors.Is(err, ErrLeaseStale) {
		t.Fatalf("revoked workspace registration error = %v", err)
	}
	if _, found, err := service.workspaceStore.LoadWorkspaceByAttempt(context.Background(), request.TenantID, request.TaskID, request.AttemptSeriesID, request.Attempt); err != nil || found {
		t.Fatalf("revoked workspace registration found=%t error=%v", found, err)
	}
}

func TestOwnedPathRejectsTraversalCaseFoldAndUnicodeAmbiguity(t *testing.T) {
	workspace := Workspace{AllowedPaths: []string{"owned/..."}, ForbiddenPaths: []string{"owned/Secret/..."}}
	for _, candidate := range []string{"../outside", ".GIT/config", "owned/secret/value", "owned/caf\u00e9.txt", "owned/cafe\u0301.txt"} {
		if _, err := ownedPath(workspace, candidate); err != ErrPathDenied {
			t.Fatalf("path %q error = %v", candidate, err)
		}
	}
	if path, err := ownedPath(workspace, "owned/safe.txt"); err != nil || path != "owned/safe.txt" {
		t.Fatalf("safe path = %q, error = %v", path, err)
	}
}

func TestSubmissionStoreSeparatesAttemptSeriesAndReturnsDeepCopies(t *testing.T) {
	store := NewMemorySubmissionStore()
	first := Submission{Manifest: contracts.SubmissionManifest{AttemptSeriesID: "series-1", Attempt: 1, SHA256: testDigest("first")}, Workspace: Workspace{TenantID: "tenant-1", TaskID: "task-1", AllowedPaths: []string{"owned/..."}}, IdempotencyKey: "one", RequestSHA256: testDigest("request-1")}
	second := Submission{Manifest: contracts.SubmissionManifest{AttemptSeriesID: "series-2", Attempt: 1, SHA256: testDigest("second")}, Workspace: Workspace{TenantID: "tenant-1", TaskID: "task-1", AllowedPaths: []string{"other/..."}}, IdempotencyKey: "two", RequestSHA256: testDigest("request-2")}
	if err := store.Put(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.Get(context.Background(), "tenant-1", "task-1", "series-1", 1)
	if err != nil || !found || loaded.Manifest.SHA256 != first.Manifest.SHA256 {
		t.Fatalf("first series load = %#v found=%t error=%v", loaded, found, err)
	}
	loaded.Workspace.AllowedPaths[0] = "tampered"
	again, _, _ := store.Get(context.Background(), "tenant-1", "task-1", "series-1", 1)
	if again.Workspace.AllowedPaths[0] != "owned/..." {
		t.Fatal("stored workspace was mutated through a returned alias")
	}
}

func TestNewServiceRequiresLeaseValidationAndSigning(t *testing.T) {
	if _, err := NewService(t.TempDir(), nil, nil, testSubmissionSigner{}, nil); err != ErrInvalidRequest {
		t.Fatalf("missing lease validator error = %v", err)
	}
	if _, err := NewService(t.TempDir(), testLeaseValidator{}, nil, nil, nil); err != ErrInvalidRequest {
		t.Fatalf("missing signer error = %v", err)
	}
}

func testModule() contracts.ModuleSpec {
	return contracts.ModuleSpec{ModuleSpecVersion: 1, PlanVersion: 1, ModuleID: "module-1", ProjectID: "project-1", Name: "Owned", ExecutionPlatform: contracts.PlatformLinux, SandboxLevel: contracts.IsolationContainer, NetworkPolicy: contracts.NetworkPolicy{Mode: contracts.NetworkDenyAll}, WorkloadProfile: contracts.WorkloadProfile{Trust: contracts.WorkloadTrusted}, AllowedPaths: []string{"owned/..."}, ForbiddenPaths: []string{".git/..."}, AcceptanceCriteria: []string{"criterion-1"}, SHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
}

func runGit(directory string, args ...string) (string, error) {
	command := exec.Command("git", args...)
	command.Dir = directory
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_AUTHOR_NAME=AOR", "GIT_AUTHOR_EMAIL=aor@example.invalid", "GIT_COMMITTER_NAME=AOR", "GIT_COMMITTER_EMAIL=aor@example.invalid")
	output, err := command.CombinedOutput()
	return string(output), err
}

func writeTestFile(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func testDigest(value string) string {
	return DigestBytes([]byte(value))
}
