package repository

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
)

type testLeaseValidator struct{}

func (testLeaseValidator) Validate(_ context.Context, validation LeaseValidation) error {
	if validation.Proof.ID == "" || validation.Proof.FencingToken < 1 || validation.TenantID == "" || validation.ProjectID == "" || validation.TaskID == "" || validation.AttemptSeriesID == "" || validation.ModuleSpecRef.Validate() != nil || validation.AgentInstanceID == "" || validation.Role != "EXECUTOR" || validation.Action == "" || validation.ResourcePath == "" || !strings.HasPrefix(validation.ParameterDigest, "sha256:") {
		return ErrLeaseStale
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
	service, err := NewService(t.TempDir(), testLeaseValidator{}, nil, nil, nil)
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
	submission, err := service.Submit(context.Background(), SubmissionRequest{WorkspaceID: workspace.ID, Attempt: 1, ClaimedCriteria: []string{"criterion-1"}, IdempotencyKey: "submit-1", Lease: lease})
	if err != nil {
		t.Fatal(err)
	}
	if submission.Manifest.BaseCommit != strings.TrimSpace(base) || submission.Manifest.HeadCommit == submission.Manifest.BaseCommit || len(submission.Manifest.CreatedFiles) != 1 {
		t.Fatalf("unexpected manifest: %#v", submission.Manifest)
	}
	replay, err := service.Submit(context.Background(), SubmissionRequest{WorkspaceID: workspace.ID, Attempt: 1, ClaimedCriteria: []string{"criterion-1"}, IdempotencyKey: "submit-1", Lease: lease})
	if err != nil || replay.Manifest.SHA256 != submission.Manifest.SHA256 {
		t.Fatalf("submission replay changed immutable result: %v %#v", err, replay.Manifest)
	}
	if _, err := service.Submit(context.Background(), SubmissionRequest{WorkspaceID: workspace.ID, Attempt: 1, ClaimedCriteria: []string{"changed"}, IdempotencyKey: "submit-1", Lease: lease}); err != ErrSubmissionConflict {
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
	service, _ := NewService(t.TempDir(), testLeaseValidator{}, nil, nil, nil)
	lease := LeaseProof{ID: "lease-1", FencingToken: 1, ExpiresAt: time.Now().Add(time.Hour)}
	workspace, err := service.CreateWorkspace(context.Background(), WorkspaceRequest{RepositoryPath: source, TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", Attempt: 1, AttemptSeriesID: "series-1", BaseCommit: strings.TrimSpace(base), ModuleSpec: testModule(), AgentIdentity: contracts.AgentIdentity{AgentInstanceID: "agent-1", Role: "EXECUTOR", LeaseID: lease.ID}, Lease: lease})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.WriteFile(context.Background(), WriteRequest{WorkspaceID: workspace.ID, Path: "owned/x.txt", Content: []byte("x"), Lease: LeaseProof{ID: lease.ID, FencingToken: 1, ExpiresAt: time.Now().Add(-time.Second)}}); err != ErrLeaseStale {
		t.Fatalf("expired lease error = %v", err)
	}
	if err := service.WriteFile(context.Background(), WriteRequest{WorkspaceID: workspace.ID, Path: "owned/x.txt", Content: []byte("x"), Lease: LeaseProof{ID: "other-lease", FencingToken: 1, ExpiresAt: time.Now().Add(time.Hour)}}); err != ErrLeaseStale {
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

func testModule() contracts.ModuleSpec {
	return contracts.ModuleSpec{ModuleSpecVersion: 1, PlanVersion: 1, ModuleID: "module-1", ProjectID: "project-1", Name: "Owned", ExecutionPlatform: contracts.PlatformLinux, SandboxLevel: contracts.IsolationContainer, NetworkPolicy: contracts.NetworkPolicy{Mode: contracts.NetworkDenyAll}, WorkloadProfile: contracts.WorkloadProfile{Trust: contracts.WorkloadTrusted}, AllowedPaths: []string{"owned/..."}, ForbiddenPaths: []string{".git/..."}, SHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
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
