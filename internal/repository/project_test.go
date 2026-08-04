package repository

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
)

func TestServiceInitializesBareRepositoryAndMaterializesWorkspace(t *testing.T) {
	root := t.TempDir()
	registry := NewMemoryRegistryStore()
	service := newRegistryTestService(t, root, registry)
	createdAt := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	repository, err := service.InitializeProjectRepository(context.Background(), "tenant-1", "project-1", createdAt)
	if err != nil {
		t.Fatal(err)
	}
	bare, err := runGit(repository.Path, "rev-parse", "--is-bare-repository")
	if err != nil || strings.TrimSpace(bare) != "true" {
		t.Fatalf("repository is not bare: %q error=%v", bare, err)
	}
	if repository.DefaultBranch != "main" || repository.Initialization != RepositoryInitializationEmpty || repository.CreatedAt != createdAt {
		t.Fatalf("repository metadata = %#v", repository)
	}
	if head, err := runGit(repository.Path, "rev-parse", "HEAD"); err != nil || strings.TrimSpace(head) != repository.BaselineCommit {
		t.Fatalf("baseline head = %q error=%v", head, err)
	}

	lease := LeaseProof{ID: "lease-1", FencingToken: 1, ExpiresAt: time.Now().Add(time.Hour)}
	workspace, err := service.CreateWorkspace(context.Background(), WorkspaceRequest{
		TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", Attempt: 1,
		AttemptSeriesID: "series-1", BaseCommit: repository.BaselineCommit, ModuleSpec: testModule(),
		AgentIdentity: contracts.AgentIdentity{AgentInstanceID: "agent-1", Role: "EXECUTOR", LeaseID: lease.ID}, Lease: lease,
	})
	if err != nil {
		t.Fatal(err)
	}
	if workspace.BaseCommit != repository.BaselineCommit || workspace.Branch != "agent/project-1/task-1/attempt-1" {
		t.Fatalf("workspace = %#v", workspace)
	}
	if err := service.WriteFile(context.Background(), WriteRequest{WorkspaceID: workspace.ID, Path: "owned/main.go", Content: []byte("package owned\n"), Lease: lease}); err != nil {
		t.Fatal(err)
	}
	submission, err := service.Submit(context.Background(), SubmissionRequest{
		WorkspaceID: workspace.ID, Attempt: 1, ClaimedCriteria: []string{"criterion-1"},
		IdempotencyKey: "bare-submit-1", Lease: lease,
	})
	if err != nil {
		t.Fatal(err)
	}
	published, err := runGit(repository.Path, "rev-parse", "refs/heads/"+workspace.Branch)
	if err != nil || strings.TrimSpace(published) != submission.Manifest.HeadCommit {
		t.Fatalf("published branch = %q error=%v", published, err)
	}
}

func TestServiceImportsProjectRepositoryAndRejectsConflictingReplay(t *testing.T) {
	source := t.TempDir()
	if _, err := runGit(source, "init", "-b", "trunk"); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, source, "owned/base.txt", "base\n")
	if _, err := runGit(source, "add", "."); err != nil {
		t.Fatal(err)
	}
	if _, err := runGit(source, "commit", "-m", "initial"); err != nil {
		t.Fatal(err)
	}
	sourceHead, err := runGit(source, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}

	service := newRegistryTestService(t, t.TempDir(), NewMemoryRegistryStore())
	request := ProjectRepositoryImportRequest{TenantID: "tenant-1", ProjectID: "project-1", SourcePath: source, CreatedAt: time.Date(2030, 2, 3, 4, 5, 6, 0, time.UTC)}
	repository, err := service.ImportProjectRepository(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if repository.Initialization != RepositoryInitializationImport || repository.DefaultBranch != "trunk" || repository.BaselineCommit != strings.TrimSpace(sourceHead) {
		t.Fatalf("imported repository = %#v", repository)
	}
	if remote, err := runGit(repository.Path, "config", "--get", "remote.origin.url"); err == nil || strings.TrimSpace(remote) != "" {
		t.Fatalf("import retained origin URL %q error=%v", remote, err)
	}
	replay, err := service.ImportProjectRepository(context.Background(), request)
	if err != nil || replay.BaselineCommit != repository.BaselineCommit {
		t.Fatalf("import replay = %#v error=%v", replay, err)
	}

	other := t.TempDir()
	if _, err := runGit(other, "init", "-b", "trunk"); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, other, "owned/other.txt", "other\n")
	if _, err := runGit(other, "add", "."); err != nil {
		t.Fatal(err)
	}
	if _, err := runGit(other, "commit", "-m", "other"); err != nil {
		t.Fatal(err)
	}
	request.SourcePath = other
	if _, err := service.ImportProjectRepository(context.Background(), request); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("conflicting import error = %v", err)
	}
}

func TestServiceRestoresWorkspaceRegistryAfterRestart(t *testing.T) {
	root := t.TempDir()
	registry := NewMemoryRegistryStore()
	service := newRegistryTestService(t, root, registry)
	repository, err := service.InitializeProjectRepository(context.Background(), "tenant-1", "project-1", time.Date(2030, 3, 4, 5, 6, 7, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	lease := LeaseProof{ID: "lease-restart", FencingToken: 2, ExpiresAt: time.Now().Add(time.Hour)}
	workspace, err := service.CreateWorkspace(context.Background(), WorkspaceRequest{
		TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-restart", Attempt: 1,
		AttemptSeriesID: "series-restart", BaseCommit: repository.BaselineCommit, ModuleSpec: testModule(),
		AgentIdentity: contracts.AgentIdentity{AgentInstanceID: "agent-restart", Role: "EXECUTOR", LeaseID: lease.ID}, Lease: lease,
	})
	if err != nil {
		t.Fatal(err)
	}

	restarted := newRegistryTestService(t, root, registry)
	restored, found, err := restarted.WorkspaceContext(context.Background(), workspace.ID)
	if err != nil || !found || restored.Path != workspace.Path || restored.Branch != workspace.Branch {
		t.Fatalf("restored workspace = %#v found=%t error=%v", restored, found, err)
	}
	if err := restarted.WriteFile(context.Background(), WriteRequest{WorkspaceID: workspace.ID, Path: "owned/restarted.txt", Content: []byte("restored\n"), Lease: lease}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(workspace.Path, "owned", "restarted.txt"))
	if err != nil || string(content) != "restored\n" {
		t.Fatalf("restored write = %q error=%v", content, err)
	}
}

func TestServiceRecoversRepositoryRegistrationFromOwnedMarker(t *testing.T) {
	root := t.TempDir()
	createdAt := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
	first := newRegistryTestService(t, root, NewMemoryRegistryStore())
	repository, err := first.InitializeProjectRepository(context.Background(), "tenant-1", "project-1", createdAt)
	if err != nil {
		t.Fatal(err)
	}

	registry := NewMemoryRegistryStore()
	restarted := newRegistryTestService(t, root, registry)
	recovered, err := restarted.InitializeProjectRepository(context.Background(), "tenant-1", "project-1", createdAt.Add(time.Hour))
	if err != nil || recovered.BaselineCommit != repository.BaselineCommit || recovered.CreatedAt != createdAt {
		t.Fatalf("recovered repository = %#v error=%v", recovered, err)
	}
	stored, found, err := registry.LoadProjectRepository(context.Background(), "tenant-1", "project-1")
	if err != nil || !found || stored.BaselineCommit != repository.BaselineCommit {
		t.Fatalf("recovered registry = %#v found=%t error=%v", stored, found, err)
	}
}

func newRegistryTestService(t *testing.T, root string, registry *MemoryRegistryStore) *Service {
	t.Helper()
	service, err := NewServiceWithConfig(ServiceConfig{
		Root: root, Leases: testLeaseValidator{}, Submissions: NewMemorySubmissionStore(),
		Workspaces: registry, ProjectRepositories: registry, Signer: testSubmissionSigner{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}
