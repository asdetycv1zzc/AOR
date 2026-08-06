package servicebootstrap

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
)

type dependencyBaseLeaseValidator struct{}

func (dependencyBaseLeaseValidator) Validate(context.Context, repository.LeaseValidation) error {
	return nil
}

type dependencyBaseTasks []state.ModuleTask

func (tasks dependencyBaseTasks) Tasks(context.Context, string, string) ([]state.ModuleTask, error) {
	return append([]state.ModuleTask(nil), tasks...), nil
}

type dependencyBaseSubmissions map[string]repository.Submission

func (submissions dependencyBaseSubmissions) Submission(_ context.Context, _ string, taskID, _ string, _ int) (repository.Submission, bool, error) {
	submission, found := submissions[taskID]
	return submission, found, nil
}

func TestDependencyWorkspaceBaseIncludesPassedDependency(t *testing.T) {
	ctx := context.Background()
	registry := repository.NewMemoryRegistryStore()
	submissionStore := repository.NewMemorySubmissionStore()
	signer, err := repository.NewHMACSigner([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := repository.NewServiceWithConfig(repository.ServiceConfig{
		Root: t.TempDir(), Leases: dependencyBaseLeaseValidator{}, Submissions: submissionStore,
		Workspaces: registry, ProjectRepositories: registry, Signer: signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	projectRepository, err := service.InitializeProjectRepository(ctx, "tenant-1", "project-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	module := dependencyBaseModule("module-dependency", "modules/dependency/**")
	lease := repository.LeaseProof{ID: "lease-dependency", FencingToken: 1, ExpiresAt: time.Now().Add(time.Hour)}
	workspace, err := service.CreateWorkspace(ctx, repository.WorkspaceRequest{
		TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-dependency", Attempt: 1,
		AttemptSeriesID: "series-dependency", BaseCommit: projectRepository.BaselineCommit, ModuleSpec: module,
		AgentIdentity: contracts.AgentIdentity{AgentInstanceID: "agent-dependency", Role: "EXECUTOR", LeaseID: lease.ID}, Lease: lease,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.WriteFile(ctx, repository.WriteRequest{
		WorkspaceID: workspace.ID, Path: "modules/dependency/value.txt", Content: []byte("passed dependency\n"), Lease: lease,
	}); err != nil {
		t.Fatal(err)
	}
	submission, err := service.Submit(ctx, repository.SubmissionRequest{
		WorkspaceID: workspace.ID, Attempt: 1, ClaimedCriteria: []string{"dependency works"},
		IdempotencyKey: "submit-dependency", Lease: lease,
	})
	if err != nil {
		t.Fatal(err)
	}
	dependency := state.ModuleTask{
		TenantID: "tenant-1", ProjectID: "project-1", ID: "task-dependency", ModuleID: "module-dependency",
		State: contracts.TaskPassed, AttemptSeriesID: "series-dependency", Attempt: 1,
		DependentTaskIDs: []string{"task-downstream"},
	}
	downstream := state.ModuleTask{
		TenantID: "tenant-1", ProjectID: "project-1", ID: "task-downstream", ModuleID: "module-downstream",
		State: contracts.TaskReadyExecution, AttemptSeriesID: "series-downstream",
	}
	resolver, err := newDependencyWorkspaceBaseResolver(service, dependencyBaseTasks{dependency, downstream}, dependencyBaseSubmissions{"task-dependency": submission})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveWorkspaceBaseCommit(ctx, "tenant-1", "project-1", "task-downstream", "series-downstream", 1)
	if err != nil {
		t.Fatal(err)
	}
	if resolved == projectRepository.BaselineCommit {
		t.Fatal("downstream workspace still uses the project baseline")
	}
	command := exec.Command("git", "-C", projectRepository.Path, "merge-base", "--is-ancestor", submission.Manifest.HeadCommit, resolved)
	if output, commandErr := command.CombinedOutput(); commandErr != nil {
		t.Fatalf("dependency commit is not in downstream base: %v: %s", commandErr, output)
	}
	downstreamModule := dependencyBaseModule("module-downstream", "modules/downstream/**")
	downstreamLease := repository.LeaseProof{ID: "lease-downstream", FencingToken: 1, ExpiresAt: time.Now().Add(time.Hour)}
	downstreamWorkspace, err := service.CreateWorkspace(ctx, repository.WorkspaceRequest{
		TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-downstream", Attempt: 1,
		AttemptSeriesID: "series-downstream", BaseCommit: resolved, ModuleSpec: downstreamModule,
		AgentIdentity: contracts.AgentIdentity{AgentInstanceID: "agent-downstream", Role: "EXECUTOR", LeaseID: downstreamLease.ID}, Lease: downstreamLease,
	})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(downstreamWorkspace.Path, "modules", "dependency", "value.txt"))
	if err != nil || string(content) != "passed dependency\n" {
		t.Fatalf("dependency content = %q error=%v", content, err)
	}
	replayed, err := resolver.ResolveWorkspaceBaseCommit(ctx, "tenant-1", "project-1", "task-downstream", "series-downstream", 1)
	if err != nil || replayed != resolved {
		t.Fatalf("replayed base=%q want=%q error=%v", replayed, resolved, err)
	}
}

func dependencyBaseModule(moduleID, allowedPath string) contracts.ModuleSpec {
	return contracts.ModuleSpec{
		ModuleSpecVersion: 1, ModuleID: moduleID, ProjectID: "project-1", PlanVersion: 1,
		Name: moduleID, Purpose: "implement module", Responsibilities: []string{"implementation"},
		AllowedPaths: []string{allowedPath}, ExecutionPlatform: contracts.PlatformLinux,
		SandboxLevel: contracts.IsolationContainer, NetworkPolicy: contracts.NetworkPolicy{Mode: contracts.NetworkDenyAll},
		WorkloadProfile:    contracts.WorkloadProfile{Trust: contracts.WorkloadTrusted},
		AcceptanceCriteria: []string{"dependency works"}, TestRequirements: []string{"go test"},
		SecurityRequirements: []string{"owned paths"},
		SHA256:               "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
}
