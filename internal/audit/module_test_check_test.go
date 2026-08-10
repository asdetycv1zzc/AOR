package audit

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/toolchain"
	"github.com/akimisaka/aor/pkg/contracts"
)

type testToolchainResolver struct {
	root string
}

func (resolver testToolchainResolver) Root() string { return resolver.root }

func (resolver testToolchainResolver) Snapshot(context.Context) (toolchain.Inventory, error) {
	return toolchain.Inventory{Tools: []toolchain.InstalledTool{testInstalledToolchain()}}, nil
}

func (resolver testToolchainResolver) Resolve(context.Context, []string) ([]toolchain.InstalledTool, error) {
	return []toolchain.InstalledTool{testInstalledToolchain()}, nil
}

func testInstalledToolchain() toolchain.InstalledTool {
	return toolchain.InstalledTool{SchemaVersion: 1, ID: "test-tool", Kind: contracts.ToolchainTest, Name: "Test Shell", Version: "1.0.0", Platform: contracts.PlatformLinux, Architecture: "amd64", Languages: []string{"Shell"}, BinDirs: []string{"bin"}, Executables: []toolchain.Executable{{Name: "sh", Path: "bin/sh"}}}
}

func testPinnedToolchain() contracts.VersionedTool {
	return contracts.VersionedTool{InventoryID: "test-tool", Kind: contracts.ToolchainTest, Name: "Test Shell", Version: "1.0.0", Platform: contracts.PlatformLinux, Architecture: "amd64", Source: contracts.ToolchainInstalled}
}

func TestModuleTestCheckRunsTheImmutableSubmissionCommit(t *testing.T) {
	repositoryRoot, head, base := testAuditRepository(t)
	toolchainRoot := filepath.Join(t.TempDir(), "toolchains")
	if err := os.MkdirAll(filepath.Join(toolchainRoot, "test-tool", "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	resolver := testToolchainResolver{root: toolchainRoot}
	check, err := NewModuleTestCheck(repositoryRoot, filepath.Join(t.TempDir(), "work"), resolver, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	result := check.Run(context.Background(), testModuleTestInput(head, base, "verify-pass.sh"))
	if result.Status != StatusPass {
		t.Fatalf("status = %s findings=%#v", result.Status, result.Findings)
	}
	var report struct {
		Command []string `json:"command"`
	}
	if err := json.Unmarshal(result.Result, &report); err != nil || len(report.Command) != 2 || report.Command[0] != "/bin/sh" || report.Command[1] != "verify-pass.sh" {
		t.Fatalf("result command = %#v err=%v", report.Command, err)
	}
	drifted := testModuleTestInput(head, base, "verify-pass.sh")
	drifted.ModuleSpec.Toolchains[0].Version = "1.0.1"
	result = check.Run(context.Background(), drifted)
	if result.Status != StatusError || len(result.Findings) != 1 || result.Findings[0].EvidencePattern != "module-test-toolchain-version" {
		t.Fatalf("toolchain drift result = %#v", result)
	}

	failing, err := NewModuleTestCheck(repositoryRoot, filepath.Join(t.TempDir(), "work"), resolver, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	result = failing.Run(context.Background(), testModuleTestInput(head, base, "verify-fail.sh"))
	if result.Status != StatusFail || len(result.Findings) != 1 {
		t.Fatalf("failing result = %#v", result)
	}
}

func testAuditRepository(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	runAuditGit(t, "", "init", "--initial-branch=main", source)
	runAuditGit(t, source, "config", "user.email", "test@example.invalid")
	runAuditGit(t, source, "config", "user.name", "AOR Test")
	if err := os.WriteFile(filepath.Join(source, "file.txt"), []byte("base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "verify-pass.sh"), []byte("exit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "verify-fail.sh"), []byte("exit 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runAuditGit(t, source, "add", "file.txt", "verify-pass.sh", "verify-fail.sh")
	runAuditGit(t, source, "commit", "-m", "base")
	base := strings.TrimSpace(runAuditGit(t, source, "rev-parse", "HEAD"))
	if err := os.WriteFile(filepath.Join(source, "file.txt"), []byte("head\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runAuditGit(t, source, "commit", "-am", "head")
	head := strings.TrimSpace(runAuditGit(t, source, "rev-parse", "HEAD"))
	repositoryRoot := filepath.Join(root, "repositories")
	repositoryPath, err := repository.ProjectRepositoryPath(repositoryRoot, "tenant_1", "project_1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(repositoryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	runAuditGit(t, "", "clone", "--bare", source, repositoryPath)
	return repositoryRoot, head, base
}

func runAuditGit(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	if directory != "" {
		command.Dir = directory
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v (%s)", arguments, err, output)
	}
	return string(output)
}

func testModuleTestInput(head, base, entrypoint string) DeterministicInput {
	return DeterministicInput{
		TenantID: "tenant_1",
		Manifest: contracts.SubmissionManifest{
			SubmissionVersion: 1, ProjectID: "project_1", ModuleTaskID: "task_1", AttemptSeriesID: "series_1", Attempt: 1,
			ModuleSpecRef: validModuleTestRef(), BaseCommit: base, HeadCommit: head, ChangedFiles: []string{"file.txt"},
			AgentIdentity: contracts.AgentIdentity{AgentInstanceID: "executor_1", Role: "EXECUTOR", LeaseID: "lease_1"}, CreatedAt: time.Now().UTC().Format(time.RFC3339), SHA256: validModuleTestDigest(),
		},
		ModuleSpec: &contracts.ModuleSpec{
			ModuleSpecVersion: 1, ModuleID: "module_1", ProjectID: "project_1", PlanVersion: 1,
			AllowedPaths: []string{"file.txt", "verify-pass.sh", "verify-fail.sh"}, ExecutionPlatform: contracts.PlatformLinux, SandboxLevel: contracts.IsolationContainer,
			NetworkPolicy: contracts.NetworkPolicy{Mode: contracts.NetworkDenyAll}, WorkloadProfile: contracts.WorkloadProfile{Trust: contracts.WorkloadTrusted},
			ToolchainIDs: []string{"test-tool"}, Toolchains: []contracts.VersionedTool{testPinnedToolchain()}, VerificationEntrypoint: entrypoint, SHA256: validModuleTestDigest(),
		},
		AllowedPaths: []string{"file.txt", "verify-pass.sh", "verify-fail.sh"}, Platform: contracts.PlatformLinux,
	}
}

func validModuleTestRef() contracts.SpecRef {
	return contracts.SpecRef{Version: 1, SHA256: validModuleTestDigest()}
}

func validModuleTestDigest() string {
	return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}
