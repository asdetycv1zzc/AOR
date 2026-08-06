package audit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/pkg/contracts"
)

func TestModuleTestCheckRunsTheImmutableSubmissionCommit(t *testing.T) {
	repositoryRoot, head, base := testAuditRepository(t)
	check, err := NewModuleTestCheck(repositoryRoot, filepath.Join(t.TempDir(), "work"), []string{"/bin/true"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	result := check.Run(context.Background(), testModuleTestInput(head, base))
	if result.Status != StatusPass {
		t.Fatalf("status = %s findings=%#v", result.Status, result.Findings)
	}

	failing, err := NewModuleTestCheck(repositoryRoot, filepath.Join(t.TempDir(), "work"), []string{"/bin/false"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	result = failing.Run(context.Background(), testModuleTestInput(head, base))
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
	runAuditGit(t, source, "add", "file.txt")
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

func testModuleTestInput(head, base string) DeterministicInput {
	return DeterministicInput{
		TenantID: "tenant_1",
		Manifest: contracts.SubmissionManifest{
			SubmissionVersion: 1, ProjectID: "project_1", ModuleTaskID: "task_1", AttemptSeriesID: "series_1", Attempt: 1,
			ModuleSpecRef: validModuleTestRef(), BaseCommit: base, HeadCommit: head, ChangedFiles: []string{"file.txt"},
			AgentIdentity: contracts.AgentIdentity{AgentInstanceID: "executor_1", Role: "EXECUTOR", LeaseID: "lease_1"}, CreatedAt: time.Now().UTC().Format(time.RFC3339), SHA256: validModuleTestDigest(),
		},
		AllowedPaths: []string{"file.txt"},
	}
}

func validModuleTestRef() contracts.SpecRef {
	return contracts.SpecRef{Version: 1, SHA256: validModuleTestDigest()}
}

func validModuleTestDigest() string {
	return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}
