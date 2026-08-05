package repository

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/google/uuid"
)

func TestPostgresRegistryStoreRequiresDatabase(t *testing.T) {
	if _, err := NewPostgresRegistryStore(nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil database error = %v", err)
	}
}

func TestPersistedWorkspaceRoundTripIncludesServiceOwnedPaths(t *testing.T) {
	workspace := Workspace{
		ID: "tenant-1:" + uuid.Must(uuid.NewV7()).String(), TenantID: "tenant-1", ProjectID: "project-1",
		TaskID: "task-1", Attempt: 1, AttemptSeriesID: "series-1", Path: "/srv/aor/workspace",
		Branch: "agent/project-1/task-1/attempt-1", BaseCommit: strings.Repeat("a", 40),
		AllowedPaths: []string{"owned/..."}, ForbiddenPaths: []string{".git/..."},
		AcceptanceCriteria: []string{"criterion-1"},
		ModuleSpecRef:      contracts.SpecRef{Version: 1, SHA256: "sha256:" + strings.Repeat("b", 64)},
		AgentIdentity:      contracts.AgentIdentity{AgentInstanceID: "agent-1", Role: "EXECUTOR", LeaseID: "lease-1"},
		gitDir:             "/srv/aor/git", repositoryPath: "/srv/aor/project.git",
	}
	content, err := marshalPersistedWorkspace(workspace)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := unmarshalPersistedWorkspace(content)
	if err != nil || !sameWorkspace(restored, workspace) {
		t.Fatalf("workspace round trip = %#v error=%v", restored, err)
	}
	restored.AllowedPaths[0] = "tampered"
	if workspace.AllowedPaths[0] != "owned/..." {
		t.Fatal("workspace round trip retained a mutable slice alias")
	}
}

func TestRepositoryRegistryMigrationIsTenantScopedAndImmutable(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "migrations", "postgres", "000020_repository_registry.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sql := string(content)
	for _, required := range []string{
		"CREATE TABLE project_repositories", "CREATE TABLE repository_workspaces",
		"project_repositories_immutable", "repository_workspaces_immutable",
		"FORCE ROW LEVEL SECURITY", "project_repositories_tenant_policy",
		"repository_workspaces_tenant_policy", "GRANT SELECT, INSERT",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("repository registry migration missing %q", required)
		}
	}
}
