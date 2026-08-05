package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/akimisaka/aor/pkg/contracts"
)

type PostgresRegistryStore struct {
	database *sql.DB
}

const workspaceRegistrationMarker = "aor-workspace.json"

type persistedWorkspace struct {
	ID                 string                  `json:"id"`
	TenantID           string                  `json:"tenantId"`
	ProjectID          string                  `json:"projectId"`
	TaskID             string                  `json:"taskId"`
	Attempt            int                     `json:"attempt"`
	AttemptSeriesID    string                  `json:"attemptSeriesId"`
	Path               string                  `json:"path"`
	Branch             string                  `json:"branch"`
	BaseCommit         string                  `json:"baseCommit"`
	AllowedPaths       []string                `json:"allowedPaths"`
	ForbiddenPaths     []string                `json:"forbiddenPaths"`
	AcceptanceCriteria []string                `json:"acceptanceCriteria"`
	ModuleSpecRef      contracts.SpecRef       `json:"moduleSpecRef"`
	AgentIdentity      contracts.AgentIdentity `json:"agentIdentity"`
	OperationLeases    bool                    `json:"operationLeases"`
	GitDir             string                  `json:"gitDir"`
	RepositoryPath     string                  `json:"repositoryPath"`
}

func NewPostgresRegistryStore(database *sql.DB) (*PostgresRegistryStore, error) {
	if database == nil {
		return nil, ErrInvalidRequest
	}
	return &PostgresRegistryStore{database: database}, nil
}

func (store *PostgresRegistryStore) LoadWorkspace(ctx context.Context, id string) (Workspace, bool, error) {
	if store == nil || store.database == nil || ctx == nil || id == "" {
		return Workspace{}, false, ErrInvalidRequest
	}
	tenantID, ok := workspaceTenantID(id)
	if !ok {
		return Workspace{}, false, ErrInvalidRequest
	}
	tx, err := store.begin(ctx, tenantID, true)
	if err != nil {
		return Workspace{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var content []byte
	err = tx.QueryRowContext(ctx, `
SELECT workspace_jsonb
FROM repository_workspaces
WHERE tenant_id = $1::uuid AND id = $2`, tenantID, id).Scan(&content)
	if errors.Is(err, sql.ErrNoRows) {
		return Workspace{}, false, nil
	}
	if err != nil {
		return Workspace{}, false, err
	}
	workspace, err := unmarshalPersistedWorkspace(content)
	if err != nil {
		return Workspace{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Workspace{}, false, err
	}
	return workspace, true, nil
}

func (store *PostgresRegistryStore) StoreWorkspace(ctx context.Context, workspace Workspace) error {
	if store == nil || store.database == nil || ctx == nil || !validStoredWorkspace(workspace) {
		return ErrInvalidRequest
	}
	content, err := marshalPersistedWorkspace(workspace)
	if err != nil {
		return err
	}
	tx, err := store.begin(ctx, workspace.TenantID, false)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
INSERT INTO repository_workspaces
  (id, tenant_id, project_id, module_task_id, attempt_series_id, attempt, workspace_jsonb)
VALUES ($1, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6, $7::jsonb)
ON CONFLICT (tenant_id, id) DO NOTHING`, workspace.ID, workspace.TenantID, workspace.ProjectID,
		workspace.TaskID, workspace.AttemptSeriesID, workspace.Attempt, content)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		var priorContent []byte
		if err := tx.QueryRowContext(ctx, `SELECT workspace_jsonb FROM repository_workspaces WHERE tenant_id = $1::uuid AND id = $2`, workspace.TenantID, workspace.ID).Scan(&priorContent); err != nil {
			return err
		}
		prior, err := unmarshalPersistedWorkspace(priorContent)
		if err != nil {
			return err
		}
		if !sameWorkspace(prior, workspace) {
			return ErrWorkspaceConflict
		}
	}
	return tx.Commit()
}

func (store *PostgresRegistryStore) LoadProjectRepository(ctx context.Context, tenantID, projectID string) (ProjectRepository, bool, error) {
	if store == nil || store.database == nil || ctx == nil || !safeIDPattern.MatchString(tenantID) || !safeIDPattern.MatchString(projectID) {
		return ProjectRepository{}, false, ErrInvalidRequest
	}
	tx, err := store.begin(ctx, tenantID, true)
	if err != nil {
		return ProjectRepository{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var repository ProjectRepository
	err = tx.QueryRowContext(ctx, `
SELECT repository_path, default_branch, baseline_commit, initialization, source_sha256, created_at
FROM project_repositories
WHERE tenant_id = $1::uuid AND project_id = $2::uuid`, tenantID, projectID).Scan(
		&repository.Path, &repository.DefaultBranch, &repository.BaselineCommit,
		&repository.Initialization, &repository.SourceSHA256, &repository.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectRepository{}, false, nil
	}
	if err != nil {
		return ProjectRepository{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return ProjectRepository{}, false, err
	}
	repository.TenantID = tenantID
	repository.ProjectID = projectID
	repository.CreatedAt = repository.CreatedAt.UTC()
	return repository, true, nil
}

func (store *PostgresRegistryStore) StoreProjectRepository(ctx context.Context, repository ProjectRepository) error {
	if store == nil || store.database == nil || ctx == nil || !validStoredProjectRepository(repository) {
		return ErrInvalidRequest
	}
	tx, err := store.begin(ctx, repository.TenantID, false)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
INSERT INTO project_repositories
  (tenant_id, project_id, repository_path, default_branch, baseline_commit, initialization, source_sha256, created_at)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8)
ON CONFLICT (tenant_id, project_id) DO NOTHING`, repository.TenantID, repository.ProjectID, repository.Path,
		repository.DefaultBranch, repository.BaselineCommit, repository.Initialization, repository.SourceSHA256, repository.CreatedAt.UTC())
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		var prior ProjectRepository
		if err := tx.QueryRowContext(ctx, `
SELECT repository_path, default_branch, baseline_commit, initialization, source_sha256, created_at
FROM project_repositories WHERE tenant_id = $1::uuid AND project_id = $2::uuid`, repository.TenantID, repository.ProjectID).Scan(
			&prior.Path, &prior.DefaultBranch, &prior.BaselineCommit, &prior.Initialization, &prior.SourceSHA256, &prior.CreatedAt); err != nil {
			return err
		}
		prior.TenantID, prior.ProjectID, prior.CreatedAt = repository.TenantID, repository.ProjectID, prior.CreatedAt.UTC()
		if !sameProjectRepository(prior, repository) {
			return ErrRepositoryConflict
		}
	}
	return tx.Commit()
}

func (store *PostgresRegistryStore) begin(ctx context.Context, tenantID string, readOnly bool) (*sql.Tx, error) {
	if tenantID == "" {
		return nil, ErrInvalidRequest
	}
	tx, err := store.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: readOnly})
	if err != nil {
		return nil, err
	}
	var superuser, bypassRLS bool
	if err := tx.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS); err != nil || superuser || bypassRLS {
		_ = tx.Rollback()
		if err != nil {
			return nil, err
		}
		return nil, ErrInvalidRequest
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func marshalPersistedWorkspace(workspace Workspace) ([]byte, error) {
	record := persistedWorkspace{
		ID: workspace.ID, TenantID: workspace.TenantID, ProjectID: workspace.ProjectID,
		TaskID: workspace.TaskID, Attempt: workspace.Attempt, AttemptSeriesID: workspace.AttemptSeriesID,
		Path: workspace.Path, Branch: workspace.Branch, BaseCommit: workspace.BaseCommit,
		AllowedPaths: append([]string(nil), workspace.AllowedPaths...), ForbiddenPaths: append([]string(nil), workspace.ForbiddenPaths...),
		AcceptanceCriteria: append([]string(nil), workspace.AcceptanceCriteria...), OperationLeases: workspace.OperationLeases, GitDir: workspace.gitDir,
		RepositoryPath: workspace.repositoryPath,
	}
	record.ModuleSpecRef = workspace.ModuleSpecRef
	record.AgentIdentity = workspace.AgentIdentity
	return json.Marshal(record)
}

func unmarshalPersistedWorkspace(content []byte) (Workspace, error) {
	var record persistedWorkspace
	if len(content) == 0 || json.Unmarshal(content, &record) != nil {
		return Workspace{}, ErrWorkspaceConflict
	}
	workspace := Workspace{
		ID: record.ID, TenantID: record.TenantID, ProjectID: record.ProjectID, TaskID: record.TaskID,
		Attempt: record.Attempt, AttemptSeriesID: record.AttemptSeriesID, Path: record.Path, Branch: record.Branch,
		BaseCommit: record.BaseCommit, AllowedPaths: append([]string(nil), record.AllowedPaths...),
		ForbiddenPaths: append([]string(nil), record.ForbiddenPaths...), AcceptanceCriteria: append([]string(nil), record.AcceptanceCriteria...),
		ModuleSpecRef: record.ModuleSpecRef, AgentIdentity: record.AgentIdentity, OperationLeases: record.OperationLeases,
		gitDir: record.GitDir, repositoryPath: record.RepositoryPath,
	}
	if !validStoredWorkspace(workspace) {
		return Workspace{}, ErrWorkspaceConflict
	}
	return workspace, nil
}

func writeWorkspaceRegistration(workspace Workspace) error {
	content, err := marshalPersistedWorkspace(workspace)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(workspace.gitDir, workspaceRegistrationMarker), content, 0o600)
}

func readWorkspaceRegistration(gitDirectory string) (Workspace, error) {
	content, err := os.ReadFile(filepath.Join(gitDirectory, workspaceRegistrationMarker))
	if err != nil || len(content) > 256<<10 {
		return Workspace{}, ErrWorkspaceConflict
	}
	return unmarshalPersistedWorkspace(content)
}

func validStoredWorkspace(workspace Workspace) bool {
	request := WorkspaceRequest{TenantID: workspace.TenantID, ProjectID: workspace.ProjectID, TaskID: workspace.TaskID, Attempt: workspace.Attempt}
	return len(workspace.ID) <= 512 && workspace.ID == workspaceID(request) && safeIDPattern.MatchString(workspace.TenantID) && safeIDPattern.MatchString(workspace.ProjectID) && safeIDPattern.MatchString(workspace.TaskID) && safeIDPattern.MatchString(workspace.AttemptSeriesID) && workspace.Attempt >= 1 && workspace.Attempt <= 3 && validateCommit(workspace.BaseCommit) == nil && workspace.ModuleSpecRef.Validate() == nil && workspace.AgentIdentity.AgentInstanceID != "" && workspace.AgentIdentity.Role == "EXECUTOR" && workspace.AgentIdentity.LeaseID != "" && filepath.IsAbs(workspace.Path) && filepath.IsAbs(workspace.gitDir) && filepath.IsAbs(workspace.repositoryPath)
}

func validStoredProjectRepository(repository ProjectRepository) bool {
	return safeIDPattern.MatchString(repository.TenantID) && safeIDPattern.MatchString(repository.ProjectID) && filepath.IsAbs(repository.Path) && validBranchName(repository.DefaultBranch) && validateCommit(repository.BaselineCommit) == nil && submissionDigestPattern.MatchString(repository.SourceSHA256) && (repository.Initialization == RepositoryInitializationEmpty || repository.Initialization == RepositoryInitializationImport) && !repository.CreatedAt.IsZero()
}

func workspaceTenantID(id string) (string, bool) {
	index := strings.IndexByte(id, ':')
	if index <= 0 {
		return "", false
	}
	tenantID := id[:index]
	return tenantID, safeIDPattern.MatchString(tenantID)
}

var _ WorkspaceStore = (*PostgresRegistryStore)(nil)
var _ ProjectRepositoryStore = (*PostgresRegistryStore)(nil)
