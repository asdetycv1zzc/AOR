package repository

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const projectRepositoryMarker = "aor-repository.json"

var branchNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)

type projectRepositoryMarkerRecord struct {
	TenantID       string    `json:"tenantId"`
	ProjectID      string    `json:"projectId"`
	DefaultBranch  string    `json:"defaultBranch"`
	BaselineCommit string    `json:"baselineCommit"`
	Initialization string    `json:"initialization"`
	SourceSHA256   string    `json:"sourceSha256"`
	CreatedAt      time.Time `json:"createdAt"`
}

func ProjectRepositoryPath(root, tenantID, projectID string) (string, error) {
	if root == "" || !safeIDPattern.MatchString(tenantID) || !safeIDPattern.MatchString(projectID) {
		return "", ErrInvalidRequest
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", ErrInvalidRequest
	}
	result := filepath.Join(absolute, "projects", cleanID(tenantID), cleanID(projectID)+".git")
	relative, err := filepath.Rel(absolute, result)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", ErrInvalidRequest
	}
	return result, nil
}

func (s *Service) InitializeProjectRepository(ctx context.Context, tenantID, projectID string, createdAt time.Time) (ProjectRepository, error) {
	return s.provisionProjectRepository(ctx, ProjectRepositoryImportRequest{
		TenantID: tenantID, ProjectID: projectID, DefaultBranch: "main", CreatedAt: createdAt,
	}, RepositoryInitializationEmpty)
}

func (s *Service) ResolveWorkspaceBaseCommit(ctx context.Context, tenantID, projectID, taskID, attemptSeriesID string, attempt int) (string, error) {
	if s == nil || ctx == nil || !safeIDPattern.MatchString(tenantID) || !safeIDPattern.MatchString(projectID) || !safeIDPattern.MatchString(taskID) || !safeIDPattern.MatchString(attemptSeriesID) || attempt < 1 || attempt > 3 {
		return "", ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	repository, found, err := s.ProjectRepository(ctx, tenantID, projectID)
	if err != nil {
		return "", err
	}
	if !found {
		repository, err = s.InitializeProjectRepository(ctx, tenantID, projectID, s.clock().UTC())
		if err != nil {
			return "", err
		}
	}
	if attempt == 1 {
		return resolveProjectCommit(ctx, repository, "refs/heads/"+repository.DefaultBranch, ErrRepositoryConflict)
	}

	previous, found, err := s.store.Get(ctx, tenantID, taskID, attemptSeriesID, attempt-1)
	if err != nil {
		return "", err
	}
	if !found {
		return "", ErrInitialCommitNeeded
	}
	if err := validateStoredSubmission(previous); err != nil {
		return "", ErrSubmissionConflict
	}
	manifest := previous.Manifest
	if previous.Workspace.TenantID != tenantID || manifest.ProjectID != projectID || manifest.ModuleTaskID != taskID || manifest.AttemptSeriesID != attemptSeriesID || manifest.Attempt != attempt-1 {
		return "", ErrSubmissionConflict
	}
	payload, err := manifestPayload(manifest)
	if err != nil || s.signer.Verify(ctx, payload, manifest.Signature) != nil {
		return "", ErrSubmissionConflict
	}
	branch := workspaceBranch(WorkspaceRequest{ProjectID: projectID, TaskID: taskID, Attempt: attempt - 1})
	commit, err := resolveProjectCommit(ctx, repository, "refs/heads/"+branch, ErrSubmissionConflict)
	if err != nil || commit != manifest.HeadCommit {
		return "", ErrSubmissionConflict
	}
	return commit, nil
}

func resolveProjectCommit(ctx context.Context, repository ProjectRepository, revision string, failure error) (string, error) {
	commit, err := gitFrom(ctx, repository.Path, "--git-dir", repository.Path, "rev-parse", "--verify", revision+"^{commit}")
	if err != nil {
		return "", failure
	}
	commit = strings.TrimSpace(commit)
	if validateCommit(commit) != nil {
		return "", failure
	}
	return commit, nil
}

func (s *Service) ImportProjectRepository(ctx context.Context, request ProjectRepositoryImportRequest) (ProjectRepository, error) {
	if strings.TrimSpace(request.SourcePath) == "" {
		return ProjectRepository{}, ErrInvalidRequest
	}
	return s.provisionProjectRepository(ctx, request, RepositoryInitializationImport)
}

func (s *Service) ProjectRepository(ctx context.Context, tenantID, projectID string) (ProjectRepository, bool, error) {
	if s == nil || contextErr(ctx) != nil || !safeIDPattern.MatchString(tenantID) || !safeIDPattern.MatchString(projectID) {
		return ProjectRepository{}, false, ErrInvalidRequest
	}
	repository, found, err := s.repositoryStore.LoadProjectRepository(ctx, tenantID, projectID)
	if err != nil || !found {
		return ProjectRepository{}, found, err
	}
	if err := s.validateProjectRepository(ctx, repository); err != nil {
		return ProjectRepository{}, false, err
	}
	return repository, true, nil
}

func (s *Service) provisionProjectRepository(ctx context.Context, request ProjectRepositoryImportRequest, initialization string) (ProjectRepository, error) {
	if s == nil || contextErr(ctx) != nil || !safeIDPattern.MatchString(request.TenantID) || !safeIDPattern.MatchString(request.ProjectID) {
		return ProjectRepository{}, ErrInvalidRequest
	}
	if request.CreatedAt.IsZero() {
		request.CreatedAt = s.clock().UTC().Truncate(time.Microsecond)
	} else {
		request.CreatedAt = request.CreatedAt.UTC().Truncate(time.Microsecond)
	}
	defaultBranch := request.DefaultBranch
	if initialization == RepositoryInitializationEmpty && defaultBranch == "" {
		defaultBranch = "main"
	}
	if defaultBranch != "" && !validBranchName(defaultBranch) {
		return ProjectRepository{}, ErrInvalidRequest
	}
	sourcePath := ""
	if initialization == RepositoryInitializationImport {
		absolute, err := filepath.Abs(request.SourcePath)
		if err != nil {
			return ProjectRepository{}, ErrInvalidRequest
		}
		info, err := os.Lstat(absolute)
		if err != nil || !info.IsDir() || unsafePathInfo(info) {
			return ProjectRepository{}, ErrInvalidRequest
		}
		if _, err := gitFrom(ctx, absolute, "rev-parse", "--git-dir"); err != nil {
			return ProjectRepository{}, ErrInitialCommitNeeded
		}
		sourcePath = absolute
	} else if initialization != RepositoryInitializationEmpty {
		return ProjectRepository{}, ErrInvalidRequest
	}
	sourceSHA256 := DigestBytes([]byte(initialization + "\x00" + sourcePath + "\x00" + defaultBranch))

	s.repositoryMu.Lock()
	defer s.repositoryMu.Unlock()
	if existing, found, err := s.repositoryStore.LoadProjectRepository(ctx, request.TenantID, request.ProjectID); err != nil {
		return ProjectRepository{}, err
	} else if found {
		if existing.Initialization != initialization || existing.SourceSHA256 != sourceSHA256 || defaultBranch != "" && existing.DefaultBranch != defaultBranch {
			return ProjectRepository{}, ErrRepositoryConflict
		}
		if err := s.validateProjectRepository(ctx, existing); err != nil {
			return ProjectRepository{}, err
		}
		return existing, nil
	}

	destination, err := ProjectRepositoryPath(s.root, request.TenantID, request.ProjectID)
	if err != nil {
		return ProjectRepository{}, err
	}
	if _, err := os.Lstat(destination); err == nil {
		return s.recoverProjectRepository(ctx, destination, request, initialization, sourceSHA256, defaultBranch)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ProjectRepository{}, err
	}
	stagingRoot := filepath.Join(s.root, ".aor-staging")
	if err := os.MkdirAll(stagingRoot, 0o700); err != nil {
		return ProjectRepository{}, err
	}
	if err := rejectSymlinkTree(s.root, stagingRoot); err != nil {
		return ProjectRepository{}, err
	}
	stage, err := os.MkdirTemp(stagingRoot, "project-")
	if err != nil {
		return ProjectRepository{}, err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	stageRepository := filepath.Join(stage, "repository.git")
	var baselineCommit string
	if initialization == RepositoryInitializationEmpty {
		baselineCommit, err = initializeBareRepository(ctx, stageRepository, defaultBranch, request.CreatedAt)
	} else {
		defaultBranch, baselineCommit, err = importBareRepository(ctx, sourcePath, stageRepository, defaultBranch)
	}
	if err != nil {
		return ProjectRepository{}, err
	}
	if err := s.hardenProjectRepository(ctx, stageRepository); err != nil {
		return ProjectRepository{}, err
	}
	repository := ProjectRepository{
		TenantID: request.TenantID, ProjectID: request.ProjectID, Path: destination,
		DefaultBranch: defaultBranch, BaselineCommit: baselineCommit,
		Initialization: initialization, SourceSHA256: sourceSHA256, CreatedAt: request.CreatedAt,
	}
	if err := writeProjectRepositoryMarker(stageRepository, repository); err != nil {
		return ProjectRepository{}, err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return ProjectRepository{}, err
	}
	if err := rejectSymlinkTree(s.root, filepath.Dir(destination)); err != nil {
		return ProjectRepository{}, err
	}
	if err := os.Rename(stageRepository, destination); err != nil {
		if _, statErr := os.Lstat(destination); statErr == nil {
			return s.recoverProjectRepository(ctx, destination, request, initialization, sourceSHA256, defaultBranch)
		}
		return ProjectRepository{}, err
	}
	if err := s.repositoryStore.StoreProjectRepository(ctx, repository); err != nil {
		return ProjectRepository{}, err
	}
	return repository, nil
}

func initializeBareRepository(ctx context.Context, repositoryPath, defaultBranch string, createdAt time.Time) (string, error) {
	if _, err := gitFrom(ctx, filepath.Dir(repositoryPath), "init", "--bare", "--initial-branch="+defaultBranch, repositoryPath); err != nil {
		return "", ErrGitUnavailable
	}
	tree, err := gitFrom(ctx, repositoryPath, "--git-dir", repositoryPath, "mktree")
	if err != nil {
		return "", ErrGitUnavailable
	}
	environment := []string{"GIT_AUTHOR_DATE=" + createdAt.Format(time.RFC3339), "GIT_COMMITTER_DATE=" + createdAt.Format(time.RFC3339)}
	commit, err := gitFromWithEnvironment(ctx, repositoryPath, environment, "--git-dir", repositoryPath, "commit-tree", strings.TrimSpace(tree), "-m", "chore(aor): initialize project repository")
	if err != nil {
		return "", ErrGitUnavailable
	}
	commit = strings.TrimSpace(commit)
	if validateCommit(commit) != nil {
		return "", ErrGitUnavailable
	}
	if _, err := gitFrom(ctx, repositoryPath, "--git-dir", repositoryPath, "update-ref", "refs/heads/"+defaultBranch, commit); err != nil {
		return "", ErrGitUnavailable
	}
	if _, err := gitFrom(ctx, repositoryPath, "--git-dir", repositoryPath, "symbolic-ref", "HEAD", "refs/heads/"+defaultBranch); err != nil {
		return "", ErrGitUnavailable
	}
	return commit, nil
}

func importBareRepository(ctx context.Context, sourcePath, repositoryPath, requestedBranch string) (string, string, error) {
	if _, err := gitFrom(ctx, filepath.Dir(repositoryPath), "clone", "--bare", "--no-local", sourcePath, repositoryPath); err != nil {
		return "", "", ErrGitUnavailable
	}
	defaultBranch := requestedBranch
	if defaultBranch == "" {
		value, err := gitFrom(ctx, repositoryPath, "--git-dir", repositoryPath, "symbolic-ref", "--short", "HEAD")
		if err != nil {
			return "", "", ErrInitialCommitNeeded
		}
		defaultBranch = strings.TrimSpace(value)
	}
	if !validBranchName(defaultBranch) {
		return "", "", ErrInvalidRequest
	}
	baseline, err := gitFrom(ctx, repositoryPath, "--git-dir", repositoryPath, "rev-parse", "--verify", "refs/heads/"+defaultBranch+"^{commit}")
	if err != nil {
		return "", "", ErrInitialCommitNeeded
	}
	baseline = strings.TrimSpace(baseline)
	if validateCommit(baseline) != nil {
		return "", "", ErrInitialCommitNeeded
	}
	if _, err := gitFrom(ctx, repositoryPath, "--git-dir", repositoryPath, "symbolic-ref", "HEAD", "refs/heads/"+defaultBranch); err != nil {
		return "", "", ErrGitUnavailable
	}
	return defaultBranch, baseline, nil
}

func (s *Service) hardenProjectRepository(ctx context.Context, repositoryPath string) error {
	disabledHooks := filepath.Join(s.root, ".aor-disabled-hooks")
	if err := os.MkdirAll(disabledHooks, 0o700); err != nil {
		return err
	}
	settings := [][2]string{
		{"core.hooksPath", disabledHooks},
		{"core.fsmonitor", "false"},
		{"fetch.fsckObjects", "true"},
		{"receive.fsckObjects", "true"},
		{"receive.denyDeletes", "true"},
		{"receive.denyNonFastForwards", "true"},
		{"transfer.fsckObjects", "true"},
	}
	for _, setting := range settings {
		if _, err := gitFrom(ctx, repositoryPath, "--git-dir", repositoryPath, "config", setting[0], setting[1]); err != nil {
			return ErrGitUnavailable
		}
	}
	_, _ = gitFrom(ctx, repositoryPath, "--git-dir", repositoryPath, "config", "--remove-section", "remote.origin")
	return nil
}

func (s *Service) recoverProjectRepository(ctx context.Context, destination string, request ProjectRepositoryImportRequest, initialization, sourceSHA256, requestedBranch string) (ProjectRepository, error) {
	marker, err := readProjectRepositoryMarker(destination)
	if err != nil || marker.TenantID != request.TenantID || marker.ProjectID != request.ProjectID || marker.Initialization != initialization || marker.SourceSHA256 != sourceSHA256 || requestedBranch != "" && marker.DefaultBranch != requestedBranch {
		return ProjectRepository{}, ErrRepositoryConflict
	}
	repository := ProjectRepository{
		TenantID: marker.TenantID, ProjectID: marker.ProjectID, Path: destination,
		DefaultBranch: marker.DefaultBranch, BaselineCommit: marker.BaselineCommit,
		Initialization: marker.Initialization, SourceSHA256: marker.SourceSHA256, CreatedAt: marker.CreatedAt.UTC(),
	}
	if err := s.validateProjectRepository(ctx, repository); err != nil {
		return ProjectRepository{}, err
	}
	if err := s.repositoryStore.StoreProjectRepository(ctx, repository); err != nil {
		return ProjectRepository{}, err
	}
	return repository, nil
}

func (s *Service) validateProjectRepository(ctx context.Context, repository ProjectRepository) error {
	if !safeIDPattern.MatchString(repository.TenantID) || !safeIDPattern.MatchString(repository.ProjectID) || !validBranchName(repository.DefaultBranch) || validateCommit(repository.BaselineCommit) != nil || !submissionDigestPattern.MatchString(repository.SourceSHA256) || repository.CreatedAt.IsZero() || repository.Initialization != RepositoryInitializationEmpty && repository.Initialization != RepositoryInitializationImport {
		return ErrRepositoryConflict
	}
	expectedPath, err := ProjectRepositoryPath(s.root, repository.TenantID, repository.ProjectID)
	if err != nil || filepath.Clean(expectedPath) != filepath.Clean(repository.Path) {
		return ErrRepositoryConflict
	}
	if err := rejectSymlinkTree(s.root, repository.Path); err != nil {
		return ErrRepositoryConflict
	}
	info, err := os.Lstat(repository.Path)
	if err != nil || !info.IsDir() || unsafePathInfo(info) {
		return ErrRepositoryNotFound
	}
	if _, err := gitFrom(ctx, repository.Path, "--git-dir", repository.Path, "rev-parse", "--verify", repository.BaselineCommit+"^{commit}"); err != nil {
		return ErrRepositoryConflict
	}
	if _, err := gitFrom(ctx, repository.Path, "--git-dir", repository.Path, "rev-parse", "--verify", "refs/heads/"+repository.DefaultBranch+"^{commit}"); err != nil {
		return ErrRepositoryConflict
	}
	marker, err := readProjectRepositoryMarker(repository.Path)
	if err != nil || marker.TenantID != repository.TenantID || marker.ProjectID != repository.ProjectID || marker.BaselineCommit != repository.BaselineCommit || marker.DefaultBranch != repository.DefaultBranch || marker.Initialization != repository.Initialization || marker.SourceSHA256 != repository.SourceSHA256 || !marker.CreatedAt.Equal(repository.CreatedAt) {
		return ErrRepositoryConflict
	}
	return nil
}

func writeProjectRepositoryMarker(repositoryPath string, repository ProjectRepository) error {
	record := projectRepositoryMarkerRecord{
		TenantID: repository.TenantID, ProjectID: repository.ProjectID,
		DefaultBranch: repository.DefaultBranch, BaselineCommit: repository.BaselineCommit,
		Initialization: repository.Initialization, SourceSHA256: repository.SourceSHA256,
		CreatedAt: repository.CreatedAt.UTC(),
	}
	content, err := json.Marshal(record)
	if err != nil {
		return ErrInvalidRequest
	}
	return os.WriteFile(filepath.Join(repositoryPath, projectRepositoryMarker), content, 0o600)
}

func readProjectRepositoryMarker(repositoryPath string) (projectRepositoryMarkerRecord, error) {
	content, err := os.ReadFile(filepath.Join(repositoryPath, projectRepositoryMarker))
	if err != nil || len(content) > 64<<10 {
		return projectRepositoryMarkerRecord{}, ErrRepositoryConflict
	}
	var marker projectRepositoryMarkerRecord
	if json.Unmarshal(content, &marker) != nil {
		return projectRepositoryMarkerRecord{}, ErrRepositoryConflict
	}
	return marker, nil
}

func validBranchName(value string) bool {
	return branchNamePattern.MatchString(value) && !strings.Contains(value, "..") &&
		!strings.Contains(value, "//") && !strings.HasPrefix(value, ".") &&
		!strings.HasSuffix(value, ".") && !strings.HasSuffix(value, "/") &&
		!strings.HasSuffix(value, ".lock") && !strings.ContainsAny(value, "~^:?*[\\")
}
