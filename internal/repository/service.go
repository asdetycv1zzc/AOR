package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akimisaka/aor/internal/observability"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/google/uuid"
)

var (
	safeIDPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	artifactDigestPattern = regexp.MustCompile(`^artifact://sha256/[0-9a-f]{64}$`)
)

type Service struct {
	root            string
	leases          LeaseValidator
	store           SubmissionStore
	workspaceStore  WorkspaceStore
	repositoryStore ProjectRepositoryStore
	signer          Signer
	clock           func() time.Time
	mu              sync.RWMutex
	workspaceMu     sync.Mutex
	submitMu        sync.Mutex
	repositoryMu    sync.Mutex
	workspaces      map[string]Workspace
}

type ServiceConfig struct {
	Root                string
	Leases              LeaseValidator
	Submissions         SubmissionStore
	Workspaces          WorkspaceStore
	ProjectRepositories ProjectRepositoryStore
	Signer              Signer
	Clock               func() time.Time
}

func NewService(root string, leases LeaseValidator, store SubmissionStore, signer Signer, clock func() time.Time) (*Service, error) {
	registry := NewMemoryRegistryStore()
	return NewServiceWithConfig(ServiceConfig{
		Root: root, Leases: leases, Submissions: store, Workspaces: registry,
		ProjectRepositories: registry, Signer: signer, Clock: clock,
	})
}

func NewServiceWithConfig(config ServiceConfig) (*Service, error) {
	if config.Root == "" || config.Leases == nil || config.Signer == nil {
		return nil, ErrInvalidRequest
	}
	absolute, err := filepath.Abs(config.Root)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, ErrInvalidRequest
	}
	if info, statErr := os.Lstat(absolute); statErr != nil || !info.IsDir() || unsafePathInfo(info) {
		return nil, ErrInvalidRequest
	}
	if config.Submissions == nil {
		config.Submissions = NewMemorySubmissionStore()
	}
	if config.Workspaces == nil || config.ProjectRepositories == nil {
		registry := NewMemoryRegistryStore()
		if config.Workspaces == nil {
			config.Workspaces = registry
		}
		if config.ProjectRepositories == nil {
			config.ProjectRepositories = registry
		}
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Service{
		root: absolute, leases: config.Leases, store: config.Submissions,
		workspaceStore: config.Workspaces, repositoryStore: config.ProjectRepositories,
		signer: config.Signer, clock: config.Clock, workspaces: make(map[string]Workspace),
	}, nil
}

func (s *Service) CreateWorkspace(ctx context.Context, request WorkspaceRequest) (Workspace, error) {
	s.workspaceMu.Lock()
	defer s.workspaceMu.Unlock()
	if err := contextErr(ctx); err != nil {
		return Workspace{}, err
	}
	executionLeaseID := request.ExecutionLeaseID
	if executionLeaseID == "" {
		executionLeaseID = request.Lease.ID
	}
	if !safeIDPattern.MatchString(request.TenantID) || !safeIDPattern.MatchString(request.ProjectID) || !safeIDPattern.MatchString(request.TaskID) || !safeIDPattern.MatchString(request.AttemptSeriesID) || request.Attempt < 1 || request.Attempt > 3 || request.ModuleSpec.Validate() != nil || request.AgentIdentity.AgentInstanceID == "" || request.AgentIdentity.Role != "EXECUTOR" || request.AgentIdentity.LeaseID != executionLeaseID || request.Lease.ID == "" || request.Lease.FencingToken < 1 {
		return Workspace{}, ErrInvalidRequest
	}
	if err := validateCommit(request.BaseCommit); err != nil {
		return Workspace{}, ErrInvalidRequest
	}
	workspaceRoot := filepath.Join(s.root, ".aor-workspaces")
	source, err := s.workspaceRepositoryPath(ctx, request)
	if err != nil {
		return Workspace{}, err
	}
	directory := filepath.Join(workspaceRoot, cleanID(request.TenantID), cleanID(request.ProjectID), cleanID(request.TaskID), fmt.Sprintf("attempt-%d", request.Attempt))
	gitDirectory := filepath.Join(s.root, ".aor-git", workspaceRequestDigest(request))
	if filepath.Clean(source) == filepath.Clean(directory) {
		return Workspace{}, ErrInvalidRequest
	}
	moduleSpecRef := contracts.SpecRef{Version: request.ModuleSpec.ModuleSpecVersion, SHA256: request.ModuleSpec.SHA256}
	parameterDigest, err := leaseParameterDigest(struct {
		Source          string            `json:"source"`
		BaseCommit      string            `json:"baseCommit"`
		ModuleSpecRef   contracts.SpecRef `json:"moduleSpecRef"`
		AttemptSeriesID string            `json:"attemptSeriesId"`
		Attempt         int               `json:"attempt"`
	}{source, request.BaseCommit, moduleSpecRef, request.AttemptSeriesID, request.Attempt})
	if err != nil {
		return Workspace{}, err
	}
	validation := LeaseValidation{Proof: request.Lease, ExecutionLeaseID: executionLeaseID, Action: LeaseActionCreateWorkspace, TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID, AttemptSeriesID: request.AttemptSeriesID, Attempt: request.Attempt, ModuleSpecRef: moduleSpecRef, AgentInstanceID: request.AgentIdentity.AgentInstanceID, Role: request.AgentIdentity.Role, ResourcePath: directory, ParameterDigest: parameterDigest}
	if err := s.validateLease(ctx, validation); err != nil {
		return Workspace{}, err
	}
	template := Workspace{TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID, Attempt: request.Attempt, AttemptSeriesID: request.AttemptSeriesID, Path: directory, Branch: workspaceBranch(request), BaseCommit: request.BaseCommit, AllowedPaths: append([]string(nil), request.ModuleSpec.AllowedPaths...), ForbiddenPaths: effectiveForbiddenPaths(request.ModuleSpec.ForbiddenPaths), AcceptanceCriteria: append([]string(nil), request.ModuleSpec.AcceptanceCriteria...), ModuleSpecRef: moduleSpecRef, AgentIdentity: request.AgentIdentity, OperationLeases: request.ExecutionLeaseID != "" && request.ExecutionLeaseID != request.Lease.ID, gitDir: gitDirectory, repositoryPath: source}
	if prior, found, priorErr := s.workspaceStore.LoadWorkspaceByAttempt(ctx, request.TenantID, request.TaskID, request.AttemptSeriesID, request.Attempt); priorErr != nil {
		return Workspace{}, priorErr
	} else if found {
		expected := template
		expected.ID = prior.ID
		if !sameWorkspace(prior, expected) {
			return Workspace{}, ErrWorkspaceConflict
		}
		if err := s.validateRecoveredWorkspace(ctx, prior); err != nil {
			return Workspace{}, err
		}
		s.mu.Lock()
		s.workspaces[prior.ID] = prior
		s.mu.Unlock()
		return cloneWorkspace(prior), nil
	}
	if pathExists(directory) || pathExists(gitDirectory) {
		recovered, err := readWorkspaceRegistration(gitDirectory)
		expected := template
		expected.ID = recovered.ID
		if err != nil || !sameWorkspace(recovered, expected) {
			return Workspace{}, ErrWorkspaceConflict
		}
		if err := s.validateRecoveredWorkspace(ctx, recovered); err != nil {
			return Workspace{}, err
		}
		if err := s.validateLease(ctx, validation); err != nil {
			return Workspace{}, err
		}
		persisted, err := s.persistWorkspace(ctx, recovered, template)
		if err != nil {
			return Workspace{}, err
		}
		s.mu.Lock()
		s.workspaces[persisted.ID] = persisted
		s.mu.Unlock()
		return cloneWorkspace(persisted), nil
	}
	id, err := newWorkspaceID(request.TenantID)
	if err != nil {
		return Workspace{}, err
	}
	workspace := template
	workspace.ID = id
	if err := os.MkdirAll(filepath.Dir(directory), 0o700); err != nil {
		return Workspace{}, err
	}
	if err := rejectSymlinkTree(s.root, directory); err != nil {
		return Workspace{}, err
	}
	if err := cloneRepository(ctx, source, directory, gitDirectory); err != nil {
		cleanupWorkspace(directory, gitDirectory)
		return Workspace{}, err
	}
	if err := configureWorkspaceVisibility(ctx, directory, request.ModuleSpec.AllowedPaths, request.ModuleSpec.ForbiddenPaths); err != nil {
		cleanupWorkspace(directory, gitDirectory)
		return Workspace{}, err
	}
	if _, err := git(ctx, directory, "rev-parse", "--verify", request.BaseCommit+"^{commit}"); err != nil {
		if _, fetchErr := git(ctx, directory, "fetch", "--no-tags", "--no-write-fetch-head", source, request.BaseCommit); fetchErr != nil {
			cleanupWorkspace(directory, gitDirectory)
			return Workspace{}, ErrInitialCommitNeeded
		}
		if _, verifyErr := git(ctx, directory, "rev-parse", "--verify", request.BaseCommit+"^{commit}"); verifyErr != nil {
			cleanupWorkspace(directory, gitDirectory)
			return Workspace{}, ErrInitialCommitNeeded
		}
	}
	if err := checkoutCommit(ctx, workspace, request.BaseCommit); err != nil {
		cleanupWorkspace(directory, gitDirectory)
		return Workspace{}, err
	}
	if err := s.validateLease(ctx, validation); err != nil {
		cleanupWorkspace(directory, gitDirectory)
		return Workspace{}, err
	}
	if err := writeWorkspaceRegistration(workspace); err != nil {
		cleanupWorkspace(directory, gitDirectory)
		return Workspace{}, err
	}
	persisted, err := s.persistWorkspace(ctx, workspace, template)
	if err != nil {
		return Workspace{}, err
	}
	s.mu.Lock()
	s.workspaces[persisted.ID] = persisted
	s.mu.Unlock()
	return cloneWorkspace(persisted), nil
}

func (s *Service) WriteFile(ctx context.Context, request WriteRequest) error {
	workspace, err := s.workspace(ctx, request.WorkspaceID)
	if err != nil {
		return err
	}
	relative, err := ownedPath(workspace, request.Path)
	if err != nil {
		return err
	}
	if len(request.Content) > 4<<20 {
		return ErrInvalidRequest
	}
	parameterDigest, err := leaseParameterDigest(struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int    `json:"size"`
	}{relative, DigestBytes(request.Content), len(request.Content)})
	if err != nil {
		return err
	}
	if err := s.validateWorkspaceLease(ctx, workspace, request.Lease, LeaseActionWriteFile, relative, parameterDigest); err != nil {
		return err
	}
	target := filepath.Join(workspace.Path, filepath.FromSlash(relative))
	if err := rejectSymlinkTree(workspace.Path, target); err != nil {
		return err
	}
	if info, statErr := os.Lstat(target); statErr == nil && unsafePathInfo(info) {
		return ErrPathDenied
	}
	if err := s.validateWorkspaceLease(ctx, workspace, request.Lease, LeaseActionWriteFile, relative, parameterDigest); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	file, err := openFileNoFollow(target)
	if err != nil {
		return err
	}
	defer file.Close()
	if unsafeOpenedFile(file) {
		return ErrPathDenied
	}
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := file.Write(request.Content); err != nil {
		return err
	}
	return file.Sync()
}

func (s *Service) DeleteFile(ctx context.Context, request DeleteRequest) error {
	workspace, err := s.workspace(ctx, request.WorkspaceID)
	if err != nil {
		return err
	}
	relative, err := ownedPath(workspace, request.Path)
	if err != nil {
		return err
	}
	parameterDigest, err := leaseParameterDigest(struct {
		Path string `json:"path"`
	}{relative})
	if err != nil {
		return err
	}
	if err := s.validateWorkspaceLease(ctx, workspace, request.Lease, LeaseActionDeleteFile, relative, parameterDigest); err != nil {
		return err
	}
	target := filepath.Join(workspace.Path, filepath.FromSlash(relative))
	if err := rejectSymlinkTree(workspace.Path, target); err != nil {
		return err
	}
	if err := s.validateWorkspaceLease(ctx, workspace, request.Lease, LeaseActionDeleteFile, relative, parameterDigest); err != nil {
		return err
	}
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Service) ReadFile(ctx context.Context, workspaceID, name string) ([]byte, error) {
	workspace, err := s.workspace(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	relative, err := ownedPath(workspace, name)
	if err != nil {
		return nil, err
	}
	target := filepath.Join(workspace.Path, filepath.FromSlash(relative))
	if err := rejectSymlinkTree(workspace.Path, target); err != nil {
		return nil, err
	}
	file, err := openReadFileNoFollow(target)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if unsafeOpenedFile(file) {
		return nil, ErrPathDenied
	}
	content, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(content) > 4<<20 {
		return nil, ErrInvalidRequest
	}
	return append([]byte(nil), content...), nil
}

func (s *Service) Submit(ctx context.Context, request SubmissionRequest) (submission Submission, resultErr error) {
	s.submitMu.Lock()
	defer s.submitMu.Unlock()
	workspace, err := s.workspace(ctx, request.WorkspaceID)
	if err != nil {
		return Submission{}, err
	}
	ctx, traceSpan := observability.StartSpan(ctx, observability.SpanRepoCommit, observability.Correlation{
		ProjectID:        workspace.ProjectID,
		WorkflowIDReason: observability.ReasonUnavailable,
		TaskID:           workspace.TaskID,
		AgentRunIDReason: observability.ReasonUnavailable,
	}, map[string]string{
		"aor.agent.id":            workspace.AgentIdentity.AgentInstanceID,
		"aor.agent.role":          workspace.AgentIdentity.Role,
		"aor.module_spec.version": strconv.Itoa(workspace.ModuleSpecRef.Version),
	})
	defer func() {
		attributes := map[string]string{}
		if submission.Manifest.HeadCommit != "" {
			attributes["aor.repo.commit.id"] = submission.Manifest.HeadCommit
		}
		observability.EndSpan(ctx, traceSpan, resultErr, observability.TraceOutcome{Attempt: request.Attempt}, attributes)
	}()
	if request.Attempt != workspace.Attempt || request.Attempt < 1 || request.Attempt > 3 || !safeCommitMetadata(request.IdempotencyKey) {
		return Submission{}, ErrInvalidRequest
	}
	if !validSubmissionMetadata(workspace, request) {
		return Submission{}, ErrInvalidRequest
	}
	if request.CreatedAt.IsZero() {
		request.CreatedAt = s.clock().UTC()
	}
	if !request.CreatedAt.Before(s.clock().UTC().Add(time.Minute)) {
		return Submission{}, ErrInvalidRequest
	}
	requestDigest, err := submissionRequestDigest(request)
	if err != nil {
		return Submission{}, err
	}
	if err := s.validateWorkspaceLease(ctx, workspace, request.Lease, LeaseActionSubmit, workspace.Path, requestDigest); err != nil {
		return Submission{}, err
	}
	if prior, found, err := s.store.Get(ctx, workspace.TenantID, workspace.TaskID, workspace.AttemptSeriesID, request.Attempt); err != nil {
		return Submission{}, err
	} else if found {
		if prior.IdempotencyKey != request.IdempotencyKey || prior.RequestSHA256 != requestDigest {
			return Submission{}, ErrSubmissionConflict
		}
		return cloneSubmission(prior), nil
	}
	changed, deleted, created, err := s.commitWorkspace(ctx, workspace, request.Lease, requestDigest, request.IdempotencyKey)
	if err != nil {
		return Submission{}, err
	}
	head, err := git(ctx, workspace.Path, "rev-parse", "HEAD")
	if err != nil {
		return Submission{}, ErrGitUnavailable
	}
	head = strings.TrimSpace(head)
	if err := s.validateWorkspaceLease(ctx, workspace, request.Lease, LeaseActionSubmit, workspace.Path, requestDigest); err != nil {
		return Submission{}, err
	}
	if err := s.publishWorkspaceCommit(ctx, workspace, head); err != nil {
		return Submission{}, err
	}
	manifest := contracts.SubmissionManifest{SubmissionVersion: 1, ProjectID: workspace.ProjectID, ModuleTaskID: workspace.TaskID, AttemptSeriesID: workspace.AttemptSeriesID, Attempt: request.Attempt, ModuleSpecRef: workspace.ModuleSpecRef, BaseCommit: workspace.BaseCommit, HeadCommit: head, ChangedFiles: changed, DeletedFiles: deleted, CreatedFiles: created, ClaimedCriteria: append([]string(nil), request.ClaimedCriteria...), LocalTestEvidenceRefs: append([]string(nil), request.LocalTestEvidenceRefs...), AgentIdentity: workspace.AgentIdentity, CreatedAt: request.CreatedAt.UTC().Format(time.RFC3339)}
	if err := fillManifestDigest(&manifest); err != nil {
		return Submission{}, err
	}
	payload, digestErr := manifestPayload(manifest)
	if digestErr != nil {
		return Submission{}, digestErr
	}
	manifest.Signature, err = s.signer.Sign(ctx, payload)
	if err != nil || !validServiceSignature(manifest.Signature) {
		return Submission{}, ErrInvalidRequest
	}
	if err := s.signer.Verify(ctx, payload, manifest.Signature); err != nil {
		return Submission{}, ErrInvalidRequest
	}
	if err := manifest.Validate(); err != nil {
		return Submission{}, err
	}
	submission = Submission{Manifest: manifest, Workspace: cloneWorkspace(workspace), CommitAt: s.clock().UTC(), IdempotencyKey: request.IdempotencyKey, RequestSHA256: requestDigest}
	if err := s.validateWorkspaceLease(ctx, workspace, request.Lease, LeaseActionSubmit, workspace.Path, requestDigest); err != nil {
		return Submission{}, err
	}
	if err := s.store.Put(ctx, submission); err != nil {
		return Submission{}, err
	}
	persisted, found, err := s.store.Get(ctx, workspace.TenantID, workspace.TaskID, workspace.AttemptSeriesID, request.Attempt)
	if err != nil {
		return Submission{}, err
	}
	if !found || persisted.IdempotencyKey != submission.IdempotencyKey || persisted.RequestSHA256 != submission.RequestSHA256 || persisted.Manifest.SHA256 != submission.Manifest.SHA256 {
		return Submission{}, ErrSubmissionConflict
	}
	return cloneSubmission(persisted), nil
}

func (s *Service) Workspace(id string) (Workspace, bool) {
	workspace, err := s.workspace(context.Background(), id)
	return workspace, err == nil
}

func (s *Service) WorkspaceContext(ctx context.Context, id string) (Workspace, bool, error) {
	workspace, err := s.workspace(ctx, id)
	if errors.Is(err, ErrWorkspaceNotFound) {
		return Workspace{}, false, nil
	}
	return workspace, err == nil, err
}

func (s *Service) workspace(ctx context.Context, id string) (Workspace, error) {
	if id == "" {
		return Workspace{}, ErrWorkspaceNotFound
	}
	s.mu.RLock()
	workspace, found := s.workspaces[id]
	s.mu.RUnlock()
	if found {
		return cloneWorkspace(workspace), nil
	}
	workspace, found, err := s.workspaceStore.LoadWorkspace(ctx, id)
	if err != nil {
		return Workspace{}, err
	}
	if !found {
		return Workspace{}, ErrWorkspaceNotFound
	}
	if err := s.validateRecoveredWorkspace(ctx, workspace); err != nil {
		return Workspace{}, err
	}
	s.mu.Lock()
	if prior, registered := s.workspaces[id]; registered {
		workspace = prior
	} else {
		s.workspaces[id] = workspace
	}
	s.mu.Unlock()
	return cloneWorkspace(workspace), nil
}

func (s *Service) persistWorkspace(ctx context.Context, workspace, template Workspace) (Workspace, error) {
	storeErr := s.workspaceStore.StoreWorkspace(ctx, workspace)
	prior, found, loadErr := s.workspaceStore.LoadWorkspaceByAttempt(ctx, workspace.TenantID, workspace.TaskID, workspace.AttemptSeriesID, workspace.Attempt)
	if loadErr == nil && found {
		expected := template
		expected.ID = prior.ID
		if !sameWorkspace(prior, expected) {
			return Workspace{}, ErrWorkspaceConflict
		}
		return prior, nil
	}
	if storeErr != nil {
		return Workspace{}, storeErr
	}
	if loadErr != nil {
		return Workspace{}, loadErr
	}
	return workspace, nil
}

func (s *Service) workspaceRepositoryPath(ctx context.Context, request WorkspaceRequest) (string, error) {
	if request.RepositoryPath != "" {
		absolute, err := filepath.Abs(request.RepositoryPath)
		if err != nil {
			return "", ErrInvalidRequest
		}
		return absolute, nil
	}
	repository, found, err := s.repositoryStore.LoadProjectRepository(ctx, request.TenantID, request.ProjectID)
	if err != nil {
		return "", err
	}
	if found {
		if err := s.validateProjectRepository(ctx, repository); err != nil {
			return "", err
		}
		return repository.Path, nil
	}
	return s.root, nil
}

func (s *Service) validateRecoveredWorkspace(ctx context.Context, workspace Workspace) error {
	if !validWorkspaceID(workspace.ID) || !safeIDPattern.MatchString(workspace.TenantID) || !safeIDPattern.MatchString(workspace.ProjectID) || !safeIDPattern.MatchString(workspace.TaskID) || !safeIDPattern.MatchString(workspace.AttemptSeriesID) || workspace.Attempt < 1 || workspace.Attempt > 3 || workspace.ModuleSpecRef.Validate() != nil || workspace.AgentIdentity.AgentInstanceID == "" || workspace.AgentIdentity.Role != "EXECUTOR" || workspace.AgentIdentity.LeaseID == "" || len(workspace.AllowedPaths) == 0 || validateCommit(workspace.BaseCommit) != nil {
		return ErrWorkspaceConflict
	}
	request := WorkspaceRequest{TenantID: workspace.TenantID, ProjectID: workspace.ProjectID, TaskID: workspace.TaskID, AttemptSeriesID: workspace.AttemptSeriesID, Attempt: workspace.Attempt}
	if workspace.Branch != workspaceBranch(request) {
		return ErrWorkspaceConflict
	}
	expectedPath := filepath.Join(s.root, ".aor-workspaces", cleanID(workspace.TenantID), cleanID(workspace.ProjectID), cleanID(workspace.TaskID), fmt.Sprintf("attempt-%d", workspace.Attempt))
	expectedGitDirectory := filepath.Join(s.root, ".aor-git", workspaceRequestDigest(request))
	if filepath.Clean(workspace.Path) != filepath.Clean(expectedPath) || filepath.Clean(workspace.gitDir) != filepath.Clean(expectedGitDirectory) || workspace.repositoryPath == "" {
		return ErrWorkspaceConflict
	}
	for _, directory := range []string{workspace.Path, workspace.gitDir} {
		if err := rejectSymlinkTree(s.root, directory); err != nil {
			return ErrWorkspaceConflict
		}
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || unsafePathInfo(info) {
			return ErrWorkspaceConflict
		}
	}
	gitDirectory, err := git(ctx, workspace.Path, "rev-parse", "--absolute-git-dir")
	if err != nil || filepath.Clean(strings.TrimSpace(gitDirectory)) != filepath.Clean(workspace.gitDir) {
		return ErrWorkspaceConflict
	}
	branch, err := git(ctx, workspace.Path, "symbolic-ref", "--short", "HEAD")
	if err != nil || strings.TrimSpace(branch) != workspace.Branch {
		return ErrWorkspaceConflict
	}
	if _, err := git(ctx, workspace.Path, "rev-parse", "--verify", workspace.BaseCommit+"^{commit}"); err != nil {
		return ErrWorkspaceConflict
	}
	recorded, err := readWorkspaceRegistration(workspace.gitDir)
	if err != nil || !sameWorkspace(recorded, workspace) {
		return ErrWorkspaceConflict
	}
	return nil
}

func cleanupWorkspace(directory, gitDirectory string) {
	if directory != "" {
		_ = os.RemoveAll(directory)
	}
	if gitDirectory != "" {
		_ = os.RemoveAll(gitDirectory)
	}
}

func pathExists(name string) bool {
	_, err := os.Lstat(name)
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

func (s *Service) validateWorkspaceLease(ctx context.Context, workspace Workspace, proof LeaseProof, action LeaseAction, resourcePath, parameterDigest string) error {
	if proof.ID == "" || workspace.AgentIdentity.LeaseID == "" || !workspace.OperationLeases && proof.ID != workspace.AgentIdentity.LeaseID {
		return ErrLeaseStale
	}
	return s.validateLease(ctx, LeaseValidation{Proof: proof, ExecutionLeaseID: workspace.AgentIdentity.LeaseID, Action: action, TenantID: workspace.TenantID, ProjectID: workspace.ProjectID, TaskID: workspace.TaskID, AttemptSeriesID: workspace.AttemptSeriesID, Attempt: workspace.Attempt, ModuleSpecRef: workspace.ModuleSpecRef, AgentInstanceID: workspace.AgentIdentity.AgentInstanceID, Role: workspace.AgentIdentity.Role, ResourcePath: resourcePath, ParameterDigest: parameterDigest})
}

func (s *Service) validateLease(ctx context.Context, validation LeaseValidation) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	lease := validation.Proof
	if lease.ID == "" || validation.ExecutionLeaseID == "" || lease.FencingToken < 1 || lease.ExpiresAt.IsZero() || validation.Action == "" || validation.TenantID == "" || validation.ProjectID == "" || validation.TaskID == "" || validation.AttemptSeriesID == "" || validation.Attempt < 1 || validation.Attempt > 3 || validation.ModuleSpecRef.Validate() != nil || validation.AgentInstanceID == "" || validation.Role != "EXECUTOR" || validation.ResourcePath == "" || !strings.HasPrefix(validation.ParameterDigest, "sha256:") {
		return ErrLeaseStale
	}
	if s.leases == nil {
		return ErrLeaseRequired
	}
	if err := s.leases.Validate(ctx, validation); err != nil {
		return fmt.Errorf("%w: %v", ErrLeaseStale, err)
	}
	return nil
}

func (s *Service) commitWorkspace(ctx context.Context, workspace Workspace, lease LeaseProof, requestDigest, idempotencyKey string) ([]string, []string, []string, error) {
	if !safeCommitMetadata(idempotencyKey) {
		return nil, nil, nil, ErrInvalidRequest
	}
	expectedMessage := submissionCommitMessage(workspace, idempotencyKey)
	head, err := git(ctx, workspace.Path, "rev-parse", "HEAD")
	if err != nil {
		return nil, nil, nil, ErrGitUnavailable
	}
	if strings.TrimSpace(head) != workspace.BaseCommit {
		message, messageErr := git(ctx, workspace.Path, "log", "-1", "--format=%B")
		if messageErr != nil || strings.TrimSpace(message) != strings.TrimSpace(expectedMessage) {
			return nil, nil, nil, ErrRepositoryDirty
		}
		nameStatus, statusErr := git(ctx, workspace.Path, "diff", "--name-status", "--find-renames", "-z", workspace.BaseCommit+"..HEAD")
		if statusErr != nil {
			return nil, nil, nil, ErrGitUnavailable
		}
		return classifyChanges(nameStatus)
	}
	status, err := git(ctx, workspace.Path, "status", "--porcelain=v1", "--untracked-files=all", "-z")
	if err != nil {
		return nil, nil, nil, ErrGitUnavailable
	}
	paths, err := parseStatusPaths(status)
	if err != nil || len(paths) == 0 {
		return nil, nil, nil, ErrRepositoryDirty
	}
	for _, name := range paths {
		if _, pathErr := ownedPath(workspace, name); pathErr != nil {
			return nil, nil, nil, pathErr
		}
	}
	if err := s.validateWorkspaceLease(ctx, workspace, lease, LeaseActionSubmit, workspace.Path, requestDigest); err != nil {
		return nil, nil, nil, err
	}
	if _, err := git(ctx, workspace.Path, "add", "--all", "."); err != nil {
		return nil, nil, nil, ErrGitUnavailable
	}
	if _, err := git(ctx, workspace.Path, "diff", "--cached", "--check"); err != nil {
		return nil, nil, nil, ErrRepositoryDirty
	}
	if err := s.validateWorkspaceLease(ctx, workspace, lease, LeaseActionSubmit, workspace.Path, requestDigest); err != nil {
		return nil, nil, nil, err
	}
	if _, err := git(ctx, workspace.Path, "commit", "--no-verify", "-m", expectedMessage); err != nil {
		return nil, nil, nil, ErrGitUnavailable
	}
	nameStatus, err := git(ctx, workspace.Path, "diff", "--name-status", "--find-renames", "-z", workspace.BaseCommit+"..HEAD")
	if err != nil {
		return nil, nil, nil, ErrGitUnavailable
	}
	return classifyChanges(nameStatus)
}

func (s *Service) publishWorkspaceCommit(ctx context.Context, workspace Workspace, head string) error {
	if validateCommit(head) != nil || workspace.repositoryPath == "" || !validBranchName(workspace.Branch) {
		return ErrInvalidRequest
	}
	targetGitDirectory, err := gitFrom(ctx, workspace.repositoryPath, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return ErrGitUnavailable
	}
	targetGitDirectory = strings.TrimSpace(targetGitDirectory)
	if !filepath.IsAbs(targetGitDirectory) {
		return ErrGitUnavailable
	}
	s.repositoryMu.Lock()
	defer s.repositoryMu.Unlock()
	disabledHooks := filepath.Join(s.root, ".aor-disabled-hooks")
	if err := os.MkdirAll(disabledHooks, 0o700); err != nil {
		return err
	}
	if _, err := gitFrom(ctx, targetGitDirectory, "--git-dir", targetGitDirectory, "-c", "core.hooksPath="+disabledHooks, "fetch", "--no-tags", "--no-write-fetch-head", workspace.gitDir, head); err != nil {
		return ErrGitUnavailable
	}
	ref := "refs/heads/" + workspace.Branch
	current, err := gitFrom(ctx, targetGitDirectory, "--git-dir", targetGitDirectory, "rev-parse", "--verify", ref+"^{commit}")
	if err == nil {
		if strings.TrimSpace(current) == head {
			return nil
		}
		return ErrSubmissionConflict
	}
	if _, err := gitFrom(ctx, targetGitDirectory, "--git-dir", targetGitDirectory, "update-ref", ref, head, strings.Repeat("0", 40)); err != nil {
		return ErrSubmissionConflict
	}
	return nil
}

func checkoutCommit(ctx context.Context, workspace Workspace, commit string) error {
	if workspace.Branch == "" {
		return ErrInvalidRequest
	}
	if _, err := git(ctx, workspace.Path, "checkout", "-B", workspace.Branch, commit); err != nil {
		return ErrGitUnavailable
	}
	return nil
}

func cloneRepository(ctx context.Context, source, directory, gitDirectory string) error {
	info, err := os.Lstat(source)
	if err != nil || !info.IsDir() || unsafePathInfo(info) {
		return ErrInitialCommitNeeded
	}
	if _, err := gitFrom(ctx, source, "rev-parse", "--git-dir"); err != nil {
		return ErrInitialCommitNeeded
	}
	if _, err := gitFrom(ctx, source, "rev-parse", "--verify", "HEAD^{commit}"); err != nil {
		return ErrInitialCommitNeeded
	}
	if gitDirectory == "" || filepath.Clean(gitDirectory) == filepath.Clean(directory) || strings.HasPrefix(filepath.Clean(gitDirectory), filepath.Clean(directory)+string(os.PathSeparator)) {
		return ErrInvalidRequest
	}
	if err := os.MkdirAll(filepath.Dir(gitDirectory), 0o700); err != nil {
		return err
	}
	if _, err := gitFrom(ctx, filepath.Dir(directory), "clone", "--no-local", "--separate-git-dir", gitDirectory, source, directory); err != nil {
		cleanupWorkspace(directory, gitDirectory)
		return ErrGitUnavailable
	}
	// Disable repository-provided hooks and file-system monitors before the
	// untrusted checkout is materialized.
	if _, err := git(ctx, directory, "config", "core.hooksPath", filepath.Join(gitDirectory, "disabled-hooks")); err != nil {
		cleanupWorkspace(directory, gitDirectory)
		return ErrGitUnavailable
	}
	return nil
}

func configureWorkspaceVisibility(ctx context.Context, directory string, allowed, forbidden []string) error {
	if len(allowed) == 0 {
		return ErrPathDenied
	}
	patterns := []string{"/*"}
	for _, value := range effectiveForbiddenPaths(forbidden) {
		clean, valid := cleanRelative(value)
		if !valid {
			return ErrPathDenied
		}
		if clean == ".git" || strings.HasPrefix(clean, ".git/") {
			continue
		}
		pattern, ok := sparsePattern(value)
		if !ok {
			return ErrPathDenied
		}
		patterns = append(patterns, "!"+pattern)
	}
	arguments := append([]string{"sparse-checkout", "set", "--no-cone", "--"}, patterns...)
	if _, err := git(ctx, directory, arguments...); err != nil {
		return ErrGitUnavailable
	}
	return validateVisibleTree(directory, effectiveForbiddenPaths(forbidden))
}

var defaultForbiddenWorkspacePaths = []string{
	"policies/...",
	"hidden-tests/...",
	".aor-hidden-tests/...",
	"audit/private/...",
	".aor-private/...",
}

func effectiveForbiddenPaths(forbidden []string) []string {
	result := append([]string(nil), forbidden...)
	result = append(result, defaultForbiddenWorkspacePaths...)
	return result
}

func sparsePattern(value string) (string, bool) {
	clean, ok := cleanRelative(value)
	if !ok || clean == ".git" || strings.HasPrefix(clean, ".git/") {
		return "", false
	}
	recursive := strings.HasSuffix(clean, "/...") || strings.HasSuffix(clean, "/**")
	clean = strings.TrimSuffix(clean, "/...")
	clean = strings.TrimSuffix(clean, "/**")
	if clean == "" || clean == "." {
		return "", false
	}
	if strings.ContainsAny(clean, "*?[") {
		return "/" + clean, true
	}
	if recursive {
		return "/" + clean + "/**", true
	}
	return "/" + clean, true
}

func validateVisibleTree(directory string, forbidden []string) error {
	return filepath.WalkDir(directory, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == directory {
			return nil
		}
		if entry.Name() == ".git" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		relative, err := filepath.Rel(directory, name)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			return nil
		}
		if !matchesAnyPath(forbidden, relative) {
			return nil
		}
		return ErrPathDenied
	})
}

func matchesAnyPath(patterns []string, candidate string) bool {
	for _, pattern := range patterns {
		if matchesPath(pattern, candidate) {
			return true
		}
	}
	return false
}

func git(ctx context.Context, directory string, args ...string) (string, error) {
	return gitFrom(ctx, directory, args...)
}

func gitFrom(ctx context.Context, directory string, args ...string) (string, error) {
	return gitFromWithEnvironment(ctx, directory, nil, args...)
}

func gitFromWithEnvironment(ctx context.Context, directory string, environment []string, args ...string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	command := exec.CommandContext(ctx, "git", args...)
	command.Dir = directory
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_AUTHOR_NAME=AOR Repository Service", "GIT_AUTHOR_EMAIL=repository-service@aor.invalid", "GIT_COMMITTER_NAME=AOR Repository Service", "GIT_COMMITTER_EMAIL=repository-service@aor.invalid")
	command.Env = append(command.Env, environment...)
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), err
	}
	return string(output), nil
}

func ownedPath(workspace Workspace, candidate string) (string, error) {
	relative, ok := cleanRelative(candidate)
	if !ok || strings.EqualFold(relative, ".git") || len(relative) > len(".git/") && strings.EqualFold(relative[:len(".git/")], ".git/") {
		return "", ErrPathDenied
	}
	for _, forbidden := range workspace.ForbiddenPaths {
		if matchesPath(forbidden, relative) || matchesPath(strings.ToLower(forbidden), strings.ToLower(relative)) {
			return "", ErrPathDenied
		}
	}
	if len(workspace.AllowedPaths) == 0 {
		return "", ErrPathDenied
	}
	for _, allowed := range workspace.AllowedPaths {
		if matchesPath(allowed, relative) {
			return relative, nil
		}
	}
	return "", ErrPathDenied
}

func matchesPath(pattern, candidate string) bool {
	cleanPattern, ok := cleanRelative(pattern)
	if !ok {
		return false
	}
	if cleanPattern == candidate || recursivePatternMatch(cleanPattern, candidate) {
		return true
	}
	if strings.ContainsAny(cleanPattern, "*?[") {
		matched, _ := path.Match(cleanPattern, candidate)
		return matched
	}
	return strings.HasPrefix(candidate, cleanPattern+"/")
}

func recursivePatternMatch(pattern, candidate string) bool {
	for _, suffix := range []string{"/...", "/**"} {
		if strings.HasSuffix(pattern, suffix) {
			root := strings.TrimSuffix(pattern, suffix)
			return candidate == root || strings.HasPrefix(candidate, root+"/")
		}
	}
	return false
}

func cleanRelative(value string) (string, bool) {
	if value == "" || strings.ContainsRune(value, 0) {
		return "", false
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return "", false
		}
	}
	normalized := strings.ReplaceAll(value, "\\", "/")
	clean := path.Clean(normalized)
	if clean != normalized || clean == "." || strings.HasPrefix(clean, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return clean, true
}

func rejectSymlinkTree(root, target string) error {
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return ErrPathDenied
	}
	current := root
	for _, segment := range strings.Split(relative, string(os.PathSeparator)) {
		if segment == "" || segment == "." {
			continue
		}
		entries, readErr := os.ReadDir(current)
		if readErr != nil {
			return readErr
		}
		for _, entry := range entries {
			if entry.Name() != segment && strings.EqualFold(entry.Name(), segment) {
				return ErrPathDenied
			}
		}
		current = filepath.Join(current, segment)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				break
			}
			return statErr
		}
		if unsafePathInfo(info) {
			return ErrPathDenied
		}
	}
	return nil
}

func parseStatusPaths(value string) ([]string, error) {
	parts := strings.Split(value, "\x00")
	paths := make([]string, 0, len(parts))
	for index := 0; index < len(parts); index++ {
		part := parts[index]
		if part == "" {
			continue
		}
		if len(part) < 4 {
			return nil, ErrRepositoryDirty
		}
		name := strings.TrimSpace(part[3:])
		if len(name) == 0 {
			return nil, ErrRepositoryDirty
		}
		if strings.HasPrefix(name, "\"") {
			return nil, ErrRepositoryDirty
		}
		paths = append(paths, name)
		if part[0] == 'R' || part[0] == 'C' || part[1] == 'R' || part[1] == 'C' {
			if index+1 >= len(parts) || parts[index+1] == "" {
				return nil, ErrRepositoryDirty
			}
			paths = append(paths, parts[index+1])
			index++
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func classifyChanges(value string) ([]string, []string, []string, error) {
	var changed, deleted, created []string
	parts := strings.Split(value, "\x00")
	for index := 0; index < len(parts); {
		status := parts[index]
		index++
		if status == "" {
			continue
		}
		if index >= len(parts) || parts[index] == "" {
			return nil, nil, nil, ErrRepositoryDirty
		}
		first := parts[index]
		index++
		switch status[0] {
		case 'R', 'C':
			if index >= len(parts) || parts[index] == "" {
				return nil, nil, nil, ErrRepositoryDirty
			}
			second := parts[index]
			index++
			changed = append(changed, first, second)
		case 'D':
			changed = append(changed, first)
			deleted = append(deleted, first)
		case 'A':
			changed = append(changed, first)
			created = append(created, first)
		default:
			changed = append(changed, first)
		}
	}
	sort.Strings(changed)
	sort.Strings(deleted)
	sort.Strings(created)
	return changed, deleted, created, nil
}

func fillManifestDigest(manifest *contracts.SubmissionManifest) error {
	manifest.SHA256 = ""
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(encoded, "sha256", "signature")
	if err != nil {
		return err
	}
	manifest.SHA256 = digest
	return nil
}

func manifestPayload(manifest contracts.SubmissionManifest) ([]byte, error) {
	manifest.SHA256 = ""
	manifest.Signature = nil
	return canonicaljson.Canonicalize(mustJSON(manifest))
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func newWorkspaceID(tenantID string) (string, error) {
	value, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return tenantID + ":" + value.String(), nil
}

func workspaceRequestDigest(request WorkspaceRequest) string {
	return workspaceIDDigest(workspaceNaturalKey(request.TenantID, request.TaskID, request.AttemptSeriesID, request.Attempt))
}

func workspaceIDDigest(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

func workspaceBranch(request WorkspaceRequest) string {
	return "agent/" + branchPart(request.ProjectID) + "/" + branchPart(request.TaskID) + "/attempt-" + strconv.Itoa(request.Attempt)
}

func branchPart(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('_')
		}
	}
	if builder.Len() == 0 {
		return "unknown"
	}
	return builder.String()
}

func submissionCommitMessage(workspace Workspace, idempotencyKey string) string {
	return fmt.Sprintf("aor(%s): submission attempt %d\n\nAOR-Task: %s\nAOR-Attempt: %d\nAOR-Attempt-Series: %s\nAOR-Module-Spec: v%d %s\nAOR-Agent: %s\nAOR-Lease: %s\nAOR-Idempotency-Key: %s", workspace.TaskID, workspace.Attempt, workspace.TaskID, workspace.Attempt, workspace.AttemptSeriesID, workspace.ModuleSpecRef.Version, workspace.ModuleSpecRef.SHA256, workspace.AgentIdentity.AgentInstanceID, workspace.AgentIdentity.LeaseID, idempotencyKey)
}

func safeCommitMetadata(value string) bool {
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00")
}

func validSubmissionMetadata(workspace Workspace, request SubmissionRequest) bool {
	if len(request.ClaimedCriteria) > 256 || len(request.LocalTestEvidenceRefs) > 256 {
		return false
	}
	allowedCriteria := make(map[string]struct{}, len(workspace.AcceptanceCriteria))
	for _, criterion := range workspace.AcceptanceCriteria {
		allowedCriteria[criterion] = struct{}{}
	}
	seenCriteria := make(map[string]struct{}, len(request.ClaimedCriteria))
	for _, criterion := range request.ClaimedCriteria {
		if criterion == "" || len(criterion) > 1024 {
			return false
		}
		if _, allowed := allowedCriteria[criterion]; !allowed {
			return false
		}
		if _, duplicate := seenCriteria[criterion]; duplicate {
			return false
		}
		seenCriteria[criterion] = struct{}{}
	}
	seenEvidence := make(map[string]struct{}, len(request.LocalTestEvidenceRefs))
	for _, reference := range request.LocalTestEvidenceRefs {
		if !artifactDigestPattern.MatchString(reference) {
			return false
		}
		if _, duplicate := seenEvidence[reference]; duplicate {
			return false
		}
		seenEvidence[reference] = struct{}{}
	}
	return true
}

func validServiceSignature(signature *contracts.Signature) bool {
	return signature != nil && signature.Type != "" && len(signature.Type) <= 128 &&
		signature.KID != "" && len(signature.KID) <= 256 && signature.JWS != "" && len(signature.JWS) <= 16<<10
}

func cleanID(value string) string {
	return strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(value)
}

func validateCommit(value string) error {
	if len(value) != 40 || strings.ToLower(value) != value {
		return ErrInvalidRequest
	}
	if _, err := hex.DecodeString(value); err != nil {
		return ErrInvalidRequest
	}
	return nil
}

func leaseParameterDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func submissionRequestDigest(request SubmissionRequest) (string, error) {
	return leaseParameterDigest(struct {
		WorkspaceID           string   `json:"workspaceId"`
		Attempt               int      `json:"attempt"`
		ClaimedCriteria       []string `json:"claimedCriteria"`
		LocalTestEvidenceRefs []string `json:"localTestEvidenceRefs"`
		IdempotencyKey        string   `json:"idempotencyKey"`
	}{request.WorkspaceID, request.Attempt, request.ClaimedCriteria, request.LocalTestEvidenceRefs, request.IdempotencyKey})
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func cloneWorkspace(value Workspace) Workspace {
	value.AllowedPaths = append([]string(nil), value.AllowedPaths...)
	value.ForbiddenPaths = append([]string(nil), value.ForbiddenPaths...)
	value.AcceptanceCriteria = append([]string(nil), value.AcceptanceCriteria...)
	return value
}

func DigestManifest(manifest contracts.SubmissionManifest) (string, error) {
	manifest.SHA256 = ""
	manifest.Signature = nil
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	return canonicaljson.DigestObjectWithoutFields(encoded, "sha256", "signature")
}

func DigestBytes(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}
