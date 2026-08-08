package repository

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
)

var (
	ErrInvalidRequest      = errors.New("invalid repository request")
	ErrWorkspaceNotFound   = errors.New("repository workspace not found")
	ErrPathDenied          = errors.New("repository path is outside module ownership")
	ErrLeaseRequired       = errors.New("repository write requires an active lease")
	ErrLeaseStale          = errors.New("repository lease is stale")
	ErrSubmissionConflict  = errors.New("submission is immutable")
	ErrGitUnavailable      = errors.New("git is unavailable")
	ErrRepositoryDirty     = errors.New("repository contains unowned changes")
	ErrInitialCommitNeeded = errors.New("workspace must have an initial commit")
	ErrWorkspaceConflict   = errors.New("repository workspace registration conflicts")
	ErrRepositoryNotFound  = errors.New("project repository not found")
	ErrRepositoryConflict  = errors.New("project repository registration conflicts")
)

type LeaseProof struct {
	ID               string
	FencingToken     int64
	ExpiresAt        time.Time
	AgentInstanceID  string
	ExecutionLeaseID string
}

type LeaseAction string

const (
	LeaseActionCreateWorkspace LeaseAction = "repository.workspace.create"
	LeaseActionWriteFile       LeaseAction = "repository.file.write"
	LeaseActionDeleteFile      LeaseAction = "repository.file.delete"
	LeaseActionSubmit          LeaseAction = "repository.submission.commit"
)

type LeaseValidation struct {
	Proof            LeaseProof
	ExecutionLeaseID string
	Action           LeaseAction
	TenantID         string
	ProjectID        string
	TaskID           string
	AttemptSeriesID  string
	Attempt          int
	ModuleSpecRef    contracts.SpecRef
	AgentInstanceID  string
	Role             string
	ResourcePath     string
	ParameterDigest  string
}

type LeaseValidator interface {
	Validate(context.Context, LeaseValidation) error
}

type WorkspaceRequest struct {
	RepositoryPath   string
	TenantID         string
	ProjectID        string
	TaskID           string
	Attempt          int
	AttemptSeriesID  string
	BaseCommit       string
	ModuleSpec       contracts.ModuleSpec
	AgentIdentity    contracts.AgentIdentity
	ExecutionLeaseID string
	Lease            LeaseProof
}

type Workspace struct {
	ID                 string
	TenantID           string
	ProjectID          string
	TaskID             string
	Attempt            int
	AttemptSeriesID    string
	Path               string
	Branch             string
	BaseCommit         string
	AllowedPaths       []string
	ForbiddenPaths     []string
	AcceptanceCriteria []string
	ModuleSpecRef      contracts.SpecRef
	AgentIdentity      contracts.AgentIdentity
	OperationLeases    bool
	// gitDir is service-owned metadata outside the mounted workspace. It is
	// intentionally private so API consumers cannot use it as a repository
	// capability.
	gitDir         string
	repositoryPath string
}

type WriteRequest struct {
	WorkspaceID string
	Path        string
	Content     []byte
	Lease       LeaseProof
}

type DeleteRequest struct {
	WorkspaceID string
	Path        string
	Lease       LeaseProof
}

type SubmissionRequest struct {
	WorkspaceID           string
	Attempt               int
	ClaimedCriteria       []string
	LocalTestEvidenceRefs []string
	Lease                 LeaseProof
	CreatedAt             time.Time
	IdempotencyKey        string
}

type Submission struct {
	ID             string                       `json:"id"`
	Manifest       contracts.SubmissionManifest `json:"manifest"`
	Workspace      Workspace                    `json:"workspace"`
	CommitAt       time.Time                    `json:"commitAt"`
	IdempotencyKey string                       `json:"idempotencyKey"`
	RequestSHA256  string                       `json:"requestSha256"`
}

type Signer interface {
	Sign(context.Context, []byte) (*contracts.Signature, error)
	Verify(context.Context, []byte, *contracts.Signature) error
}

type SubmissionStore interface {
	Get(context.Context, string, string, string, int) (Submission, bool, error)
	Put(context.Context, Submission) error
}

type WorkspaceStore interface {
	LoadWorkspace(context.Context, string) (Workspace, bool, error)
	LoadWorkspaceByAttempt(context.Context, string, string, string, int) (Workspace, bool, error)
	StoreWorkspace(context.Context, Workspace) error
}

const (
	RepositoryInitializationEmpty  = "EMPTY"
	RepositoryInitializationImport = "IMPORT"
)

type ProjectRepository struct {
	TenantID       string
	ProjectID      string
	Path           string
	DefaultBranch  string
	BaselineCommit string
	Initialization string
	SourceSHA256   string
	CreatedAt      time.Time
}

type ProjectRepositoryStore interface {
	LoadProjectRepository(context.Context, string, string) (ProjectRepository, bool, error)
	StoreProjectRepository(context.Context, ProjectRepository) error
}

type ProjectRepositoryImportRequest struct {
	TenantID      string
	ProjectID     string
	SourcePath    string
	DefaultBranch string
	CreatedAt     time.Time
}

type MemoryRegistryStore struct {
	mu            sync.RWMutex
	workspaces    map[string]Workspace
	workspaceKeys map[string]string
	repositories  map[string]ProjectRepository
}

func NewMemoryRegistryStore() *MemoryRegistryStore {
	return &MemoryRegistryStore{
		workspaces:    make(map[string]Workspace),
		workspaceKeys: make(map[string]string),
		repositories:  make(map[string]ProjectRepository),
	}
}

func (s *MemoryRegistryStore) LoadWorkspace(_ context.Context, id string) (Workspace, bool, error) {
	if s == nil || id == "" {
		return Workspace{}, false, ErrInvalidRequest
	}
	s.mu.RLock()
	workspace, found := s.workspaces[id]
	s.mu.RUnlock()
	return cloneWorkspace(workspace), found, nil
}

func (s *MemoryRegistryStore) LoadWorkspaceByAttempt(_ context.Context, tenantID, taskID, attemptSeriesID string, attempt int) (Workspace, bool, error) {
	if s == nil || !safeIDPattern.MatchString(tenantID) || !safeIDPattern.MatchString(taskID) || !safeIDPattern.MatchString(attemptSeriesID) || attempt < 1 || attempt > 3 {
		return Workspace{}, false, ErrInvalidRequest
	}
	s.mu.RLock()
	id, found := s.workspaceKeys[workspaceNaturalKey(tenantID, taskID, attemptSeriesID, attempt)]
	workspace := s.workspaces[id]
	s.mu.RUnlock()
	return cloneWorkspace(workspace), found, nil
}

func (s *MemoryRegistryStore) StoreWorkspace(_ context.Context, workspace Workspace) error {
	tenantID, validID := workspaceTenantID(workspace.ID)
	if s == nil || !validID || tenantID != workspace.TenantID || !validWorkspaceID(workspace.ID) {
		return ErrInvalidRequest
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.workspaces == nil {
		s.workspaces = make(map[string]Workspace)
	}
	if s.workspaceKeys == nil {
		s.workspaceKeys = make(map[string]string)
	}
	if prior, found := s.workspaces[workspace.ID]; found {
		if sameWorkspace(prior, workspace) {
			return nil
		}
		return ErrWorkspaceConflict
	}
	naturalKey := workspaceNaturalKey(workspace.TenantID, workspace.TaskID, workspace.AttemptSeriesID, workspace.Attempt)
	if priorID, found := s.workspaceKeys[naturalKey]; found {
		prior := s.workspaces[priorID]
		if sameWorkspaceBinding(prior, workspace) {
			return nil
		}
		return ErrWorkspaceConflict
	}
	s.workspaces[workspace.ID] = cloneWorkspace(workspace)
	s.workspaceKeys[naturalKey] = workspace.ID
	return nil
}

func (s *MemoryRegistryStore) LoadProjectRepository(_ context.Context, tenantID, projectID string) (ProjectRepository, bool, error) {
	if s == nil || tenantID == "" || projectID == "" {
		return ProjectRepository{}, false, ErrInvalidRequest
	}
	s.mu.RLock()
	repository, found := s.repositories[projectRepositoryKey(tenantID, projectID)]
	s.mu.RUnlock()
	return repository, found, nil
}

func (s *MemoryRegistryStore) StoreProjectRepository(_ context.Context, repository ProjectRepository) error {
	if s == nil || repository.TenantID == "" || repository.ProjectID == "" {
		return ErrInvalidRequest
	}
	key := projectRepositoryKey(repository.TenantID, repository.ProjectID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if prior, found := s.repositories[key]; found {
		if sameProjectRepository(prior, repository) {
			return nil
		}
		return ErrRepositoryConflict
	}
	s.repositories[key] = repository
	return nil
}

type MemorySubmissionStore struct {
	mu    sync.RWMutex
	items map[string]Submission
}

func NewMemorySubmissionStore() *MemorySubmissionStore {
	return &MemorySubmissionStore{items: make(map[string]Submission)}
}

func (s *MemorySubmissionStore) Get(_ context.Context, tenantID, taskID, attemptSeriesID string, attempt int) (Submission, bool, error) {
	s.mu.RLock()
	value, ok := s.items[submissionKey(tenantID, taskID, attemptSeriesID, attempt)]
	s.mu.RUnlock()
	return cloneSubmission(value), ok, nil
}

func (s *MemorySubmissionStore) Put(_ context.Context, submission Submission) error {
	if submission.ID == "" {
		id, err := newSubmissionID()
		if err != nil {
			return err
		}
		submission.ID = id.String()
	}
	key := submissionKey(submission.Workspace.TenantID, submission.Workspace.TaskID, submission.Manifest.AttemptSeriesID, submission.Manifest.Attempt)
	s.mu.Lock()
	defer s.mu.Unlock()
	if prior, ok := s.items[key]; ok {
		if prior.Manifest.SHA256 == submission.Manifest.SHA256 && prior.IdempotencyKey == submission.IdempotencyKey {
			return nil
		}
		return ErrSubmissionConflict
	}
	s.items[key] = cloneSubmission(submission)
	return nil
}

func submissionKey(tenantID, taskID, attemptSeriesID string, attempt int) string {
	return tenantID + "\x00" + taskID + "\x00" + attemptSeriesID + "\x00" + strconv.Itoa(attempt)
}

func cloneSubmission(value Submission) Submission {
	value.Manifest.ChangedFiles = append([]string{}, value.Manifest.ChangedFiles...)
	value.Manifest.DeletedFiles = append([]string{}, value.Manifest.DeletedFiles...)
	value.Manifest.CreatedFiles = append([]string{}, value.Manifest.CreatedFiles...)
	value.Manifest.ClaimedCriteria = append([]string{}, value.Manifest.ClaimedCriteria...)
	value.Manifest.LocalTestEvidenceRefs = append([]string{}, value.Manifest.LocalTestEvidenceRefs...)
	if value.Manifest.Signature != nil {
		signature := *value.Manifest.Signature
		value.Manifest.Signature = &signature
	}
	value.Workspace = cloneWorkspace(value.Workspace)
	return value
}

func projectRepositoryKey(tenantID, projectID string) string {
	return tenantID + "\x00" + projectID
}

func workspaceNaturalKey(tenantID, taskID, attemptSeriesID string, attempt int) string {
	return tenantID + "\x00" + taskID + "\x00" + attemptSeriesID + "\x00" + strconv.Itoa(attempt)
}

func sameWorkspace(left, right Workspace) bool {
	return left.ID == right.ID && left.TenantID == right.TenantID && left.ProjectID == right.ProjectID &&
		left.TaskID == right.TaskID && left.Attempt == right.Attempt && left.AttemptSeriesID == right.AttemptSeriesID &&
		left.Path == right.Path && left.Branch == right.Branch && left.BaseCommit == right.BaseCommit &&
		left.ModuleSpecRef == right.ModuleSpecRef && left.AgentIdentity == right.AgentIdentity && left.OperationLeases == right.OperationLeases &&
		left.gitDir == right.gitDir && left.repositoryPath == right.repositoryPath &&
		sameStrings(left.AllowedPaths, right.AllowedPaths) && sameStrings(left.ForbiddenPaths, right.ForbiddenPaths) &&
		sameStrings(left.AcceptanceCriteria, right.AcceptanceCriteria)
}

func sameWorkspaceBinding(left, right Workspace) bool {
	left.ID = ""
	right.ID = ""
	if left.OperationLeases && right.OperationLeases {
		left.AgentIdentity = contracts.AgentIdentity{}
		right.AgentIdentity = contracts.AgentIdentity{}
	}
	return sameWorkspace(left, right)
}

func sameProjectRepository(left, right ProjectRepository) bool {
	return left.TenantID == right.TenantID && left.ProjectID == right.ProjectID && left.Path == right.Path &&
		left.DefaultBranch == right.DefaultBranch && left.BaselineCommit == right.BaselineCommit &&
		left.Initialization == right.Initialization && left.SourceSHA256 == right.SourceSHA256 &&
		left.CreatedAt.Equal(right.CreatedAt)
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

var _ WorkspaceStore = (*MemoryRegistryStore)(nil)
var _ ProjectRepositoryStore = (*MemoryRegistryStore)(nil)
