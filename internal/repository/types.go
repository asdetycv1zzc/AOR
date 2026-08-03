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
)

type LeaseProof struct {
	ID           string
	FencingToken int64
	ExpiresAt    time.Time
}

type LeaseAction string

const (
	LeaseActionCreateWorkspace LeaseAction = "repository.workspace.create"
	LeaseActionWriteFile       LeaseAction = "repository.file.write"
	LeaseActionDeleteFile      LeaseAction = "repository.file.delete"
	LeaseActionSubmit          LeaseAction = "repository.submission.commit"
)

type LeaseValidation struct {
	Proof           LeaseProof
	Action          LeaseAction
	TenantID        string
	ProjectID       string
	TaskID          string
	AttemptSeriesID string
	Attempt         int
	ModuleSpecRef   contracts.SpecRef
	AgentInstanceID string
	Role            string
	ResourcePath    string
	ParameterDigest string
}

type LeaseValidator interface {
	Validate(context.Context, LeaseValidation) error
}

type WorkspaceRequest struct {
	RepositoryPath  string
	TenantID        string
	ProjectID       string
	TaskID          string
	Attempt         int
	AttemptSeriesID string
	BaseCommit      string
	ModuleSpec      contracts.ModuleSpec
	AgentIdentity   contracts.AgentIdentity
	Lease           LeaseProof
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
	value.Manifest.ChangedFiles = append([]string(nil), value.Manifest.ChangedFiles...)
	value.Manifest.DeletedFiles = append([]string(nil), value.Manifest.DeletedFiles...)
	value.Manifest.CreatedFiles = append([]string(nil), value.Manifest.CreatedFiles...)
	value.Manifest.ClaimedCriteria = append([]string(nil), value.Manifest.ClaimedCriteria...)
	value.Manifest.LocalTestEvidenceRefs = append([]string(nil), value.Manifest.LocalTestEvidenceRefs...)
	if value.Manifest.Signature != nil {
		signature := *value.Manifest.Signature
		value.Manifest.Signature = &signature
	}
	value.Workspace = cloneWorkspace(value.Workspace)
	return value
}
