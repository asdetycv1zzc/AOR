package integration

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
)

var (
	ErrInvalidRequest = errors.New("invalid integration request")
	ErrConflict       = errors.New("integration conflict")
	ErrNotAudited     = errors.New("integration audit has not passed")
	ErrMergeConflict  = errors.New("merge executor reported a conflict")
	ErrMergePending   = errors.New("integration merge is pending recovery")
	ErrImmutable      = errors.New("integration result is immutable")
)

type Candidate struct {
	TaskID           string
	ModuleID         string
	SubmissionCommit string
	ModuleSpecRef    contracts.SpecRef
	OwnedPaths       []string
	PublicInterfaces []string
	EvidenceSHA256   string
	AuditPassed      bool
}

type Request struct {
	TenantID        string
	ProjectID       string
	IntegrationID   string
	IdempotencyKey  string
	BaseCommit      string
	Candidates      []Candidate
	PolicyDigest    string
	ExpectedVersion int64
	CreatedAt       time.Time
	PrincipalID     string
	LeaseID         string
	FencingToken    int64
}

type VerifiedRequest struct {
	TenantID        string
	ProjectID       string
	IntegrationID   string
	BaseCommit      string
	Candidates      []Candidate
	PolicyDigest    string
	ExpectedVersion int64
	PrincipalID     string
	LeaseID         string
	FencingToken    int64
	Authorization   string
}

type Gate interface {
	Validate(context.Context, Request) (VerifiedRequest, error)
}

type Finding struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Category string   `json:"category"`
	Summary  string   `json:"summary"`
	Tasks    []string `json:"tasks"`
}

type Audit struct {
	IntegrationID  string    `json:"integrationId"`
	ProjectID      string    `json:"projectId"`
	Findings       []Finding `json:"findings"`
	EvidenceSHA256 string    `json:"evidenceSha256"`
	Passed         bool      `json:"passed"`
	CreatedAt      time.Time `json:"createdAt"`
}

type MergeResult struct {
	TenantID      string `json:"tenantId"`
	IntegrationID string `json:"integrationId"`
	ProjectID     string `json:"projectId"`
	Commit        string `json:"commit"`
	RequestDigest string `json:"requestDigest"`
	Audit         Audit  `json:"audit"`
	Duplicate     bool   `json:"duplicate"`
	Pending       bool   `json:"pending"`
}

type MergeExecutor interface {
	Merge(context.Context, string, []string, string) (string, error)
	Lookup(context.Context, string) (string, bool, error)
}

type Store interface {
	Get(context.Context, string, string) (MergeResult, bool, error)
	RecordConflict(context.Context, MergeResult) (MergeResult, bool, error)
	Reserve(context.Context, MergeResult) (MergeResult, bool, error)
	Complete(context.Context, MergeResult) error
}

type MemoryStore struct {
	mu    sync.RWMutex
	items map[string]MergeResult
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{items: make(map[string]MergeResult)} }

func (s *MemoryStore) Get(_ context.Context, tenantID, id string) (MergeResult, bool, error) {
	s.mu.RLock()
	result, ok := s.items[tenantID+"\x00"+id]
	s.mu.RUnlock()
	return cloneResult(result), ok, nil
}

func (s *MemoryStore) RecordConflict(_ context.Context, result MergeResult) (MergeResult, bool, error) {
	if !validConflictResult(result) {
		return MergeResult{}, false, ErrInvalidRequest
	}
	key := result.TenantID + "\x00" + result.IntegrationID
	s.mu.Lock()
	defer s.mu.Unlock()
	if prior, ok := s.items[key]; ok {
		if sameConflictResult(prior, result) {
			return cloneResult(prior), false, nil
		}
		return MergeResult{}, false, ErrImmutable
	}
	s.items[key] = cloneResult(result)
	return cloneResult(result), true, nil
}

func (s *MemoryStore) Reserve(_ context.Context, result MergeResult) (MergeResult, bool, error) {
	key := result.TenantID + "\x00" + result.IntegrationID
	s.mu.Lock()
	defer s.mu.Unlock()
	if prior, ok := s.items[key]; ok {
		if prior.RequestDigest == result.RequestDigest {
			return cloneResult(prior), false, nil
		}
		return MergeResult{}, false, ErrImmutable
	}
	result.Pending = true
	s.items[key] = cloneResult(result)
	return cloneResult(result), true, nil
}

func (s *MemoryStore) Complete(_ context.Context, result MergeResult) error {
	key := result.TenantID + "\x00" + result.IntegrationID
	s.mu.Lock()
	defer s.mu.Unlock()
	prior, ok := s.items[key]
	if !ok || prior.RequestDigest != result.RequestDigest || prior.Audit.EvidenceSHA256 != result.Audit.EvidenceSHA256 {
		return ErrImmutable
	}
	if !prior.Pending {
		if prior.Commit == result.Commit {
			return nil
		}
		return ErrImmutable
	}
	result.Pending = false
	s.items[key] = cloneResult(result)
	return nil
}

func cloneResult(result MergeResult) MergeResult {
	result.Audit.Findings = append([]Finding(nil), result.Audit.Findings...)
	for index := range result.Audit.Findings {
		result.Audit.Findings[index].Tasks = append([]string(nil), result.Audit.Findings[index].Tasks...)
	}
	return result
}

func validConflictResult(result MergeResult) bool {
	return result.TenantID != "" && result.ProjectID != "" && result.IntegrationID != "" &&
		result.Commit == "" && result.RequestDigest == "" && !result.Duplicate && !result.Pending &&
		result.Audit.IntegrationID == result.IntegrationID && result.Audit.ProjectID == result.ProjectID &&
		!result.Audit.Passed && len(result.Audit.Findings) > 0 && digestPattern(result.Audit.EvidenceSHA256) &&
		!result.Audit.CreatedAt.IsZero()
}

func sameConflictResult(left, right MergeResult) bool {
	return validConflictResult(left) && validConflictResult(right) &&
		left.TenantID == right.TenantID && left.ProjectID == right.ProjectID && left.IntegrationID == right.IntegrationID &&
		left.Audit.EvidenceSHA256 == right.Audit.EvidenceSHA256 && reflect.DeepEqual(left.Audit.Findings, right.Audit.Findings)
}
