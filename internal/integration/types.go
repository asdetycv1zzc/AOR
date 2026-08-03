package integration

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
)

var (
	ErrInvalidRequest = errors.New("invalid integration request")
	ErrConflict       = errors.New("integration conflict")
	ErrNotAudited     = errors.New("integration audit has not passed")
	ErrMergeConflict  = errors.New("merge executor reported a conflict")
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
}

type Finding struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Category string   `json:"category"`
	Summary  string   `json:"summary"`
	Tasks    []string `json:"tasks"`
}

type Audit struct {
	IntegrationID  string
	ProjectID      string
	Findings       []Finding
	EvidenceSHA256 string
	Passed         bool
	CreatedAt      time.Time
}

type MergeResult struct {
	TenantID      string `json:"tenantId"`
	IntegrationID string `json:"integrationId"`
	ProjectID     string `json:"projectId"`
	Commit        string `json:"commit"`
	RequestDigest string `json:"requestDigest"`
	Audit         Audit  `json:"audit"`
	Duplicate     bool   `json:"duplicate"`
}

type MergeExecutor interface {
	Merge(context.Context, string, []string, string) (string, error)
}

type Store interface {
	Get(context.Context, string, string) (MergeResult, bool, error)
	Put(context.Context, MergeResult) error
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

func (s *MemoryStore) Put(_ context.Context, result MergeResult) error {
	key := result.TenantID + "\x00" + result.IntegrationID
	s.mu.Lock()
	defer s.mu.Unlock()
	if prior, ok := s.items[key]; ok {
		if prior.Commit == result.Commit && prior.RequestDigest == result.RequestDigest && prior.Audit.EvidenceSHA256 == result.Audit.EvidenceSHA256 {
			return nil
		}
		return ErrImmutable
	}
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
