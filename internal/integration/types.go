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
	ErrInvalidRequest    = errors.New("invalid integration request")
	ErrConflict          = errors.New("integration conflict")
	ErrNotAudited        = errors.New("integration audit has not passed")
	ErrMergeConflict     = errors.New("merge executor reported a conflict")
	ErrMergePending      = errors.New("integration merge is pending recovery")
	ErrAttemptState      = errors.New("integration attempt state conflict")
	ErrAttemptsExhausted = errors.New("integration attempts exhausted")
	ErrImmutable         = errors.New("integration result is immutable")
)

type TaskState string

const (
	TaskReworkRequired      TaskState = "REWORK_REQUIRED"
	TaskExecuting           TaskState = "EXECUTING"
	TaskMergeReserved       TaskState = "MERGE_RESERVED"
	TaskBlockedUserDecision TaskState = "BLOCKED_USER_DECISION"
	TaskDone                TaskState = "DONE"
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
	OwnerTaskID     string
	Attempt         int
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
	OwnerTaskID     string
	Attempt         int
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
	OwnerTaskID   string `json:"ownerTaskId,omitempty"`
	Attempt       int    `json:"attempt"`
	Commit        string `json:"commit"`
	RequestDigest string `json:"requestDigest"`
	Audit         Audit  `json:"audit"`
	Duplicate     bool   `json:"duplicate"`
	Pending       bool   `json:"pending"`
}

type IntegrationTask struct {
	TenantID    string
	ProjectID   string
	ID          string
	OwnerTaskID string
	State       TaskState
	Version     int64
	Attempt     int
	Conflict    Audit
}

type StartAttemptRequest struct {
	TenantID        string
	ProjectID       string
	IntegrationID   string
	OwnerTaskID     string
	Attempt         int
	ExpectedVersion int64
}

type MergeExecutor interface {
	Merge(context.Context, string, []string, string) (string, error)
	Lookup(context.Context, string) (string, bool, error)
}

type Store interface {
	Get(context.Context, string, string) (MergeResult, bool, error)
	GetTask(context.Context, string, string) (IntegrationTask, bool, error)
	StartAttempt(context.Context, StartAttemptRequest) (IntegrationTask, bool, error)
	RecordConflict(context.Context, MergeResult) (MergeResult, bool, error)
	Reserve(context.Context, MergeResult) (MergeResult, bool, error)
	Complete(context.Context, MergeResult) error
}

type memoryRecord struct {
	result MergeResult
	task   IntegrationTask
}

type MemoryStore struct {
	mu    sync.RWMutex
	items map[string]memoryRecord
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{items: make(map[string]memoryRecord)} }

func (s *MemoryStore) Get(_ context.Context, tenantID, id string) (MergeResult, bool, error) {
	s.mu.RLock()
	record, ok := s.items[tenantID+"\x00"+id]
	s.mu.RUnlock()
	return cloneResult(record.result), ok, nil
}

func (s *MemoryStore) GetTask(_ context.Context, tenantID, id string) (IntegrationTask, bool, error) {
	s.mu.RLock()
	record, ok := s.items[tenantID+"\x00"+id]
	s.mu.RUnlock()
	return cloneIntegrationTask(record.task), ok, nil
}

func (s *MemoryStore) StartAttempt(_ context.Context, request StartAttemptRequest) (IntegrationTask, bool, error) {
	if !validStartAttemptRequest(request) {
		return IntegrationTask{}, false, ErrInvalidRequest
	}
	key := request.TenantID + "\x00" + request.IntegrationID
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.items[key]
	if !ok || record.task.ProjectID != request.ProjectID || record.task.OwnerTaskID != request.OwnerTaskID {
		return IntegrationTask{}, false, ErrAttemptState
	}
	if record.task.State == TaskBlockedUserDecision && record.task.Attempt == request.Attempt && record.task.Version > request.ExpectedVersion {
		return cloneIntegrationTask(record.task), false, ErrAttemptsExhausted
	}
	if record.task.Attempt == request.Attempt && record.task.Version > request.ExpectedVersion {
		return cloneIntegrationTask(record.task), false, nil
	}
	if record.task.State != TaskReworkRequired || record.task.Version != request.ExpectedVersion || record.task.Attempt+1 != request.Attempt {
		return cloneIntegrationTask(record.task), false, ErrAttemptState
	}
	record.task.State = TaskExecuting
	record.task.Attempt = request.Attempt
	record.task.Version++
	record.result.Attempt = request.Attempt
	s.items[key] = record
	return cloneIntegrationTask(record.task), true, nil
}

func (s *MemoryStore) RecordConflict(_ context.Context, result MergeResult) (MergeResult, bool, error) {
	if !validConflictResult(result) {
		return MergeResult{}, false, ErrInvalidRequest
	}
	key := result.TenantID + "\x00" + result.IntegrationID
	s.mu.Lock()
	defer s.mu.Unlock()
	if prior, ok := s.items[key]; ok {
		terminalConflict := prior.task.State == TaskReworkRequired || prior.task.State == TaskBlockedUserDecision
		if terminalConflict {
			if sameConflictResult(prior.result, result) {
				return cloneResult(prior.result), false, nil
			}
			return MergeResult{}, false, ErrImmutable
		}
		initialMergeFailure := result.Attempt == 0 && prior.task.State == TaskMergeReserved && prior.task.Attempt == 0 && prior.task.OwnerTaskID == "" && isMergeFailureAudit(result.Audit, result.OwnerTaskID)
		if !initialMergeFailure && (prior.task.OwnerTaskID != result.OwnerTaskID || prior.task.Attempt != result.Attempt) {
			return MergeResult{}, false, ErrAttemptState
		}
		reworkFailure := result.Attempt > 0 &&
			(prior.task.State == TaskExecuting || prior.task.State == TaskMergeReserved && isMergeFailureAudit(result.Audit, result.OwnerTaskID))
		if !initialMergeFailure && !reworkFailure {
			return MergeResult{}, false, ErrAttemptState
		}
		prior.result = cloneResult(result)
		prior.task.OwnerTaskID = result.OwnerTaskID
		prior.task.Conflict = cloneAudit(result.Audit)
		prior.task.Version++
		if result.Attempt == 3 {
			prior.task.State = TaskBlockedUserDecision
		} else {
			prior.task.State = TaskReworkRequired
		}
		s.items[key] = prior
		return cloneResult(prior.result), true, nil
	}
	if result.Attempt != 0 {
		return MergeResult{}, false, ErrAttemptState
	}
	s.items[key] = memoryRecord{
		result: cloneResult(result),
		task: IntegrationTask{
			TenantID: result.TenantID, ProjectID: result.ProjectID, ID: result.IntegrationID,
			OwnerTaskID: result.OwnerTaskID, State: TaskReworkRequired, Version: 1,
			Conflict: cloneAudit(result.Audit),
		},
	}
	return cloneResult(result), true, nil
}

func (s *MemoryStore) Reserve(_ context.Context, result MergeResult) (MergeResult, bool, error) {
	key := result.TenantID + "\x00" + result.IntegrationID
	s.mu.Lock()
	defer s.mu.Unlock()
	if prior, ok := s.items[key]; ok {
		if prior.result.RequestDigest == result.RequestDigest && prior.result.Audit.EvidenceSHA256 == result.Audit.EvidenceSHA256 {
			return cloneResult(prior.result), false, nil
		}
		if result.Attempt == 0 || prior.task.State != TaskExecuting || prior.task.Attempt != result.Attempt || prior.task.OwnerTaskID != result.OwnerTaskID {
			return MergeResult{}, false, ErrAttemptState
		}
		result.Pending = true
		prior.result = cloneResult(result)
		prior.task.State = TaskMergeReserved
		prior.task.Version++
		s.items[key] = prior
		return cloneResult(prior.result), true, nil
	}
	if result.Attempt != 0 || result.OwnerTaskID != "" {
		return MergeResult{}, false, ErrAttemptState
	}
	result.Pending = true
	s.items[key] = memoryRecord{
		result: cloneResult(result),
		task:   IntegrationTask{TenantID: result.TenantID, ProjectID: result.ProjectID, ID: result.IntegrationID, State: TaskMergeReserved, Version: 1},
	}
	return cloneResult(result), true, nil
}

func (s *MemoryStore) Complete(_ context.Context, result MergeResult) error {
	key := result.TenantID + "\x00" + result.IntegrationID
	s.mu.Lock()
	defer s.mu.Unlock()
	prior, ok := s.items[key]
	if !ok || prior.result.RequestDigest != result.RequestDigest || prior.result.Audit.EvidenceSHA256 != result.Audit.EvidenceSHA256 {
		return ErrImmutable
	}
	if !prior.result.Pending {
		if prior.result.Commit == result.Commit && prior.task.State == TaskDone {
			return nil
		}
		return ErrImmutable
	}
	if prior.task.State != TaskMergeReserved || prior.task.OwnerTaskID != result.OwnerTaskID || prior.task.Attempt != result.Attempt {
		return ErrAttemptState
	}
	result.Pending = false
	prior.result = cloneResult(result)
	prior.task.State = TaskDone
	prior.task.Version++
	s.items[key] = prior
	return nil
}

func cloneResult(result MergeResult) MergeResult {
	result.Audit = cloneAudit(result.Audit)
	return result
}

func cloneAudit(audit Audit) Audit {
	audit.Findings = append([]Finding(nil), audit.Findings...)
	for index := range audit.Findings {
		audit.Findings[index].Tasks = append([]string(nil), audit.Findings[index].Tasks...)
	}
	return audit
}

func cloneIntegrationTask(task IntegrationTask) IntegrationTask {
	task.Conflict = cloneAudit(task.Conflict)
	return task
}

func validConflictResult(result MergeResult) bool {
	return result.TenantID != "" && result.ProjectID != "" && result.IntegrationID != "" &&
		result.OwnerTaskID != "" && result.Attempt >= 0 && result.Attempt <= 3 &&
		result.Commit == "" && result.RequestDigest == "" && !result.Duplicate && !result.Pending &&
		result.Audit.IntegrationID == result.IntegrationID && result.Audit.ProjectID == result.ProjectID &&
		!result.Audit.Passed && len(result.Audit.Findings) > 0 && digestPattern(result.Audit.EvidenceSHA256) &&
		!result.Audit.CreatedAt.IsZero()
}

func sameConflictResult(left, right MergeResult) bool {
	return validConflictResult(left) && validConflictResult(right) &&
		left.TenantID == right.TenantID && left.ProjectID == right.ProjectID && left.IntegrationID == right.IntegrationID &&
		left.OwnerTaskID == right.OwnerTaskID && left.Attempt == right.Attempt &&
		left.Audit.EvidenceSHA256 == right.Audit.EvidenceSHA256 && reflect.DeepEqual(left.Audit.Findings, right.Audit.Findings)
}

func validStartAttemptRequest(request StartAttemptRequest) bool {
	return request.TenantID != "" && request.ProjectID != "" && request.IntegrationID != "" && request.OwnerTaskID != "" &&
		request.Attempt >= 1 && request.Attempt <= 3 && request.ExpectedVersion >= 1
}

func isMergeFailureAudit(audit Audit, ownerTaskID string) bool {
	if len(audit.Findings) != 1 {
		return false
	}
	finding := audit.Findings[0]
	if finding.ID != "merge-conflict" || finding.Severity != "BLOCKING" || finding.Category != "MERGE" {
		return false
	}
	for _, taskID := range finding.Tasks {
		if taskID == ownerTaskID {
			return true
		}
	}
	return false
}
