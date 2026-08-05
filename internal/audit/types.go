package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/pkg/contracts"
)

var (
	ErrInvalidInput       = errors.New("invalid audit input")
	ErrEvidenceConflict   = errors.New("audit evidence is immutable")
	ErrAuditRunConflict   = errors.New("audit run is immutable")
	ErrDeterministicGate  = errors.New("deterministic audit gate failed")
	ErrBlindContext       = errors.New("auditor context is not blind")
	ErrAuditorUnavailable = errors.New("fresh auditor is unavailable")
	ErrArtifactStore      = errors.New("audit artifact store is required for streaming output")
)

type CheckStatus string

const (
	StatusPass  CheckStatus = "PASS"
	StatusFail  CheckStatus = "FAIL"
	StatusError CheckStatus = "ERROR"
)

type CheckResult struct {
	Status       CheckStatus
	Findings     []contracts.AuditFinding
	Stdout       []byte
	Stderr       []byte
	Result       []byte
	StdoutStream *StreamOutput
	StderrStream *StreamOutput
	ResultStream *StreamOutput
}

// StreamOutput lets a check hand a large result directly to the artifact store.
// The callback must not retain the destination after it returns.
type StreamOutput struct {
	MediaType string
	Write     func(context.Context, io.Writer) error
}

type ArtifactPublisher interface {
	Put(context.Context, artifact.PutRequest, func(io.Writer) error) (artifact.Manifest, error)
}

type Check interface {
	ID() string
	Run(context.Context, DeterministicInput) CheckResult
}

type DeterministicInput struct {
	TenantID           string
	SubmissionID       string
	Manifest           contracts.SubmissionManifest
	ModuleSpecRef      contracts.SpecRef
	AllowedPaths       []string
	ForbiddenPaths     []string
	RequiredCriteria   []string
	PolicyDigest       string
	Platform           contracts.ExecutionPlatform
	Isolation          contracts.IsolationLevel
	SandboxAttestation string
}

type BlindAuditInput struct {
	ProjectID           string
	TaskID              string
	Attempt             int
	ModuleSpecRef       contracts.SpecRef
	BaseCommit          string
	SubmissionCommit    string
	ChangedFiles        []string
	RequiredCriteria    []string
	DeterministicChecks []contracts.EvidenceCheck
	EvidenceBundle      contracts.EvidenceBundle
}

type LLMAuditResult struct {
	AuditorRunID    string
	ModelIdentity   string
	PromptDigest    string
	ContextDigest   string
	Verdict         string
	Findings        []contracts.AuditFinding
	CriteriaResults []contracts.CriterionResult
	ResidualRisks   []string
	Confidence      float64
}

type Auditor interface {
	Audit(context.Context, BlindAuditInput) (LLMAuditResult, error)
}

type AuditorFactory interface {
	New(context.Context) (Auditor, error)
}

type Signer interface {
	Sign(context.Context, []byte) (*contracts.Signature, error)
	Verify(context.Context, []byte, *contracts.Signature) error
}

type EvidenceStore interface {
	Put(context.Context, string, contracts.EvidenceBundle) error
	Get(context.Context, string, string, string, string, int) (contracts.EvidenceBundle, bool, error)
}

type AuditRun struct {
	TenantID          string
	ProjectID         string
	SubmissionID      string
	Phase             string
	PipelineVersion   string
	Platform          contracts.ExecutionPlatform
	Isolation         contracts.IsolationLevel
	StartedAt         time.Time
	CompletedAt       time.Time
	Verdict           string
	EvidenceBundleRef string
	Findings          []contracts.AuditFinding
}

type AuditRunStore interface {
	Put(context.Context, AuditRun) error
}

type MemoryEvidenceStore struct {
	mu    sync.RWMutex
	items map[string]contracts.EvidenceBundle
}

func NewMemoryEvidenceStore() *MemoryEvidenceStore {
	return &MemoryEvidenceStore{items: make(map[string]contracts.EvidenceBundle)}
}

func (s *MemoryEvidenceStore) Put(_ context.Context, tenantID string, bundle contracts.EvidenceBundle) error {
	key := evidenceKey(tenantID, bundle.ProjectID, bundle.TaskID, bundle.AttemptSeriesID, bundle.Attempt)
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, ok := s.items[key]; ok {
		if previous.ManifestSHA256 == bundle.ManifestSHA256 {
			return nil
		}
		return ErrEvidenceConflict
	}
	s.items[key] = cloneBundle(bundle)
	return nil
}

func (s *MemoryEvidenceStore) Get(_ context.Context, tenantID, projectID, taskID, attemptSeriesID string, attempt int) (contracts.EvidenceBundle, bool, error) {
	s.mu.RLock()
	bundle, ok := s.items[evidenceKey(tenantID, projectID, taskID, attemptSeriesID, attempt)]
	s.mu.RUnlock()
	return cloneBundle(bundle), ok, nil
}

func evidenceKey(tenantID, projectID, taskID, attemptSeriesID string, attempt int) string {
	return tenantID + "\x00" + projectID + "\x00" + taskID + "\x00" + attemptSeriesID + "\x00" + fmt.Sprint(attempt)
}

func cloneBundle(bundle contracts.EvidenceBundle) contracts.EvidenceBundle {
	bundle.Checks = append([]contracts.EvidenceCheck(nil), bundle.Checks...)
	bundle.Findings = cloneFindings(bundle.Findings)
	bundle.CriteriaResults = cloneCriteriaResults(bundle.CriteriaResults)
	bundle.ResidualRisks = cloneStrings(bundle.ResidualRisks)
	bundle.Artifacts = cloneStrings(bundle.Artifacts)
	if bundle.Signature != nil {
		signature := *bundle.Signature
		bundle.Signature = &signature
	}
	return bundle
}

func cloneFindings(findings []contracts.AuditFinding) []contracts.AuditFinding {
	if findings == nil {
		return nil
	}
	result := make([]contracts.AuditFinding, len(findings))
	copy(result, findings)
	for index := range result {
		result[index].EvidenceRefs = cloneStrings(findings[index].EvidenceRefs)
	}
	return result
}

func cloneCriteriaResults(criteria []contracts.CriterionResult) []contracts.CriterionResult {
	if criteria == nil {
		return nil
	}
	result := make([]contracts.CriterionResult, len(criteria))
	copy(result, criteria)
	for index := range result {
		result[index].EvidenceRefs = cloneStrings(criteria[index].EvidenceRefs)
	}
	return result
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	result := make([]string, len(values))
	copy(result, values)
	return result
}

type AuditResult struct {
	Bundle        contracts.EvidenceBundle
	Deterministic []contracts.EvidenceCheck
	LLM           *LLMAuditResult
	Verdict       string
}

type Pipeline struct {
	checks    []Check
	auditors  AuditorFactory
	signer    Signer
	store     EvidenceStore
	runStore  AuditRunStore
	artifacts ArtifactPublisher
	clock     func() time.Time
	version   string
}
