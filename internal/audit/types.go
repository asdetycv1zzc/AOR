package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
)

var (
	ErrInvalidInput       = errors.New("invalid audit input")
	ErrEvidenceConflict   = errors.New("audit evidence is immutable")
	ErrDeterministicGate  = errors.New("deterministic audit gate failed")
	ErrBlindContext       = errors.New("auditor context is not blind")
	ErrAuditorUnavailable = errors.New("fresh auditor is unavailable")
)

type CheckStatus string

const (
	StatusPass  CheckStatus = "PASS"
	StatusFail  CheckStatus = "FAIL"
	StatusError CheckStatus = "ERROR"
)

type CheckResult struct {
	Status   CheckStatus
	Findings []string
	Stdout   []byte
	Stderr   []byte
	Result   []byte
}

type Check interface {
	ID() string
	Run(context.Context, DeterministicInput) CheckResult
}

type DeterministicInput struct {
	Manifest           contracts.SubmissionManifest
	ModuleSpecRef      contracts.SpecRef
	AllowedPaths       []string
	ForbiddenPaths     []string
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
	DeterministicChecks []contracts.EvidenceCheck
	EvidenceBundle      contracts.EvidenceBundle
}

type LLMAuditResult struct {
	AuditorRunID  string
	ModelIdentity string
	PromptDigest  string
	ContextDigest string
	Verdict       string
	Findings      []string
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
	Put(context.Context, contracts.EvidenceBundle) error
	Get(context.Context, string, string, int) (contracts.EvidenceBundle, bool, error)
}

type MemoryEvidenceStore struct {
	mu    sync.RWMutex
	items map[string]contracts.EvidenceBundle
}

func NewMemoryEvidenceStore() *MemoryEvidenceStore {
	return &MemoryEvidenceStore{items: make(map[string]contracts.EvidenceBundle)}
}

func (s *MemoryEvidenceStore) Put(_ context.Context, bundle contracts.EvidenceBundle) error {
	key := bundle.ProjectID + "\x00" + bundle.TaskID + "\x00" + fmt.Sprint(bundle.Attempt)
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

func (s *MemoryEvidenceStore) Get(_ context.Context, projectID, taskID string, attempt int) (contracts.EvidenceBundle, bool, error) {
	s.mu.RLock()
	bundle, ok := s.items[projectID+"\x00"+taskID+"\x00"+fmt.Sprint(attempt)]
	s.mu.RUnlock()
	return cloneBundle(bundle), ok, nil
}

func cloneBundle(bundle contracts.EvidenceBundle) contracts.EvidenceBundle {
	bundle.Checks = append([]contracts.EvidenceCheck(nil), bundle.Checks...)
	bundle.Findings = append([]string(nil), bundle.Findings...)
	bundle.Artifacts = append([]string(nil), bundle.Artifacts...)
	return bundle
}

type AuditResult struct {
	Bundle        contracts.EvidenceBundle
	Deterministic []contracts.EvidenceCheck
	LLM           *LLMAuditResult
	Verdict       string
}

type Pipeline struct {
	checks   []Check
	auditors AuditorFactory
	signer   Signer
	store    EvidenceStore
	clock    func() time.Time
	version  string
}
