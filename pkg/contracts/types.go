package contracts

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// ProjectState is the persisted project aggregate state. DONE is intentionally absent.
type ProjectState string

const (
	ProjectCreated             ProjectState = "CREATED"
	ProjectGoalNegotiating     ProjectState = "GOAL_NEGOTIATING"
	ProjectGoalSuspended       ProjectState = "GOAL_SUSPENDED"
	ProjectPlanning            ProjectState = "PLANNING"
	ProjectExecuting           ProjectState = "EXECUTING"
	ProjectIntegrating         ProjectState = "INTEGRATING"
	ProjectGlobalAudit         ProjectState = "GLOBAL_AUDIT"
	ProjectBlockedUserDecision ProjectState = "BLOCKED_USER_DECISION"
	ProjectPaused              ProjectState = "PAUSED"
	ProjectCompleted           ProjectState = "COMPLETED"
	ProjectAborted             ProjectState = "ABORTED"
	ProjectFailedSystem        ProjectState = "FAILED_SYSTEM"
	ProjectArchived            ProjectState = "ARCHIVED"
)

// ModuleTaskState is the persisted module task state. Module completion is computed separately.
type ModuleTaskState string

const (
	TaskDefined             ModuleTaskState = "DEFINED"
	TaskQueuedPlanning      ModuleTaskState = "QUEUED_PLANNING"
	TaskPlanning            ModuleTaskState = "PLANNING"
	TaskReadyExecution      ModuleTaskState = "READY_EXECUTION"
	TaskQueuedExecution     ModuleTaskState = "QUEUED_EXECUTION"
	TaskExecuting           ModuleTaskState = "EXECUTING"
	TaskSubmitted           ModuleTaskState = "SUBMITTED"
	TaskDeterministicAudit  ModuleTaskState = "DETERMINISTIC_AUDIT"
	TaskLLMAudit            ModuleTaskState = "LLM_AUDIT"
	TaskReworkRequired      ModuleTaskState = "REWORK_REQUIRED"
	TaskBlockedDependency   ModuleTaskState = "BLOCKED_DEPENDENCY"
	TaskBlockedUserDecision ModuleTaskState = "BLOCKED_USER_DECISION"
	TaskPassed              ModuleTaskState = "PASSED"
	TaskIntegrated          ModuleTaskState = "INTEGRATED"
	TaskCanceled            ModuleTaskState = "CANCELED"
	TaskSuperseded          ModuleTaskState = "SUPERSEDED"
)

// GoalStatus is the immutable spec envelope status.
type GoalStatus string

const (
	GoalDraft      GoalStatus = "DRAFT"
	GoalApproved   GoalStatus = "APPROVED"
	GoalSuperseded GoalStatus = "SUPERSEDED"
	GoalRejected   GoalStatus = "REJECTED"
)

type RiskTolerance string

const (
	RiskLow    RiskTolerance = "LOW"
	RiskMedium RiskTolerance = "MEDIUM"
	RiskHigh   RiskTolerance = "HIGH"
)

type DataClassification string

const (
	DataPublic       DataClassification = "PUBLIC"
	DataInternal     DataClassification = "INTERNAL"
	DataConfidential DataClassification = "CONFIDENTIAL"
	DataRestricted   DataClassification = "RESTRICTED"
)

type ExecutionPlatform string

const (
	PlatformLinux   ExecutionPlatform = "LINUX"
	PlatformWindows ExecutionPlatform = "WINDOWS"
)

type IsolationLevel string

const (
	IsolationContainer IsolationLevel = "CONTAINER"
	IsolationNone      IsolationLevel = "NONE"
)

type NetworkMode string

const (
	NetworkDenyAll      NetworkMode = "DENY_ALL"
	NetworkAllowlist    NetworkMode = "ALLOWLIST"
	NetworkUnrestricted NetworkMode = "UNRESTRICTED"
)

type WorkloadTrust string

const (
	WorkloadTrusted   WorkloadTrust = "TRUSTED"
	WorkloadUntrusted WorkloadTrust = "UNTRUSTED"
)

// SpecRef binds a versioned immutable document.
type SpecRef struct {
	Version int    `json:"version"`
	SHA256  string `json:"sha256"`
}

// AgentIdentity is safe-to-log identity metadata, never a provider secret.
type AgentIdentity struct {
	AgentInstanceID string `json:"agentInstanceId"`
	Role            string `json:"role"`
	Provider        string `json:"provider,omitempty"`
	Model           string `json:"model,omitempty"`
	LeaseID         string `json:"leaseId,omitempty"`
}

type ApprovalActor struct {
	ActorID    string `json:"actorId"`
	ApprovedAt string `json:"approvedAt"`
}

type Signature struct {
	Type string `json:"type"`
	KID  string `json:"kid"`
	JWS  string `json:"jws"`
}

type Outcome struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
}

type Scope struct {
	Included []string `json:"included"`
	Excluded []string `json:"excluded"`
}

type NonFunctionalRequirements struct {
	Security    []string `json:"security"`
	Privacy     []string `json:"privacy"`
	Performance []string `json:"performance"`
	Reliability []string `json:"reliability"`
	Operability []string `json:"operability"`
}

type AcceptanceCriterion struct {
	ID           string `json:"id"`
	Statement    string `json:"statement"`
	EvidenceType string `json:"evidenceType"`
}

type Assumption struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
	Status    string `json:"status"`
}

// GoalContent is the canonical immutable GoalSpec content shape.
type GoalContent struct {
	GoalSpecVersion           int                       `json:"goalSpecVersion"`
	ProjectID                 string                    `json:"projectId"`
	Version                   int                       `json:"version"`
	Title                     string                    `json:"title"`
	Summary                   string                    `json:"summary"`
	ProblemStatement          string                    `json:"problemStatement"`
	BusinessOutcomes          []Outcome                 `json:"businessOutcomes"`
	Scope                     Scope                     `json:"scope"`
	UserPersonas              []string                  `json:"userPersonas"`
	FunctionalRequirements    []string                  `json:"functionalRequirements"`
	NonFunctionalRequirements NonFunctionalRequirements `json:"nonFunctionalRequirements"`
	Constraints               []string                  `json:"constraints"`
	Assumptions               []Assumption              `json:"assumptions"`
	Decisions                 []string                  `json:"decisions"`
	UnresolvedItems           []string                  `json:"unresolvedItems"`
	AcceptanceCriteria        []AcceptanceCriterion     `json:"acceptanceCriteria"`
	RiskTolerance             RiskTolerance             `json:"riskTolerance"`
	HumanApprovalPoints       []string                  `json:"humanApprovalPoints"`
	DataClassification        DataClassification        `json:"dataClassification"`
	DeploymentTargets         []string                  `json:"deploymentTargets"`
	SourceReferences          []string                  `json:"sourceReferences"`
	CreatedAt                 string                    `json:"createdAt"`
	CreatedBy                 AgentIdentity             `json:"createdBy"`
}

type GoalSpec struct {
	Content       GoalContent    `json:"content"`
	Status        GoalStatus     `json:"status"`
	ApprovedBy    *ApprovalActor `json:"approvedBy,omitempty"`
	ContentSHA256 string         `json:"contentSha256"`
	Signature     *Signature     `json:"signature,omitempty"`
}

type Architecture struct {
	Style           string   `json:"style"`
	Components      []string `json:"components"`
	DataFlows       []string `json:"dataFlows"`
	TrustBoundaries []string `json:"trustBoundaries"`
	DeploymentUnits []string `json:"deploymentUnits"`
}

type PlanModule struct {
	ModuleID           string            `json:"moduleId"`
	Name               string            `json:"name"`
	Responsibility     string            `json:"responsibility"`
	ExecutionPlatform  ExecutionPlatform `json:"executionPlatform"`
	SandboxLevel       IsolationLevel    `json:"sandboxLevel"`
	OwnedPaths         []string          `json:"ownedPaths"`
	ForbiddenPaths     []string          `json:"forbiddenPaths"`
	PublicInterfaces   []string          `json:"publicInterfaces"`
	Dependencies       []string          `json:"dependencies"`
	AcceptanceCriteria []string          `json:"acceptanceCriteria"`
	Risk               string            `json:"risk"`
}

type PlanSpec struct {
	PlanSpecVersion   int          `json:"planSpecVersion"`
	ProjectID         string       `json:"projectId"`
	GoalSpecRef       SpecRef      `json:"goalSpecRef"`
	Architecture      Architecture `json:"architecture"`
	QualityAttributes []string     `json:"qualityAttributes"`
	Modules           []PlanModule `json:"modules"`
	IntegrationPlan   []string     `json:"integrationPlan"`
	ReleasePlan       []string     `json:"releasePlan"`
	TestStrategy      []string     `json:"testStrategy"`
	RollbackStrategy  []string     `json:"rollbackStrategy"`
	OpenDecisions     []string     `json:"openDecisions"`
	SHA256            string       `json:"sha256"`
}

type Budget struct {
	MaxInputTokens  int    `json:"maxInputTokens"`
	MaxOutputTokens int    `json:"maxOutputTokens"`
	MaxCost         string `json:"maxCost"`
	Currency        string `json:"currency"`
}

type ModuleSpec struct {
	ModuleSpecVersion         int               `json:"moduleSpecVersion"`
	ModuleID                  string            `json:"moduleId"`
	ProjectID                 string            `json:"projectId"`
	PlanVersion               int               `json:"planVersion"`
	Name                      string            `json:"name"`
	Purpose                   string            `json:"purpose"`
	Responsibilities          []string          `json:"responsibilities"`
	NonResponsibilities       []string          `json:"nonResponsibilities"`
	Inputs                    []string          `json:"inputs"`
	Outputs                   []string          `json:"outputs"`
	Interfaces                []string          `json:"interfaces"`
	DataOwnership             []string          `json:"dataOwnership"`
	Dependencies              []string          `json:"dependencies"`
	AllowedPaths              []string          `json:"allowedPaths"`
	ForbiddenPaths            []string          `json:"forbiddenPaths"`
	ExecutionPlatform         ExecutionPlatform `json:"executionPlatform"`
	SandboxLevel              IsolationLevel    `json:"sandboxLevel"`
	NetworkPolicy             NetworkPolicy     `json:"networkPolicy"`
	WorkloadProfile           WorkloadProfile   `json:"workloadProfile"`
	ToolCapabilities          []string          `json:"toolCapabilities"`
	KnowledgeRefs             []string          `json:"knowledgeRefs"`
	AcceptanceCriteria        []string          `json:"acceptanceCriteria"`
	TestRequirements          []string          `json:"testRequirements"`
	ObservabilityRequirements []string          `json:"observabilityRequirements"`
	SecurityRequirements      []string          `json:"securityRequirements"`
	Budget                    Budget            `json:"budget"`
	SHA256                    string            `json:"sha256"`
}

type NetworkPolicy struct {
	Mode         NetworkMode `json:"mode"`
	Destinations []string    `json:"destinations"`
}

type WorkloadProfile struct {
	Trust                             WorkloadTrust `json:"trust"`
	HostileMultiTenant                bool          `json:"hostileMultiTenant"`
	RequiresNetworkIsolation          bool          `json:"requiresNetworkIsolation"`
	RequiresHiddenTestConfidentiality bool          `json:"requiresHiddenTestConfidentiality"`
}

type SubmissionManifest struct {
	SubmissionVersion     int           `json:"submissionVersion"`
	ProjectID             string        `json:"projectId"`
	ModuleTaskID          string        `json:"moduleTaskId"`
	AttemptSeriesID       string        `json:"attemptSeriesId"`
	Attempt               int           `json:"attempt"`
	ModuleSpecRef         SpecRef       `json:"moduleSpecRef"`
	BaseCommit            string        `json:"baseCommit"`
	HeadCommit            string        `json:"headCommit"`
	ChangedFiles          []string      `json:"changedFiles"`
	DeletedFiles          []string      `json:"deletedFiles"`
	CreatedFiles          []string      `json:"createdFiles"`
	ClaimedCriteria       []string      `json:"claimedCriteria"`
	LocalTestEvidenceRefs []string      `json:"localTestEvidenceRefs"`
	AgentIdentity         AgentIdentity `json:"agentIdentity"`
	CreatedAt             string        `json:"createdAt"`
	SHA256                string        `json:"sha256"`
	Signature             *Signature    `json:"signature,omitempty"`
}

type CheckTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type EvidenceCheck struct {
	CheckID      string    `json:"checkId"`
	Ordinal      int       `json:"ordinal"`
	Type         string    `json:"type"`
	Status       string    `json:"status"`
	Tool         CheckTool `json:"tool"`
	StartedAt    string    `json:"startedAt"`
	CompletedAt  string    `json:"completedAt"`
	StdoutURI    string    `json:"stdoutUri"`
	StderrURI    string    `json:"stderrUri"`
	ResultURI    string    `json:"resultUri"`
	ResultSHA256 string    `json:"resultSha256"`
}

type LLMAudit struct {
	AuditorRunID          string `json:"auditorRunId"`
	ModelIdentity         string `json:"modelIdentity"`
	PromptDigest          string `json:"promptDigest"`
	ContextManifestDigest string `json:"contextManifestDigest"`
	Verdict               string `json:"verdict"`
}

type EvidenceBundle struct {
	EvidenceBundleVersion int               `json:"evidenceBundleVersion"`
	ProjectID             string            `json:"projectId"`
	TaskID                string            `json:"taskId"`
	AttemptSeriesID       string            `json:"attemptSeriesId"`
	Attempt               int               `json:"attempt"`
	SpecVersion           int               `json:"specVersion"`
	BaseCommit            string            `json:"baseCommit"`
	SubmissionCommit      string            `json:"submissionCommit"`
	PipelineVersion       string            `json:"pipelineVersion"`
	PolicyBundleDigest    string            `json:"policyBundleDigest"`
	ExecutionPlatform     ExecutionPlatform `json:"executionPlatform"`
	IsolationLevel        IsolationLevel    `json:"isolationLevel"`
	SandboxAttestation    string            `json:"sandboxAttestation"`
	Checks                []EvidenceCheck   `json:"checks"`
	Findings              []string          `json:"findings"`
	Artifacts             []string          `json:"artifacts"`
	LLMAudit              LLMAudit          `json:"llmAudit"`
	ManifestSHA256        string            `json:"manifestSha256"`
	Signature             *Signature        `json:"signature,omitempty"`
}

type Decision string

const (
	DecisionAbortProject              Decision = "ABORT_PROJECT"
	DecisionAbortModule               Decision = "ABORT_MODULE"
	DecisionReviseGoal                Decision = "REVISE_GOAL"
	DecisionReviseModuleSpec          Decision = "REVISE_MODULE_SPEC"
	DecisionHandOffToHuman            Decision = "HAND_OFF_TO_HUMAN"
	DecisionAuthorizeNewAttemptSeries Decision = "AUTHORIZE_NEW_ATTEMPT_SERIES"
)

type UserDecisionReport struct {
	ReportVersion      string            `json:"reportVersion"`
	ProjectID          string            `json:"projectId"`
	GoalSpec           SpecRef           `json:"goalSpec"`
	ModuleTaskID       string            `json:"moduleTaskId"`
	ModuleName         string            `json:"moduleName"`
	State              ModuleTaskState   `json:"state"`
	AttemptLimit       int               `json:"attemptLimit"`
	Attempts           []AttemptSummary  `json:"attempts"`
	BlockingFindings   []BlockingFinding `json:"blockingFindings"`
	FrozenTaskIDs      []string          `json:"frozenTaskIds"`
	CriticalPathImpact bool              `json:"criticalPathImpact"`
	AllowedDecisions   []Decision        `json:"allowedDecisions"`
	GeneratedAt        string            `json:"generatedAt"`
	Signature          *Signature        `json:"signature,omitempty"`
}

type AttemptSummary struct {
	Attempt          int      `json:"attempt"`
	SubmissionCommit string   `json:"submissionCommit"`
	FailureStage     string   `json:"failureStage"`
	FindingIDs       []string `json:"findingIds"`
	EvidenceURI      string   `json:"evidenceUri"`
}

type BlockingFinding struct {
	ID                   string `json:"id"`
	Severity             string `json:"severity"`
	Category             string `json:"category"`
	Summary              string `json:"summary"`
	Location             string `json:"location"`
	ReproductionURI      string `json:"reproductionUri"`
	FirstObservedAttempt int    `json:"firstObservedAttempt"`
	LastObservedAttempt  int    `json:"lastObservedAttempt"`
}

// CompletionEvidence is the deterministic subset used by the computed DONE predicate.
type CompletionEvidence struct {
	SubmissionImmutable bool
	AuditPassed         bool
	MergeQueued         bool
	NoBlockingFindings  bool
	RequiredEvidence    bool
}

func (e CompletionEvidence) Done(state ModuleTaskState) bool {
	return state == TaskIntegrated && e.SubmissionImmutable && e.AuditPassed && e.MergeQueued && e.NoBlockingFindings && e.RequiredEvidence
}

func (r SpecRef) Validate() error {
	if r.Version < 1 {
		return fmt.Errorf("spec version must be positive")
	}
	return validateDigest(r.SHA256)
}

func validateDigest(value string) error {
	if !digestPattern.MatchString(value) {
		return fmt.Errorf("invalid sha256 digest")
	}
	return nil
}

func validateCommit(value string) error {
	if !commitPattern.MatchString(value) {
		return fmt.Errorf("commit must be 40 lowercase hexadecimal characters")
	}
	return nil
}

func validPlatformIsolation(platform ExecutionPlatform, isolation IsolationLevel) bool {
	return (platform == PlatformLinux && isolation == IsolationContainer) || (platform == PlatformWindows && isolation == IsolationNone)
}

func (m ModuleSpec) Validate() error {
	if m.ModuleSpecVersion < 1 || m.PlanVersion < 1 || m.ModuleID == "" || m.ProjectID == "" {
		return fmt.Errorf("module identity and versions are required")
	}
	if !validPlatformIsolation(m.ExecutionPlatform, m.SandboxLevel) {
		return fmt.Errorf("execution platform and sandbox level do not match")
	}
	if m.ExecutionPlatform == PlatformWindows {
		if m.NetworkPolicy.Mode != NetworkUnrestricted || len(m.NetworkPolicy.Destinations) != 0 {
			return fmt.Errorf("windows NONE provider cannot claim network isolation")
		}
		if m.WorkloadProfile.Trust != WorkloadTrusted || m.WorkloadProfile.HostileMultiTenant || m.WorkloadProfile.RequiresNetworkIsolation || m.WorkloadProfile.RequiresHiddenTestConfidentiality {
			return fmt.Errorf("windows NONE provider accepts only trusted work without isolation or hidden-test requirements")
		}
	} else if m.NetworkPolicy.Mode == NetworkUnrestricted {
		return fmt.Errorf("unrestricted network is only valid for windows NONE disclosure")
	}
	if m.WorkloadProfile.Trust != WorkloadTrusted && m.WorkloadProfile.Trust != WorkloadUntrusted {
		return fmt.Errorf("workload trust must be declared")
	}
	if err := validateDigest(m.SHA256); err != nil {
		return err
	}
	return nil
}

func (s SubmissionManifest) Validate() error {
	if s.SubmissionVersion < 1 || s.ProjectID == "" || s.ModuleTaskID == "" || s.AttemptSeriesID == "" || s.Attempt < 1 || s.Attempt > 3 {
		return fmt.Errorf("submission identity or attempt is invalid")
	}
	if err := s.ModuleSpecRef.Validate(); err != nil {
		return err
	}
	if err := validateCommit(s.BaseCommit); err != nil {
		return fmt.Errorf("base commit: %w", err)
	}
	if err := validateCommit(s.HeadCommit); err != nil {
		return fmt.Errorf("head commit: %w", err)
	}
	if s.BaseCommit == s.HeadCommit {
		return fmt.Errorf("submission must change the head commit")
	}
	if s.AgentIdentity.AgentInstanceID == "" || s.AgentIdentity.Role != "EXECUTOR" || s.AgentIdentity.LeaseID == "" {
		return fmt.Errorf("submission requires a lease-bound Executor identity")
	}
	if _, err := time.Parse(time.RFC3339, s.CreatedAt); err != nil {
		return fmt.Errorf("submission createdAt must be RFC3339")
	}
	return validateDigest(s.SHA256)
}

func (e EvidenceBundle) Validate() error {
	if e.EvidenceBundleVersion < 1 || e.ProjectID == "" || e.TaskID == "" || e.Attempt < 1 || e.Attempt > 3 {
		return fmt.Errorf("evidence identity or attempt is invalid")
	}
	if !validPlatformIsolation(e.ExecutionPlatform, e.IsolationLevel) {
		return fmt.Errorf("evidence platform and isolation level do not match")
	}
	if err := validateCommit(e.BaseCommit); err != nil {
		return fmt.Errorf("base commit: %w", err)
	}
	if err := validateCommit(e.SubmissionCommit); err != nil {
		return fmt.Errorf("submission commit: %w", err)
	}
	if e.ExecutionPlatform == PlatformLinux && !strings.HasPrefix(e.SandboxAttestation, "oci:") {
		return fmt.Errorf("linux evidence requires an OCI-bound sandbox attestation")
	}
	if e.ExecutionPlatform == PlatformWindows && e.SandboxAttestation != "windows:none" {
		return fmt.Errorf("windows evidence must disclose NONE")
	}
	return validateDigest(e.ManifestSHA256)
}

func (g GoalSpec) Validate() error {
	if g.Content.GoalSpecVersion < 1 || g.Content.ProjectID == "" || g.Content.Version < 1 || g.Content.Title == "" || g.Content.Summary == "" || g.Content.ProblemStatement == "" {
		return fmt.Errorf("goal identity and versions are required")
	}
	switch g.Status {
	case GoalDraft, GoalApproved, GoalSuperseded, GoalRejected:
	default:
		return fmt.Errorf("unknown GoalStatus")
	}
	if len(g.Content.BusinessOutcomes) == 0 || len(g.Content.AcceptanceCriteria) == 0 || g.Content.CreatedBy.AgentInstanceID == "" || g.Content.CreatedBy.Role == "" {
		return fmt.Errorf("goal outcomes, acceptance criteria, and creator are required")
	}
	if _, err := time.Parse(time.RFC3339, g.Content.CreatedAt); err != nil {
		return fmt.Errorf("goal createdAt must be RFC3339")
	}
	if g.Status == GoalApproved {
		if len(g.Content.UnresolvedItems) != 0 || g.ApprovedBy == nil {
			return fmt.Errorf("approved goal must have no unresolved items and must be user approved")
		}
	}
	return validateDigest(g.ContentSHA256)
}
