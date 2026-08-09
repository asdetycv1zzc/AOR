package goalplan

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
)

var (
	ErrInvalidRequest    = errors.New("invalid goal or plan request")
	ErrAgentOutput       = errors.New("invalid agent output")
	ErrArtifactNotFound  = errors.New("required immutable artifact not found")
	ErrOwnershipConflict = errors.New("plan ownership conflict")
)

type AgentInvocation struct {
	InvocationID string
	TenantID     string
	ProjectID    string
	TaskID       string
	Role         agentruntime.Role
	Stage        string
	Inputs       []ArtifactPointer
	Payload      json.RawMessage
}

type ArtifactPointer struct {
	Kind          ArtifactKind `json:"kind"`
	SpecID        string       `json:"specId"`
	Version       int          `json:"version"`
	URI           string       `json:"uri"`
	ContentSHA256 string       `json:"contentSha256"`
}

type AgentRecord struct {
	RunID           string
	AgentInstanceID string
	Role            agentruntime.Role
	Payload         json.RawMessage
}

type AgentInvoker interface {
	Invoke(ctx context.Context, invocation AgentInvocation) (AgentRecord, error)
}

type ProjectCommander interface {
	HandleProject(ctx context.Context, request orchestrator.ProjectRequest) (orchestrator.ProjectOutcome, error)
	HandleTask(ctx context.Context, request orchestrator.TaskRequest) (orchestrator.TaskOutcome, error)
	QueuePlanTasks(ctx context.Context, request orchestrator.QueuePlanTasksRequest) (orchestrator.QueuePlanTasksOutcome, error)
	PublishPlan(ctx context.Context, request orchestrator.PublishPlanRequest) (orchestrator.PublishPlanOutcome, error)
	Project(ctx context.Context, tenantID, projectID string) (state.Project, bool, error)
}

type ChallengeFinding struct {
	Severity       string `json:"severity"`
	AffectedClause string `json:"affectedClause"`
	Evidence       string `json:"evidence"`
	Question       string `json:"question"`
}

type ChallengeReport struct {
	ReportVersion int                     `json:"reportVersion"`
	ProjectID     string                  `json:"projectId"`
	GoalSpecRef   contracts.SpecRef       `json:"goalSpecRef"`
	Findings      []ChallengeFinding      `json:"findings"`
	CreatedAt     string                  `json:"createdAt"`
	CreatedBy     contracts.AgentIdentity `json:"createdBy"`
	SHA256        string                  `json:"sha256"`
}

type NegotiationRequest struct {
	TenantID               string
	ProjectID              string
	GoalSpecID             string
	MessageID              string
	UserPrincipalID        string
	UserInput              []byte
	GoalAgentCount         int
	PreviousRef            *contracts.SpecRef
	SupersedeApprovedGoal  bool
	ImpactedTaskIDs        []string
	ExpectedProjectVersion int64
	IdempotencyKey         string
	MessageAccepted        bool
}

type NegotiationResult struct {
	Goal              contracts.GoalSpec
	Artifact          SpecArtifact
	Challenge         *ChallengeReport
	ChallengeArtifact *SpecArtifact
	Project           orchestrator.ProjectOutcome
}

type ApprovalRequest struct {
	TenantID               string
	ProjectID              string
	GoalSpecID             string
	GoalRef                contracts.SpecRef
	UserPrincipalID        string
	ExpectedProjectVersion int64
	IdempotencyKey         string
	Approval               ApprovalBinding
}

type ApprovalBinding struct {
	RecordID       string
	ApprovalType   string
	SubjectType    string
	SubjectID      string
	SubjectVersion int
	SubjectSHA256  string
	PrincipalID    string
	Reason         string
	IssuedAt       time.Time
	ExpiresAt      *time.Time
	RevokedAt      *time.Time
	Signature      string
}

type PlanningRequest struct {
	TenantID               string
	ProjectID              string
	PrincipalID            string
	GoalSpecID             string
	GoalRef                contracts.SpecRef
	PlanSpecID             string
	PlanVersion            int
	ModuleTaskIDs          map[string]string
	AttemptSeriesIDs       map[string]string
	ModuleSpecVersions     map[string]int
	RetainedModules        map[string]bool
	ExpectedProjectVersion int64
	IdempotencyKey         string
}

type PlanAnalysis struct {
	AnalysisVersion  int               `json:"analysisVersion"`
	ProjectID        string            `json:"projectId"`
	PlanSpecRef      contracts.SpecRef `json:"planSpecRef"`
	TopologicalOrder []string          `json:"topologicalOrder"`
	CriticalPath     []string          `json:"criticalPath"`
	PathOwners       map[string]string `json:"pathOwners"`
	CreatedAt        string            `json:"createdAt"`
	SHA256           string            `json:"sha256"`
}

type PlanningResult struct {
	Plan             contracts.PlanSpec
	PlanArtifact     SpecArtifact
	ModuleSpecs      map[string]contracts.ModuleSpec
	ModuleArtifacts  map[string]SpecArtifact
	Analysis         PlanAnalysis
	AnalysisArtifact SpecArtifact
	Publication      orchestrator.PublishPlanOutcome
}
