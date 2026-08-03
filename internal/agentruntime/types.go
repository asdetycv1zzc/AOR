package agentruntime

import (
	"context"
	"encoding/json"
	"time"

	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/toolbroker"
	"github.com/akimisaka/aor/pkg/aop"
)

const (
	AOPVersion                 = aop.Version
	AOPExtensionURI            = aop.ExtensionURI
	DefaultHeartbeatSeconds    = 30
	MissedHeartbeatLimit       = 3
	MaximumActiveAgentLimit    = 8
	MaximumContextItems        = 100
	MaximumContextItemBytes    = 32 << 10
	MaximumContextBytes        = 1 << 20
	MaximumPromptBundleBytes   = 256 << 10
	MaximumResponseSchemaBytes = 256 << 10
	MaximumAgentOutputBytes    = 1 << 20
)

type Role string

const (
	RoleGoalProposer     Role = "GOAL_PROPOSER"
	RoleGoalChallenger   Role = "GOAL_CHALLENGER"
	RolePlanSupervisor   Role = "PLAN_SUPERVISOR"
	RoleModulePlanner    Role = "MODULE_PLANNER"
	RoleExecutor         Role = "EXECUTOR"
	RoleModuleAuditor    Role = "MODULE_AUDITOR"
	RoleGlobalAuditor    Role = "GLOBAL_AUDITOR"
	RoleKnowledgeCurator Role = "KNOWLEDGE_CURATOR"
)

func (r Role) Valid() bool {
	switch r {
	case RoleGoalProposer, RoleGoalChallenger, RolePlanSupervisor, RoleModulePlanner,
		RoleExecutor, RoleModuleAuditor, RoleGlobalAuditor, RoleKnowledgeCurator:
		return true
	default:
		return false
	}
}

type State string

const (
	StateDeclared          State = "DECLARED"
	StateQueued            State = "QUEUED"
	StateLeased            State = "LEASED"
	StateStarting          State = "STARTING"
	StateRunning           State = "RUNNING"
	StateWaitingInput      State = "WAITING_INPUT"
	StateWaitingTool       State = "WAITING_TOOL"
	StateWaitingDependency State = "WAITING_DEPENDENCY"
	StateCompleted         State = "COMPLETED"
	StateFailed            State = "FAILED"
	StateCanceled          State = "CANCELED"
	StateExpired           State = "EXPIRED"
	StateTerminated        State = "TERMINATED"
)

func (s State) Terminal() bool {
	switch s {
	case StateCompleted, StateFailed, StateCanceled, StateExpired, StateTerminated:
		return true
	default:
		return false
	}
}

type LeaseOperation string

const (
	LeaseOperationAssign    LeaseOperation = "ASSIGN"
	LeaseOperationHeartbeat LeaseOperation = "HEARTBEAT"
	LeaseOperationRenew     LeaseOperation = "RENEW"
	LeaseOperationModel     LeaseOperation = "MODEL"
	LeaseOperationTool      LeaseOperation = "TOOL"
	LeaseOperationResult    LeaseOperation = "RESULT"
)

type AgentLease struct {
	LeaseID                  string    `json:"leaseId"`
	AgentInstanceID          string    `json:"agentInstanceId"`
	TenantID                 string    `json:"tenantId"`
	ProjectID                string    `json:"projectId"`
	TaskID                   string    `json:"taskId,omitempty"`
	Role                     Role      `json:"role"`
	IssuedAt                 time.Time `json:"issuedAt"`
	ExpiresAt                time.Time `json:"expiresAt"`
	LastHeartbeatAt          time.Time `json:"lastHeartbeatAt"`
	HeartbeatIntervalSeconds int       `json:"heartbeatIntervalSeconds"`
	Capabilities             []string  `json:"capabilities"`
	PolicyVersion            string    `json:"policyVersion"`
	BudgetAccountID          string    `json:"budgetAccountId"`
	Nonce                    string    `json:"nonce"`
	FencingToken             int64     `json:"fencingToken"`
	Signature                string    `json:"signature"`
}

type LeaseAuthority interface {
	Validate(ctx context.Context, lease AgentLease, operation LeaseOperation) error
	Heartbeat(ctx context.Context, lease AgentLease) (AgentLease, error)
	Renew(ctx context.Context, lease AgentLease) (AgentLease, error)
}

type PromptBundle struct {
	BundleID      string `json:"bundleId"`
	Version       string `json:"version"`
	Role          Role   `json:"role"`
	GlobalSafety  string `json:"globalSafety"`
	RolePrompt    string `json:"rolePrompt"`
	FixedWorkflow string `json:"fixedWorkflow"`
	OutputRules   string `json:"outputRules"`
	SHA256        string `json:"sha256"`
}

type TrustLevel string

const (
	TrustSignedPolicy        TrustLevel = "SIGNED_POLICY"
	TrustCurated             TrustLevel = "CURATED"
	TrustProjectApproved     TrustLevel = "PROJECT_APPROVED"
	TrustGeneratedUnreviewed TrustLevel = "GENERATED_UNREVIEWED"
	TrustExternalUntrusted   TrustLevel = "EXTERNAL_UNTRUSTED"
)

func (t TrustLevel) Valid() bool {
	switch t {
	case TrustSignedPolicy, TrustCurated, TrustProjectApproved, TrustGeneratedUnreviewed, TrustExternalUntrusted:
		return true
	default:
		return false
	}
}

type ContextKind string

const (
	ContextGoalReference       ContextKind = "GOAL_REFERENCE"
	ContextPlanReference       ContextKind = "PLAN_REFERENCE"
	ContextModuleReference     ContextKind = "MODULE_REFERENCE"
	ContextKnowledgeSnippet    ContextKind = "KNOWLEDGE_SNIPPET"
	ContextTaskState           ContextKind = "TASK_STATE"
	ContextUserInput           ContextKind = "USER_INPUT"
	ContextRepositoryContent   ContextKind = "REPOSITORY_CONTENT"
	ContextToolOutput          ContextKind = "TOOL_OUTPUT"
	ContextDeterministicDiff   ContextKind = "DETERMINISTIC_DIFF"
	ContextDeterministicResult ContextKind = "DETERMINISTIC_RESULT"
	ContextPriorFinding        ContextKind = "PRIOR_FINDING"
	ContextExecutorStatement   ContextKind = "EXECUTOR_STATEMENT"
	ContextPrivateScratchpad   ContextKind = "PRIVATE_SCRATCHPAD"
	ContextAuditorFreeText     ContextKind = "AUDITOR_FREE_TEXT"
	ContextExecutorIdentity    ContextKind = "EXECUTOR_IDENTITY"
)

func (k ContextKind) Valid() bool {
	switch k {
	case ContextGoalReference, ContextPlanReference, ContextModuleReference, ContextKnowledgeSnippet,
		ContextTaskState, ContextUserInput, ContextRepositoryContent, ContextToolOutput,
		ContextDeterministicDiff, ContextDeterministicResult, ContextPriorFinding,
		ContextExecutorStatement, ContextPrivateScratchpad, ContextAuditorFreeText, ContextExecutorIdentity:
		return true
	default:
		return false
	}
}

type ContextItem struct {
	ID           string      `json:"id"`
	Kind         ContextKind `json:"kind"`
	Reference    string      `json:"reference"`
	Revision     string      `json:"revision,omitempty"`
	SHA256       string      `json:"sha256"`
	SourceSHA256 string      `json:"sourceSha256,omitempty"`
	LineStart    int         `json:"lineStart,omitempty"`
	LineEnd      int         `json:"lineEnd,omitempty"`
	Trust        TrustLevel  `json:"trust"`
	Content      string      `json:"content"`
}

type ContextManifest struct {
	ManifestID string        `json:"manifestId"`
	Version    string        `json:"version"`
	Role       Role          `json:"role"`
	Items      []ContextItem `json:"items"`
	SHA256     string        `json:"sha256"`
}

type Declaration struct {
	RunID              string
	Envelope           aop.Envelope
	TenantID           string
	ProjectID          string
	TaskID             string
	AgentInstanceID    string
	Role               Role
	PromptBundle       PromptBundle
	ContextManifest    ContextManifest
	ResponseSchemaRef  string
	ResponseSchema     json.RawMessage
	Tools              []modelgateway.ToolDefinition
	ToolSchemaDigest   string
	PolicyVersion      string
	PolicyDigest       string
	DataClassification string
	Priority           int
}

type ModelCall struct {
	RequestID           string
	Provider            string
	Model               string
	ReservationID       string
	MaxOutputTokens     int
	Temperature         float64
	Seed                *int64
	ProviderPolicy      string
	CachePolicy         string
	WorstCaseCostMicros int64
	MaxAttempts         int
}

type ToolCall struct {
	RequestID   string
	ToolID      string
	Version     string
	Parameters  json.RawMessage
	Approval    *toolbroker.Approval
	BudgetToken string
}

type AgentOutput struct {
	Intent  aop.Intent      `json:"intent"`
	Payload json.RawMessage `json:"payload"`
}

type AcceptedResult struct {
	RunID                    string          `json:"runId"`
	MessageID                string          `json:"messageId"`
	IdempotencyKey           string          `json:"idempotencyKey"`
	CorrelationID            string          `json:"correlationId"`
	ExpectedAggregateVersion int64           `json:"expectedAggregateVersion"`
	Traceparent              string          `json:"traceparent"`
	Intent                   aop.Intent      `json:"intent"`
	Payload                  json.RawMessage `json:"payload"`
	OutputSHA256             string          `json:"outputSha256"`
	AcceptedAt               time.Time       `json:"acceptedAt"`
	LeaseID                  string          `json:"leaseId"`
	FencingToken             int64           `json:"fencingToken"`
	PromptDigest             string          `json:"promptDigest"`
	ContextDigest            string          `json:"contextDigest"`
}

type Snapshot struct {
	RunID               string
	TenantID            string
	ProjectID           string
	TaskID              string
	AgentInstanceID     string
	Role                Role
	State               State
	LeaseID             string
	PromptBundleVersion string
	PromptDigest        string
	ContextDigest       string
	Busy                bool
}
