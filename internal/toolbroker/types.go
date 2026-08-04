package toolbroker

import (
	"context"
	"net/http"
	"time"
)

type Risk string

const (
	RiskLow      Risk = "LOW"
	RiskMedium   Risk = "MEDIUM"
	RiskHigh     Risk = "HIGH"
	RiskCritical Risk = "CRITICAL"
)

type SideEffect string

const (
	SideEffectNone         SideEffect = "NONE"
	SideEffectReversible   SideEffect = "REVERSIBLE"
	SideEffectIrreversible SideEffect = "IRREVERSIBLE"
)

type NetworkAccess string

const (
	NetworkNone      NetworkAccess = "NONE"
	NetworkAllowlist NetworkAccess = "ALLOWLIST"
	NetworkOpen      NetworkAccess = "OPEN"
)

type FilesystemAccess string

const (
	FilesystemNone        FilesystemAccess = "NONE"
	FilesystemRead        FilesystemAccess = "READ"
	FilesystemScopedWrite FilesystemAccess = "SCOPED_WRITE"
)

type ApprovalRequirement string

const (
	ApprovalNever  ApprovalRequirement = "NEVER"
	ApprovalPolicy ApprovalRequirement = "POLICY"
	ApprovalAlways ApprovalRequirement = "ALWAYS"
)

type ToolDescriptor struct {
	ToolID          string        `json:"toolId"`
	Version         string        `json:"version"`
	MCPServerID     string        `json:"mcpServerId"`
	InputSchemaRef  string        `json:"inputSchemaRef"`
	OutputSchemaRef string        `json:"outputSchemaRef"`
	InputSchema     []byte        `json:"-"`
	OutputSchema    []byte        `json:"-"`
	Risk            Risk          `json:"risk"`
	SideEffect      SideEffect    `json:"sideEffect"`
	NetworkAccess   NetworkAccess `json:"networkAccess"`
	// AllowedNetworkTargets contains absolute origin URLs accepted by a network
	// tool. Paths, query parameters, credentials, and wildcards are forbidden.
	AllowedNetworkTargets []string            `json:"allowedNetworkTargets"`
	FilesystemAccess      FilesystemAccess    `json:"filesystemAccess"`
	RequiresApproval      ApprovalRequirement `json:"requiresApproval"`
	AllowedRoles          []string            `json:"allowedRoles"`
	RateLimit             string              `json:"rateLimit"`
	TimeoutSeconds        int                 `json:"timeoutSeconds"`
	MaxOutputBytes        int                 `json:"maxOutputBytes"`
}

type Principal struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Role string `json:"role"`
}

type Lease struct {
	ID           string `json:"id"`
	ExpiresAt    string `json:"expiresAt"`
	FencingToken int64  `json:"fencingToken"`
}

type Approval struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expiresAt,omitempty"`
	Revoked   bool   `json:"revoked"`
}

type ToolRequest struct {
	RequestID       string
	TenantID        string
	ProjectID       string
	TaskID          string
	Principal       Principal
	Lease           Lease
	Approval        *Approval
	ToolID          string
	Version         string
	Parameters      []byte
	PolicyVersion   string
	BudgetAccountID string
}

type ArtifactRef struct {
	URI       string `json:"uri"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	MediaType string `json:"mediaType"`
}

type ToolResult struct {
	InvocationID string
	Output       []byte
	Artifact     *ArtifactRef
	OutputSHA256 string
	TrustLevel   string
	Redacted     bool
}

type LeaseChecker interface {
	Validate(context.Context, LeaseValidation) error
}

type LeaseValidation struct {
	Lease           Lease
	Principal       Principal
	TenantID        string
	ProjectID       string
	TaskID          string
	ToolID          string
	ToolVersion     string
	MCPServerID     string
	Action          string
	Resource        string
	ParameterSHA256 string
	PolicyVersion   string
	BudgetAccountID string
	ApprovalID      string
	At              time.Time
}

type executionAuthorizationContextKey struct{}

// ExecutionAuthorizationFromContext returns the broker-validated lease binding
// supplied to an in-process tool. External MCP transports cannot manufacture
// this private context value.
func ExecutionAuthorizationFromContext(ctx context.Context) (LeaseValidation, bool) {
	if ctx == nil {
		return LeaseValidation{}, false
	}
	validation, ok := ctx.Value(executionAuthorizationContextKey{}).(LeaseValidation)
	return validation, ok
}

type PolicyDecision struct {
	Allow         bool
	PolicyVersion string
	ReasonCodes   []string
}

type PolicyEvaluator interface {
	Evaluate(ctx context.Context, descriptor ToolDescriptor, request ToolRequest) (PolicyDecision, error)
}

type ToolExecutor interface {
	Execute(ctx context.Context, descriptor ToolDescriptor, parameters []byte) ([]byte, error)
}

// NetworkToolExecutor is the only executor contract accepted for a tool that
// needs network access. The broker supplies an HTTP client whose resolver,
// dialer, and redirect handling are bound to the approved destination.
type NetworkToolExecutor interface {
	ExecuteNetwork(ctx context.Context, descriptor ToolDescriptor, parameters []byte, client *http.Client) ([]byte, error)
}

type ArtifactStore interface {
	Put(ctx context.Context, request ToolRequest, data []byte, mediaType string) (ArtifactRef, error)
}

type InvocationRecorder interface {
	Record(ctx context.Context, invocation Invocation) error
}

type Invocation struct {
	InvocationID  string
	RequestID     string
	TenantID      string
	ProjectID     string
	TaskID        string
	PrincipalID   string
	ToolID        string
	ToolVersion   string
	Risk          Risk
	InputSHA256   string
	Decision      string
	PolicyVersion string
	OutputSHA256  string
	TrustLevel    string
	Redacted      bool
	Status        string
	StartedAt     time.Time
	OccurredAt    time.Time
}

type InvocationAttempt struct {
	InvocationID string
	RequestID    string
	TenantID     string
	ProjectID    string
	TaskID       string
	PrincipalID  string
	ToolID       string
	ToolVersion  string
	Status       string
	ReasonCode   string
	OccurredAt   time.Time
}

type InvocationAttemptRecorder interface {
	RecordAttempt(context.Context, InvocationAttempt) error
}
