package toolbroker

import "context"

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
	ToolID           string              `json:"toolId"`
	Version          string              `json:"version"`
	MCPServerID      string              `json:"mcpServerId"`
	InputSchemaRef   string              `json:"inputSchemaRef"`
	OutputSchemaRef  string              `json:"outputSchemaRef"`
	InputSchema      []byte              `json:"-"`
	OutputSchema     []byte              `json:"-"`
	Risk             Risk                `json:"risk"`
	SideEffect       SideEffect          `json:"sideEffect"`
	NetworkAccess    NetworkAccess       `json:"networkAccess"`
	FilesystemAccess FilesystemAccess    `json:"filesystemAccess"`
	RequiresApproval ApprovalRequirement `json:"requiresApproval"`
	AllowedRoles     []string            `json:"allowedRoles"`
	RateLimit        string              `json:"rateLimit"`
	TimeoutSeconds   int                 `json:"timeoutSeconds"`
	MaxOutputBytes   int                 `json:"maxOutputBytes"`
}

type Principal struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Role string `json:"role"`
}

type Lease struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expiresAt"`
}

type Approval struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expiresAt,omitempty"`
	Revoked   bool   `json:"revoked"`
}

type ToolRequest struct {
	RequestID     string
	TenantID      string
	ProjectID     string
	TaskID        string
	Principal     Principal
	Lease         Lease
	Approval      *Approval
	ToolID        string
	Version       string
	Parameters    []byte
	PolicyVersion string
	BudgetToken   string
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
	Validate(ctx context.Context, lease Lease, principal Principal, tenantID, projectID, taskID string) error
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

type ArtifactStore interface {
	Put(ctx context.Context, data []byte, mediaType string) (ArtifactRef, error)
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
	PolicyVersion string
	OutputSHA256  string
	TrustLevel    string
	Redacted      bool
}
