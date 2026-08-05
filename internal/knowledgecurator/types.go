package knowledgecurator

import (
	"context"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/knowledge"
	"github.com/akimisaka/aor/internal/leaseauthority"
	"github.com/akimisaka/aor/internal/state"
)

type Status string

const (
	StatusDraft    Status = "DRAFT"
	StatusApproved Status = "APPROVED"
	StatusApplied  Status = "APPLIED"
)

type Document struct {
	Path        string                     `json:"path"`
	Title       string                     `json:"title"`
	Tags        []string                   `json:"tags"`
	TrustLevel  knowledge.TrustLevel       `json:"trustLevel"`
	ContentType string                     `json:"contentType"`
	Content     string                     `json:"content"`
	Source      *knowledge.SourceReference `json:"source,omitempty"`
}

type Proposal struct {
	BaseRevision        string                     `json:"baseRevision"`
	ParentOrderExplicit bool                       `json:"parentOrderExplicit"`
	Parents             []knowledge.ParentSnapshot `json:"parents"`
	Overrides           []string                   `json:"overrides"`
	Documents           []Document                 `json:"documents"`
	DeletePaths         []string                   `json:"deletePaths"`
}

type DraftRequest struct {
	Principal              authn.Principal
	TenantID               string
	ProjectID              string
	ExpectedProjectVersion int64
	IdempotencyKey         string
	Instruction            string
	Proposal               Proposal
}

type ApprovalRequest struct {
	Principal              authn.Principal
	TenantID               string
	ProjectID              string
	UpdateID               string
	ExpectedProjectVersion int64
	ProposalDigest         string
	Reason                 string
	IdempotencyKey         string
}

type Record struct {
	UpdateID       string                     `json:"updateId"`
	TenantID       string                     `json:"tenantId"`
	ProjectID      string                     `json:"projectId"`
	ProjectVersion int64                      `json:"projectVersion"`
	Status         Status                     `json:"status"`
	ProposalDigest string                     `json:"proposalDigest"`
	ChangeSummary  string                     `json:"changeSummary"`
	Validation     knowledge.ValidationReport `json:"validationReport"`
	Proposal       Proposal                   `json:"proposal"`
	DraftURI       string                     `json:"draftUri"`
	DraftSHA256    string                     `json:"draftSha256"`
	SourceRunID    string                     `json:"sourceRunId"`
	ApprovalID     string                     `json:"approvalId,omitempty"`
	Revision       string                     `json:"revision,omitempty"`
	CreatedAt      time.Time                  `json:"createdAt"`
	ApprovedAt     *time.Time                 `json:"approvedAt,omitempty"`
	AppliedAt      *time.Time                 `json:"appliedAt,omitempty"`
}

type ProjectReader interface {
	Project(context.Context, string, string) (state.Project, bool, error)
}

type KnowledgeService interface {
	Manifest(context.Context, knowledge.Access, string) (knowledge.Manifest, error)
	ValidateProposal(context.Context, knowledge.Access, knowledge.UpdateProposal) (knowledge.ProposalValidation, error)
	Update(context.Context, knowledge.Access, knowledge.UpdateProposal) (knowledge.UpdateResult, error)
}

type LeaseIssuer interface {
	Issue(context.Context, authn.Principal, leaseauthority.GrantRequest) (authz.CapabilityLease, error)
}

type AgentInvoker interface {
	Invoke(context.Context, goalplan.AgentInvocation) (goalplan.AgentRecord, error)
}
