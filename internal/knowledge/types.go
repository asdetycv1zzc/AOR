// Package knowledge provides project-scoped, immutable knowledge references.
package knowledge

import (
	"context"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
)

const (
	DefaultSearchLimit = 8
	MaxSearchLimit     = 20
	MaxReadLines       = 200
	MaxReadBytes       = 32 * 1024
)

type TrustLevel string

const (
	TrustSignedPolicy        TrustLevel = "SIGNED_POLICY"
	TrustCurated             TrustLevel = "CURATED"
	TrustProjectApproved     TrustLevel = "PROJECT_APPROVED"
	TrustGeneratedUnreviewed TrustLevel = "GENERATED_UNREVIEWED"
	TrustExternalUntrusted   TrustLevel = "EXTERNAL_UNTRUSTED"
)

func (level TrustLevel) Valid() bool {
	switch level {
	case TrustSignedPolicy, TrustCurated, TrustProjectApproved, TrustGeneratedUnreviewed, TrustExternalUntrusted:
		return true
	default:
		return false
	}
}

func trustRank(level TrustLevel) int {
	switch level {
	case TrustSignedPolicy:
		return 5
	case TrustCurated:
		return 4
	case TrustProjectApproved:
		return 3
	case TrustGeneratedUnreviewed:
		return 2
	case TrustExternalUntrusted:
		return 1
	default:
		return 0
	}
}

// Access contains authenticated caller facts and side-effect proofs. Project
// state is resolved through ScopeResolver instead of trusting it from the
// request. TaskID is optional correlation metadata and is not an authorization
// scope for project knowledge.
type Access struct {
	Principal       authn.Principal
	TenantID        string
	ProjectID       string
	TaskID          string
	Lease           *authz.LeaseReference
	Approval        *authz.Approval
	ParameterDigest string
	BudgetAccountID string
	PolicyVersion   string
}

type ScopeResolver interface {
	ResolveProject(context.Context, string, string) (authz.ProjectScope, error)
}

type ParentSnapshot struct {
	ProjectID string `json:"projectId"`
	Revision  string `json:"revision"`
	Order     int    `json:"order"`
}

// SourceReference records the immutable origin asserted for a knowledge
// document.  The reference is deliberately small: the URI identifies the
// source, revision pins its version, and SHA256 binds the cited bytes.
type SourceReference struct {
	URI        string     `json:"uri"`
	Revision   string     `json:"revision"`
	SHA256     string     `json:"sha256"`
	TrustLevel TrustLevel `json:"trustLevel"`
}

type DocumentInput struct {
	Path        string
	Title       string
	Tags        []string
	TrustLevel  TrustLevel
	ContentType string
	Content     []byte
	Source      *SourceReference
}

type DocumentMetadata struct {
	Path        string           `json:"path"`
	Title       string           `json:"title"`
	Tags        []string         `json:"tags"`
	TrustLevel  TrustLevel       `json:"trustLevel"`
	ContentType string           `json:"contentType"`
	SHA256      string           `json:"sha256"`
	LineCount   int              `json:"lineCount"`
	Source      *SourceReference `json:"source,omitempty"`
}

type Manifest struct {
	Version             int                `json:"version"`
	TenantID            string             `json:"tenantId"`
	ProjectID           string             `json:"projectId"`
	Revision            string             `json:"revision"`
	CreatedAt           time.Time          `json:"createdAt"`
	ParentOrderExplicit bool               `json:"parentOrderExplicit"`
	Parents             []ParentSnapshot   `json:"parents"`
	Overrides           []string           `json:"overrides"`
	Documents           []DocumentMetadata `json:"documents"`
}

type UpdateProposal struct {
	BaseRevision        string
	ParentOrderExplicit bool
	Parents             []ParentSnapshot
	Overrides           []string
	Documents           []DocumentInput
	DeletePaths         []string
}

type ProposalValidation struct {
	Digest        string           `json:"digest"`
	DocumentCount int              `json:"documentCount"`
	Report        ValidationReport `json:"validationReport"`
}

type ValidationStatus string

const (
	ValidationPassed ValidationStatus = "PASS"
	ValidationFailed ValidationStatus = "FAIL"
)

// ValidationCheck is a deterministic, machine-readable gate result.  Checks
// are sorted by rule ID and path before they are persisted.
type ValidationCheck struct {
	RuleID  string           `json:"ruleId"`
	Status  ValidationStatus `json:"status"`
	Path    string           `json:"path,omitempty"`
	Message string           `json:"message,omitempty"`
}

type ValidationReport struct {
	Version        int               `json:"version"`
	ProposalDigest string            `json:"proposalDigest"`
	Passed         bool              `json:"passed"`
	Checks         []ValidationCheck `json:"checks"`
	SHA256         string            `json:"sha256"`
}

type Reference struct {
	ResourceURI     string           `json:"resourceUri"`
	LocalPath       string           `json:"localPath"`
	ScopeRevision   string           `json:"scopeRevision"`
	SourceProjectID string           `json:"sourceProjectId"`
	Path            string           `json:"path"`
	Revision        string           `json:"revision"`
	SHA256          string           `json:"sha256"`
	LineStart       int              `json:"lineStart"`
	LineEnd         int              `json:"lineEnd"`
	Encoding        string           `json:"encoding"`
	LineEnding      string           `json:"lineEnding"`
	ContentType     string           `json:"contentType"`
	Title           string           `json:"title"`
	Tags            []string         `json:"tags"`
	TrustLevel      TrustLevel       `json:"trustLevel"`
	Source          *SourceReference `json:"source,omitempty"`
	RetrievalScore  float64          `json:"retrievalScore"`
}

type SearchRequest struct {
	Access Access
	Path   string
	Title  string
	Tags   []string
	Text   string
	Limit  int
}

type SearchResponse struct {
	Revision   string      `json:"revision"`
	References []Reference `json:"references"`
}

type ReadRangeRequest struct {
	Access    Access
	Reference Reference
	LineStart int
	LineEnd   int
}

type ReadRangeResponse struct {
	Reference Reference `json:"reference"`
	Content   string    `json:"content"`
	NextLine  int       `json:"nextLine,omitempty"`
}

type UpdateResult struct {
	Manifest Manifest `json:"manifest"`
	Digest   string   `json:"proposalDigest"`
}

type IndexSnapshot struct {
	TenantID  string    `json:"tenantId"`
	ProjectID string    `json:"projectId"`
	Revision  string    `json:"revision"`
	BuiltAt   time.Time `json:"builtAt"`
	Documents int       `json:"documents"`
}

type Repository interface {
	Initialize(context.Context, string, string, time.Time) (Manifest, error)
	Head(context.Context, string, string) (string, error)
	Load(context.Context, string, string, string) (Snapshot, error)
	Commit(context.Context, CommitRequest) (Manifest, error)
	LocalPath(string, string, string, string) (string, error)
}

type Snapshot struct {
	Manifest  Manifest
	Documents map[string]StoredDocument
}

type StoredDocument struct {
	Metadata DocumentMetadata
	Content  []byte
}

type CommitRequest struct {
	TenantID     string
	ProjectID    string
	BaseRevision string
	Snapshot     Snapshot
}
