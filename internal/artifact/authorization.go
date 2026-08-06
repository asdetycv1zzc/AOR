package artifact

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

const publicationLeaseTTL = 5 * time.Minute

var ErrCommitAuthorization = errors.New("artifact publication commit authorization rejected")

type PublicationAuthorization struct {
	Lease           authz.LeaseReference
	BudgetAccountID string
	ApprovalID      string
	origin          authn.Principal
}

type publicationAuthorizationPolicy interface {
	authz.PolicyEvaluator
	authz.LeaseGrantEvaluator
}

type capabilityPublicationLeaseManager interface {
	IssueWithAuthoritativeTime(context.Context, authz.LeaseRequest, time.Time) (authz.CapabilityLease, error)
	ValidateWithAuthoritativeTime(context.Context, authz.LeaseCheck, time.Time) (authz.CapabilityLease, error)
}

type CapabilityPublisherConfig struct {
	Catalog           *PostgresS3Catalog
	Leases            capabilityPublicationLeaseManager
	Policy            publicationAuthorizationPolicy
	ServiceID         string
	DeploymentProfile string
}

// CapabilityPublisher is the only production publication entry point. It
// obtains a short-lived, content-bound lease (and optionally revalidates an
// independently-created approval) before the catalog commits the manifest.
type CapabilityPublisher struct {
	catalog           *PostgresS3Catalog
	leases            capabilityPublicationLeaseManager
	policy            publicationAuthorizationPolicy
	serviceID         string
	deploymentProfile string
}

func NewCapabilityPublisher(config CapabilityPublisherConfig) (*CapabilityPublisher, error) {
	if config.Catalog == nil || config.Catalog.database == nil || config.Leases == nil || config.Policy == nil || !safeText(config.ServiceID, 256) || !validPublicationDeploymentProfile(config.DeploymentProfile) {
		return nil, ErrInvalidRequest
	}
	validator, err := newCapabilityPublicationValidator(capabilityPublicationValidatorConfig{
		Leases: config.Leases, Policy: config.Policy,
	})
	if err != nil {
		return nil, err
	}
	if config.Catalog.publicationValidator != nil {
		return nil, ErrInvalidRequest
	}
	config.Catalog.publicationValidator = validator
	config.Catalog.deploymentProfile = config.DeploymentProfile
	return &CapabilityPublisher{
		catalog: config.Catalog, leases: config.Leases, policy: config.Policy,
		serviceID: config.ServiceID, deploymentProfile: config.DeploymentProfile,
	}, nil
}

func (publisher *CapabilityPublisher) Publish(ctx context.Context, publication Publication) (Record, error) {
	if publisher == nil || publisher.catalog == nil || publisher.leases == nil || publisher.policy == nil || ctx == nil || ctx.Err() != nil || !validPublication(publication) {
		return Record{}, ErrInvalidRequest
	}
	origin, found := authn.PrincipalFromContext(ctx)
	if !found || origin.TenantID != publication.TenantID || origin.ProjectID != "" && origin.ProjectID != publication.ProjectID {
		return Record{}, ErrCommitAuthorization
	}
	if err := validateContent(publication.Data); err != nil {
		return Record{}, err
	}
	if publication.ArtifactID == "" {
		artifactID, err := newArtifactID()
		if err != nil {
			return Record{}, err
		}
		publication.ArtifactID = artifactID
	}
	service := authn.Principal{
		ID: publisher.serviceID, Type: authn.PrincipalService, Role: authn.RoleService,
		TenantID: publication.TenantID, ProjectID: publication.ProjectID,
	}
	serviceContext, err := authn.ContextWithPrincipal(ctx, service)
	if err != nil {
		return Record{}, ErrCommitAuthorization
	}
	serviceContext = context.WithValue(serviceContext, publicationOriginContextKey{}, origin)
	publication, scope, resource, parameterDigest, grant, fencingToken, authorizationTime, err := publisher.authorizePublication(serviceContext, publication)
	if err != nil {
		return Record{}, err
	}
	lease, err := publisher.leases.IssueWithAuthoritativeTime(serviceContext, authz.LeaseRequest{
		IdempotencyKey:  "",
		AgentInstanceID: service.ID, Principal: service,
		TenantID: publication.TenantID, ProjectID: publication.ProjectID,
		ProjectVersion: scope.Project.StateVersion, TaskID: scope.Task.ID,
		TaskVersion: scope.Task.StateVersion, SpecDigest: scope.Task.SpecDigest,
		Role: service.Role, Action: authz.ActionArtifactPublish,
		Resource: resource, ParameterDigest: parameterDigest,
		Capabilities: []string{authz.ActionArtifactPublish}, PolicyVersion: grant.PolicyVersion,
		BudgetAccountID: scope.Budget.AccountID, TTL: publicationLeaseTTL,
		HeartbeatInterval: time.Minute, Grant: grant, FencingToken: fencingToken,
	}, authorizationTime)
	if err != nil {
		return Record{}, err
	}
	publication.Authorization = PublicationAuthorization{
		Lease: lease.Reference(), BudgetAccountID: scope.Budget.AccountID,
		ApprovalID: publication.ApprovalID, origin: origin,
	}
	return publisher.catalog.Publish(serviceContext, publication)
}

func (publisher *CapabilityPublisher) authorizePublication(ctx context.Context, publication Publication) (Publication, publicationCommitScope, authz.Resource, string, authz.PolicyDecision, int64, time.Time, error) {
	tx, err := beginCatalogTx(ctx, publisher.catalog.database, publication.TenantID, false)
	if err != nil {
		return Publication{}, publicationCommitScope{}, authz.Resource{}, "", authz.PolicyDecision{}, 0, time.Time{}, err
	}
	defer func() { _ = tx.Rollback() }()
	project, err := loadPublicationProject(ctx, tx, publication.TenantID, publication.ProjectID, false)
	if err != nil {
		return Publication{}, publicationCommitScope{}, authz.Resource{}, "", authz.PolicyDecision{}, 0, time.Time{}, mapPublicationLookupError(err)
	}
	task, latestFencing, err := loadPublicationTask(ctx, tx, publication, publisher.deploymentProfile, false)
	if err != nil {
		return Publication{}, publicationCommitScope{}, authz.Resource{}, "", authz.PolicyDecision{}, 0, time.Time{}, mapPublicationLookupError(err)
	}
	budget, err := loadPublicationBudget(ctx, tx, publication.TenantID, publication.ProjectID, publication.ProjectID, false)
	if err != nil || !budget.Available {
		return Publication{}, publicationCommitScope{}, authz.Resource{}, "", authz.PolicyDecision{}, 0, time.Time{}, ErrCommitAuthorization
	}
	var authorizationTime time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&authorizationTime); err != nil {
		return Publication{}, publicationCommitScope{}, authz.Resource{}, "", authz.PolicyDecision{}, 0, time.Time{}, err
	}
	authorizationTime = authorizationTime.UTC()
	if publication.RetentionUntil == nil {
		value := authorizationTime.AddDate(1, 0, 0)
		publication.RetentionUntil = &value
	} else {
		value := publication.RetentionUntil.UTC()
		publication.RetentionUntil = &value
	}
	if !publication.RetentionUntil.After(authorizationTime) {
		return Publication{}, publicationCommitScope{}, authz.Resource{}, "", authz.PolicyDecision{}, 0, time.Time{}, ErrInvalidRequest
	}
	resource, parameterDigest, err := PublicationAuthorizationBinding(publication)
	if err != nil || !publicationDeletionScopeMatches(resource, project) {
		return Publication{}, publicationCommitScope{}, authz.Resource{}, "", authz.PolicyDecision{}, 0, time.Time{}, ErrCommitAuthorization
	}
	var approval *authz.Approval
	if publication.ApprovalID != "" {
		approval, err = loadPublicationApproval(ctx, tx, publication, publication.ApprovalID)
		if err != nil {
			return Publication{}, publicationCommitScope{}, authz.Resource{}, "", authz.PolicyDecision{}, 0, time.Time{}, mapPublicationLookupError(err)
		}
	}
	scope := publicationCommitScope{
		Principal: authn.Principal{
			ID: publisher.serviceID, Type: authn.PrincipalService, Role: authn.RoleService,
			TenantID: publication.TenantID, ProjectID: publication.ProjectID,
		},
		Project: project.Scope, Task: task, Budget: budget, Approval: approval,
		DeletionStatus: project.DeletionStatus, DeletionID: project.DeletionID,
		AuthorizationTime: authorizationTime,
	}
	grant, err := publisher.policy.EvaluateLeaseGrant(ctx, publicationPolicyInput(scope.Principal, resource, parameterDigest, scope, nil))
	if err != nil || grant.Decision != authz.DecisionAllow || grant.Binding == nil {
		return Publication{}, publicationCommitScope{}, authz.Resource{}, "", authz.PolicyDecision{}, 0, time.Time{}, ErrCommitAuthorization
	}
	if err := tx.Commit(); err != nil {
		return Publication{}, publicationCommitScope{}, authz.Resource{}, "", authz.PolicyDecision{}, 0, time.Time{}, err
	}
	if latestFencing < 1 {
		latestFencing = 1
	}
	return publication, scope, resource, parameterDigest, grant, latestFencing, authorizationTime, nil
}

func (publisher *CapabilityPublisher) List(ctx context.Context, tenantID, projectID, cursor string, limit int) (Page, error) {
	return publisher.catalog.List(ctx, tenantID, projectID, cursor, limit)
}

func (publisher *CapabilityPublisher) Get(ctx context.Context, tenantID, projectID, artifactID string) (Record, error) {
	return publisher.catalog.Get(ctx, tenantID, projectID, artifactID)
}

func (publisher *CapabilityPublisher) Open(ctx context.Context, tenantID, projectID, artifactID string) (Record, io.ReadCloser, error) {
	return publisher.catalog.Open(ctx, tenantID, projectID, artifactID)
}

func (publisher *CapabilityPublisher) GetByIdempotencyKey(ctx context.Context, tenantID, projectID, key string) (Record, error) {
	return publisher.catalog.GetByIdempotencyKey(ctx, tenantID, projectID, key)
}

func (publisher *CapabilityPublisher) OpenByIdempotencyKey(ctx context.Context, tenantID, projectID, key string) (Record, io.ReadCloser, error) {
	return publisher.catalog.OpenByIdempotencyKey(ctx, tenantID, projectID, key)
}

// publicationCommitScope contains only authoritative facts read under the
// catalog transaction that commits the artifact manifest.
type publicationCommitScope struct {
	Principal         authn.Principal
	Project           authz.ProjectScope
	Task              authz.TaskScope
	Budget            authz.BudgetScope
	Approval          *authz.Approval
	DeletionStatus    string
	DeletionID        string
	AuthorizationTime time.Time
}

type capabilityPublicationValidatorConfig struct {
	Leases interface {
		ValidateWithAuthoritativeTime(context.Context, authz.LeaseCheck, time.Time) (authz.CapabilityLease, error)
	}
	Policy authz.PolicyEvaluator
}

type capabilityPublicationValidator struct {
	leases interface {
		ValidateWithAuthoritativeTime(context.Context, authz.LeaseCheck, time.Time) (authz.CapabilityLease, error)
	}
	policy authz.PolicyEvaluator
}

type publicationOriginContextKey struct{}

func newCapabilityPublicationValidator(config capabilityPublicationValidatorConfig) (*capabilityPublicationValidator, error) {
	if config.Leases == nil || config.Policy == nil {
		return nil, ErrInvalidRequest
	}
	return &capabilityPublicationValidator{leases: config.Leases, policy: config.Policy}, nil
}

func (validator *capabilityPublicationValidator) validateCommit(ctx context.Context, publication Publication, authorization PublicationAuthorization, scope publicationCommitScope) error {
	if validator == nil || validator.leases == nil || validator.policy == nil || ctx == nil || ctx.Err() != nil {
		return ErrCommitAuthorization
	}
	current, authenticated := authn.PrincipalFromContext(ctx)
	origin, originAuthenticated := ctx.Value(publicationOriginContextKey{}).(authn.Principal)
	if !authenticated || !originAuthenticated || origin.Validate() != nil ||
		!samePublicationOrigin(origin, authorization.origin) ||
		current.ID != scope.Principal.ID || current.Type != scope.Principal.Type || current.Role != scope.Principal.Role || current.TenantID != scope.Principal.TenantID || current.ProjectID != scope.Principal.ProjectID {
		return ErrCommitAuthorization
	}
	if scope.Principal.Validate() != nil || scope.Principal.Type != authn.PrincipalService || scope.Principal.Role != authn.RoleService || scope.Principal.TenantID != publication.TenantID || scope.Principal.ProjectID != publication.ProjectID ||
		scope.Project.TenantID != publication.TenantID || scope.Project.ID != publication.ProjectID || scope.Project.StateVersion < 0 ||
		!uuidValuePattern.MatchString(publication.ArtifactID) || publication.RetentionUntil == nil || !publication.RetentionUntil.After(scope.AuthorizationTime) || scope.AuthorizationTime.IsZero() ||
		authorization.BudgetAccountID == "" || authorization.BudgetAccountID != scope.Budget.AccountID || !scope.Budget.Available || authorization.ApprovalID != publication.ApprovalID || authorization.Lease.ID == "" || authorization.Lease.FencingToken < 1 || authorization.Lease.PolicyVersion == "" || authorization.Lease.ExpiresAt.IsZero() {
		return ErrCommitAuthorization
	}
	if publication.TaskID == "" {
		if !emptyPublicationTaskScope(scope.Task) {
			return ErrCommitAuthorization
		}
	} else if scope.Task.TenantID != publication.TenantID || scope.Task.ProjectID != publication.ProjectID || scope.Task.ID != publication.TaskID || scope.Task.StateVersion < 0 || scope.Task.SpecDigest == "" || terminalPublicationTaskState(scope.Task.State) {
		return ErrCommitAuthorization
	}
	resource, parameterDigest, err := PublicationAuthorizationBinding(publication)
	if err != nil || !publicationDeletionScopeMatches(resource, publicationProject{Scope: scope.Project, DeletionStatus: scope.DeletionStatus, DeletionID: scope.DeletionID}) || !publicationProjectStateAllowed(scope.Project.State, resource) {
		return ErrCommitAuthorization
	}
	if !publicationApprovalMatches(scope, resource, parameterDigest, authorization.ApprovalID) {
		return ErrCommitAuthorization
	}

	check := authz.LeaseCheck{
		LeaseID: authorization.Lease.ID, AgentInstanceID: scope.Principal.ID,
		PrincipalID: scope.Principal.ID, PrincipalType: scope.Principal.Type,
		TenantID: publication.TenantID, ProjectID: publication.ProjectID,
		ProjectVersion: scope.Project.StateVersion, TaskID: scope.Task.ID,
		TaskVersion: scope.Task.StateVersion, SpecDigest: scope.Task.SpecDigest,
		Role: scope.Principal.Role, Action: authz.ActionArtifactPublish,
		Resource: resource, ParameterDigest: parameterDigest,
		PolicyVersion:   authorization.Lease.PolicyVersion,
		BudgetAccountID: authorization.BudgetAccountID,
		Capability:      authz.ActionArtifactPublish,
		FencingToken:    authorization.Lease.FencingToken,
		At:              scope.AuthorizationTime,
	}
	lease, err := validator.leases.ValidateWithAuthoritativeTime(ctx, check, scope.AuthorizationTime)
	if err != nil || !lease.ExpiresAt.Equal(authorization.Lease.ExpiresAt) {
		return ErrCommitAuthorization
	}
	input := publicationPolicyInput(scope.Principal, resource, parameterDigest, scope, &lease)
	decision, err := validator.policy.Evaluate(ctx, input)
	if err != nil || decision.Decision != authz.DecisionAllow || decision.PolicyVersion != lease.PolicyVersion || decision.Constraints.MaxBytes > 0 && int64(len(publication.Data)) > decision.Constraints.MaxBytes {
		return ErrCommitAuthorization
	}
	return nil
}

func samePublicationOrigin(left, right authn.Principal) bool {
	return left.ID == right.ID && left.Type == right.Type && left.Role == right.Role && left.TenantID == right.TenantID && left.ProjectID == right.ProjectID && left.Issuer == right.Issuer && left.Subject == right.Subject && maps.Equal(left.Attributes, right.Attributes)
}

func publicationPolicyInput(principal authn.Principal, resource authz.Resource, parameterDigest string, scope publicationCommitScope, lease *authz.CapabilityLease) authz.PolicyInput {
	input := authz.PolicyInput{
		Principal: principal, Project: scope.Project, Task: scope.Task,
		Action: authz.ActionArtifactPublish, Resource: resource,
		ParameterDigest: parameterDigest, Budget: scope.Budget,
		Approval: scope.Approval,
		Context: authz.ExecutionContext{
			Platform: scope.Task.ExecutionPlatform, SandboxLevel: scope.Task.SandboxLevel,
			AuthorizationTime: scope.AuthorizationTime.Format(time.RFC3339Nano),
		},
	}
	if lease != nil {
		reference := lease.Reference()
		input.Lease = &reference
	}
	return input
}

func publicationApprovalMatches(scope publicationCommitScope, resource authz.Resource, parameterDigest, approvalID string) bool {
	if approvalID == "" {
		return scope.Approval == nil
	}
	approval := scope.Approval
	if approval == nil || approval.ID != approvalID || approval.TenantID != scope.Project.TenantID || approval.ProjectID != scope.Project.ID || approval.SubjectID != resource.ID || approval.SubjectDigest != parameterDigest || approval.SubjectType != authz.ActionArtifactPublish || approval.Signature == "" || approval.IssuedAt.After(scope.AuthorizationTime) || !scope.AuthorizationTime.Before(approval.ExpiresAt) || approval.RevokedAt != nil && !approval.RevokedAt.After(scope.AuthorizationTime) {
		return false
	}
	version := scope.Project.StateVersion
	if scope.Task.ID != "" {
		version = scope.Task.StateVersion
	}
	return approval.SubjectVersion == version
}

type publicationProject struct {
	Scope          authz.ProjectScope
	DeletionStatus string
	DeletionID     string
}

func loadPublicationProject(ctx context.Context, tx *sql.Tx, tenantID, projectID string, updateLock bool) (publicationProject, error) {
	query := `
SELECT state, state_version, data_classification,
       COALESCE(deletion_status, ''), COALESCE(deletion_id, '')
FROM projects
WHERE tenant_id = $1::uuid AND id = $2::uuid`
	if updateLock {
		query += ` FOR UPDATE`
	} else {
		query += ` FOR SHARE`
	}
	project := publicationProject{Scope: authz.ProjectScope{TenantID: tenantID, ID: projectID}}
	err := tx.QueryRowContext(ctx, query, tenantID, projectID).Scan(
		&project.Scope.State, &project.Scope.StateVersion, &project.Scope.Classification,
		&project.DeletionStatus, &project.DeletionID,
	)
	return project, err
}

func loadPublicationTask(ctx context.Context, tx *sql.Tx, publication Publication, deploymentProfile string, updateLock bool) (authz.TaskScope, int64, error) {
	if publication.TaskID == "" {
		return authz.TaskScope{}, 1, nil
	}
	query := `
SELECT t.state, t.state_version, t.latest_fencing_token,
       ms.content_sha256, ms.execution_platform, ms.isolation_level,
       ms.content_jsonb
FROM module_tasks t
JOIN module_specs ms ON ms.tenant_id = t.tenant_id AND ms.id = t.module_spec_id
WHERE t.tenant_id = $1::uuid AND t.project_id = $2::uuid AND t.id = $3::uuid`
	if updateLock {
		query += ` FOR UPDATE OF t`
	} else {
		query += ` FOR SHARE OF t`
	}
	var task authz.TaskScope
	var latestFencing int64
	var moduleJSON []byte
	var platform, sandboxLevel string
	err := tx.QueryRowContext(ctx, query, publication.TenantID, publication.ProjectID, publication.TaskID).Scan(
		&task.State, &task.StateVersion, &latestFencing, &task.SpecDigest,
		&platform, &sandboxLevel, &moduleJSON,
	)
	if err != nil {
		return authz.TaskScope{}, 0, err
	}
	var module contracts.ModuleSpec
	if json.Unmarshal(moduleJSON, &module) != nil || module.ProjectID != publication.ProjectID || module.SHA256 != task.SpecDigest || string(module.ExecutionPlatform) != platform || string(module.SandboxLevel) != sandboxLevel || len(module.AllowedPaths) > 256 {
		return authz.TaskScope{}, 0, ErrCommitAuthorization
	}
	task.TenantID, task.ProjectID, task.ID = publication.TenantID, publication.ProjectID, publication.TaskID
	task.ExecutionPlatform, task.SandboxLevel = platform, sandboxLevel
	task.OwnedPaths = append([]string(nil), module.AllowedPaths...)
	task.WorkloadTrust = string(module.WorkloadProfile.Trust)
	task.DeploymentProfile = deploymentProfile
	task.HostileMultiTenant = module.WorkloadProfile.HostileMultiTenant
	task.RequiresNetworkIsolation = module.WorkloadProfile.RequiresNetworkIsolation
	task.RequiresHiddenConfidentiality = module.WorkloadProfile.RequiresHiddenTestConfidentiality
	return task, latestFencing, nil
}

func loadPublicationBudget(ctx context.Context, tx *sql.Tx, tenantID, projectID, accountID string, updateLock bool) (authz.BudgetScope, error) {
	query := `
SELECT id,
	       scope_type = 'PROJECT' AND scope_id = $2
       AND hard_limit_micros >= spent_micros + reserved_micros
       AND hard_limit_micros - spent_micros - reserved_micros > 0
       AND period_start <= clock_timestamp()
       AND (period_end IS NULL OR clock_timestamp() < period_end)
FROM budget_accounts
WHERE tenant_id = $1::uuid AND id = $3`
	if updateLock {
		query += ` FOR UPDATE`
	} else {
		query += ` FOR SHARE`
	}
	var budget authz.BudgetScope
	err := tx.QueryRowContext(ctx, query, tenantID, projectID, accountID).Scan(&budget.AccountID, &budget.Available)
	return budget, err
}

func loadPublicationApproval(ctx context.Context, tx *sql.Tx, publication Publication, approvalID string) (*authz.Approval, error) {
	approval := &authz.Approval{ID: approvalID}
	var constraints []byte
	var expiresAt, revokedAt sql.NullTime
	err := tx.QueryRowContext(ctx, `
SELECT tenant_id::text, project_id::text, principal_id, subject_type, subject_id,
       subject_version, subject_sha256, constraints_jsonb, issued_at, expires_at,
       revoked_at, signature
FROM approvals
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3::uuid
  AND approval_type = 'ARTIFACT_PUBLICATION'
FOR SHARE`, publication.TenantID, publication.ProjectID, approvalID).Scan(
		&approval.TenantID, &approval.ProjectID, &approval.PrincipalID,
		&approval.SubjectType, &approval.SubjectID, &approval.SubjectVersion,
		&approval.SubjectDigest, &constraints, &approval.IssuedAt, &expiresAt,
		&revokedAt, &approval.Signature,
	)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		CoApproverID string `json:"coApproverId"`
	}
	if json.Unmarshal(constraints, &parsed) != nil || !expiresAt.Valid {
		return nil, ErrCommitAuthorization
	}
	approval.CoApproverID = parsed.CoApproverID
	approval.IssuedAt, approval.ExpiresAt = approval.IssuedAt.UTC(), expiresAt.Time.UTC()
	if revokedAt.Valid {
		value := revokedAt.Time.UTC()
		approval.RevokedAt = &value
	}
	return approval, nil
}

func lockPublicationLeasePrincipal(ctx context.Context, tx *sql.Tx, publication Publication, leaseID string) (authn.Principal, error) {
	principal := authn.Principal{TenantID: publication.TenantID, ProjectID: publication.ProjectID}
	var principalType string
	err := tx.QueryRowContext(ctx, `
SELECT principal_id, principal_type, role
FROM agent_leases
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3
FOR UPDATE`, publication.TenantID, publication.ProjectID, leaseID).Scan(
		&principal.ID, &principalType, &principal.Role,
	)
	principal.Type = authn.PrincipalType(principalType)
	return principal, err
}

func loadPublicationCommitScope(ctx context.Context, tx *sql.Tx, publication Publication, authorization PublicationAuthorization, deploymentProfile string) (publicationCommitScope, publicationProject, error) {
	principal, err := lockPublicationLeasePrincipal(ctx, tx, publication, authorization.Lease.ID)
	if err != nil {
		return publicationCommitScope{}, publicationProject{}, mapPublicationLookupError(err)
	}
	project, err := loadPublicationProject(ctx, tx, publication.TenantID, publication.ProjectID, true)
	if err != nil {
		return publicationCommitScope{}, publicationProject{}, mapPublicationLookupError(err)
	}
	task, _, err := loadPublicationTask(ctx, tx, publication, deploymentProfile, true)
	if err != nil {
		return publicationCommitScope{}, publicationProject{}, mapPublicationLookupError(err)
	}
	budget, err := loadPublicationBudget(ctx, tx, publication.TenantID, publication.ProjectID, authorization.BudgetAccountID, true)
	if err != nil {
		return publicationCommitScope{}, publicationProject{}, mapPublicationLookupError(err)
	}
	var approval *authz.Approval
	if authorization.ApprovalID != "" {
		approval, err = loadPublicationApproval(ctx, tx, publication, authorization.ApprovalID)
		if err != nil {
			return publicationCommitScope{}, publicationProject{}, mapPublicationLookupError(err)
		}
	}
	var authorizationTime time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&authorizationTime); err != nil {
		return publicationCommitScope{}, publicationProject{}, err
	}
	return publicationCommitScope{
		Principal: principal, Project: project.Scope, Task: task, Budget: budget,
		Approval: approval, DeletionStatus: project.DeletionStatus, DeletionID: project.DeletionID,
		AuthorizationTime: authorizationTime.UTC(),
	}, project, nil
}

func validatePublicationAuthorizationStillActive(ctx context.Context, tx *sql.Tx, publication Publication, authorization PublicationAuthorization) error {
	var active bool
	err := tx.QueryRowContext(ctx, `
SELECT
  EXISTS (
    SELECT 1 FROM agent_leases
    WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3
      AND state = 'ACTIVE' AND fencing_token = $4
      AND expires_at > clock_timestamp()
      AND last_heartbeat_at + heartbeat_interval_seconds * interval '3 seconds' > clock_timestamp()
  )
  AND (
    $5 = '' OR EXISTS (
    SELECT 1 FROM approvals
    WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = NULLIF($5, '')::uuid
      AND approval_type = 'ARTIFACT_PUBLICATION'
      AND issued_at <= clock_timestamp() AND expires_at > clock_timestamp()
      AND (revoked_at IS NULL OR revoked_at > clock_timestamp())
    )
  )
  AND EXISTS (
    SELECT 1 FROM budget_accounts
    WHERE tenant_id = $1::uuid AND id = $6
      AND scope_type = 'PROJECT' AND scope_id = $2
      AND hard_limit_micros >= spent_micros + reserved_micros
      AND hard_limit_micros - spent_micros - reserved_micros > 0
      AND period_start <= clock_timestamp()
      AND (period_end IS NULL OR clock_timestamp() < period_end)
  )`, publication.TenantID, publication.ProjectID, authorization.Lease.ID,
		authorization.Lease.FencingToken, authorization.ApprovalID,
		authorization.BudgetAccountID).Scan(&active)
	if err != nil || !active {
		return ErrCommitAuthorization
	}
	return nil
}

func PublicationAuthorizationBinding(publication Publication) (authz.Resource, string, error) {
	if !validPublication(publication) {
		return authz.Resource{}, "", ErrInvalidRequest
	}
	metadata := cloneMetadataMap(publication.Metadata)
	if metadata == nil {
		return authz.Resource{}, "", ErrInvalidRequest
	}
	if publication.TaskID != "" {
		metadata["taskId"] = publication.TaskID
	}
	digest := digestBytes(publication.Data)
	uri, err := URIFromDigest(digest)
	if err != nil {
		return authz.Resource{}, "", err
	}
	var retentionUntil string
	if publication.RetentionUntil != nil {
		retentionUntil = publication.RetentionUntil.UTC().Format(time.RFC3339Nano)
	}
	encoded, err := json.Marshal(struct {
		TenantID           string         `json:"tenantId"`
		ProjectID          string         `json:"projectId"`
		TaskID             string         `json:"taskId,omitempty"`
		ArtifactID         string         `json:"artifactId,omitempty"`
		IdempotencyKey     string         `json:"idempotencyKey,omitempty"`
		CreatedByPrincipal string         `json:"createdByPrincipal"`
		ContentType        string         `json:"contentType"`
		Metadata           map[string]any `json:"metadata"`
		RetentionUntil     string         `json:"retentionUntil,omitempty"`
		SHA256             string         `json:"sha256"`
		SizeBytes          int64          `json:"sizeBytes"`
	}{
		TenantID: publication.TenantID, ProjectID: publication.ProjectID,
		TaskID: publication.TaskID, ArtifactID: publication.ArtifactID,
		IdempotencyKey:     publication.IdempotencyKey,
		CreatedByPrincipal: publication.CreatedByPrincipal,
		ContentType:        publication.ContentType, Metadata: metadata,
		RetentionUntil: retentionUntil, SHA256: digest, SizeBytes: int64(len(publication.Data)),
	})
	if err != nil {
		return authz.Resource{}, "", ErrInvalidRequest
	}
	parameterDigest, err := canonicaljson.Digest(encoded)
	if err != nil {
		return authz.Resource{}, "", ErrInvalidRequest
	}
	resource := authz.Resource{Type: "artifact", ID: uri}
	if metadataString(metadata, "kind") == "deletion-proof" {
		deletionID := metadataString(metadata, "deletionId")
		if deletionID == "" {
			return authz.Resource{}, "", ErrInvalidRequest
		}
		resource.Attributes = map[string]string{"operation": "deletion-proof", "deletionId": deletionID}
	} else if metadataString(metadata, "kind") == "project-export" {
		resource.Attributes = map[string]string{"operation": "project-export"}
	}
	return resource, parameterDigest, nil
}

func digestBytes(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func artifactDeletionProof(resource authz.Resource) bool {
	return resource.Attributes["operation"] == "deletion-proof" && resource.Attributes["deletionId"] != ""
}

func artifactProjectExport(resource authz.Resource) bool {
	return resource.Attributes["operation"] == "project-export"
}

func publicationDeletionScopeMatches(resource authz.Resource, project publicationProject) bool {
	if artifactDeletionProof(resource) {
		return project.DeletionStatus == "ERASING" && project.DeletionID == resource.Attributes["deletionId"]
	}
	return project.DeletionStatus != "ERASING" && project.DeletionStatus != "COMPLETED"
}

func terminalPublicationProjectState(state string) bool {
	switch state {
	case "PAUSED", "ABORTED", "FAILED_SYSTEM", "ARCHIVED":
		return true
	default:
		return false
	}
}

func publicationProjectStateAllowed(state string, resource authz.Resource) bool {
	if !terminalPublicationProjectState(state) {
		return true
	}
	if artifactProjectExport(resource) {
		return state == "PAUSED" || state == "ABORTED" || state == "ARCHIVED"
	}
	return (state == "PAUSED" || state == "ARCHIVED") && artifactDeletionProof(resource)
}

func terminalPublicationTaskState(state string) bool {
	switch state {
	case "CANCELED", "SUPERSEDED", "PASSED", "INTEGRATED":
		return true
	default:
		return false
	}
}

func emptyPublicationTaskScope(task authz.TaskScope) bool {
	return task.TenantID == "" && task.ProjectID == "" && task.ID == "" && task.State == "" && task.StateVersion == 0 && task.SpecDigest == "" && len(task.OwnedPaths) == 0 && task.ExecutionPlatform == "" && task.SandboxLevel == "" && task.WorkloadTrust == "" && task.DeploymentProfile == "" && !task.HostileMultiTenant && !task.RequiresNetworkIsolation && !task.RequiresHiddenConfidentiality
}

func validPublicationDeploymentProfile(value string) bool {
	switch value {
	case "LOCAL", "TEST", "PREPRODUCTION", "PRODUCTION":
		return true
	default:
		return false
	}
}

func mapPublicationLookupError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCommitAuthorization
	}
	return err
}

var (
	_ Publisher = (*CapabilityPublisher)(nil)
	_ Catalog   = (*CapabilityPublisher)(nil)
)
