package execution

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
)

const executionCommitPolicyVersion = "executor-assignment-v1"

type executionLeaseReader interface {
	GetForTenant(context.Context, string, string) (authz.CapabilityLease, bool, error)
}

// OrchestratorTaskAuthority adapts the durable Orchestrator command service to
// the executor coordinator. It signs transition capabilities in-process and
// rehydrates their relational facts immediately before the event transaction.
type OrchestratorTaskAuthority struct {
	service *orchestrator.Service
	db      *sql.DB
	signer  orchestrator.CommitSigner
	leases  executionLeaseReader
	clock   func() time.Time
}

func NewOrchestratorTaskAuthority(store eventing.Store, database *sql.DB, signer orchestrator.CommitSigner, leases executionLeaseReader, clock func() time.Time) (*OrchestratorTaskAuthority, error) {
	if store == nil || database == nil || signer == nil || leases == nil {
		return nil, ErrExecutionUnavailable
	}
	if clock == nil {
		clock = time.Now
	}
	authority := &OrchestratorTaskAuthority{db: database, signer: signer, leases: leases, clock: clock}
	boundary, err := orchestrator.NewSignedCommitBoundary(signer, authority)
	if err != nil {
		return nil, err
	}
	authority.service = orchestrator.NewWithBoundary(store, clock, boundary)
	return authority, nil
}

func (authority *OrchestratorTaskAuthority) Project(ctx context.Context, tenantID, projectID string) (state.Project, bool, error) {
	if authority == nil || authority.service == nil {
		return state.Project{}, false, ErrExecutionUnavailable
	}
	return authority.service.Project(ctx, tenantID, projectID)
}

func (authority *OrchestratorTaskAuthority) Task(ctx context.Context, tenantID, projectID, taskID string) (state.ModuleTask, bool, error) {
	if authority == nil || authority.service == nil {
		return state.ModuleTask{}, false, ErrExecutionUnavailable
	}
	return authority.service.Task(ctx, tenantID, projectID, taskID)
}

func (authority *OrchestratorTaskAuthority) Tasks(ctx context.Context, tenantID, projectID string) ([]state.ModuleTask, error) {
	if authority == nil || authority.service == nil {
		return nil, ErrExecutionUnavailable
	}
	return authority.service.Tasks(ctx, tenantID, projectID)
}

func (authority *OrchestratorTaskAuthority) LeaseExecution(ctx context.Context, request LeaseTaskRequest) (state.ModuleTask, bool, error) {
	if authority == nil || authority.service == nil || !validLeaseTaskAuthorityRequest(request) {
		return state.ModuleTask{}, false, ErrInvalidRequest
	}
	current, found, err := authority.service.Task(ctx, request.TenantID, request.ProjectID, request.TaskID)
	if err != nil || !found {
		return state.ModuleTask{}, false, err
	}
	if current.Version != request.ExpectedVersion ||
		(current.State != contracts.TaskReadyExecution && !(request.Recover && current.State == contracts.TaskExecuting)) ||
		request.FencingToken <= current.FencingToken || request.Recover && current.State != contracts.TaskExecuting ||
		!request.Recover && current.State != contracts.TaskReadyExecution {
		return state.ModuleTask{}, false, ErrAssignmentInvalid
	}
	command := state.TaskCommand{Type: state.TaskCommandLeaseExecution, FencingToken: request.FencingToken, Recover: request.Recover}
	digest, err := orchestrator.TaskParameterDigest(orchestrator.TaskRequest{
		TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		PrincipalID: request.AgentInstanceID, ExpectedVersion: request.ExpectedVersion, Command: command,
	})
	if err != nil {
		return state.ModuleTask{}, false, err
	}
	project, found, err := authority.service.Project(ctx, request.TenantID, request.ProjectID)
	if err != nil || !found {
		return state.ModuleTask{}, false, err
	}
	now := authority.clock().UTC()
	authorization, err := authority.signAuthorization(orchestrator.CommitCapability{
		CapabilityVersion: orchestrator.CommitCapabilityVersion,
		TenantID:          request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		PrincipalID: request.AgentInstanceID, PrincipalType: string(authn.PrincipalAgentInstance), Role: authn.RoleExecutor,
		Action: string(state.TaskCommandLeaseExecution), ExpectedVersion: request.ExpectedVersion,
		ProjectVersion: project.Version, TaskVersion: current.Version, ParameterDigest: digest,
		ModuleSpecRef: current.ModuleSpecRef, LeaseID: request.ExecutionID, FencingToken: request.FencingToken,
		PolicyVersion: executionCommitPolicyVersion, BudgetAccountID: project.ID,
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		return state.ModuleTask{}, false, err
	}
	outcome, err := authority.service.HandleTask(ctx, orchestrator.TaskRequest{
		TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		PrincipalID: request.AgentInstanceID, IdempotencyKey: request.ExecutionID + ":lease",
		ExpectedVersion: request.ExpectedVersion, Command: command, Authorization: authorization,
	})
	return outcome.Task, outcome.Duplicate, err
}

func (authority *OrchestratorTaskAuthority) SubmitExecution(ctx context.Context, request SubmitTaskRequest) (state.ModuleTask, bool, error) {
	if authority == nil || authority.service == nil || !validSubmitTaskAuthorityRequest(request) {
		return state.ModuleTask{}, false, ErrInvalidRequest
	}
	current, found, err := authority.service.Task(ctx, request.TenantID, request.ProjectID, request.TaskID)
	if err != nil || !found {
		return state.ModuleTask{}, false, err
	}
	project, found, err := authority.service.Project(ctx, request.TenantID, request.ProjectID)
	if err != nil || !found {
		return state.ModuleTask{}, false, err
	}
	lease, found, err := authority.leases.GetForTenant(ctx, request.TenantID, request.Submission.AgentIdentity.LeaseID)
	if err != nil || !found || lease.State != authz.LeaseActive || lease.IsExpired(authority.clock().UTC()) {
		return state.ModuleTask{}, false, ErrSubmissionInvalid
	}
	command := state.TaskCommand{
		Type: state.TaskCommandSubmit, FencingToken: request.FencingToken,
		ModuleSpecRef: request.ModuleSpecRef, AttemptSeriesID: request.AttemptSeriesID,
	}
	digest, err := orchestrator.TaskParameterDigest(orchestrator.TaskRequest{
		TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		PrincipalID: request.Submission.AgentIdentity.AgentInstanceID, ExpectedVersion: request.ExpectedVersion, Command: command,
	})
	if err != nil {
		return state.ModuleTask{}, false, err
	}
	now := authority.clock().UTC()
	expires := now.Add(time.Minute)
	if lease.ExpiresAt.Before(expires) {
		expires = lease.ExpiresAt
	}
	if !now.Before(expires) {
		return state.ModuleTask{}, false, ErrSubmissionInvalid
	}
	authorization, err := authority.signAuthorization(orchestrator.CommitCapability{
		CapabilityVersion: orchestrator.CommitCapabilityVersion,
		TenantID:          request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		PrincipalID: request.Submission.AgentIdentity.AgentInstanceID, PrincipalType: string(authn.PrincipalAgentInstance), Role: authn.RoleExecutor,
		Action: string(state.TaskCommandSubmit), ExpectedVersion: request.ExpectedVersion,
		ProjectVersion: project.Version, TaskVersion: current.Version, ParameterDigest: digest,
		ModuleSpecRef: request.ModuleSpecRef, LeaseID: request.Submission.AgentIdentity.LeaseID,
		FencingToken: request.FencingToken, PolicyVersion: lease.PolicyVersion,
		BudgetAccountID: lease.BudgetAccountID, IssuedAt: now, ExpiresAt: expires,
	})
	if err != nil {
		return state.ModuleTask{}, false, err
	}
	outcome, err := authority.service.HandleTask(ctx, orchestrator.TaskRequest{
		TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		PrincipalID:     request.Submission.AgentIdentity.AgentInstanceID,
		IdempotencyKey:  request.ExecutionID + ":submit:" + request.Submission.AgentIdentity.LeaseID,
		ExpectedVersion: request.ExpectedVersion, Command: command, Authorization: authorization,
	})
	return outcome.Task, outcome.Duplicate, err
}

func (authority *OrchestratorTaskAuthority) signAuthorization(capability orchestrator.CommitCapability) (orchestrator.CommitAuthorization, error) {
	return orchestrator.SignCommitCapability(capability, authority.signer)
}

func validLeaseTaskAuthorityRequest(request LeaseTaskRequest) bool {
	return validID(request.ExecutionID) && validID(request.TenantID) && validID(request.ProjectID) && validID(request.TaskID) && validID(request.AgentInstanceID) && request.ExpectedVersion >= 0 && request.FencingToken > 0
}

func validSubmitTaskAuthorityRequest(request SubmitTaskRequest) bool {
	return validID(request.ExecutionID) && validID(request.TenantID) && validID(request.ProjectID) && validID(request.TaskID) && request.ExpectedVersion >= 0 && request.FencingToken > 0 && request.ModuleSpecRef.Validate() == nil && validID(request.AttemptSeriesID) && request.Submission.Validate() == nil
}

type executionCommitFacts struct {
	db     *sql.DB
	leases executionLeaseReader
}

func (facts *executionCommitFacts) Revalidate(ctx context.Context, capability orchestrator.CommitCapability) error {
	if facts == nil || facts.db == nil || facts.leases == nil || ctx == nil || ctx.Err() != nil {
		return ErrExecutionUnavailable
	}
	tx, err := facts.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var superuser, bypassRLS bool
	if err := tx.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS); err != nil {
		return err
	}
	if superuser || bypassRLS {
		return ErrAssignmentInvalid
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, capability.TenantID); err != nil {
		return err
	}
	var projectState, taskState, seriesID, specDigest, executionID, agentID, assignmentLeaseID, role, agentState string
	var projectVersion, taskVersion, latestFence, assignmentFence int64
	var specVersion int
	var accountID string
	var hardLimit, spent, reserved int64
	var periodEnd sql.NullTime
	var now time.Time
	err = tx.QueryRowContext(ctx, `
SELECT p.state, p.state_version, t.state, t.state_version,
       COALESCE(t.active_attempt_series_id::text, ''), t.latest_fencing_token,
       ms.version, ms.content_sha256, ea.execution_id, ea.agent_instance_id,
       COALESCE(ea.lease_id, ''), ea.fencing_token, ai.role, ai.state,
       ba.id, ba.hard_limit_micros, ba.spent_micros, ba.reserved_micros, ba.period_end,
       clock_timestamp()
FROM projects AS p
JOIN module_tasks AS t ON t.tenant_id = p.tenant_id AND t.project_id = p.id
JOIN module_specs AS ms ON ms.tenant_id = t.tenant_id AND ms.id = t.module_spec_id
JOIN execution_assignments AS ea ON ea.tenant_id = t.tenant_id AND ea.project_id = t.project_id
  AND ea.module_task_id = t.id AND ea.module_spec_id = t.module_spec_id
  AND ea.attempt_series_id = t.active_attempt_series_id
JOIN agent_instances AS ai ON ai.tenant_id = ea.tenant_id AND ai.id = ea.agent_instance_id
JOIN budget_accounts AS ba ON ba.tenant_id = p.tenant_id AND ba.id = $6
WHERE p.tenant_id = $1::uuid AND p.id = $2::uuid AND t.id = $3::uuid
  AND (($4 = 'LEASE_EXECUTION' AND ea.execution_id = $5)
       OR ($4 <> 'LEASE_EXECUTION' AND ea.lease_id = $5))`,
		capability.TenantID, capability.ProjectID, capability.TaskID, capability.Action, capability.LeaseID, capability.BudgetAccountID).Scan(
		&projectState, &projectVersion, &taskState, &taskVersion, &seriesID, &latestFence,
		&specVersion, &specDigest, &executionID, &agentID, &assignmentLeaseID, &assignmentFence,
		&role, &agentState, &accountID, &hardLimit, &spent, &reserved, &periodEnd, &now)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAssignmentInvalid
	}
	if err != nil {
		return err
	}
	now = now.UTC()
	if projectState != string(contracts.ProjectExecuting) || projectVersion != capability.ProjectVersion || taskVersion != capability.TaskVersion ||
		specVersion != capability.ModuleSpecRef.Version || specDigest != capability.ModuleSpecRef.SHA256 || seriesID == "" ||
		agentID != capability.PrincipalID || role != authn.RoleExecutor || agentState == "FAILED" || agentState == "CANCELED" || agentState == "EXPIRED" || agentState == "TERMINATED" ||
		accountID != capability.BudgetAccountID || hardLimit < 0 || spent < 0 || reserved < 0 || spent > hardLimit || reserved > hardLimit-spent || periodEnd.Valid && !now.Before(periodEnd.Time) {
		return ErrAssignmentInvalid
	}
	if capability.PrincipalType != string(authn.PrincipalAgentInstance) || capability.Role != authn.RoleExecutor || capability.BudgetAccountID != capability.ProjectID {
		return ErrAssignmentInvalid
	}
	switch capability.Action {
	case string(state.TaskCommandLeaseExecution):
		if (taskState != string(contracts.TaskReadyExecution) && taskState != string(contracts.TaskExecuting)) ||
			latestFence+1 != capability.FencingToken || assignmentFence != capability.FencingToken ||
			executionID != capability.LeaseID || assignmentLeaseID != "" || capability.PolicyVersion != executionCommitPolicyVersion {
			return ErrAssignmentInvalid
		}
	case string(state.TaskCommandSubmit):
		if taskState != string(contracts.TaskExecuting) || latestFence != capability.FencingToken || assignmentFence != capability.FencingToken || assignmentLeaseID != capability.LeaseID {
			return ErrAssignmentInvalid
		}
		lease, found, leaseErr := facts.leases.GetForTenant(ctx, capability.TenantID, capability.LeaseID)
		if leaseErr != nil || !found || lease.State != authz.LeaseActive || lease.IsExpired(now) ||
			lease.AgentInstanceID != capability.PrincipalID || lease.PrincipalID != capability.PrincipalID || lease.PrincipalType != authn.PrincipalAgentInstance ||
			lease.TenantID != capability.TenantID || lease.ProjectID != capability.ProjectID || lease.TaskID != capability.TaskID ||
			lease.ProjectVersion != capability.ProjectVersion || lease.TaskVersion != capability.TaskVersion || lease.SpecDigest != capability.ModuleSpecRef.SHA256 ||
			lease.Role != authn.RoleExecutor || lease.Action != authz.ActionModelGenerate || lease.PolicyVersion != capability.PolicyVersion || lease.BudgetAccountID != capability.BudgetAccountID || lease.FencingToken != capability.FencingToken {
			return ErrAssignmentInvalid
		}
	default:
		return ErrAssignmentInvalid
	}
	return nil
}

func (authority *OrchestratorTaskAuthority) revalidator() *executionCommitFacts {
	return &executionCommitFacts{db: authority.db, leases: authority.leases}
}

func (authority *OrchestratorTaskAuthority) Revalidate(ctx context.Context, capability orchestrator.CommitCapability) error {
	if authority == nil {
		return ErrExecutionUnavailable
	}
	return authority.revalidator().Revalidate(ctx, capability)
}

var _ TaskAuthority = (*OrchestratorTaskAuthority)(nil)
