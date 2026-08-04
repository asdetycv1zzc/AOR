package orchestrator

import (
	"context"
	"errors"
	"time"

	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
)

var ErrCommitBoundary = errors.New("orchestrator commit boundary rejected the command")

type CommitAuthorization struct {
	Capability CommitCapability `json:"capability"`
	Signature  string           `json:"signature"`
}

type CommitValidation struct {
	TenantID         string
	ProjectID        string
	TaskID           string
	PrincipalID      string
	Action           string
	ExpectedVersion  int64
	Project          state.Project
	Task             state.ModuleTask
	ParameterDigest  string
	EvidenceSHA256   []string
	Claims           map[string]bool
	ModuleSpecRef    contracts.SpecRef
	GoalSpecRef      contracts.SpecRef
	FencingToken     int64
	ApprovalRecordID string
	Authorization    CommitAuthorization
	CommitAt         time.Time
}

func (s *Service) validateProjectCommit(ctx context.Context, request ProjectRequest, current state.Project, command state.ProjectCommand, parameterDigest string) error {
	evidence := []string{}
	claims := map[string]bool{}
	if command.Guard != nil {
		evidence = append(evidence, command.Guard.EvidenceSHA256)
		claims["all_tasks_passed"] = command.Guard.AllTasksPassed
		claims["all_tasks_integrated"] = command.Guard.AllTasksIntegrated
		claims["integration_audit_passed"] = command.Guard.IntegrationAuditPassed
	}
	if command.Completion != nil {
		evidence = append(evidence, command.Completion.EvidenceSHA256)
		claims["all_tasks_integrated"] = command.Completion.AllTasksIntegrated
		claims["goal_criteria_satisfied"] = command.Completion.GoalCriteriaSatisfied
		claims["global_audit_passed"] = command.Completion.GlobalAuditPassed
		claims["release_artifacts_signed"] = command.Completion.ReleaseArtifactsSigned
		claims["no_blocking_findings"] = command.Completion.NoBlockingFindings
	}
	goalRef := contracts.SpecRef{}
	if command.GoalSpecRef != nil {
		goalRef = *command.GoalSpecRef
	} else if command.Goal != nil {
		goalRef = contracts.SpecRef{Version: command.Goal.Version, SHA256: command.Goal.SHA256}
	}
	approvalID := ""
	if command.Approval != nil {
		approvalID = command.Approval.RecordID
	}
	validation := CommitValidation{TenantID: request.TenantID, ProjectID: request.ProjectID, PrincipalID: request.PrincipalID, Action: string(command.Type), ExpectedVersion: request.ExpectedVersion, Project: current, ParameterDigest: parameterDigest, EvidenceSHA256: evidence, Claims: claims, GoalSpecRef: goalRef, ApprovalRecordID: approvalID, Authorization: request.Authorization, CommitAt: command.At}
	return s.validateCommitBoundary(ctx, validation)
}

func (s *Service) validateTaskCommit(ctx context.Context, request TaskRequest, project state.Project, current state.ModuleTask, command state.TaskCommand, parameterDigest string) error {
	evidence := []string{}
	if command.AuditEvidenceSHA256 != "" {
		evidence = append(evidence, command.AuditEvidenceSHA256)
	}
	claims := map[string]bool{}
	switch command.Type {
	case state.TaskCommandStartAudit:
		claims["submission_validated"] = command.SubmissionValidated
	case state.TaskCommandLLMSuccess:
		claims["fresh_auditor"] = command.FreshAuditor
		claims["blind_audit_context"] = command.BlindAuditContext
		claims["no_blocking_findings"] = command.NoBlockingFindings
	case state.TaskCommandLLMFailure:
		claims["fresh_auditor"] = command.FreshAuditor
		claims["blind_audit_context"] = command.BlindAuditContext
	case state.TaskCommandIntegrate:
		claims["dependencies_satisfied"] = command.DependenciesSatisfied
		claims["merge_gate_passed"] = command.MergeGatePassed
	}
	moduleRef := command.ModuleSpecRef
	if moduleRef.Version == 0 {
		moduleRef = current.ModuleSpecRef
	}
	approvalID := ""
	if command.Approval != nil {
		approvalID = command.Approval.RecordID
	}
	validation := CommitValidation{TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID, PrincipalID: request.PrincipalID, Action: string(command.Type), ExpectedVersion: request.ExpectedVersion, Project: project, Task: current, ParameterDigest: parameterDigest, EvidenceSHA256: evidence, Claims: claims, ModuleSpecRef: moduleRef, FencingToken: command.FencingToken, ApprovalRecordID: approvalID, Authorization: request.Authorization, CommitAt: command.At}
	return s.validateCommitBoundary(ctx, validation)
}

func (s *Service) validatePlanCommit(ctx context.Context, request PublishPlanRequest, project state.Project, parameterDigest string, at time.Time) error {
	validation := CommitValidation{TenantID: request.TenantID, ProjectID: request.ProjectID, PrincipalID: request.PrincipalID, Action: string(state.ProjectCommandPublishPlan), ExpectedVersion: request.ExpectedProjectVersion, Project: project, ParameterDigest: parameterDigest, EvidenceSHA256: []string{request.GoalSpecRef.SHA256, request.PlanRef.SHA256}, Claims: map[string]bool{"dag_validated": true, "module_specs_validated": true}, GoalSpecRef: request.GoalSpecRef, Authorization: request.Authorization, CommitAt: at}
	return s.validateCommitBoundary(ctx, validation)
}

func (s *Service) validateCommitBoundary(ctx context.Context, validation CommitValidation) error {
	if s == nil || s.boundary == nil || validation.TenantID == "" || validation.ProjectID == "" || validation.PrincipalID == "" || validation.Action == "" || validation.ParameterDigest == "" || validation.CommitAt.IsZero() {
		return ErrCommitBoundary
	}
	if err := s.boundary.Validate(ctx, cloneCommitValidation(validation)); err != nil {
		return ErrCommitBoundary
	}
	return nil
}

type CommitBoundary interface {
	Validate(context.Context, CommitValidation) error
}

type unavailableBoundary struct{}

func (unavailableBoundary) Validate(context.Context, CommitValidation) error {
	return ErrCommitBoundary
}

func cloneCommitValidation(value CommitValidation) CommitValidation {
	value.Project = cloneBoundaryProject(value.Project)
	value.Task = cloneBoundaryTask(value.Task)
	value.EvidenceSHA256 = append([]string(nil), value.EvidenceSHA256...)
	claims := make(map[string]bool, len(value.Claims))
	for key, enabled := range value.Claims {
		claims[key] = enabled
	}
	value.Claims = claims
	value.Authorization.Capability = cloneCommitCapability(value.Authorization.Capability)
	return value
}

func cloneBoundaryProject(value state.Project) state.Project {
	value.DeploymentTargets = append([]string(nil), value.DeploymentTargets...)
	if value.Goal != nil {
		goal := *value.Goal
		goal.UnresolvedItems = append([]string(nil), value.Goal.UnresolvedItems...)
		value.Goal = &goal
	}
	if value.Plan != nil {
		plan := *value.Plan
		value.Plan = &plan
	}
	if value.Deletion != nil {
		deletion := *value.Deletion
		deletion.StartedAt = cloneTimePointer(value.Deletion.StartedAt)
		deletion.CompletedAt = cloneTimePointer(value.Deletion.CompletedAt)
		deletion.BackupExpiresAt = cloneTimePointer(value.Deletion.BackupExpiresAt)
		value.Deletion = &deletion
	}
	value.LegalHolds = append([]state.ProjectLegalHold(nil), value.LegalHolds...)
	for index := range value.LegalHolds {
		value.LegalHolds[index].ReleasedAt = cloneTimePointer(value.LegalHolds[index].ReleasedAt)
	}
	return value
}

func cloneBoundaryTask(value state.ModuleTask) state.ModuleTask {
	value.AttemptSeriesIDs = append([]string(nil), value.AttemptSeriesIDs...)
	value.DependentTaskIDs = append([]string(nil), value.DependentTaskIDs...)
	value.FrozenDependentIDs = append([]string(nil), value.FrozenDependentIDs...)
	value.BlockingTaskIDs = append([]string(nil), value.BlockingTaskIDs...)
	return value
}
