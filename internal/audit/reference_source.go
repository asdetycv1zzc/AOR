package audit

import (
	"context"

	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
)

// ModuleAuditStateReader exposes the authoritative aggregate projections needed
// to bind a blind audit request to its current project and task versions.
type ModuleAuditStateReader interface {
	Project(context.Context, string, string) (state.Project, bool, error)
	Task(context.Context, string, string, string) (state.ModuleTask, bool, error)
}

type StateModuleAuditReferenceSource struct {
	state ModuleAuditStateReader
}

func NewStateModuleAuditReferenceSource(source ModuleAuditStateReader) (*StateModuleAuditReferenceSource, error) {
	if source == nil {
		return nil, ErrRuntimeAuditorUnavailable
	}
	return &StateModuleAuditReferenceSource{state: source}, nil
}

func (source *StateModuleAuditReferenceSource) Resolve(ctx context.Context, input BlindAuditInput) (ModuleAuditReferences, error) {
	if source == nil || source.state == nil || ctx == nil || ctx.Err() != nil ||
		validateBlindInput(input) != nil || !validAuditRunID(input.AuditRunID) ||
		!validCoordinatorID(input.TenantID) || !validCoordinatorID(input.AttemptSeriesID) {
		return ModuleAuditReferences{}, ErrInvalidAuditRequest
	}
	project, found, err := source.state.Project(ctx, input.TenantID, input.ProjectID)
	if err != nil {
		return ModuleAuditReferences{}, err
	}
	if !found || !projectMatchesModuleAudit(project, input) {
		return ModuleAuditReferences{}, ErrInvalidAuditRequest
	}
	task, found, err := source.state.Task(ctx, input.TenantID, input.ProjectID, input.TaskID)
	if err != nil {
		return ModuleAuditReferences{}, err
	}
	if !found || !taskMatchesModuleAudit(task, input) {
		return ModuleAuditReferences{}, ErrInvalidAuditRequest
	}
	return ModuleAuditReferences{
		TenantID:           project.TenantID,
		ProjectVersion:     project.Version,
		TaskVersion:        task.Version,
		GoalSpec:           contracts.SpecRef{Version: project.Goal.Version, SHA256: project.Goal.SHA256},
		PlanSpec:           *project.Plan,
		DataClassification: project.DataClassification,
	}, nil
}

func projectMatchesModuleAudit(project state.Project, input BlindAuditInput) bool {
	if project.TenantID != input.TenantID || project.ID != input.ProjectID || project.Version < 1 ||
		project.State != contracts.ProjectExecuting && project.State != contracts.ProjectGlobalAudit ||
		project.Goal == nil || project.Goal.Status != contracts.GoalApproved || project.Goal.ApprovedBy == "" ||
		project.Goal.ApprovalRecordID == "" || project.Plan == nil || project.Plan.Validate() != nil ||
		!moduleAuditClassification(project.DataClassification) {
		return false
	}
	goal := contracts.SpecRef{Version: project.Goal.Version, SHA256: project.Goal.SHA256}
	return goal.Validate() == nil
}

func taskMatchesModuleAudit(task state.ModuleTask, input BlindAuditInput) bool {
	return task.TenantID == input.TenantID && task.ProjectID == input.ProjectID && task.ID == input.TaskID &&
		task.State == contracts.TaskLLMAudit && task.Version > 0 && task.ModuleID != "" &&
		task.ModuleSpecRef == input.ModuleSpecRef && task.AttemptSeriesID == input.AttemptSeriesID && task.Attempt == input.Attempt
}

var _ ModuleAuditReferenceSource = (*StateModuleAuditReferenceSource)(nil)
