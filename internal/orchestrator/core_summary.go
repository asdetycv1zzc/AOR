package orchestrator

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

func (s *Service) coreSummaryTransition(ctx context.Context, request TaskRequest, project state.Project, passed state.ModuleTask, at time.Time, requestDigest string) ([]eventing.ProjectionUpdate, []eventing.DomainEvent, error) {
	if !s.coreOnly || project.CoreSummary != nil || project.State != contracts.ProjectExecuting || project.Goal == nil || project.Plan == nil || passed.State != contracts.TaskPassed {
		return nil, nil, nil
	}
	tasks, err := s.Tasks(ctx, request.TenantID, request.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	foundPassed := false
	for index := range tasks {
		if tasks[index].ID == passed.ID {
			tasks[index] = passed
			foundPassed = true
			break
		}
	}
	if !foundPassed {
		tasks = append(tasks, passed)
	}
	modules := make([]state.CoreModuleOutcome, 0, len(tasks))
	for _, task := range tasks {
		if task.State == contracts.TaskCanceled || task.State == contracts.TaskSuperseded {
			continue
		}
		if task.State != contracts.TaskPassed {
			return nil, nil, nil
		}
		modules = append(modules, state.CoreModuleOutcome{
			TaskID: task.ID, ModuleID: task.ModuleID, State: task.State, Version: task.Version,
			ModuleSpecRef: task.ModuleSpecRef, Attempt: task.Attempt, AttemptSeriesID: task.AttemptSeriesID,
		})
	}
	if len(modules) == 0 {
		return nil, nil, nil
	}
	sort.Slice(modules, func(left, right int) bool { return modules[left].TaskID < modules[right].TaskID })
	summary := state.CoreSummary{
		SummaryVersion: 1, TenantID: project.TenantID, ProjectID: project.ID, Status: "COMPLETED",
		GoalSpecRef: contracts.SpecRef{Version: project.Goal.Version, SHA256: project.Goal.SHA256},
		PlanSpecRef: *project.Plan, Modules: modules, CreatedAt: at.UTC(),
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		return nil, nil, err
	}
	summary.SummarySHA256, err = canonicaljson.DigestObjectWithoutFields(encoded, "summarySha256", "createdAt")
	if err != nil {
		return nil, nil, err
	}
	transition, stateErr := state.DecideProject(project, state.ProjectCommand{
		Type: state.ProjectCommandPublishCoreSummary, ActorID: request.PrincipalID, CoreSummary: &summary, At: at,
	})
	if stateErr != nil {
		return nil, nil, stateErr
	}
	update, event, _, err := encodeProjectTransition(ProjectRequest{
		TenantID: request.TenantID, ProjectID: request.ProjectID, PrincipalID: request.PrincipalID,
		ExpectedVersion: project.Version,
	}, transition, requestDigest)
	if err != nil {
		return nil, nil, err
	}
	return []eventing.ProjectionUpdate{update}, []eventing.DomainEvent{event}, nil
}
