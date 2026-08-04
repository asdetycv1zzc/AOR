package orchestrator

import (
	"context"
	"encoding/json"
	"slices"
	"sort"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type PlanTaskDefinition struct {
	ModuleID        string
	TaskID          string
	ModuleSpecRef   contracts.SpecRef
	AttemptSeriesID string
	Retain          bool
}

type PublishPlanRequest struct {
	TenantID               string
	ProjectID              string
	PrincipalID            string
	IdempotencyKey         string
	ExpectedProjectVersion int64
	GoalSpecRef            contracts.SpecRef
	PlanRef                contracts.SpecRef
	DAG                    map[string][]string
	Tasks                  []PlanTaskDefinition
	Authorization          CommitAuthorization
}

type PublishPlanOutcome struct {
	Project   state.Project      `json:"project"`
	Tasks     []state.ModuleTask `json:"tasks"`
	Events    []eventing.DomainEvent
	Duplicate bool
}

func (s *Service) PublishPlan(ctx context.Context, request PublishPlanRequest) (PublishPlanOutcome, error) {
	if err := validatePublishPlanRequest(request); err != nil {
		return PublishPlanOutcome{}, err
	}
	request.Tasks = append([]PlanTaskDefinition(nil), request.Tasks...)
	sort.Slice(request.Tasks, func(left, right int) bool { return request.Tasks[left].ModuleID < request.Tasks[right].ModuleID })
	digest, err := commandDigest(request.ExpectedProjectVersion, request)
	if err != nil {
		return PublishPlanOutcome{}, err
	}
	if prior, found, lookupErr := s.store.Lookup(ctx, request.TenantID, request.PrincipalID, request.IdempotencyKey, digest); lookupErr != nil {
		return PublishPlanOutcome{}, lookupErr
	} else if found {
		outcome, decodeErr := decodePublishPlanResult(prior.Result)
		outcome.Events = prior.Events
		outcome.Duplicate = true
		return outcome, decodeErr
	}

	projection, found, err := s.store.Load(ctx, request.TenantID, "project", request.ProjectID)
	if err != nil {
		return PublishPlanOutcome{}, err
	}
	if !found {
		return PublishPlanOutcome{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	project, err := decodeProject(projection.State)
	if err != nil {
		return PublishPlanOutcome{}, err
	}
	if project.Version != request.ExpectedProjectVersion {
		return PublishPlanOutcome{}, versionConflict(request.ExpectedProjectVersion, project.Version)
	}
	at := s.clock().UTC()
	projectCommand := state.ProjectCommand{Type: state.ProjectCommandPublishPlan, ActorID: request.PrincipalID, GoalSpecRef: &request.GoalSpecRef, Plan: &request.PlanRef, DAG: cloneGraph(request.DAG), At: at}
	projectEvent, decisionErr := state.DecideProject(project, projectCommand)
	if decisionErr != nil {
		return PublishPlanOutcome{}, decisionErr
	}
	projectRequest := ProjectRequest{TenantID: request.TenantID, ProjectID: request.ProjectID, PrincipalID: request.PrincipalID, ExpectedVersion: request.ExpectedProjectVersion}
	projectUpdate, projectDomainEvent, _, err := encodeProjectTransition(projectRequest, projectEvent, digest)
	if err != nil {
		return PublishPlanOutcome{}, err
	}
	updates := []eventing.ProjectionUpdate{projectUpdate}
	events := []eventing.DomainEvent{projectDomainEvent}
	tasks := make([]state.ModuleTask, 0, len(request.Tasks))
	dependentIDs := planDependentTaskIDs(request.Tasks, request.DAG)
	for _, definition := range request.Tasks {
		existing, exists, loadErr := s.store.Load(ctx, request.TenantID, "task", definition.TaskID)
		if loadErr != nil {
			return PublishPlanOutcome{}, loadErr
		}
		if definition.Retain {
			if !exists {
				return PublishPlanOutcome{}, aorerrors.New(aorerrors.CodeNotFound, "", map[string]any{"scope": "retained plan task"})
			}
			retained, decodeErr := decodeTask(existing.State)
			if decodeErr != nil {
				return PublishPlanOutcome{}, decodeErr
			}
			if retained.TenantID != request.TenantID || retained.ProjectID != request.ProjectID || retained.ModuleSpecRef != definition.ModuleSpecRef || retained.AttemptSeriesID != definition.AttemptSeriesID || retained.State == contracts.TaskSuperseded || retained.State == contracts.TaskCanceled || !slices.Equal(retained.DependentTaskIDs, dependentIDs[definition.ModuleID]) {
				return PublishPlanOutcome{}, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "retained plan task"})
			}
			tasks = append(tasks, retained)
			continue
		}
		if exists || existing.Version != 0 {
			return PublishPlanOutcome{}, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "plan task"})
		}
		transition, taskErr := state.DecideTask(state.ModuleTask{}, state.TaskCommand{
			Type: state.TaskCommandDefine, TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: definition.TaskID,
			ModuleSpecRef: definition.ModuleSpecRef, AttemptSeriesID: definition.AttemptSeriesID,
			DependentTaskIDs: dependentIDs[definition.ModuleID], At: at,
		})
		if taskErr != nil {
			return PublishPlanOutcome{}, taskErr
		}
		update, event, _, encodeErr := encodeTaskTransition(request.TenantID, request.ProjectID, definition.TaskID, 0, transition, digest)
		if encodeErr != nil {
			return PublishPlanOutcome{}, encodeErr
		}
		updates = append(updates, update)
		events = append(events, event)
		tasks = append(tasks, transition.Projection)
	}
	result, err := json.Marshal(struct {
		Project state.Project      `json:"project"`
		Tasks   []state.ModuleTask `json:"tasks"`
	}{Project: projectEvent.Projection, Tasks: tasks})
	if err != nil {
		return PublishPlanOutcome{}, err
	}
	if err := s.validatePlanCommit(ctx, request, project, digest, at); err != nil {
		return PublishPlanOutcome{}, err
	}
	applyEventTrace(ctx, digest, events)
	transaction, err := s.store.Execute(ctx, eventing.TransactionRequest{
		TenantID: request.TenantID, PrincipalID: request.PrincipalID, IdempotencyKey: request.IdempotencyKey, RequestSHA256: digest,
		Updates: updates, Events: events, Result: result, ResultSHA256: mustDigest(result),
	})
	if err != nil {
		return PublishPlanOutcome{}, err
	}
	outcome, err := decodePublishPlanResult(transaction.Result)
	outcome.Events = transaction.Events
	outcome.Duplicate = transaction.Duplicate
	return outcome, err
}

func validatePublishPlanRequest(request PublishPlanRequest) error {
	if err := validateRequest(request.TenantID, request.ProjectID, request.PrincipalID, request.IdempotencyKey, request.ExpectedProjectVersion); err != nil {
		return err
	}
	if request.GoalSpecRef.Validate() != nil || request.PlanRef.Validate() != nil || !state.ValidateDAG(request.DAG) || len(request.Tasks) != len(request.DAG) {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "plan publication"})
	}
	seenModules := make(map[string]bool, len(request.Tasks))
	seenTasks := make(map[string]bool, len(request.Tasks))
	seenSeries := make(map[string]bool, len(request.Tasks))
	for _, task := range request.Tasks {
		_, moduleExists := request.DAG[task.ModuleID]
		if task.ModuleID == "" || task.TaskID == "" || task.AttemptSeriesID == "" || task.ModuleSpecRef.Validate() != nil || !moduleExists || seenModules[task.ModuleID] || seenTasks[task.TaskID] || seenSeries[task.AttemptSeriesID] {
			return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "plan task definition"})
		}
		seenModules[task.ModuleID] = true
		seenTasks[task.TaskID] = true
		seenSeries[task.AttemptSeriesID] = true
	}
	return nil
}

func planDependentTaskIDs(tasks []PlanTaskDefinition, graph map[string][]string) map[string][]string {
	taskByModule := make(map[string]string, len(tasks))
	for _, task := range tasks {
		taskByModule[task.ModuleID] = task.TaskID
	}
	result := make(map[string][]string, len(tasks))
	for moduleID, dependencies := range graph {
		for _, dependency := range dependencies {
			result[dependency] = append(result[dependency], taskByModule[moduleID])
		}
	}
	for moduleID := range graph {
		sort.Strings(result[moduleID])
	}
	return result
}

func decodePublishPlanResult(value []byte) (PublishPlanOutcome, error) {
	var result struct {
		Project state.Project      `json:"project"`
		Tasks   []state.ModuleTask `json:"tasks"`
	}
	if err := json.Unmarshal(value, &result); err != nil {
		return PublishPlanOutcome{}, err
	}
	return PublishPlanOutcome{Project: result.Project, Tasks: result.Tasks}, nil
}

func cloneGraph(graph map[string][]string) map[string][]string {
	result := make(map[string][]string, len(graph))
	for id, dependencies := range graph {
		result[id] = append([]string(nil), dependencies...)
	}
	return result
}
