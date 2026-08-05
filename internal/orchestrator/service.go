package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/idempotency"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
	"github.com/google/uuid"
)

type Clock func() time.Time

type Service struct {
	store    eventing.Store
	clock    Clock
	boundary CommitBoundary
}

type ProjectRequest struct {
	TenantID        string
	ProjectID       string
	PrincipalID     string
	IdempotencyKey  string
	ExpectedVersion int64
	Command         state.ProjectCommand
	Authorization   CommitAuthorization
}

type ProjectOutcome struct {
	Project   state.Project
	Events    []eventing.DomainEvent
	Duplicate bool
}

type TaskRequest struct {
	TenantID        string
	ProjectID       string
	TaskID          string
	PrincipalID     string
	IdempotencyKey  string
	ExpectedVersion int64
	Command         state.TaskCommand
	Authorization   CommitAuthorization
}

type TaskOutcome struct {
	Task      state.ModuleTask
	Events    []eventing.DomainEvent
	Duplicate bool
}

func New(store eventing.Store, clock Clock) *Service {
	return &Service{store: store, clock: clock, boundary: unavailableBoundary{}}
}

func NewWithBoundary(store eventing.Store, clock Clock, boundary CommitBoundary) *Service {
	if boundary == nil {
		boundary = unavailableBoundary{}
	}
	return &Service{store: store, clock: clock, boundary: boundary}
}

func (s *Service) HandleProject(ctx context.Context, request ProjectRequest) (ProjectOutcome, error) {
	if err := validateRequest(request.TenantID, request.ProjectID, request.PrincipalID, request.IdempotencyKey, request.ExpectedVersion); err != nil {
		return ProjectOutcome{}, err
	}
	command := request.Command
	command.TenantID = request.TenantID
	command.ProjectID = request.ProjectID
	command.ActorID = request.PrincipalID
	command.At = time.Time{}
	command, err := prepareGoalCommand(request, command)
	if err != nil {
		return ProjectOutcome{}, err
	}
	digestCommand := goalDigestCommand(command)
	if digestCommand.Type == state.ProjectCommandCreate {
		// The server allocates a fresh unpredictable ID for every attempt. The
		// principal-scoped idempotency record returns the first committed ID.
		digestCommand.ProjectID = ""
	}
	digest, err := commandDigest(request.ExpectedVersion, digestCommand)
	if err != nil {
		return ProjectOutcome{}, err
	}
	if prior, found, lookupErr := s.store.Lookup(ctx, request.TenantID, request.PrincipalID, request.IdempotencyKey, digest); lookupErr != nil {
		return ProjectOutcome{}, lookupErr
	} else if found {
		project, decodeErr := decodeProject(prior.Result)
		return ProjectOutcome{Project: project, Events: prior.Events, Duplicate: true}, decodeErr
	}

	projection, found, err := s.store.Load(ctx, request.TenantID, "project", request.ProjectID)
	if err != nil {
		return ProjectOutcome{}, err
	}
	current := state.Project{}
	if found {
		current, err = decodeProject(projection.State)
		if err != nil {
			return ProjectOutcome{}, err
		}
	} else if command.Type != state.ProjectCommandCreate {
		return ProjectOutcome{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	if current.Version != request.ExpectedVersion {
		return ProjectOutcome{}, versionConflict(request.ExpectedVersion, current.Version)
	}
	command.At = s.clock().UTC()
	command, err = finalizeGoalCommand(command)
	if err != nil {
		return ProjectOutcome{}, err
	}
	projectEvent, decideErr := state.DecideProject(current, command)
	if decideErr != nil {
		return ProjectOutcome{}, decideErr
	}
	update, domainEvent, result, encodeErr := encodeProjectTransition(request, projectEvent, digest)
	if encodeErr != nil {
		return ProjectOutcome{}, encodeErr
	}
	updates := []eventing.ProjectionUpdate{update}
	events := []eventing.DomainEvent{domainEvent}
	goalUpdates, goalEvents, goalErr := s.goalRelatedTransitions(ctx, request, current, command, digest)
	if goalErr != nil {
		return ProjectOutcome{}, goalErr
	}
	updates = append(updates, goalUpdates...)
	events = append(events, goalEvents...)
	var approvals []eventing.ApprovalRecord
	if command.Type == state.ProjectCommandApproveGoal || command.Type == state.ProjectCommandApproveRelease {
		approvals = approvalRecords(request.TenantID, request.ProjectID, command.Approval)
	}
	if command.Type == state.ProjectCommandSupersedeGoal || command.Type == state.ProjectCommandRequestGoalChange {
		for _, taskID := range command.ImpactedTaskIDs {
			taskProjection, taskFound, loadErr := s.store.Load(ctx, request.TenantID, "task", taskID)
			if loadErr != nil {
				return ProjectOutcome{}, loadErr
			}
			if !taskFound {
				return ProjectOutcome{}, aorerrors.New(aorerrors.CodeNotFound, "", map[string]any{"scope": "impacted task"})
			}
			task, decodeErr := decodeTask(taskProjection.State)
			if decodeErr != nil {
				return ProjectOutcome{}, decodeErr
			}
			if task.TenantID != request.TenantID || task.ProjectID != request.ProjectID {
				return ProjectOutcome{}, aorerrors.New(aorerrors.CodeForbidden, "", nil)
			}
			taskEvent, taskErr := state.DecideTask(task, state.TaskCommand{Type: state.TaskCommandSupersede, At: command.At})
			if taskErr != nil {
				return ProjectOutcome{}, taskErr
			}
			taskUpdate, taskDomainEvent, _, taskEncodeErr := encodeTaskTransition(request.TenantID, request.ProjectID, taskID, task.Version, taskEvent, digest)
			if taskEncodeErr != nil {
				return ProjectOutcome{}, taskEncodeErr
			}
			updates = append(updates, taskUpdate)
			events = append(events, taskDomainEvent)
		}
	}
	applyEventTrace(ctx, digest, events)
	if err := s.validateProjectCommit(ctx, request, current, command, digest); err != nil {
		return ProjectOutcome{}, err
	}
	transactionResult, err := s.store.Execute(ctx, eventing.TransactionRequest{
		TenantID: request.TenantID, PrincipalID: request.PrincipalID, IdempotencyKey: request.IdempotencyKey, RequestSHA256: digest,
		Updates: updates, Events: events, Approvals: approvals, Result: result, ResultSHA256: mustDigest(result),
	})
	if err != nil {
		return ProjectOutcome{}, err
	}
	project, err := decodeProject(transactionResult.Result)
	return ProjectOutcome{Project: project, Events: transactionResult.Events, Duplicate: transactionResult.Duplicate}, err
}

func (s *Service) HandleTask(ctx context.Context, request TaskRequest) (TaskOutcome, error) {
	if err := validateRequest(request.TenantID, request.ProjectID, request.PrincipalID, request.IdempotencyKey, request.ExpectedVersion); err != nil || request.TaskID == "" {
		if err != nil {
			return TaskOutcome{}, err
		}
		return TaskOutcome{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "taskId"})
	}
	command := normalizedTaskCommand(request)
	digest, err := TaskParameterDigest(request)
	if err != nil {
		return TaskOutcome{}, err
	}
	if prior, found, lookupErr := s.store.Lookup(ctx, request.TenantID, request.PrincipalID, request.IdempotencyKey, digest); lookupErr != nil {
		return TaskOutcome{}, lookupErr
	} else if found {
		task, decodeErr := decodeTask(prior.Result)
		return TaskOutcome{Task: task, Events: prior.Events, Duplicate: true}, decodeErr
	}
	projectProjection, projectFound, projectErr := s.store.Load(ctx, request.TenantID, "project", request.ProjectID)
	if projectErr != nil {
		return TaskOutcome{}, projectErr
	}
	if !projectFound {
		return TaskOutcome{}, aorerrors.New(aorerrors.CodeGoalNotApproved, "", nil)
	}
	project, decodeProjectErr := decodeProject(projectProjection.State)
	if decodeProjectErr != nil {
		return TaskOutcome{}, decodeProjectErr
	}
	planningCommand := command.Type == state.TaskCommandStartPlanning || command.Type == state.TaskCommandAttachModuleSpec
	if project.Goal == nil || project.Goal.ApprovedBy == "" || planningCommand && (project.State != contracts.ProjectPlanning || project.Plan != nil) || !planningCommand && project.Plan == nil {
		return TaskOutcome{}, aorerrors.New(aorerrors.CodeGoalNotApproved, "", nil)
	}
	if project.State == "PAUSED" || project.State == "ABORTED" || project.State == "ARCHIVED" || project.State == "COMPLETED" {
		return TaskOutcome{}, aorerrors.New(aorerrors.CodeTaskBlocked, "", map[string]any{"scope": string(project.State)})
	}

	projection, found, err := s.store.Load(ctx, request.TenantID, "task", request.TaskID)
	if err != nil {
		return TaskOutcome{}, err
	}
	current := state.ModuleTask{}
	if found {
		current, err = decodeTask(projection.State)
		if err != nil {
			return TaskOutcome{}, err
		}
		if current.TenantID != request.TenantID || current.ProjectID != request.ProjectID {
			return TaskOutcome{}, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "task project"})
		}
	} else if command.Type != state.TaskCommandDefine {
		return TaskOutcome{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	if current.Version != request.ExpectedVersion {
		return TaskOutcome{}, versionConflict(request.ExpectedVersion, current.Version)
	}
	command.At = s.clock().UTC()
	taskEvent, decideErr := state.DecideTask(current, command)
	if decideErr != nil {
		return TaskOutcome{}, decideErr
	}
	update, domainEvent, result, encodeErr := encodeTaskTransition(request.TenantID, request.ProjectID, request.TaskID, request.ExpectedVersion, taskEvent, digest)
	if encodeErr != nil {
		return TaskOutcome{}, encodeErr
	}
	updates := []eventing.ProjectionUpdate{update}
	events := []eventing.DomainEvent{domainEvent}
	var approvals []eventing.ApprovalRecord
	if command.Type == state.TaskCommandAuthorizeNewSeries {
		approvals = approvalRecords(request.TenantID, request.ProjectID, command.Approval)
	}
	if taskEvent.Projection.State == "BLOCKED_USER_DECISION" {
		for _, dependentID := range taskEvent.Projection.FrozenDependentIDs {
			dependentProjection, dependentFound, loadErr := s.store.Load(ctx, request.TenantID, "task", dependentID)
			if loadErr != nil {
				return TaskOutcome{}, loadErr
			}
			if !dependentFound {
				return TaskOutcome{}, aorerrors.New(aorerrors.CodeNotFound, "", map[string]any{"scope": "dependent task"})
			}
			dependent, decodeErr := decodeTask(dependentProjection.State)
			if decodeErr != nil {
				return TaskOutcome{}, decodeErr
			}
			if dependent.TenantID != request.TenantID || dependent.ProjectID != request.ProjectID {
				return TaskOutcome{}, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "dependent task project"})
			}
			blockedEvent, blockErr := state.DecideTask(dependent, state.TaskCommand{Type: state.TaskCommandBlockDependency, BlockingTaskID: request.TaskID, At: command.At})
			if blockErr != nil {
				return TaskOutcome{}, blockErr
			}
			dependentUpdate, dependentEvent, _, encodeErr := encodeTaskTransition(request.TenantID, request.ProjectID, dependentID, dependent.Version, blockedEvent, digest)
			if encodeErr != nil {
				return TaskOutcome{}, encodeErr
			}
			updates = append(updates, dependentUpdate)
			events = append(events, dependentEvent)
		}
	}
	if command.Type == state.TaskCommandAuthorizeNewSeries {
		for _, dependentID := range current.FrozenDependentIDs {
			dependentProjection, dependentFound, loadErr := s.store.Load(ctx, request.TenantID, "task", dependentID)
			if loadErr != nil {
				return TaskOutcome{}, loadErr
			}
			if !dependentFound {
				return TaskOutcome{}, aorerrors.New(aorerrors.CodeNotFound, "", map[string]any{"scope": "dependent task"})
			}
			dependent, decodeErr := decodeTask(dependentProjection.State)
			if decodeErr != nil {
				return TaskOutcome{}, decodeErr
			}
			if dependent.TenantID != request.TenantID || dependent.ProjectID != request.ProjectID {
				return TaskOutcome{}, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "dependent task project"})
			}
			if !contains(dependent.BlockingTaskIDs, request.TaskID) {
				continue
			}
			unblockedEvent, unblockErr := state.DecideTask(dependent, state.TaskCommand{Type: state.TaskCommandUnblockDependency, BlockingTaskID: request.TaskID, At: command.At})
			if unblockErr != nil {
				return TaskOutcome{}, unblockErr
			}
			dependentUpdate, dependentEvent, _, encodeErr := encodeTaskTransition(request.TenantID, request.ProjectID, dependentID, dependent.Version, unblockedEvent, digest)
			if encodeErr != nil {
				return TaskOutcome{}, encodeErr
			}
			updates = append(updates, dependentUpdate)
			events = append(events, dependentEvent)
		}
	}
	if command.Type == state.TaskCommandIntegrate {
		dependentUpdates, dependentEvents, propagationErr := s.readyIntegratedDependents(ctx, request, taskEvent.Projection, command.At, digest)
		if propagationErr != nil {
			return TaskOutcome{}, propagationErr
		}
		updates = append(updates, dependentUpdates...)
		events = append(events, dependentEvents...)
	}
	applyEventTrace(ctx, digest, events)
	if err := s.validateTaskCommit(ctx, request, project, current, command, digest); err != nil {
		return TaskOutcome{}, err
	}
	transactionResult, err := s.store.Execute(ctx, eventing.TransactionRequest{
		TenantID: request.TenantID, PrincipalID: request.PrincipalID, IdempotencyKey: request.IdempotencyKey, RequestSHA256: digest,
		Updates: updates, Events: events, Approvals: approvals, Result: result, ResultSHA256: mustDigest(result),
	})
	if err != nil {
		return TaskOutcome{}, err
	}
	task, err := decodeTask(transactionResult.Result)
	return TaskOutcome{Task: task, Events: transactionResult.Events, Duplicate: transactionResult.Duplicate}, err
}

// TaskParameterDigest returns the exact digest enforced by HandleTask. Trusted
// commit-authority adapters use it when binding a signed capability.
func TaskParameterDigest(request TaskRequest) (string, error) {
	return commandDigest(request.ExpectedVersion, normalizedTaskCommand(request))
}

func normalizedTaskCommand(request TaskRequest) state.TaskCommand {
	command := request.Command
	command.TenantID = request.TenantID
	command.ProjectID = request.ProjectID
	command.TaskID = request.TaskID
	command.ActorID = request.PrincipalID
	command.At = time.Time{}
	return command
}

func (s *Service) readyIntegratedDependents(ctx context.Context, request TaskRequest, integrated state.ModuleTask, at time.Time, digest string) ([]eventing.ProjectionUpdate, []eventing.DomainEvent, error) {
	if len(integrated.DependentTaskIDs) == 0 {
		return nil, nil, nil
	}
	tasks, err := s.Tasks(ctx, request.TenantID, request.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	byID := make(map[string]state.ModuleTask, len(tasks))
	for _, task := range tasks {
		byID[task.ID] = task
	}
	byID[integrated.ID] = integrated

	dependentIDs := append([]string(nil), integrated.DependentTaskIDs...)
	sort.Strings(dependentIDs)
	updates := make([]eventing.ProjectionUpdate, 0, len(dependentIDs))
	events := make([]eventing.DomainEvent, 0, len(dependentIDs))
	for _, dependentID := range dependentIDs {
		dependent, found := byID[dependentID]
		if !found {
			return nil, nil, aorerrors.New(aorerrors.CodeNotFound, "", map[string]any{"scope": "dependent task"})
		}
		if dependent.State != contracts.TaskDefined || !allTaskDependenciesIntegrated(byID, dependentID) {
			continue
		}
		ready, readyErr := state.DecideTask(dependent, state.TaskCommand{Type: state.TaskCommandReadyExecution, At: at})
		if readyErr != nil {
			return nil, nil, readyErr
		}
		update, event, _, encodeErr := encodeTaskTransition(request.TenantID, request.ProjectID, dependentID, dependent.Version, ready, digest)
		if encodeErr != nil {
			return nil, nil, encodeErr
		}
		updates = append(updates, update)
		events = append(events, event)
	}
	return updates, events, nil
}

func allTaskDependenciesIntegrated(tasks map[string]state.ModuleTask, dependentID string) bool {
	found := false
	for _, task := range tasks {
		if task.State == contracts.TaskCanceled || task.State == contracts.TaskSuperseded || !contains(task.DependentTaskIDs, dependentID) {
			continue
		}
		found = true
		if task.State != contracts.TaskIntegrated {
			return false
		}
	}
	return found
}

func encodeProjectTransition(request ProjectRequest, transition state.ProjectEvent, requestDigest string) (eventing.ProjectionUpdate, eventing.DomainEvent, json.RawMessage, error) {
	result, err := json.Marshal(transition.Projection)
	if err != nil {
		return eventing.ProjectionUpdate{}, eventing.DomainEvent{}, nil, err
	}
	payload, err := transitionPayload(request.TenantID, request.ProjectID, transition.AggregateVersion, result)
	if err != nil {
		return eventing.ProjectionUpdate{}, eventing.DomainEvent{}, nil, err
	}
	event, err := newEvent(request.TenantID, request.ProjectID, "project", request.ProjectID, transition.Type, transition.AggregateVersion, transition.OccurredAt, payload, requestDigest)
	if err != nil {
		return eventing.ProjectionUpdate{}, eventing.DomainEvent{}, nil, err
	}
	update := eventing.ProjectionUpdate{TenantID: request.TenantID, ProjectID: request.ProjectID, AggregateType: "project", AggregateID: request.ProjectID, ExpectedVersion: request.ExpectedVersion, NextVersion: transition.AggregateVersion, State: result}
	return update, event, result, nil
}

func encodeTaskTransition(tenantID, projectID, taskID string, expectedVersion int64, transition state.TaskEvent, requestDigest string) (eventing.ProjectionUpdate, eventing.DomainEvent, json.RawMessage, error) {
	result, err := json.Marshal(transition.Projection)
	if err != nil {
		return eventing.ProjectionUpdate{}, eventing.DomainEvent{}, nil, err
	}
	payload, err := transitionPayload(tenantID, projectID, transition.AggregateVersion, result)
	if err != nil {
		return eventing.ProjectionUpdate{}, eventing.DomainEvent{}, nil, err
	}
	event, err := newEvent(tenantID, projectID, "task", taskID, transition.Type, transition.AggregateVersion, transition.OccurredAt, payload, requestDigest)
	if err != nil {
		return eventing.ProjectionUpdate{}, eventing.DomainEvent{}, nil, err
	}
	update := eventing.ProjectionUpdate{TenantID: tenantID, ProjectID: projectID, AggregateType: "task", AggregateID: taskID, ExpectedVersion: expectedVersion, NextVersion: transition.AggregateVersion, State: result}
	return update, event, result, nil
}

func transitionPayload(tenantID, projectID string, version int64, projection json.RawMessage) (json.RawMessage, error) {
	return json.Marshal(struct {
		TenantID         string          `json:"tenantId"`
		ProjectID        string          `json:"projectId"`
		AggregateVersion int64           `json:"aggregateVersion"`
		Projection       json.RawMessage `json:"projection"`
	}{TenantID: tenantID, ProjectID: projectID, AggregateVersion: version, Projection: projection})
}

func newEvent(tenantID, projectID, aggregateType, aggregateID, eventType string, version int64, at time.Time, payload json.RawMessage, requestDigest string) (eventing.DomainEvent, error) {
	eventID, err := newRecordUUIDv7()
	if err != nil {
		return eventing.DomainEvent{}, err
	}
	return eventing.DomainEvent{
		EventID: eventID, TenantID: tenantID, ProjectID: projectID,
		AggregateType: aggregateType, AggregateID: aggregateID, AggregateVersion: version, Type: eventType, Payload: payload, PayloadSHA256: mustDigest(payload), OccurredAt: at,
		CorrelationID: stableID("corr", requestDigest), Traceparent: fallbackTraceParent(requestDigest),
	}, nil
}

func commandDigest(expectedVersion int64, command any) (string, error) {
	value, err := json.Marshal(struct {
		ExpectedVersion int64 `json:"expectedVersion"`
		Command         any   `json:"command"`
	}{ExpectedVersion: expectedVersion, Command: command})
	if err != nil {
		return "", err
	}
	return idempotency.RequestDigest(value)
}

func mustDigest(value []byte) string {
	digest, err := canonicaljson.Digest(value)
	if err != nil {
		panic(err)
	}
	return digest
}

func approvalRecords(tenantID, projectID string, approval *state.ApprovalBinding) []eventing.ApprovalRecord {
	if approval == nil {
		return nil
	}
	return []eventing.ApprovalRecord{{
		ID: approval.RecordID, TenantID: tenantID, ProjectID: projectID, ApprovalType: approval.ApprovalType, SubjectType: approval.SubjectType,
		SubjectID: approval.SubjectID, SubjectVersion: approval.SubjectVersion, SubjectSHA256: approval.SubjectSHA256, PrincipalID: approval.PrincipalID,
		Reason: approval.Reason, IssuedAt: approval.IssuedAt, ExpiresAt: approval.ExpiresAt, RevokedAt: approval.RevokedAt, Signature: approval.Signature,
	}}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func stableID(prefix, input string) string {
	sum := sha256.Sum256([]byte(input))
	return prefix + "_" + hex.EncodeToString(sum[:16])
}

func newRecordUUIDv7() (string, error) {
	value, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return value.String(), nil
}

func decodeProject(value []byte) (state.Project, error) {
	var project state.Project
	if err := json.Unmarshal(value, &project); err != nil {
		return state.Project{}, fmt.Errorf("decode project projection: %w", err)
	}
	return project, nil
}

func decodeTask(value []byte) (state.ModuleTask, error) {
	var task state.ModuleTask
	if err := json.Unmarshal(value, &task); err != nil {
		return state.ModuleTask{}, fmt.Errorf("decode task projection: %w", err)
	}
	return task, nil
}

func validateRequest(tenantID, projectID, principalID, key string, expectedVersion int64) error {
	if tenantID == "" || projectID == "" || principalID == "" || key == "" || expectedVersion < 0 {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "orchestrator command"})
	}
	return nil
}

func versionConflict(expected, actual int64) error {
	return aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"expectedVersion": expected, "actualVersion": actual})
}
