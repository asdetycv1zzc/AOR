package state

import (
	"fmt"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type ModuleTask struct {
	TenantID           string                    `json:"tenantId"`
	ProjectID          string                    `json:"projectId"`
	ID                 string                    `json:"id"`
	ModuleID           string                    `json:"moduleId,omitempty"`
	State              contracts.ModuleTaskState `json:"state"`
	Version            int64                     `json:"version"`
	PlanningSpecRef    contracts.SpecRef         `json:"planningSpecRef,omitempty"`
	ModuleSpecRef      contracts.SpecRef         `json:"moduleSpecRef"`
	AttemptSeriesID    string                    `json:"attemptSeriesId"`
	AttemptSeriesIDs   []string                  `json:"attemptSeriesIds"`
	Attempt            int                       `json:"attempt"`
	FencingToken       int64                     `json:"fencingToken"`
	DependentTaskIDs   []string                  `json:"dependentTaskIds"`
	FrozenDependentIDs []string                  `json:"frozenDependentIds"`
	BlockingTaskIDs    []string                  `json:"blockingTaskIds"`
	BlockedFromState   contracts.ModuleTaskState `json:"blockedFromState,omitempty"`
}

type TaskCommandType string

const (
	TaskCommandDefine               TaskCommandType = "DEFINE_TASK"
	TaskCommandQueuePlanning        TaskCommandType = "QUEUE_PLANNING"
	TaskCommandStartPlanning        TaskCommandType = "START_PLANNING"
	TaskCommandAttachModuleSpec     TaskCommandType = "ATTACH_MODULE_SPEC"
	TaskCommandReadyExecution       TaskCommandType = "READY_EXECUTION"
	TaskCommandLeaseExecution       TaskCommandType = "LEASE_EXECUTION"
	TaskCommandSubmit               TaskCommandType = "SUBMIT_IMPLEMENTATION"
	TaskCommandStartAudit           TaskCommandType = "START_AUDIT"
	TaskCommandDeterministicSuccess TaskCommandType = "DETERMINISTIC_SUCCESS"
	TaskCommandDeterministicFailure TaskCommandType = "DETERMINISTIC_FAILURE"
	TaskCommandLLMSuccess           TaskCommandType = "LLM_SUCCESS"
	TaskCommandLLMFailure           TaskCommandType = "LLM_FAILURE"
	TaskCommandQueueRework          TaskCommandType = "QUEUE_REWORK"
	TaskCommandIntegrate            TaskCommandType = "INTEGRATE"
	TaskCommandBlockDependency      TaskCommandType = "BLOCK_DEPENDENCY"
	TaskCommandUnblockDependency    TaskCommandType = "UNBLOCK_DEPENDENCY"
	TaskCommandAuthorizeNewSeries   TaskCommandType = "AUTHORIZE_NEW_ATTEMPT_SERIES"
	TaskCommandSupersede            TaskCommandType = "SUPERSEDE"
)

type TaskCommand struct {
	Type                  TaskCommandType
	TenantID              string
	ProjectID             string
	TaskID                string
	ModuleID              string
	PlanningSpecRef       contracts.SpecRef
	ModuleSpecRef         contracts.SpecRef
	AttemptSeriesID       string
	FencingToken          int64
	DependentTaskIDs      []string
	BlockingTaskID        string
	ActorID               string
	Decision              contracts.Decision
	NewAttemptSeriesID    string
	Approval              *ApprovalBinding
	SubmissionValidated   bool
	AuditEvidenceSHA256   string
	FreshAuditor          bool
	BlindAuditContext     bool
	NoBlockingFindings    bool
	DependenciesSatisfied bool
	MergeGatePassed       bool
	At                    time.Time
}

type TaskEvent struct {
	Type             string     `json:"type"`
	AggregateVersion int64      `json:"aggregateVersion"`
	OccurredAt       time.Time  `json:"occurredAt"`
	Projection       ModuleTask `json:"projection"`
}

func DecideTask(current ModuleTask, command TaskCommand) (TaskEvent, *aorerrors.Error) {
	if command.At.IsZero() {
		return TaskEvent{}, invalidTask(command, "trusted time is required")
	}
	next := cloneTask(current)
	eventType := ""
	switch command.Type {
	case TaskCommandDefine:
		if current.Version != 0 || current.ID != "" || command.TenantID == "" || command.ProjectID == "" || command.TaskID == "" || command.AttemptSeriesID == "" || command.ModuleSpecRef.Validate() != nil || invalidDependents(command.TaskID, command.DependentTaskIDs) {
			return TaskEvent{}, invalidTask(command, "task definition guard")
		}
		next = ModuleTask{
			TenantID: command.TenantID, ProjectID: command.ProjectID, ID: command.TaskID, State: contracts.TaskDefined,
			ModuleSpecRef: command.ModuleSpecRef, AttemptSeriesID: command.AttemptSeriesID, AttemptSeriesIDs: []string{command.AttemptSeriesID}, DependentTaskIDs: append([]string(nil), command.DependentTaskIDs...),
		}
		eventType = "io.aor.module.defined.v1"
	case TaskCommandQueuePlanning:
		if current.Version != 0 || current.ID != "" || command.TenantID == "" || command.ProjectID == "" || command.TaskID == "" || command.ModuleID == "" || command.PlanningSpecRef.Validate() != nil || invalidDependents(command.TaskID, command.DependentTaskIDs) {
			return TaskEvent{}, invalidTask(command, "planning task guard")
		}
		next = ModuleTask{
			TenantID: command.TenantID, ProjectID: command.ProjectID, ID: command.TaskID, ModuleID: command.ModuleID,
			State: contracts.TaskQueuedPlanning, PlanningSpecRef: command.PlanningSpecRef,
			DependentTaskIDs: append([]string(nil), command.DependentTaskIDs...),
		}
		eventType = "io.aor.module.planning-queued.v1"
	case TaskCommandStartPlanning:
		if current.State != contracts.TaskQueuedPlanning || current.ModuleID == "" || current.PlanningSpecRef.Validate() != nil || current.ModuleSpecRef != (contracts.SpecRef{}) || current.AttemptSeriesID != "" || len(current.AttemptSeriesIDs) != 0 {
			return TaskEvent{}, transitionTask(command, current.State)
		}
		next.State = contracts.TaskPlanning
		eventType = "io.aor.module.planning-started.v1"
	case TaskCommandAttachModuleSpec:
		if current.State != contracts.TaskPlanning || current.ModuleID == "" || current.PlanningSpecRef.Validate() != nil || current.ModuleSpecRef != (contracts.SpecRef{}) || command.ModuleSpecRef.Validate() != nil || command.AttemptSeriesID == "" {
			return TaskEvent{}, transitionTask(command, current.State)
		}
		next.ModuleSpecRef = command.ModuleSpecRef
		next.AttemptSeriesID = command.AttemptSeriesID
		next.AttemptSeriesIDs = []string{command.AttemptSeriesID}
		next.State = contracts.TaskDefined
		eventType = "io.aor.module.spec-attached.v1"
	case TaskCommandReadyExecution:
		if current.State != contracts.TaskDefined && current.State != contracts.TaskReworkRequired {
			if current.State == contracts.TaskBlockedUserDecision {
				return TaskEvent{}, aorerrors.New(aorerrors.CodeAttemptLimitReached, "", nil)
			}
			return TaskEvent{}, transitionTask(command, current.State)
		}
		if current.Attempt >= 3 {
			return TaskEvent{}, aorerrors.New(aorerrors.CodeAttemptLimitReached, "", nil)
		}
		next.State = contracts.TaskReadyExecution
		eventType = "io.aor.module.execution-ready.v1"
	case TaskCommandLeaseExecution:
		if current.State != contracts.TaskReadyExecution || command.FencingToken <= current.FencingToken {
			if command.FencingToken <= current.FencingToken {
				return TaskEvent{}, aorerrors.New(aorerrors.CodeLeaseExpired, "", nil)
			}
			return TaskEvent{}, transitionTask(command, current.State)
		}
		next.FencingToken = command.FencingToken
		next.State = contracts.TaskExecuting
		eventType = "io.aor.module.execution-leased.v1"
	case TaskCommandSubmit:
		if current.State != contracts.TaskExecuting {
			return TaskEvent{}, transitionTask(command, current.State)
		}
		if command.FencingToken != current.FencingToken {
			return TaskEvent{}, aorerrors.New(aorerrors.CodeLeaseExpired, "", nil)
		}
		if command.ModuleSpecRef != current.ModuleSpecRef || command.AttemptSeriesID != current.AttemptSeriesID {
			return TaskEvent{}, aorerrors.New(aorerrors.CodeSpecSuperseded, "", nil)
		}
		if current.Attempt >= 3 {
			return TaskEvent{}, aorerrors.New(aorerrors.CodeAttemptLimitReached, "", nil)
		}
		next.Attempt++
		next.State = contracts.TaskSubmitted
		eventType = "io.aor.module.implementation-submitted.v1"
	case TaskCommandStartAudit:
		if current.State != contracts.TaskSubmitted || !command.SubmissionValidated || !validDigest(command.AuditEvidenceSHA256) {
			return TaskEvent{}, transitionTask(command, current.State)
		}
		next.State = contracts.TaskDeterministicAudit
		eventType = "io.aor.module.deterministic-audit-started.v1"
	case TaskCommandDeterministicSuccess:
		if current.State != contracts.TaskDeterministicAudit || !validDigest(command.AuditEvidenceSHA256) {
			return TaskEvent{}, transitionTask(command, current.State)
		}
		next.State = contracts.TaskLLMAudit
		eventType = "io.aor.module.deterministic-audit-passed.v1"
	case TaskCommandDeterministicFailure:
		if current.State != contracts.TaskDeterministicAudit || !validDigest(command.AuditEvidenceSHA256) {
			return TaskEvent{}, transitionTask(command, current.State)
		}
		if current.Attempt == 3 {
			next.State = contracts.TaskBlockedUserDecision
			next.FrozenDependentIDs = append([]string(nil), current.DependentTaskIDs...)
			eventType = "io.aor.module.blocked-user-decision.v1"
		} else {
			next.State = contracts.TaskReworkRequired
			eventType = "io.aor.module.deterministic-audit-failed.v1"
		}
	case TaskCommandLLMSuccess:
		if current.State != contracts.TaskLLMAudit || !command.FreshAuditor || !command.BlindAuditContext || !command.NoBlockingFindings || !validDigest(command.AuditEvidenceSHA256) {
			return TaskEvent{}, transitionTask(command, current.State)
		}
		next.State = contracts.TaskPassed
		eventType = "io.aor.module.llm-audit-passed.v1"
	case TaskCommandLLMFailure:
		if current.State != contracts.TaskLLMAudit || !command.FreshAuditor || !command.BlindAuditContext || !validDigest(command.AuditEvidenceSHA256) {
			return TaskEvent{}, transitionTask(command, current.State)
		}
		if current.Attempt == 3 {
			next.State = contracts.TaskBlockedUserDecision
			next.FrozenDependentIDs = append([]string(nil), current.DependentTaskIDs...)
			eventType = "io.aor.module.blocked-user-decision.v1"
		} else {
			next.State = contracts.TaskReworkRequired
			eventType = "io.aor.module.llm-audit-failed.v1"
		}
	case TaskCommandQueueRework:
		if current.State == contracts.TaskBlockedUserDecision || current.Attempt >= 3 {
			return TaskEvent{}, aorerrors.New(aorerrors.CodeAttemptLimitReached, "", nil)
		}
		if current.State != contracts.TaskReworkRequired {
			return TaskEvent{}, transitionTask(command, current.State)
		}
		next.State = contracts.TaskReadyExecution
		eventType = "io.aor.module.rework-queued.v1"
	case TaskCommandIntegrate:
		if current.State != contracts.TaskPassed || !command.DependenciesSatisfied || !command.MergeGatePassed || !validDigest(command.AuditEvidenceSHA256) {
			return TaskEvent{}, transitionTask(command, current.State)
		}
		next.State = contracts.TaskIntegrated
		eventType = "io.aor.module.integrated.v1"
	case TaskCommandBlockDependency:
		if command.BlockingTaskID == "" || command.BlockingTaskID == current.ID || containsString(current.BlockingTaskIDs, command.BlockingTaskID) || current.State == contracts.TaskIntegrated || current.State == contracts.TaskCanceled || current.State == contracts.TaskSuperseded || current.State == contracts.TaskBlockedUserDecision {
			return TaskEvent{}, transitionTask(command, current.State)
		}
		if current.State != contracts.TaskBlockedDependency {
			next.BlockedFromState = current.State
		}
		next.BlockingTaskIDs = append(next.BlockingTaskIDs, command.BlockingTaskID)
		next.State = contracts.TaskBlockedDependency
		eventType = "io.aor.module.blocked-dependency.v1"
	case TaskCommandUnblockDependency:
		if current.State != contracts.TaskBlockedDependency || command.BlockingTaskID == "" || !containsString(current.BlockingTaskIDs, command.BlockingTaskID) {
			return TaskEvent{}, transitionTask(command, current.State)
		}
		next.BlockingTaskIDs = removeString(next.BlockingTaskIDs, command.BlockingTaskID)
		if len(next.BlockingTaskIDs) == 0 {
			next.State = current.BlockedFromState
			next.BlockedFromState = ""
		}
		eventType = "io.aor.module.unblocked-dependency.v1"
	case TaskCommandAuthorizeNewSeries:
		if current.State != contracts.TaskBlockedUserDecision || command.Decision != contracts.DecisionAuthorizeNewAttemptSeries || command.ActorID == "" || command.Approval == nil || command.NewAttemptSeriesID == "" || containsString(current.AttemptSeriesIDs, command.NewAttemptSeriesID) {
			if command.Approval == nil {
				return TaskEvent{}, aorerrors.New(aorerrors.CodeApprovalRequired, "", nil)
			}
			return TaskEvent{}, transitionTask(command, current.State)
		}
		if command.ModuleSpecRef.Validate() != nil {
			return TaskEvent{}, invalidTask(command, "new ModuleSpec reference")
		}
		if !command.Approval.validAt(command.At, command.ActorID, "AUTHORIZE_NEW_ATTEMPT_SERIES", "MODULE_TASK", current.ID, current.ModuleSpecRef.Version, current.ModuleSpecRef.SHA256) {
			return TaskEvent{}, aorerrors.New(aorerrors.CodeApprovalRequired, "", nil)
		}
		next.AttemptSeriesID = command.NewAttemptSeriesID
		next.AttemptSeriesIDs = append(next.AttemptSeriesIDs, command.NewAttemptSeriesID)
		next.ModuleSpecRef = command.ModuleSpecRef
		next.Attempt = 0
		next.State = contracts.TaskReadyExecution
		next.FrozenDependentIDs = nil
		eventType = "io.aor.module.attempt-series-authorized.v1"
	case TaskCommandSupersede:
		if current.State == contracts.TaskIntegrated || current.State == contracts.TaskCanceled || current.State == contracts.TaskSuperseded {
			return TaskEvent{}, transitionTask(command, current.State)
		}
		next.State = contracts.TaskSuperseded
		eventType = "io.aor.module.superseded.v1"
	default:
		return TaskEvent{}, invalidTask(command, "unknown command")
	}
	next.Version = current.Version + 1
	return TaskEvent{Type: eventType, AggregateVersion: next.Version, OccurredAt: command.At.UTC(), Projection: next}, nil
}

func ApplyTask(current ModuleTask, event TaskEvent) (ModuleTask, error) {
	if event.AggregateVersion != current.Version+1 || event.Projection.Version != event.AggregateVersion || event.Projection.ID == "" || event.OccurredAt.IsZero() {
		return ModuleTask{}, fmt.Errorf("task event version or projection is invalid")
	}
	return cloneTask(event.Projection), nil
}

func cloneTask(task ModuleTask) ModuleTask {
	next := task
	next.AttemptSeriesIDs = append([]string(nil), task.AttemptSeriesIDs...)
	next.DependentTaskIDs = append([]string(nil), task.DependentTaskIDs...)
	next.FrozenDependentIDs = append([]string(nil), task.FrozenDependentIDs...)
	next.BlockingTaskIDs = append([]string(nil), task.BlockingTaskIDs...)
	return next
}

func invalidDependents(taskID string, values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if value == "" || value == taskID || seen[value] {
			return true
		}
		seen[value] = true
	}
	return false
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func removeString(values []string, removed string) []string {
	result := make([]string, 0, len(values)-1)
	for _, value := range values {
		if value != removed {
			result = append(result, value)
		}
	}
	return result
}

func invalidTask(command TaskCommand, reason string) *aorerrors.Error {
	return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": string(command.Type) + ": " + reason})
}

func transitionTask(command TaskCommand, current contracts.ModuleTaskState) *aorerrors.Error {
	return aorerrors.New(aorerrors.CodeInvalidStateTransition, "", map[string]any{"scope": string(command.Type), "actualVersion": current})
}
