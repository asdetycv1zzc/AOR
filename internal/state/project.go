package state

import (
	"fmt"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type Project struct {
	TenantID                string                 `json:"tenantId"`
	ID                      string                 `json:"id"`
	Name                    string                 `json:"name"`
	CreatedBy               string                 `json:"createdBy"`
	DataClassification      string                 `json:"dataClassification"`
	RiskTolerance           string                 `json:"riskTolerance"`
	State                   contracts.ProjectState `json:"state"`
	Version                 int64                  `json:"version"`
	GoalAgentCount          int                    `json:"goalAgentCount"`
	Goal                    *GoalRecord            `json:"goal,omitempty"`
	Plan                    *contracts.SpecRef     `json:"plan,omitempty"`
	ReleaseApprovalRecordID string                 `json:"releaseApprovalRecordId,omitempty"`
	PausedFromState         contracts.ProjectState `json:"pausedFromState,omitempty"`
}

type GoalRecord struct {
	ID               string   `json:"id"`
	Version          int      `json:"version"`
	SHA256           string   `json:"sha256"`
	UnresolvedItems  []string `json:"unresolvedItems"`
	ApprovedBy       string   `json:"approvedBy,omitempty"`
	ApprovalRecordID string   `json:"approvalRecordId,omitempty"`
}

type CompletionFacts struct {
	AllTasksIntegrated     bool   `json:"allTasksIntegrated"`
	GoalCriteriaSatisfied  bool   `json:"goalCriteriaSatisfied"`
	GlobalAuditPassed      bool   `json:"globalAuditPassed"`
	ReleaseArtifactsSigned bool   `json:"releaseArtifactsSigned"`
	NoBlockingFindings     bool   `json:"noBlockingFindings"`
	EvidenceSHA256         string `json:"evidenceSha256"`
}

type ProjectGuardFacts struct {
	AllTasksPassed         bool   `json:"allTasksPassed"`
	AllTasksIntegrated     bool   `json:"allTasksIntegrated"`
	IntegrationAuditPassed bool   `json:"integrationAuditPassed"`
	EvidenceSHA256         string `json:"evidenceSha256"`
}

type ProjectCommandType string

const (
	ProjectCommandCreate               ProjectCommandType = "CREATE_PROJECT"
	ProjectCommandStartGoalNegotiation ProjectCommandType = "START_GOAL_NEGOTIATION"
	ProjectCommandProposeGoal          ProjectCommandType = "PROPOSE_GOAL"
	ProjectCommandApproveGoal          ProjectCommandType = "APPROVE_GOAL"
	ProjectCommandSupersedeGoal        ProjectCommandType = "SUPERSEDE_GOAL"
	ProjectCommandPublishPlan          ProjectCommandType = "PUBLISH_PLAN"
	ProjectCommandBeginIntegration     ProjectCommandType = "BEGIN_INTEGRATION"
	ProjectCommandBeginGlobalAudit     ProjectCommandType = "BEGIN_GLOBAL_AUDIT"
	ProjectCommandApproveRelease       ProjectCommandType = "APPROVE_RELEASE"
	ProjectCommandComplete             ProjectCommandType = "COMPLETE_PROJECT"
	ProjectCommandPause                ProjectCommandType = "PAUSE_PROJECT"
	ProjectCommandResume               ProjectCommandType = "RESUME_PROJECT"
	ProjectCommandAbort                ProjectCommandType = "ABORT_PROJECT"
)

type ProjectCommand struct {
	Type               ProjectCommandType
	TenantID           string
	ProjectID          string
	ActorID            string
	GoalAgentCount     int
	Goal               *GoalRecord
	Plan               *contracts.SpecRef
	GoalSpecRef        *contracts.SpecRef
	DAG                map[string][]string
	Approval           *ApprovalBinding
	Completion         *CompletionFacts
	Guard              *ProjectGuardFacts
	ImpactedTaskIDs    []string
	Name               string
	DataClassification string
	RiskTolerance      string
	At                 time.Time
}

type ProjectEvent struct {
	Type             string    `json:"type"`
	AggregateVersion int64     `json:"aggregateVersion"`
	OccurredAt       time.Time `json:"occurredAt"`
	Projection       Project   `json:"projection"`
}

func DecideProject(current Project, command ProjectCommand) (ProjectEvent, *aorerrors.Error) {
	if command.At.IsZero() || command.ActorID == "" {
		return ProjectEvent{}, invalidProject(command, "actor and trusted time are required")
	}
	next := cloneProject(current)
	eventType := ""
	switch command.Type {
	case ProjectCommandCreate:
		if current.Version != 0 || current.ID != "" || command.TenantID == "" || command.ProjectID == "" || command.GoalAgentCount < 1 || command.GoalAgentCount > 2 {
			return ProjectEvent{}, invalidProject(command, "project creation guard")
		}
		name := command.Name
		if name == "" {
			name = command.ProjectID
		}
		dataClassification := command.DataClassification
		if dataClassification == "" {
			dataClassification = "INTERNAL"
		}
		riskTolerance := command.RiskTolerance
		if riskTolerance == "" {
			riskTolerance = "MEDIUM"
		}
		next = Project{TenantID: command.TenantID, ID: command.ProjectID, Name: name, CreatedBy: command.ActorID, DataClassification: dataClassification, RiskTolerance: riskTolerance, State: contracts.ProjectCreated, GoalAgentCount: command.GoalAgentCount}
		eventType = "io.aor.project.created.v1"
	case ProjectCommandStartGoalNegotiation:
		if current.State != contracts.ProjectCreated {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.State = contracts.ProjectGoalNegotiating
		eventType = "io.aor.goal.negotiation-started.v1"
	case ProjectCommandProposeGoal:
		if current.State != contracts.ProjectGoalNegotiating || command.Goal == nil || command.Goal.ID == "" || command.Goal.Version < 1 || command.Goal.SHA256 == "" {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		if current.Goal != nil && command.Goal.Version <= current.Goal.Version {
			return ProjectEvent{}, aorerrors.New(aorerrors.CodeSpecSuperseded, "", nil)
		}
		goal := *command.Goal
		goal.UnresolvedItems = append([]string(nil), command.Goal.UnresolvedItems...)
		next.Goal = &goal
		eventType = "io.aor.goal.proposed.v1"
	case ProjectCommandApproveGoal:
		if current.State != contracts.ProjectGoalNegotiating || current.Goal == nil || command.Goal == nil || command.Approval == nil {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		if current.Goal.ID != command.Goal.ID || current.Goal.Version != command.Goal.Version || current.Goal.SHA256 != command.Goal.SHA256 {
			return ProjectEvent{}, aorerrors.New(aorerrors.CodeGoalHashMismatch, "", nil)
		}
		if len(current.Goal.UnresolvedItems) != 0 || len(command.Goal.UnresolvedItems) != 0 {
			return ProjectEvent{}, aorerrors.New(aorerrors.CodeGoalNotApproved, "", nil)
		}
		if !command.Approval.validAt(command.At, command.ActorID, "GOAL_APPROVAL", "GOAL_SPEC", current.Goal.ID, current.Goal.Version, current.Goal.SHA256) {
			return ProjectEvent{}, aorerrors.New(aorerrors.CodeApprovalRequired, "", nil)
		}
		next.Goal.ApprovedBy = command.ActorID
		next.Goal.ApprovalRecordID = command.Approval.RecordID
		next.State = contracts.ProjectPlanning
		eventType = "io.aor.goal.approved.v1"
	case ProjectCommandSupersedeGoal:
		if terminalProjectState(current.State) || current.Goal == nil || current.Goal.ApprovedBy == "" || command.Goal == nil || command.Goal.Version <= current.Goal.Version || command.Goal.SHA256 == "" {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		if hasDuplicateStrings(command.ImpactedTaskIDs) {
			return ProjectEvent{}, invalidProject(command, "duplicate impacted task")
		}
		goal := *command.Goal
		goal.UnresolvedItems = append([]string(nil), command.Goal.UnresolvedItems...)
		goal.ApprovedBy = ""
		goal.ApprovalRecordID = ""
		next.Goal = &goal
		next.Plan = nil
		next.ReleaseApprovalRecordID = ""
		next.State = contracts.ProjectGoalNegotiating
		eventType = "io.aor.goal.superseded.v1"
	case ProjectCommandPublishPlan:
		if current.State != contracts.ProjectPlanning || current.Goal == nil || current.Goal.ApprovedBy == "" || command.Plan == nil || command.GoalSpecRef == nil {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		if !ValidateDAG(command.DAG) {
			return ProjectEvent{}, invalidProject(command, "plan dependency graph is not a DAG")
		}
		if command.GoalSpecRef.Version != current.Goal.Version || command.GoalSpecRef.SHA256 != current.Goal.SHA256 {
			return ProjectEvent{}, aorerrors.New(aorerrors.CodeGoalHashMismatch, "", nil)
		}
		if err := command.Plan.Validate(); err != nil {
			return ProjectEvent{}, invalidProject(command, err.Error())
		}
		plan := *command.Plan
		next.Plan = &plan
		next.State = contracts.ProjectExecuting
		eventType = "io.aor.plan.published.v1"
	case ProjectCommandBeginIntegration:
		if current.State != contracts.ProjectExecuting || command.Guard == nil || !command.Guard.AllTasksPassed || !validDigest(command.Guard.EvidenceSHA256) {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.State = contracts.ProjectIntegrating
		eventType = "io.aor.project.integration-started.v1"
	case ProjectCommandBeginGlobalAudit:
		if current.State != contracts.ProjectIntegrating || command.Guard == nil || !command.Guard.AllTasksIntegrated || !command.Guard.IntegrationAuditPassed || !validDigest(command.Guard.EvidenceSHA256) {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.State = contracts.ProjectGlobalAudit
		eventType = "io.aor.project.global-audit-started.v1"
	case ProjectCommandApproveRelease:
		if current.State != contracts.ProjectGlobalAudit || current.Plan == nil || command.Approval == nil || !command.Approval.validAt(command.At, command.ActorID, "RELEASE_APPROVAL", "PROJECT", current.ID, int(current.Version), current.Plan.SHA256) {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.ReleaseApprovalRecordID = command.Approval.RecordID
		eventType = "io.aor.approval.committed.v1"
	case ProjectCommandComplete:
		if current.State != contracts.ProjectGlobalAudit || current.ReleaseApprovalRecordID == "" || command.Completion == nil || !command.Completion.allSatisfied() {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.State = contracts.ProjectCompleted
		eventType = "io.aor.project.completed.v1"
	case ProjectCommandPause:
		if terminalProjectState(current.State) || current.State == contracts.ProjectPaused {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.PausedFromState = current.State
		if current.State == contracts.ProjectGoalNegotiating {
			next.State = contracts.ProjectGoalSuspended
		} else {
			next.State = contracts.ProjectPaused
		}
		eventType = "io.aor.project.paused.v1"
	case ProjectCommandResume:
		if current.State != contracts.ProjectPaused && current.State != contracts.ProjectGoalSuspended {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		if current.State == contracts.ProjectGoalSuspended {
			next.State = contracts.ProjectGoalNegotiating
		} else if current.PausedFromState != "" {
			next.State = current.PausedFromState
		} else if current.Goal == nil || current.Goal.ApprovedBy == "" {
			next.State = contracts.ProjectGoalNegotiating
		} else if current.Plan == nil {
			next.State = contracts.ProjectPlanning
		} else {
			next.State = contracts.ProjectExecuting
		}
		next.PausedFromState = ""
		eventType = "io.aor.project.resumed.v1"
	case ProjectCommandAbort:
		if terminalProjectState(current.State) {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.State = contracts.ProjectAborted
		eventType = "io.aor.project.aborted.v1"
	default:
		return ProjectEvent{}, invalidProject(command, "unknown command")
	}
	next.Version = current.Version + 1
	return ProjectEvent{Type: eventType, AggregateVersion: next.Version, OccurredAt: command.At.UTC(), Projection: next}, nil
}

func ValidateDAG(graph map[string][]string) bool {
	if len(graph) == 0 {
		return false
	}
	indegree := make(map[string]int, len(graph))
	reverse := make(map[string][]string, len(graph))
	for node := range graph {
		indegree[node] = 0
	}
	for node, dependencies := range graph {
		seen := make(map[string]bool, len(dependencies))
		for _, dependency := range dependencies {
			if dependency == node || seen[dependency] {
				return false
			}
			if _, exists := graph[dependency]; !exists {
				return false
			}
			seen[dependency] = true
			indegree[node]++
			reverse[dependency] = append(reverse[dependency], node)
		}
	}
	queue := make([]string, 0, len(graph))
	for node, degree := range indegree {
		if degree == 0 {
			queue = append(queue, node)
		}
	}
	visited := 0
	for len(queue) != 0 {
		node := queue[0]
		queue = queue[1:]
		visited++
		for _, dependent := range reverse[node] {
			indegree[dependent]--
			if indegree[dependent] == 0 {
				queue = append(queue, dependent)
			}
		}
	}
	return visited == len(graph)
}

func hasDuplicateStrings(values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			return true
		}
		seen[value] = true
	}
	return false
}

func ApplyProject(current Project, event ProjectEvent) (Project, error) {
	if event.AggregateVersion != current.Version+1 || event.Projection.Version != event.AggregateVersion || event.Projection.ID == "" || event.OccurredAt.IsZero() {
		return Project{}, fmt.Errorf("project event version or projection is invalid")
	}
	return cloneProject(event.Projection), nil
}

func cloneProject(project Project) Project {
	next := project
	if project.Goal != nil {
		goal := *project.Goal
		goal.UnresolvedItems = append([]string(nil), project.Goal.UnresolvedItems...)
		next.Goal = &goal
	}
	if project.Plan != nil {
		plan := *project.Plan
		next.Plan = &plan
	}
	return next
}

func (f CompletionFacts) allSatisfied() bool {
	return f.AllTasksIntegrated && f.GoalCriteriaSatisfied && f.GlobalAuditPassed && f.ReleaseArtifactsSigned && f.NoBlockingFindings && validDigest(f.EvidenceSHA256)
}

func validDigest(value string) bool {
	return contracts.SpecRef{Version: 1, SHA256: value}.Validate() == nil
}

func terminalProjectState(state contracts.ProjectState) bool {
	return state == contracts.ProjectCompleted || state == contracts.ProjectAborted || state == contracts.ProjectArchived
}

func invalidProject(command ProjectCommand, reason string) *aorerrors.Error {
	return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": string(command.Type) + ": " + reason})
}

func transitionProject(command ProjectCommand, current contracts.ProjectState) *aorerrors.Error {
	return aorerrors.New(aorerrors.CodeInvalidStateTransition, "", map[string]any{"scope": string(command.Type), "actualVersion": current})
}
