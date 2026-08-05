package workflow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	temporalclient "go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	temporalworkflow "go.temporal.io/sdk/workflow"
)

const (
	ProjectLifecycleWorkflowName = "aor.project.lifecycle.v1"
	ProjectLifecycleSignalName   = "aor.project.lifecycle.event.v1"
	ProjectLifecycleQueryName    = "aor.project.lifecycle.snapshot.v1"
	lifecycleHistoryLimit        = 500
	lifecycleBufferLimit         = 1024
)

var ErrInvalidProjectLifecycle = errors.New("invalid project lifecycle input")

type ProjectLifecycleRequest struct {
	TenantID       string `json:"tenantId"`
	ProjectID      string `json:"projectId"`
	CreatedBy      string `json:"createdBy"`
	GoalAgentCount int    `json:"goalAgentCount"`
}

type ProjectLifecycleInput struct {
	TenantID        string                 `json:"tenantId"`
	ProjectID       string                 `json:"projectId"`
	CreatedBy       string                 `json:"createdBy"`
	GoalAgentCount  int                    `json:"goalAgentCount"`
	State           contracts.ProjectState `json:"state"`
	ProjectVersion  int64                  `json:"projectVersion"`
	PausedFrom      contracts.ProjectState `json:"pausedFrom,omitempty"`
	ProcessedEvents int64                  `json:"processedEvents"`
	RejectedSignals int64                  `json:"rejectedSignals"`
}

type ProjectLifecycleEvent struct {
	EventID          string                 `json:"eventId"`
	Type             string                 `json:"type"`
	AggregateVersion int64                  `json:"aggregateVersion"`
	State            contracts.ProjectState `json:"state"`
	PayloadSHA256    string                 `json:"payloadSha256"`
	OccurredAt       time.Time              `json:"occurredAt"`
}

type ProjectLifecycleSnapshot struct {
	TenantID        string                 `json:"tenantId"`
	ProjectID       string                 `json:"projectId"`
	State           contracts.ProjectState `json:"state"`
	ProjectVersion  int64                  `json:"projectVersion"`
	PausedFrom      contracts.ProjectState `json:"pausedFrom,omitempty"`
	ProcessedEvents int64                  `json:"processedEvents"`
	RejectedSignals int64                  `json:"rejectedSignals"`
	BufferedEvents  int                    `json:"bufferedEvents"`
}

type ProjectLifecycleStartResult struct {
	WorkflowID string `json:"workflowId"`
	RunID      string `json:"runId,omitempty"`
	Duplicate  bool   `json:"duplicate,omitempty"`
}

type projectLifecycleClient interface {
	ExecuteWorkflow(context.Context, temporalclient.StartWorkflowOptions, interface{}, ...interface{}) (temporalclient.WorkflowRun, error)
}

type ProjectLifecycleStarter struct {
	client    projectLifecycleClient
	taskQueue string
}

func NewProjectLifecycleStarter(client projectLifecycleClient, taskQueue string) (*ProjectLifecycleStarter, error) {
	if client == nil || !identifierPattern.MatchString(taskQueue) {
		return nil, ErrInvalidProjectLifecycle
	}
	return &ProjectLifecycleStarter{client: client, taskQueue: taskQueue}, nil
}

func (starter *ProjectLifecycleStarter) Start(ctx context.Context, request ProjectLifecycleRequest) (ProjectLifecycleStartResult, error) {
	if starter == nil || starter.client == nil || ctx == nil || !validProjectLifecycleRequest(request) {
		return ProjectLifecycleStartResult{}, ErrInvalidProjectLifecycle
	}
	input := ProjectLifecycleInput{
		TenantID: request.TenantID, ProjectID: request.ProjectID, CreatedBy: request.CreatedBy,
		GoalAgentCount: request.GoalAgentCount, State: contracts.ProjectCreated, ProjectVersion: 1,
	}
	return starter.Ensure(ctx, input)
}

// Ensure starts a lifecycle at a durable projection checkpoint. Starting from
// a later checkpoint allows deployments to adopt projects that predate the
// lifecycle worker without requiring synthetic historical transitions.
func (starter *ProjectLifecycleStarter) Ensure(ctx context.Context, input ProjectLifecycleInput) (ProjectLifecycleStartResult, error) {
	if starter == nil || starter.client == nil || ctx == nil {
		return ProjectLifecycleStartResult{}, ErrInvalidProjectLifecycle
	}
	if err := validateProjectLifecycleInput(input); err != nil {
		return ProjectLifecycleStartResult{}, err
	}
	workflowID := projectLifecycleWorkflowID(input.TenantID, input.ProjectID)
	run, err := starter.client.ExecuteWorkflow(ctx, temporalclient.StartWorkflowOptions{
		ID: workflowID, TaskQueue: starter.taskQueue,
		WorkflowIDReusePolicy:                    enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
		WorkflowExecutionErrorWhenAlreadyStarted: true,
	}, ProjectLifecycleWorkflowName, input)
	if err != nil {
		var alreadyStarted *serviceerror.WorkflowExecutionAlreadyStarted
		if errors.As(err, &alreadyStarted) {
			return ProjectLifecycleStartResult{WorkflowID: workflowID, RunID: alreadyStarted.RunId, Duplicate: true}, nil
		}
		return ProjectLifecycleStartResult{}, fmt.Errorf("start project lifecycle workflow: %w", err)
	}
	result := ProjectLifecycleStartResult{WorkflowID: workflowID}
	if run != nil {
		result.RunID = run.GetRunID()
	}
	return result, nil
}

func ProjectLifecycleWorkflow(ctx temporalworkflow.Context, input ProjectLifecycleInput) (ProjectLifecycleSnapshot, error) {
	if err := validateProjectLifecycleInput(input); err != nil {
		return ProjectLifecycleSnapshot{}, temporal.NewNonRetryableApplicationError(err.Error(), "AORInvalidArgument", nil)
	}
	snapshot := ProjectLifecycleSnapshot{
		TenantID: input.TenantID, ProjectID: input.ProjectID, State: input.State,
		ProjectVersion: input.ProjectVersion, PausedFrom: input.PausedFrom,
		ProcessedEvents: input.ProcessedEvents, RejectedSignals: input.RejectedSignals,
	}
	buffer := make(map[int64]ProjectLifecycleEvent)
	seen := make(map[int64]string)
	if err := temporalworkflow.SetQueryHandler(ctx, ProjectLifecycleQueryName, func() (ProjectLifecycleSnapshot, error) {
		current := snapshot
		current.BufferedEvents = len(buffer)
		return current, nil
	}); err != nil {
		return ProjectLifecycleSnapshot{}, temporal.NewNonRetryableApplicationError(err.Error(), "AORWorkflowQuery", nil)
	}
	signals := temporalworkflow.GetSignalChannel(ctx, ProjectLifecycleSignalName)
	appliedThisRun := 0
	for {
		var event ProjectLifecycleEvent
		signals.Receive(ctx, &event)
		if err := validateProjectLifecycleEvent(event, snapshot); err != nil {
			snapshot.RejectedSignals++
			continue
		}
		if event.AggregateVersion <= snapshot.ProjectVersion {
			if digest, found := seen[event.AggregateVersion]; !found || digest != event.PayloadSHA256 {
				snapshot.RejectedSignals++
			}
			continue
		}
		if prior, found := buffer[event.AggregateVersion]; found {
			if prior.PayloadSHA256 != event.PayloadSHA256 || prior.Type != event.Type || prior.State != event.State {
				snapshot.RejectedSignals++
			}
			continue
		}
		if len(buffer) >= lifecycleBufferLimit {
			snapshot.RejectedSignals++
			continue
		}
		buffer[event.AggregateVersion] = event
		for {
			nextVersion := snapshot.ProjectVersion + 1
			next, found := buffer[nextVersion]
			if !found {
				break
			}
			delete(buffer, nextVersion)
			if err := applyProjectLifecycleEvent(&snapshot, next); err != nil {
				snapshot.RejectedSignals++
				break
			}
			seen[next.AggregateVersion] = next.PayloadSHA256
			snapshot.ProcessedEvents++
			appliedThisRun++
			if snapshot.State == contracts.ProjectArchived {
				snapshot.BufferedEvents = len(buffer)
				return snapshot, nil
			}
			if appliedThisRun >= lifecycleHistoryLimit && len(buffer) == 0 {
				continuation := ProjectLifecycleInput{
					TenantID: snapshot.TenantID, ProjectID: snapshot.ProjectID, CreatedBy: input.CreatedBy,
					GoalAgentCount: input.GoalAgentCount, State: snapshot.State, ProjectVersion: snapshot.ProjectVersion,
					PausedFrom: snapshot.PausedFrom, ProcessedEvents: snapshot.ProcessedEvents, RejectedSignals: snapshot.RejectedSignals,
				}
				return ProjectLifecycleSnapshot{}, temporalworkflow.NewContinueAsNewError(ctx, ProjectLifecycleWorkflowName, continuation)
			}
		}
	}
}

func applyProjectLifecycleEvent(snapshot *ProjectLifecycleSnapshot, event ProjectLifecycleEvent) error {
	current := snapshot.State
	expected := contracts.ProjectState("")
	switch event.Type {
	case "io.aor.goal.negotiation-started.v1", "io.aor.goal.message-received.v1":
		if current == contracts.ProjectCreated || current == contracts.ProjectGoalNegotiating {
			expected = contracts.ProjectGoalNegotiating
		}
	case "io.aor.goal.proposed.v1", "io.aor.goal.rejected.v1":
		if current == contracts.ProjectGoalNegotiating {
			expected = contracts.ProjectGoalNegotiating
		}
	case "io.aor.goal.approved.v1":
		if current == contracts.ProjectGoalNegotiating {
			expected = contracts.ProjectPlanning
		}
	case "io.aor.goal.change-requested.v1", "io.aor.goal.superseded.v1":
		if !terminalLifecycleState(current) && current != contracts.ProjectCreated {
			expected = contracts.ProjectGoalNegotiating
		}
	case "io.aor.plan.published.v1":
		if current == contracts.ProjectPlanning {
			expected = contracts.ProjectExecuting
		}
	case "io.aor.project.integration-started.v1":
		if current == contracts.ProjectExecuting {
			expected = contracts.ProjectIntegrating
		}
	case "io.aor.project.global-audit-started.v1":
		if current == contracts.ProjectIntegrating {
			expected = contracts.ProjectGlobalAudit
		}
	case "io.aor.project.global-audit-remediation-started.v1":
		if current == contracts.ProjectGlobalAudit && (event.State == contracts.ProjectExecuting || event.State == contracts.ProjectIntegrating) {
			expected = event.State
		}
	case "io.aor.approval.committed.v1":
		if current == contracts.ProjectGlobalAudit {
			expected = contracts.ProjectGlobalAudit
		}
	case "io.aor.project.completed.v1":
		if current == contracts.ProjectGlobalAudit {
			expected = contracts.ProjectCompleted
		}
	case "io.aor.project.paused.v1":
		if !terminalLifecycleState(current) && current != contracts.ProjectPaused && current != contracts.ProjectGoalSuspended {
			snapshot.PausedFrom = current
			if current == contracts.ProjectGoalNegotiating {
				expected = contracts.ProjectGoalSuspended
			} else {
				expected = contracts.ProjectPaused
			}
		}
	case "io.aor.project.resumed.v1":
		if current == contracts.ProjectPaused || current == contracts.ProjectGoalSuspended {
			expected = snapshot.PausedFrom
			if expected == "" {
				expected = event.State
			}
			snapshot.PausedFrom = ""
		}
	case "io.aor.project.aborted.v1":
		if !terminalLifecycleState(current) {
			expected = contracts.ProjectAborted
		}
	case "io.aor.project.archived.v1":
		if current == contracts.ProjectCompleted || current == contracts.ProjectAborted {
			expected = contracts.ProjectArchived
		}
	}
	if expected == "" || event.State != expected {
		return ErrInvalidProjectLifecycle
	}
	snapshot.State = expected
	snapshot.ProjectVersion = event.AggregateVersion
	return nil
}

func validateProjectLifecycleEvent(event ProjectLifecycleEvent, snapshot ProjectLifecycleSnapshot) error {
	if !identifierPattern.MatchString(event.EventID) || event.AggregateVersion < 1 || event.AggregateVersion > snapshot.ProjectVersion+lifecycleBufferLimit || !validLifecycleState(event.State) || !validLifecycleDigest(event.PayloadSHA256) || event.OccurredAt.IsZero() {
		return ErrInvalidProjectLifecycle
	}
	return nil
}

func validateProjectLifecycleInput(input ProjectLifecycleInput) error {
	request := ProjectLifecycleRequest{TenantID: input.TenantID, ProjectID: input.ProjectID, CreatedBy: input.CreatedBy, GoalAgentCount: input.GoalAgentCount}
	if !validProjectLifecycleRequest(request) || input.ProjectVersion < 1 || input.ProcessedEvents < 0 || input.RejectedSignals < 0 || !validLifecycleState(input.State) || input.PausedFrom != "" && !validLifecycleState(input.PausedFrom) {
		return ErrInvalidProjectLifecycle
	}
	return nil
}

func validProjectLifecycleRequest(request ProjectLifecycleRequest) bool {
	return identifierPattern.MatchString(request.TenantID) && identifierPattern.MatchString(request.ProjectID) &&
		identifierPattern.MatchString(request.CreatedBy) && (request.GoalAgentCount == 1 || request.GoalAgentCount == 2)
}

func validLifecycleState(value contracts.ProjectState) bool {
	switch value {
	case contracts.ProjectCreated, contracts.ProjectGoalNegotiating, contracts.ProjectGoalSuspended,
		contracts.ProjectPlanning, contracts.ProjectExecuting, contracts.ProjectIntegrating,
		contracts.ProjectGlobalAudit, contracts.ProjectBlockedUserDecision, contracts.ProjectPaused,
		contracts.ProjectCompleted, contracts.ProjectAborted, contracts.ProjectFailedSystem, contracts.ProjectArchived:
		return true
	default:
		return false
	}
}

func terminalLifecycleState(value contracts.ProjectState) bool {
	return value == contracts.ProjectCompleted || value == contracts.ProjectAborted || value == contracts.ProjectFailedSystem || value == contracts.ProjectArchived
}

func validLifecycleDigest(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for _, character := range value[7:] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func projectLifecycleWorkflowID(tenantID, projectID string) string {
	return "aor-project-" + tenantID + "-" + projectID
}
