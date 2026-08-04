package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
	"go.temporal.io/api/serviceerror"
	temporalclient "go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
	temporalworkflow "go.temporal.io/sdk/workflow"
)

func TestProjectLifecycleWorkflowBuffersEventsAndEnforcesApprovalGate(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	environment := suite.NewTestWorkflowEnvironment()
	environment.RegisterWorkflowWithOptions(ProjectLifecycleWorkflow, temporalworkflow.RegisterOptions{Name: ProjectLifecycleWorkflowName})
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	input := lifecycleTestInput()

	environment.RegisterDelayedCallback(func() {
		// A plan cannot advance directly from CREATED. A later valid version 2
		// event replaces the rejected signal and releases buffered version 3.
		environment.SignalWorkflow(ProjectLifecycleSignalName, lifecycleEvent(2, "io.aor.plan.published.v1", contracts.ProjectExecuting, now))
		environment.SignalWorkflow(ProjectLifecycleSignalName, lifecycleEvent(3, "io.aor.goal.approved.v1", contracts.ProjectPlanning, now.Add(time.Second)))
		environment.SignalWorkflow(ProjectLifecycleSignalName, lifecycleEvent(2, "io.aor.goal.negotiation-started.v1", contracts.ProjectGoalNegotiating, now.Add(2*time.Second)))
		environment.SignalWorkflow(ProjectLifecycleSignalName, lifecycleEvent(4, "io.aor.plan.published.v1", contracts.ProjectExecuting, now.Add(3*time.Second)))
		environment.SignalWorkflow(ProjectLifecycleSignalName, lifecycleEvent(5, "io.aor.project.integration-started.v1", contracts.ProjectIntegrating, now.Add(4*time.Second)))
		environment.SignalWorkflow(ProjectLifecycleSignalName, lifecycleEvent(6, "io.aor.project.global-audit-started.v1", contracts.ProjectGlobalAudit, now.Add(5*time.Second)))
		environment.SignalWorkflow(ProjectLifecycleSignalName, lifecycleEvent(7, "io.aor.approval.committed.v1", contracts.ProjectGlobalAudit, now.Add(6*time.Second)))
		environment.SignalWorkflow(ProjectLifecycleSignalName, lifecycleEvent(8, "io.aor.project.completed.v1", contracts.ProjectCompleted, now.Add(7*time.Second)))
		environment.SignalWorkflow(ProjectLifecycleSignalName, lifecycleEvent(9, "io.aor.project.archived.v1", contracts.ProjectArchived, now.Add(8*time.Second)))
	}, time.Millisecond)

	environment.ExecuteWorkflow(ProjectLifecycleWorkflowName, input)
	if err := environment.GetWorkflowError(); err != nil {
		t.Fatal(err)
	}
	var snapshot ProjectLifecycleSnapshot
	if err := environment.GetWorkflowResult(&snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.State != contracts.ProjectArchived || snapshot.ProjectVersion != 9 || snapshot.ProcessedEvents != 8 || snapshot.RejectedSignals != 1 || snapshot.BufferedEvents != 0 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestProjectLifecycleWorkflowRestoresPausedStage(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	environment := suite.NewTestWorkflowEnvironment()
	environment.RegisterWorkflowWithOptions(ProjectLifecycleWorkflow, temporalworkflow.RegisterOptions{Name: ProjectLifecycleWorkflowName})
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	environment.RegisterDelayedCallback(func() {
		environment.SignalWorkflow(ProjectLifecycleSignalName, lifecycleEvent(2, "io.aor.goal.negotiation-started.v1", contracts.ProjectGoalNegotiating, now))
		environment.SignalWorkflow(ProjectLifecycleSignalName, lifecycleEvent(3, "io.aor.project.paused.v1", contracts.ProjectGoalSuspended, now.Add(time.Second)))
		environment.SignalWorkflow(ProjectLifecycleSignalName, lifecycleEvent(4, "io.aor.project.resumed.v1", contracts.ProjectGoalNegotiating, now.Add(2*time.Second)))
		environment.SignalWorkflow(ProjectLifecycleSignalName, lifecycleEvent(5, "io.aor.project.aborted.v1", contracts.ProjectAborted, now.Add(3*time.Second)))
		environment.SignalWorkflow(ProjectLifecycleSignalName, lifecycleEvent(6, "io.aor.project.archived.v1", contracts.ProjectArchived, now.Add(4*time.Second)))
	}, time.Millisecond)
	environment.ExecuteWorkflow(ProjectLifecycleWorkflowName, lifecycleTestInput())
	if err := environment.GetWorkflowError(); err != nil {
		t.Fatal(err)
	}
	var snapshot ProjectLifecycleSnapshot
	if err := environment.GetWorkflowResult(&snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.State != contracts.ProjectArchived || snapshot.PausedFrom != "" || snapshot.RejectedSignals != 0 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestProjectLifecycleStarterUsesStableIDAndTreatsAlreadyStartedAsDuplicate(t *testing.T) {
	client := &lifecycleStartClient{err: serviceerror.NewWorkflowExecutionAlreadyStarted("exists", "request", "run-1")}
	starter, err := NewProjectLifecycleStarter(client, "aor-control-plane")
	if err != nil {
		t.Fatal(err)
	}
	request := ProjectLifecycleRequest{TenantID: "tenant-1", ProjectID: "project-1", CreatedBy: "user-1", GoalAgentCount: 2}
	first, err := starter.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := starter.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Duplicate || first.RunID != "run-1" || first.WorkflowID != second.WorkflowID || client.options.ID != first.WorkflowID || client.options.TaskQueue != "aor-control-plane" || client.workflow != ProjectLifecycleWorkflowName {
		t.Fatalf("first = %#v second = %#v options = %#v", first, second, client.options)
	}
}

func TestProjectLifecycleWorkflowRejectsInvalidInput(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	environment := suite.NewTestWorkflowEnvironment()
	environment.RegisterWorkflowWithOptions(ProjectLifecycleWorkflow, temporalworkflow.RegisterOptions{Name: ProjectLifecycleWorkflowName})
	input := lifecycleTestInput()
	input.GoalAgentCount = 3
	environment.ExecuteWorkflow(ProjectLifecycleWorkflowName, input)
	if err := environment.GetWorkflowError(); err == nil {
		t.Fatal("invalid lifecycle input was accepted")
	}
}

type lifecycleStartClient struct {
	options  temporalclient.StartWorkflowOptions
	workflow interface{}
	err      error
}

func (client *lifecycleStartClient) ExecuteWorkflow(_ context.Context, options temporalclient.StartWorkflowOptions, workflow interface{}, _ ...interface{}) (temporalclient.WorkflowRun, error) {
	client.options = options
	client.workflow = workflow
	return nil, client.err
}

func lifecycleTestInput() ProjectLifecycleInput {
	return ProjectLifecycleInput{TenantID: "tenant-1", ProjectID: "project-1", CreatedBy: "user-1", GoalAgentCount: 2, State: contracts.ProjectCreated, ProjectVersion: 1}
}

func lifecycleEvent(version int64, eventType string, projectState contracts.ProjectState, occurredAt time.Time) ProjectLifecycleEvent {
	return ProjectLifecycleEvent{
		EventID: "event-" + string(rune('a'+version)), Type: eventType, AggregateVersion: version,
		State: projectState, PayloadSHA256: "sha256:" + repeatHex(byte(version)), OccurredAt: occurredAt,
	}
}

func repeatHex(value byte) string {
	digits := "0123456789abcdef"
	result := make([]byte, 64)
	for index := range result {
		result[index] = digits[int(value)%len(digits)]
	}
	return string(result)
}

var _ projectLifecycleClient = (*lifecycleStartClient)(nil)
