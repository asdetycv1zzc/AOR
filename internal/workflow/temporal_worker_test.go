package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	temporalworkflow "go.temporal.io/sdk/workflow"
)

type temporalEffect struct{}

func (temporalEffect) Execute(_ context.Context, key string, payload json.RawMessage) (json.RawMessage, error) {
	return json.Marshal(struct {
		Key     string          `json:"key"`
		Payload json.RawMessage `json:"payload"`
	}{Key: key, Payload: payload})
}

func TestProjectExecutionWorkflowUsesNamedRetryableActivity(t *testing.T) {
	activities, err := NewActivities(temporalEffect{})
	if err != nil {
		t.Fatal(err)
	}
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterWorkflowWithOptions(ProjectExecutionWorkflow, temporalworkflow.RegisterOptions{Name: ProjectExecutionWorkflowName})
	env.RegisterActivityWithOptions(activities.Execute, activity.RegisterOptions{Name: ExecuteActivityName})
	input := ExecutionInput{TenantID: "tenant_1", ProjectID: "project_1", TaskID: "task_1", ActivityID: "activity_1", Payload: json.RawMessage(`{"value":1}`)}
	env.ExecuteWorkflow(ProjectExecutionWorkflowName, input)
	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("workflow error = %v", env.GetWorkflowError())
	}
	var output ExecutionOutput
	if err := env.GetWorkflowResult(&output); err != nil {
		t.Fatal(err)
	}
	if output.IdempotencyKey == "" || len(output.Output) == 0 {
		t.Fatalf("workflow output = %#v", output)
	}
}

func TestProjectExecutionWorkflowRejectsInvalidInputAsNonRetryable(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterWorkflowWithOptions(ProjectExecutionWorkflow, temporalworkflow.RegisterOptions{Name: ProjectExecutionWorkflowName})
	env.ExecuteWorkflow(ProjectExecutionWorkflowName, ExecutionInput{TenantID: "", ProjectID: "project_1", TaskID: "task_1", ActivityID: "activity_1", Payload: json.RawMessage(`{}`)})
	err := env.GetWorkflowError()
	if err == nil {
		t.Fatal("invalid workflow input unexpectedly succeeded")
	}
	var appErr *temporal.ApplicationError
	if !errors.As(err, &appErr) || appErr.Type() != "AORInvalidArgument" {
		t.Fatalf("workflow error = %v", err)
	}
}
