package servicebootstrap

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/commandapproval"
	"github.com/akimisaka/aor/internal/execution"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/projectactivity"
	"github.com/akimisaka/aor/internal/sandbox"
	"github.com/akimisaka/aor/internal/toolbroker"
)

type commandReviewerFunc func(context.Context, commandapproval.Request) (commandapproval.Result, error)

func (reviewer commandReviewerFunc) Review(ctx context.Context, request commandapproval.Request) (commandapproval.Result, error) {
	return reviewer(ctx, request)
}

type commandReporterRecorder struct {
	requests []commandapproval.Request
	results  []commandapproval.Result
}

func (reporter *commandReporterRecorder) Report(_ context.Context, request commandapproval.Request, result commandapproval.Result) error {
	reporter.requests = append(reporter.requests, request)
	reporter.results = append(reporter.results, result)
	return nil
}

type commandScopeStub struct {
	scope commandExecutionScope
	err   error
}

func (stub commandScopeStub) Resolve(context.Context, string) (commandExecutionScope, error) {
	return stub.scope, stub.err
}

type commandRunnerStub struct {
	calls   int
	request commandRunRequest
	result  commandRunResult
	err     error
}

func (runner *commandRunnerStub) Run(_ context.Context, request commandRunRequest) (commandRunResult, error) {
	runner.calls++
	runner.request = request
	return runner.result, runner.err
}

func commandTestScope(t *testing.T) commandExecutionScope {
	return commandExecutionScope{
		TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", AgentID: "agent-1",
		BudgetAccountID: "budget-1", DataClassification: "INTERNAL", WorkspacePath: t.TempDir(),
		AllowedPaths: []string{"internal/..."}, ForbiddenPaths: []string{".git/...", "hidden-tests/..."},
	}
}

func TestCommandMCPToolHasBoundedReviewedPolicy(t *testing.T) {
	tools := commandMCPTools()
	policies := commandMCPPolicies()
	if len(tools) != 1 || tools[0].Name != execution.RepositoryExecuteCommand || len(policies) != 1 {
		t.Fatalf("tools=%#v policies=%#v", tools, policies)
	}
	policy := policies[execution.RepositoryExecuteCommand]
	if policy.Risk != toolbroker.RiskHigh || policy.SideEffect != toolbroker.SideEffectNone || policy.NetworkAccess != toolbroker.NetworkNone || policy.FilesystemAccess != toolbroker.FilesystemRead || policy.RequiresApproval != toolbroker.ApprovalPolicy || policy.MaxOutputBytes != commandToolMaximumOutput {
		t.Fatalf("command policy=%#v", policy)
	}
	if tools[0].InputSchema["additionalProperties"] != false || tools[0].OutputSchema["additionalProperties"] != false {
		t.Fatalf("command schemas must reject unknown fields: %#v", tools[0])
	}
}

func TestCommandMCPClientReportsEscalationWithoutRunning(t *testing.T) {
	reporter := &commandReporterRecorder{}
	layer, err := commandapproval.NewLayer(commandReviewerFunc(func(context.Context, commandapproval.Request) (commandapproval.Result, error) {
		return commandapproval.Result{Decision: commandapproval.DecisionEscalate, Reason: "network access requested", RiskCodes: []string{commandapproval.RiskNetworkAccess}}, nil
	}), reporter)
	if err != nil {
		t.Fatal(err)
	}
	runner := &commandRunnerStub{}
	client, err := newCommandMCPClient(commandScopeStub{scope: commandTestScope(t)}, layer, runner)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.CallToolWithRequestID(context.Background(), execution.RepositoryExecuteCommand, map[string]any{
		"workspaceId": "workspace-1", "executable": "custom-tool", "arguments": []any{"inspect"}, "timeoutSeconds": 30,
	}, "invocation-1")
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || result.StructuredContent["status"] != "REPORTED" || runner.calls != 0 || len(reporter.results) != 1 {
		t.Fatalf("result=%#v runner calls=%d reports=%#v", result, runner.calls, reporter.results)
	}
}

func TestCommandArgumentsRejectEnvironmentAssignmentExecutable(t *testing.T) {
	if validCommandArguments(commandArguments{WorkspaceID: "workspace-1", Executable: "FOO=bar", Arguments: []string{"sh", "-c", "id"}, TimeoutSeconds: 30}) {
		t.Fatal("environment assignment must not be accepted as an executable")
	}
}

func TestCommandMCPClientRunsOnlyApprovedArgv(t *testing.T) {
	reporter := &commandReporterRecorder{}
	layer, err := commandapproval.NewLayer(commandReviewerFunc(func(_ context.Context, request commandapproval.Request) (commandapproval.Result, error) {
		if request.Executable != "go" || !reflect.DeepEqual(request.Arguments, []string{"test", "./..."}) {
			t.Fatalf("review request=%#v", request)
		}
		return commandapproval.Result{Decision: commandapproval.DecisionApprove, Reason: "repository tests"}, nil
	}), reporter)
	if err != nil {
		t.Fatal(err)
	}
	runner := &commandRunnerStub{result: commandRunResult{ExitCode: 1, Stdout: "test output", Stderr: "failed"}}
	scope := commandTestScope(t)
	client, err := newCommandMCPClient(commandScopeStub{scope: scope}, layer, runner)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.CallToolWithRequestID(context.Background(), execution.RepositoryExecuteCommand, map[string]any{
		"workspaceId": "workspace-1", "executable": "go", "arguments": []any{"test", "./..."}, "timeoutSeconds": 45,
	}, "invocation-2")
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || result.StructuredContent["status"] != "EXECUTED" || result.StructuredContent["exitCode"] != 1 || runner.calls != 1 || len(reporter.results) != 0 {
		t.Fatalf("result=%#v runner=%#v reports=%#v", result, runner, reporter.results)
	}
	if runner.request.Executable != "go" || !reflect.DeepEqual(runner.request.Arguments, []string{"test", "./..."}) || runner.request.Directory != scope.WorkspacePath || runner.request.Timeout != 45*time.Second {
		t.Fatalf("runner request=%#v", runner.request)
	}
	if runner.request.TenantID != scope.TenantID || runner.request.ProjectID != scope.ProjectID || runner.request.TaskID != scope.TaskID || runner.request.InvocationID != "invocation-2" {
		t.Fatalf("runner scope=%#v", runner.request)
	}
}

func TestCommandMCPClientReportsSandboxSecurityFailure(t *testing.T) {
	reporter := &commandReporterRecorder{}
	layer, err := commandapproval.NewLayer(commandReviewerFunc(func(context.Context, commandapproval.Request) (commandapproval.Result, error) {
		return commandapproval.Result{Decision: commandapproval.DecisionApprove, Reason: "repository tests"}, nil
	}), reporter)
	if err != nil {
		t.Fatal(err)
	}
	runner := &commandRunnerStub{err: sandbox.ErrAttestationFailed}
	client, err := newCommandMCPClient(commandScopeStub{scope: commandTestScope(t)}, layer, runner)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.CallToolWithRequestID(context.Background(), execution.RepositoryExecuteCommand, map[string]any{
		"workspaceId": "workspace-1", "executable": "go", "arguments": []any{"test", "./..."}, "timeoutSeconds": 45,
	}, "invocation-security")
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || result.StructuredContent["status"] != "REPORTED" || runner.calls != 1 || len(reporter.results) != 1 || !containsCommandRisk(reporter.results[0].RiskCodes, commandapproval.RiskSandboxViolation) {
		t.Fatalf("result=%#v runner=%#v reports=%#v", result, runner, reporter.results)
	}
}

func containsCommandRisk(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

type commandGatewayRecorder struct {
	request  modelgateway.NormalizedRequest
	options  modelgateway.GenerateOptions
	response modelgateway.NormalizedResponse
	err      error
}

func (gateway *commandGatewayRecorder) Generate(_ context.Context, request modelgateway.NormalizedRequest, options modelgateway.GenerateOptions) (modelgateway.NormalizedResponse, error) {
	gateway.request = request
	gateway.options = options
	return gateway.response, gateway.err
}

func TestModelCommandReviewerUsesDedicatedLowReasoningRoute(t *testing.T) {
	gateway := &commandGatewayRecorder{response: modelgateway.NormalizedResponse{Content: json.RawMessage(`{"decision":"APPROVE","reason":"bounded test command","riskCodes":[]}`)}}
	reviewer, err := newModelCommandReviewer(gateway)
	if err != nil {
		t.Fatal(err)
	}
	request := commandapproval.Request{
		TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", AgentID: "agent-1",
		BudgetAccountID: "budget-1", DataClassification: "CONFIDENTIAL",
		Executable: "go", Arguments: []string{"test", "./..."}, WorkingDir: "/workspace/repository",
		AllowedPaths: []string{"internal/..."}, ForbiddenPaths: []string{".git/..."},
		Timeout: time.Minute, RequestID: "review-1", IdempotencyKey: "invocation-1",
	}
	result, err := reviewer.Review(context.Background(), request)
	if err != nil || !result.Allowed() {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if gateway.request.Model != commandReviewModel || gateway.request.Role != "EXECUTOR" || gateway.request.ReasoningEffort != "low" || gateway.request.ContextWindowTokens != 400_000 || gateway.request.MaxOutputTokens != commandReviewMaxOutput || gateway.request.DataClassification != "CONFIDENTIAL" {
		t.Fatalf("review request=%#v", gateway.request)
	}
	if gateway.options.Provider != "openai" || gateway.options.AccountID != "budget-1" || gateway.options.MaxAttempts != 1 || gateway.options.ReservationID == "" || len(gateway.request.ResponseSchema) == 0 {
		t.Fatalf("review options=%#v schema=%s", gateway.options, gateway.request.ResponseSchema)
	}
	var payload struct {
		AllowedPaths   []string `json:"allowedPaths"`
		ForbiddenPaths []string `json:"forbiddenPaths"`
	}
	if len(gateway.request.Messages) != 2 || json.Unmarshal([]byte(gateway.request.Messages[1].Content), &payload) != nil ||
		!reflect.DeepEqual(payload.AllowedPaths, request.AllowedPaths) || !reflect.DeepEqual(payload.ForbiddenPaths, request.ForbiddenPaths) {
		t.Fatalf("review payload=%#v messages=%#v", payload, gateway.request.Messages)
	}
}

func TestModelCommandReviewerRejectsInvalidResponse(t *testing.T) {
	gateway := &commandGatewayRecorder{response: modelgateway.NormalizedResponse{Content: json.RawMessage(`{"decision":"ALLOW","reason":"no","riskCodes":[]}`)}}
	reviewer, err := newModelCommandReviewer(gateway)
	if err != nil {
		t.Fatal(err)
	}
	_, err = reviewer.Review(context.Background(), commandapproval.Request{
		TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", AgentID: "agent-1", BudgetAccountID: "budget-1", DataClassification: "INTERNAL",
		Executable: "go", Arguments: []string{"test"}, WorkingDir: "/workspace/repository", AllowedPaths: []string{"internal/..."},
		Timeout: time.Minute, RequestID: "review-2", IdempotencyKey: "invocation-2",
	})
	if err != commandapproval.ErrInvalidDecision {
		t.Fatalf("error=%v", err)
	}
}

type commandActivityStoreRecorder struct {
	message projectactivity.Message
}

func (store *commandActivityStoreRecorder) Upsert(_ context.Context, message projectactivity.Message) error {
	store.message = message
	return nil
}

func TestCommandReporterWritesRedactedSystemActivity(t *testing.T) {
	store := &commandActivityStoreRecorder{}
	now := time.Date(2026, time.August, 14, 12, 0, 0, 0, time.UTC)
	reporter, err := newProjectActivityCommandReporter(store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	secret := "hunter2"
	err = reporter.Report(context.Background(), commandapproval.Request{
		TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", AgentID: "agent-1",
		Executable: "custom-tool", Arguments: []string{"--password", secret}, RequestID: "review-1", IdempotencyKey: "invocation-1",
	}, commandapproval.Result{Decision: commandapproval.DecisionEscalate, Reason: "credential argument", RiskCodes: []string{"CREDENTIAL"}})
	if err != nil {
		t.Fatal(err)
	}
	message := store.message
	if message.Flow != projectactivity.FlowExecution || message.Sender != projectactivity.SenderSystem || message.State != projectactivity.StateCompleted || message.ErrorCode != "COMMAND_REVIEW_ESCALATED" || message.CreatedAt != now {
		t.Fatalf("message=%#v", message)
	}
	if message.RequestID == "review-1" || message.RequestID != message.ID {
		t.Fatalf("report request ID must not collide with the model activity: %#v", message)
	}
	if strings.Contains(message.Content, secret) || !strings.Contains(message.Content, "[REDACTED]") {
		t.Fatalf("content was not redacted: %s", message.Content)
	}
}
