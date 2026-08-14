package commandapproval

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type reviewerFunc func(context.Context, Request) (Result, error)

func (function reviewerFunc) Review(ctx context.Context, request Request) (Result, error) {
	return function(ctx, request)
}

type recordingReporter struct {
	requests []Request
	results  []Result
	err      error
}

func (reporter *recordingReporter) Report(_ context.Context, request Request, result Result) error {
	reporter.requests = append(reporter.requests, request)
	reporter.results = append(reporter.results, result)
	return reporter.err
}

func validRequest() Request {
	return Request{
		TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", AgentID: "agent-1", BudgetAccountID: "budget-1", DataClassification: "INTERNAL",
		Executable: "go", Arguments: []string{"test", "./..."}, WorkingDir: "/workspace/repository", Timeout: time.Minute,
		AllowedPaths: []string{"internal/..."}, ForbiddenPaths: []string{".git/...", "hidden-tests/..."},
		RequestID: "request-1", IdempotencyKey: "command-1",
	}
}

func TestLayerApprovesValidReviewerDecision(t *testing.T) {
	reporter := &recordingReporter{}
	layer, err := NewLayer(reviewerFunc(func(_ context.Context, request Request) (Result, error) {
		request.Arguments[0] = "mutated"
		request.AllowedPaths[0] = "mutated"
		request.ForbiddenPaths[0] = "mutated"
		return Result{Decision: DecisionApprove, Reason: "required test command"}, nil
	}), reporter)
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest()
	result, err := layer.Review(context.Background(), request)
	if err != nil || !result.Allowed() {
		t.Fatalf("expected approval, result=%+v err=%v", result, err)
	}
	if request.Arguments[0] != "test" {
		t.Fatal("reviewer mutated the caller's request")
	}
	if request.AllowedPaths[0] != "internal/..." || request.ForbiddenPaths[0] != ".git/..." {
		t.Fatal("reviewer mutated the caller's workspace boundaries")
	}
	if len(reporter.results) != 0 {
		t.Fatal("approved command must not be reported")
	}
}

func TestLayerGuardrailsEscalateBeforeReviewer(t *testing.T) {
	tests := []struct {
		name       string
		executable string
		arguments  []string
		risk       string
	}{
		{name: "sudo", executable: "/usr/bin/sudo", arguments: []string{"go", "test"}, risk: RiskPrivilegeEscalation},
		{name: "docker", executable: "docker.exe", arguments: []string{"ps"}, risk: RiskHostControl},
		{name: "podman", executable: "podman", arguments: []string{"images"}, risk: RiskHostControl},
		{name: "kubectl", executable: "kubectl", arguments: []string{"get", "pods"}, risk: RiskHostControl},
		{name: "git push", executable: "git", arguments: []string{"-C", "repo", "push", "origin", "main"}, risk: RiskRemoteMutation},
		{name: "recursive forced rm", executable: "rm", arguments: []string{"-rf", "build"}, risk: RiskDestructiveFS},
		{name: "shell eval", executable: "bash", arguments: []string{"-lc", "go test ./..."}, risk: RiskInterpreterEval},
		{name: "powershell eval", executable: "powershell.exe", arguments: []string{"-Command", "Get-ChildItem"}, risk: RiskInterpreterEval},
		{name: "python eval", executable: "python3", arguments: []string{"-c", "print(1)"}, risk: RiskInterpreterEval},
		{name: "database drop", executable: "psql", arguments: []string{"-c", "DROP DATABASE app"}, risk: RiskDestructiveDatabase},
		{name: "redis flush", executable: "redis-cli", arguments: []string{"FLUSHALL"}, risk: RiskDestructiveDatabase},
		{name: "dropdb", executable: "dropdb", arguments: []string{"app"}, risk: RiskDestructiveDatabase},
		{name: "network client", executable: "curl", arguments: []string{"https://example.com"}, risk: RiskNetworkAccess},
		{name: "git fetch", executable: "git", arguments: []string{"fetch", "origin"}, risk: RiskNetworkAccess},
		{name: "absolute path escape", executable: "cat", arguments: []string{"/run/secrets/key"}, risk: RiskWorkspaceEscape},
		{name: "relative path escape", executable: "cat", arguments: []string{"../../secret"}, risk: RiskWorkspaceEscape},
		{name: "option path escape", executable: "custom-tool", arguments: []string{"--output=/tmp/result"}, risk: RiskWorkspaceEscape},
		{name: "file URL escape", executable: "custom-tool", arguments: []string{"file:///etc/passwd"}, risk: RiskWorkspaceEscape},
		{name: "credential flag", executable: "custom-tool", arguments: []string{"--password", "hunter2"}, risk: RiskCredentialExposure},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			reporter := &recordingReporter{}
			layer, err := NewLayer(reviewerFunc(func(context.Context, Request) (Result, error) {
				called = true
				return Result{Decision: DecisionApprove, Reason: "approved"}, nil
			}), reporter)
			if err != nil {
				t.Fatal(err)
			}
			request := validRequest()
			request.Executable = test.executable
			request.Arguments = test.arguments
			result, reviewErr := layer.Review(context.Background(), request)
			if reviewErr != nil || result.Allowed() || called {
				t.Fatalf("guardrail did not fail closed, result=%+v err=%v reviewerCalled=%v", result, reviewErr, called)
			}
			if len(reporter.results) != 1 || !containsString(reporter.results[0].RiskCodes, test.risk) {
				t.Fatalf("expected reported risk %s, reports=%+v", test.risk, reporter.results)
			}
		})
	}
}

func TestLayerGuardrailRejectsWorkspaceSymlinkEscape(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(workspace, "outside")); err != nil {
		t.Fatal(err)
	}
	reviewerCalled := false
	reporter := &recordingReporter{}
	layer, err := NewLayer(reviewerFunc(func(context.Context, Request) (Result, error) {
		reviewerCalled = true
		return Result{Decision: DecisionApprove, Reason: "approved"}, nil
	}), reporter)
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest()
	request.WorkingDir = workspace
	request.Arguments = []string{"outside/secret"}
	result, err := layer.Review(context.Background(), request)
	if err != nil || result.Allowed() || reviewerCalled || len(reporter.results) != 1 || !containsString(reporter.results[0].RiskCodes, RiskWorkspaceEscape) {
		t.Fatalf("result=%+v err=%v reviewerCalled=%v reports=%+v", result, err, reviewerCalled, reporter.results)
	}
}

func TestRedactArgumentsHandlesSeparatedAndAssignedCredentials(t *testing.T) {
	arguments := []string{"--password", "hunter2", "--api-key=plain-value", "sk-0123456789abcdefghijklmnop"}
	redacted := RedactArguments(arguments, "[REDACTED]")
	if reflect.DeepEqual(arguments, redacted) || strings.Contains(strings.Join(redacted, " "), "hunter2") || strings.Contains(strings.Join(redacted, " "), "plain-value") || strings.Contains(strings.Join(redacted, " "), "sk-0123456789") {
		t.Fatalf("redacted arguments=%#v", redacted)
	}
	if arguments[1] != "hunter2" {
		t.Fatal("redaction mutated the caller's arguments")
	}
}

func TestLayerReportsReviewerFailureAndInvalidDecision(t *testing.T) {
	tests := []struct {
		name       string
		reviewer   Reviewer
		expected   error
		expectedRC string
	}{
		{
			name: "failure", expected: ErrReviewerFailed, expectedRC: RiskReviewerFailure,
			reviewer: reviewerFunc(func(context.Context, Request) (Result, error) { return Result{}, errors.New("offline") }),
		},
		{
			name: "invalid decision", expected: ErrInvalidDecision, expectedRC: RiskInvalidDecision,
			reviewer: reviewerFunc(func(context.Context, Request) (Result, error) {
				return Result{Decision: Decision("ALLOW"), Reason: "not in the contract"}, nil
			}),
		},
		{
			name: "invalid decision error", expected: ErrInvalidDecision, expectedRC: RiskInvalidDecision,
			reviewer: reviewerFunc(func(context.Context, Request) (Result, error) {
				return Result{}, ErrInvalidDecision
			}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reporter := &recordingReporter{}
			layer, err := NewLayer(test.reviewer, reporter)
			if err != nil {
				t.Fatal(err)
			}
			result, reviewErr := layer.Review(context.Background(), validRequest())
			if !errors.Is(reviewErr, test.expected) || result.Allowed() {
				t.Fatalf("expected closed failure %v, result=%+v err=%v", test.expected, result, reviewErr)
			}
			if len(reporter.results) != 1 || !containsString(reporter.results[0].RiskCodes, test.expectedRC) {
				t.Fatalf("failure was not reported: %+v", reporter.results)
			}
		})
	}
}

func TestLayerKeepsEscalationWhenReportingFails(t *testing.T) {
	reporter := &recordingReporter{err: errors.New("store unavailable")}
	layer, err := NewLayer(reviewerFunc(func(context.Context, Request) (Result, error) {
		return Result{Decision: DecisionEscalate, Reason: "needs user review", RiskCodes: []string{"POLICY_UNCERTAIN"}}, nil
	}), reporter)
	if err != nil {
		t.Fatal(err)
	}
	result, reviewErr := layer.Review(context.Background(), validRequest())
	if result.Allowed() || !errors.Is(reviewErr, ErrReportFailed) {
		t.Fatalf("reporting failure must remain closed, result=%+v err=%v", result, reviewErr)
	}
}

func TestLayerReportsPostApprovalSecuritySignal(t *testing.T) {
	reporter := &recordingReporter{}
	layer, err := NewLayer(MockReviewer{}, reporter)
	if err != nil {
		t.Fatal(err)
	}
	result, err := layer.Escalate(context.Background(), validRequest(), "sandbox attestation changed", RiskSandboxViolation)
	if err != nil || result.Allowed() || len(reporter.results) != 1 || !containsString(reporter.results[0].RiskCodes, RiskSandboxViolation) {
		t.Fatalf("result=%+v reports=%+v error=%v", result, reporter.results, err)
	}
}

func TestLayerAllowsBenignCommandsToReachReviewer(t *testing.T) {
	tests := []Request{
		func() Request {
			request := validRequest()
			request.Executable = "git"
			request.Arguments = []string{"status"}
			return request
		}(),
		func() Request {
			request := validRequest()
			request.Executable = "rm"
			request.Arguments = []string{"build.log"}
			return request
		}(),
		func() Request {
			request := validRequest()
			request.Executable = "psql"
			request.Arguments = []string{"-c", "SELECT 1"}
			return request
		}(),
	}
	for _, request := range tests {
		called := false
		layer, err := NewLayer(reviewerFunc(func(context.Context, Request) (Result, error) {
			called = true
			return Result{Decision: DecisionApprove, Reason: "benign"}, nil
		}), &recordingReporter{})
		if err != nil {
			t.Fatal(err)
		}
		result, reviewErr := layer.Review(context.Background(), request)
		if reviewErr != nil || !result.Allowed() || !called {
			t.Fatalf("benign command was not reviewed, request=%+v result=%+v err=%v", request, result, reviewErr)
		}
	}
}

func TestMockReviewerIsDeterministicAndConservative(t *testing.T) {
	reviewer := MockReviewer{}
	safe := validRequest()
	approved, err := reviewer.Review(context.Background(), safe)
	if err != nil || !approved.Allowed() {
		t.Fatalf("expected go test approval, result=%+v err=%v", approved, err)
	}

	unknown := validRequest()
	unknown.Executable = "custom-tool"
	first, err := reviewer.Review(context.Background(), unknown)
	if err != nil || first.Allowed() {
		t.Fatalf("unknown command must escalate, result=%+v err=%v", first, err)
	}
	second, err := reviewer.Review(context.Background(), unknown)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("mock result must be deterministic, first=%+v second=%+v err=%v", first, second, err)
	}
}
