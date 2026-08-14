package servicebootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/commandapproval"
	"github.com/akimisaka/aor/internal/credentials"
	"github.com/akimisaka/aor/internal/execution"
	"github.com/akimisaka/aor/internal/mockenv"
	"github.com/akimisaka/aor/internal/projectactivity"
	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/runtimeclient"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	"github.com/akimisaka/aor/internal/sandbox"
	"github.com/akimisaka/aor/internal/toolbroker"
	"github.com/akimisaka/aor/internal/toolchain"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/akimisaka/aor/pkg/mcp"
)

const (
	commandMCPServerID       = "aor-command"
	commandToolOutputLimit   = 64 << 10
	commandToolMaximumOutput = 1 << 20
)

type commandArguments struct {
	WorkspaceID    string   `json:"workspaceId"`
	Executable     string   `json:"executable"`
	Arguments      []string `json:"arguments"`
	TimeoutSeconds int      `json:"timeoutSeconds"`
}

type commandExecutionScope struct {
	TenantID           string
	ProjectID          string
	TaskID             string
	AgentID            string
	BudgetAccountID    string
	DataClassification string
	WorkspacePath      string
	AllowedPaths       []string
	ForbiddenPaths     []string
	Module             contracts.ModuleSpec
}

type commandScopeResolver interface {
	Resolve(context.Context, string) (commandExecutionScope, error)
}

type repositoryCommandScopeResolver struct {
	service   *repository.Service
	authority *repositoryExecutionAuthority
}

func (resolver repositoryCommandScopeResolver) Resolve(ctx context.Context, workspaceID string) (commandExecutionScope, error) {
	if resolver.service == nil || resolver.authority == nil || strings.TrimSpace(workspaceID) == "" {
		return commandExecutionScope{}, repository.ErrInvalidRequest
	}
	claim, _, err := resolver.authority.claimForServerRoles(ctx, commandMCPServerID, execution.RepositoryExecuteCommand, authn.RoleExecutor)
	if err != nil {
		return commandExecutionScope{}, err
	}
	workspace, found, err := resolver.service.WorkspaceContext(ctx, workspaceID)
	if err != nil {
		return commandExecutionScope{}, err
	}
	if !found {
		return commandExecutionScope{}, repository.ErrWorkspaceNotFound
	}
	if err := resolver.authority.validateWorkspaceRead(ctx, claim, workspace); err != nil {
		return commandExecutionScope{}, err
	}
	scope, err := resolver.authority.loadScope(ctx, claim, workspace.AttemptSeriesID, workspace.Attempt)
	if err != nil {
		return commandExecutionScope{}, err
	}
	return commandExecutionScope{
		TenantID: claim.TenantID, ProjectID: claim.ProjectID, TaskID: claim.TaskID,
		AgentID: claim.Principal.ID, BudgetAccountID: claim.BudgetAccountID,
		DataClassification: scope.dataClassification, WorkspacePath: workspace.Path,
		AllowedPaths: append([]string(nil), workspace.AllowedPaths...), ForbiddenPaths: append([]string(nil), workspace.ForbiddenPaths...),
		Module: scope.module,
	}, nil
}

type commandRunRequest struct {
	TenantID     string
	ProjectID    string
	TaskID       string
	InvocationID string
	Executable   string
	Arguments    []string
	Directory    string
	Timeout      time.Duration
	Module       contracts.ModuleSpec
}

type commandRunResult struct {
	ExitCode        int
	Stdout          string
	Stderr          string
	TimedOut        bool
	StdoutTruncated bool
	StderrTruncated bool
}

type commandRunner interface {
	Run(context.Context, commandRunRequest) (commandRunResult, error)
}

type commandMCPClient struct {
	scopes    commandScopeResolver
	approvals *commandapproval.Layer
	runner    commandRunner
}

func newCommandMCPClient(scopes commandScopeResolver, approvals *commandapproval.Layer, runner commandRunner) (*commandMCPClient, error) {
	if scopes == nil || approvals == nil || runner == nil {
		return nil, ErrWorkerConfiguration
	}
	return &commandMCPClient{scopes: scopes, approvals: approvals, runner: runner}, nil
}

func (client *commandMCPClient) Initialize(ctx context.Context) (mcp.InitializeResponse, error) {
	if client == nil || ctx == nil {
		return mcp.InitializeResponse{}, toolbroker.ErrInvalidRequest
	}
	return mcp.InitializeResponse{
		ProtocolVersion: mcp.BaselineProtocolVersion,
		Capabilities:    map[string]any{"tools": map[string]any{"listChanged": false}},
		ServerInfo:      mcp.Implementation{Name: commandMCPServerID, Version: repositoryMCPVersion, Description: "AOR reviewed command execution"},
	}, nil
}

func (client *commandMCPClient) ListTools(ctx context.Context, cursor string) (mcp.ToolListResult, error) {
	if client == nil || ctx == nil || cursor != "" {
		return mcp.ToolListResult{}, toolbroker.ErrInvalidRequest
	}
	return mcp.ToolListResult{Tools: commandMCPTools()}, nil
}

func (client *commandMCPClient) CallTool(ctx context.Context, name string, arguments map[string]any) (mcp.ToolCallResult, error) {
	invocationID, _ := toolbroker.InvocationRequestIDFromContext(ctx)
	return client.callTool(ctx, name, arguments, invocationID)
}

func (client *commandMCPClient) CallToolWithRequestID(ctx context.Context, name string, arguments map[string]any, invocationID string) (mcp.ToolCallResult, error) {
	return client.callTool(ctx, name, arguments, invocationID)
}

func (client *commandMCPClient) callTool(ctx context.Context, name string, arguments map[string]any, invocationID string) (mcp.ToolCallResult, error) {
	if client == nil || client.scopes == nil || client.approvals == nil || client.runner == nil || ctx == nil || name != execution.RepositoryExecuteCommand {
		return mcp.ToolCallResult{}, toolbroker.ErrUnknownTool
	}
	var input commandArguments
	if err := decodeCommandArguments(arguments, &input); err != nil || !validCommandArguments(input) {
		return mcp.ToolCallResult{}, toolbroker.ErrInvalidRequest
	}
	scope, err := client.scopes.Resolve(ctx, input.WorkspaceID)
	if err != nil {
		return mcp.ToolCallResult{}, err
	}
	if strings.TrimSpace(invocationID) == "" {
		return mcp.ToolCallResult{}, toolbroker.ErrInvalidRequest
	}
	reviewRequest := commandapproval.Request{
		TenantID: scope.TenantID, ProjectID: scope.ProjectID, TaskID: scope.TaskID,
		AgentID: scope.AgentID, BudgetAccountID: scope.BudgetAccountID, DataClassification: scope.DataClassification,
		Executable: input.Executable, Arguments: append([]string(nil), input.Arguments...), WorkingDir: scope.WorkspacePath,
		AllowedPaths: append([]string(nil), scope.AllowedPaths...), ForbiddenPaths: append([]string(nil), scope.ForbiddenPaths...),
		Timeout: time.Duration(input.TimeoutSeconds) * time.Second, RequestID: commandReviewRequestID(invocationID, input), IdempotencyKey: invocationID,
	}
	review, reviewErr := client.approvals.Review(ctx, reviewRequest)
	if !review.Allowed() {
		if ctx.Err() != nil || errors.Is(reviewErr, commandapproval.ErrReportFailed) {
			return mcp.ToolCallResult{}, reviewErr
		}
		return commandToolResult(map[string]any{
			"status": "REPORTED", "exitCode": -1, "stdout": "", "stderr": "",
			"timedOut": false, "stdoutTruncated": false, "stderrTruncated": false,
			"reason": review.Reason, "riskCodes": append([]string(nil), review.RiskCodes...),
		}, true), nil
	}
	if reviewErr != nil {
		return mcp.ToolCallResult{}, reviewErr
	}
	runResult, err := client.runner.Run(ctx, commandRunRequest{
		TenantID: scope.TenantID, ProjectID: scope.ProjectID, TaskID: scope.TaskID, InvocationID: invocationID,
		Executable: input.Executable, Arguments: append([]string(nil), input.Arguments...),
		Directory: scope.WorkspacePath, Timeout: time.Duration(input.TimeoutSeconds) * time.Second, Module: scope.Module,
	})
	if err != nil {
		if reason, riskCodes, report := commandExecutionEscalation(err); report {
			escalation, reportErr := client.approvals.Escalate(ctx, reviewRequest, reason, riskCodes...)
			if reportErr != nil {
				return mcp.ToolCallResult{}, reportErr
			}
			return commandToolResult(map[string]any{
				"status": "REPORTED", "exitCode": -1, "stdout": "", "stderr": "",
				"timedOut": false, "stdoutTruncated": false, "stderrTruncated": false,
				"reason": escalation.Reason, "riskCodes": append([]string(nil), escalation.RiskCodes...),
			}, true), nil
		}
		return commandToolResult(map[string]any{
			"status": "FAILED", "exitCode": -1, "stdout": "", "stderr": "command could not be started",
			"timedOut": false, "stdoutTruncated": false, "stderrTruncated": false,
		}, true), nil
	}
	failed := runResult.ExitCode != 0 || runResult.TimedOut
	return commandToolResult(map[string]any{
		"status": "EXECUTED", "exitCode": runResult.ExitCode, "stdout": runResult.Stdout, "stderr": runResult.Stderr,
		"timedOut": runResult.TimedOut, "stdoutTruncated": runResult.StdoutTruncated, "stderrTruncated": runResult.StderrTruncated,
	}, failed), nil
}

func commandExecutionEscalation(err error) (string, []string, bool) {
	risks := make([]string, 0, 2)
	if errors.Is(err, sandbox.ErrCredentialDetected) {
		risks = append(risks, commandapproval.RiskCredentialExposure)
	}
	if errors.Is(err, sandbox.ErrAttestationFailed) || errors.Is(err, sandbox.ErrUnsafeWorkload) || errors.Is(err, sandbox.ErrCleanupFailed) {
		risks = append(risks, commandapproval.RiskSandboxViolation)
	}
	if len(risks) == 0 {
		return "", nil, false
	}
	return "the command sandbox rejected a security-sensitive execution condition", risks, true
}

func (client *commandMCPClient) Close() error { return nil }

func decodeCommandArguments(arguments map[string]any, target *commandArguments) error {
	encoded, err := json.Marshal(arguments)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return toolbroker.ErrInvalidRequest
	}
	return nil
}

func validCommandArguments(input commandArguments) bool {
	cleanExecutable := filepath.Clean(input.Executable)
	if strings.TrimSpace(input.WorkspaceID) == "" || len(input.WorkspaceID) > 512 || strings.TrimSpace(input.Executable) != input.Executable || input.Executable == "" || len(input.Executable) > 4096 ||
		strings.ContainsAny(input.WorkspaceID+input.Executable, "\x00\r\n") || strings.ContainsRune(input.Executable, '=') || filepath.IsAbs(input.Executable) || cleanExecutable == "." || cleanExecutable == ".." || strings.HasPrefix(cleanExecutable, ".."+string(filepath.Separator)) ||
		input.TimeoutSeconds <= 0 || input.TimeoutSeconds > 3600 || len(input.Arguments) > 256 {
		return false
	}
	for _, argument := range input.Arguments {
		if len(argument) > 16<<10 || strings.ContainsRune(argument, '\x00') {
			return false
		}
	}
	return true
}

func commandReviewRequestID(invocationID string, input commandArguments) string {
	encoded, _ := json.Marshal(input)
	digest := sha256.Sum256(append([]byte(invocationID+"\x00"), encoded...))
	return "command-review-" + hex.EncodeToString(digest[:])
}

func commandToolResult(structured map[string]any, isError bool) mcp.ToolCallResult {
	message := "reviewed command completed"
	if isError {
		message = "reviewed command did not complete successfully"
	}
	return mcp.ToolCallResult{Content: []mcp.Content{{Type: "text", Text: message}}, StructuredContent: structured, IsError: isError}
}

func commandMCPTools() []mcp.Tool {
	stringProperty := func(maximum int) map[string]any {
		return map[string]any{"type": "string", "minLength": 1, "maxLength": maximum}
	}
	input := map[string]any{
		"type": "object", "required": []any{"workspaceId", "executable", "arguments", "timeoutSeconds"}, "additionalProperties": false,
		"properties": map[string]any{
			"workspaceId": stringProperty(512), "executable": stringProperty(4096),
			"arguments":      map[string]any{"type": "array", "maxItems": 256, "items": map[string]any{"type": "string", "maxLength": 16 << 10}},
			"timeoutSeconds": map[string]any{"type": "integer", "minimum": 1, "maximum": 3600},
		},
	}
	output := map[string]any{
		"type": "object", "required": []any{"status", "exitCode", "stdout", "stderr", "timedOut", "stdoutTruncated", "stderrTruncated"}, "additionalProperties": false,
		"properties": map[string]any{
			"status": map[string]any{"enum": []any{"EXECUTED", "REPORTED", "FAILED"}}, "exitCode": map[string]any{"type": "integer"},
			"stdout": map[string]any{"type": "string", "maxLength": commandToolOutputLimit}, "stderr": map[string]any{"type": "string", "maxLength": commandToolOutputLimit},
			"timedOut": map[string]any{"type": "boolean"}, "stdoutTruncated": map[string]any{"type": "boolean"}, "stderrTruncated": map[string]any{"type": "boolean"},
			"reason":    map[string]any{"type": "string", "maxLength": 16 << 10},
			"riskCodes": map[string]any{"type": "array", "maxItems": 64, "items": stringProperty(128)},
		},
	}
	return []mcp.Tool{{
		Name:        execution.RepositoryExecuteCommand,
		Description: "Inspect, build, or test a disposable copy of the lease-bound repository workspace after deterministic and model review; changes are discarded, and network access and shell evaluation are not allowed",
		InputSchema: input, OutputSchema: output,
	}}
}

func commandMCPPolicies() map[string]toolbroker.MCPToolPolicy {
	return map[string]toolbroker.MCPToolPolicy{
		execution.RepositoryExecuteCommand: {
			Risk: toolbroker.RiskHigh, SideEffect: toolbroker.SideEffectNone,
			NetworkAccess: toolbroker.NetworkNone, FilesystemAccess: toolbroker.FilesystemRead,
			RequiresApproval: toolbroker.ApprovalPolicy, AllowedRoles: []string{authn.RoleExecutor},
			RateLimit: "2/s", TimeoutSeconds: 3600, MaxOutputBytes: commandToolMaximumOutput,
		},
	}
}

type projectActivityCommandReporter struct {
	store commandActivityStore
	clock func() time.Time
}

type commandActivityStore interface {
	Upsert(context.Context, projectactivity.Message) error
}

func newProjectActivityCommandReporter(store commandActivityStore, clock func() time.Time) (*projectActivityCommandReporter, error) {
	if store == nil {
		return nil, ErrWorkerConfiguration
	}
	if clock == nil {
		clock = time.Now
	}
	return &projectActivityCommandReporter{store: store, clock: clock}, nil
}

func (reporter *projectActivityCommandReporter) Report(ctx context.Context, request commandapproval.Request, result commandapproval.Result) error {
	if reporter == nil || reporter.store == nil || reporter.clock == nil {
		return ErrWorkerConfiguration
	}
	content, err := json.Marshal(struct {
		Type       string   `json:"type"`
		Executable string   `json:"executable"`
		Arguments  []string `json:"arguments"`
		Reason     string   `json:"reason"`
		RiskCodes  []string `json:"riskCodes"`
	}{Type: "COMMAND_REVIEW_ESCALATION", Executable: request.Executable, Arguments: commandapproval.RedactArguments(request.Arguments, "[REDACTED]"), Reason: result.Reason, RiskCodes: result.RiskCodes})
	if err != nil {
		return err
	}
	redacted, _ := credentials.Redact(string(content), "[REDACTED]")
	redacted = truncateCommandText(redacted, 64<<10)
	now := reporter.clock().UTC()
	digest := sha256.Sum256(content)
	idDigest := sha256.Sum256([]byte(request.TenantID + "\x00" + request.ProjectID + "\x00" + request.IdempotencyKey))
	reportID := "command-review-report-" + hex.EncodeToString(idDigest[:])
	return reporter.store.Upsert(ctx, projectactivity.Message{
		TenantID: request.TenantID, ProjectID: request.ProjectID,
		ID: reportID, RequestID: reportID,
		TaskID: request.TaskID, Flow: projectactivity.FlowExecution, AgentInstanceID: request.AgentID,
		Role: "COMMAND_REVIEWER", Sender: projectactivity.SenderSystem, State: projectactivity.StateCompleted,
		Content: redacted, ErrorCode: "COMMAND_REVIEW_ESCALATED", PrincipalID: request.AgentID,
		IdempotencyKey: request.IdempotencyKey, RequestSHA256: "sha256:" + hex.EncodeToString(digest[:]),
		CreatedAt: now, UpdatedAt: now,
	})
}

func truncateCommandText(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	value = value[:maximum]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func configuredCommandMCP(config runtimeconfig.Config, clients *runtimeclient.Clients, gateway commandReviewGateway, repositoryClient *repositoryMCPClient, provider sandbox.SandboxProvider) (*commandMCPClient, error) {
	if clients == nil || repositoryClient == nil || repositoryClient.service == nil || repositoryClient.authority == nil || provider == nil {
		return nil, ErrWorkerConfiguration
	}
	activityStore, err := projectactivity.NewStore(clients.Database())
	if err != nil {
		return nil, err
	}
	reporter, err := newProjectActivityCommandReporter(activityStore, time.Now)
	if err != nil {
		return nil, err
	}
	var reviewer commandapproval.Reviewer
	if mockenv.Enabled {
		reviewer = commandapproval.MockReviewer{}
	} else {
		reviewer, err = newModelCommandReviewer(gateway)
		if err != nil {
			return nil, err
		}
	}
	approvals, err := commandapproval.NewLayer(reviewer, reporter)
	if err != nil {
		return nil, err
	}
	toolchains, err := toolchain.NewFilesystem(config.ToolchainRoot)
	if err != nil {
		return nil, err
	}
	runner, err := newSandboxCommandRunner(provider, toolchains, configuredImageDigest(config.Sandbox.ImageReference), config.Integration.DependencyCache, config.DeploymentProfile)
	if err != nil {
		return nil, err
	}
	return newCommandMCPClient(repositoryCommandScopeResolver{service: repositoryClient.service, authority: repositoryClient.authority}, approvals, runner)
}

var _ toolbroker.MCPToolClient = (*commandMCPClient)(nil)
