// Package commandapproval decides whether a structured command may execute.
package commandapproval

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/akimisaka/aor/internal/credentials"
)

type Decision string

const (
	DecisionApprove  Decision = "APPROVE"
	DecisionEscalate Decision = "ESCALATE"
)

const (
	RiskPrivilegeEscalation = "PRIVILEGE_ESCALATION"
	RiskHostControl         = "HOST_CONTROL"
	RiskRemoteMutation      = "REMOTE_MUTATION"
	RiskDestructiveFS       = "DESTRUCTIVE_FILESYSTEM"
	RiskInterpreterEval     = "INTERPRETER_EVAL"
	RiskDestructiveDatabase = "DESTRUCTIVE_DATABASE"
	RiskNetworkAccess       = "NETWORK_ACCESS"
	RiskWorkspaceEscape     = "WORKSPACE_ESCAPE"
	RiskCredentialExposure  = "CREDENTIAL_EXPOSURE"
	RiskSandboxViolation    = "SANDBOX_VIOLATION"
	RiskReviewerFailure     = "REVIEWER_FAILURE"
	RiskReviewerEscalation  = "REVIEWER_ESCALATION"
	RiskInvalidDecision     = "INVALID_REVIEW_DECISION"
	RiskInvalidRequest      = "INVALID_REQUEST"
	RiskMockReviewRequired  = "MOCK_REVIEW_REQUIRED"
)

var (
	ErrInvalidConfiguration = errors.New("invalid command approval configuration")
	ErrInvalidRequest       = errors.New("invalid command approval request")
	ErrReviewerFailed       = errors.New("command reviewer failed")
	ErrInvalidDecision      = errors.New("command reviewer returned an invalid decision")
	ErrReportFailed         = errors.New("command escalation report failed")
)

type Request struct {
	TenantID           string
	ProjectID          string
	TaskID             string
	AgentID            string
	BudgetAccountID    string
	DataClassification string
	Executable         string
	Arguments          []string
	WorkingDir         string
	AllowedPaths       []string
	ForbiddenPaths     []string
	Timeout            time.Duration
	RequestID          string
	IdempotencyKey     string
}

type Result struct {
	Decision  Decision
	Reason    string
	RiskCodes []string
}

func (result Result) Allowed() bool {
	return result.Decision == DecisionApprove
}

type Reviewer interface {
	Review(context.Context, Request) (Result, error)
}

type Reporter interface {
	Report(context.Context, Request, Result) error
}

type Layer struct {
	reviewer Reviewer
	reporter Reporter
}

func NewLayer(reviewer Reviewer, reporter Reporter) (*Layer, error) {
	if reviewer == nil || reporter == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Layer{reviewer: reviewer, reporter: reporter}, nil
}

// Review fails closed. Every escalation is sent to the reporter before the
// result is returned to the caller.
func (layer *Layer) Review(ctx context.Context, request Request) (Result, error) {
	if err := validateRequest(request); err != nil {
		result := escalation("command approval request is incomplete", RiskInvalidRequest)
		return layer.report(ctx, request, result, fmt.Errorf("%w: %v", ErrInvalidRequest, err))
	}

	if result, guarded := guardrailResult(request); guarded {
		return layer.report(ctx, request, result, nil)
	}

	result, err := layer.reviewer.Review(ctx, cloneRequest(request))
	if err != nil {
		if errors.Is(err, ErrInvalidDecision) {
			invalid := escalation("the command reviewer returned an invalid decision; the command was not approved", RiskInvalidDecision)
			return layer.report(ctx, request, invalid, ErrInvalidDecision)
		}
		failed := escalation("the command reviewer failed; the command was not approved", RiskReviewerFailure)
		return layer.report(ctx, request, failed, fmt.Errorf("%w: %v", ErrReviewerFailed, err))
	}

	result.Reason = strings.TrimSpace(result.Reason)
	result.RiskCodes = normalizedRiskCodes(result.RiskCodes)
	if !validResult(result) {
		invalid := escalation("the command reviewer returned an invalid decision; the command was not approved", RiskInvalidDecision)
		return layer.report(ctx, request, invalid, ErrInvalidDecision)
	}
	if result.Decision == DecisionEscalate {
		if len(result.RiskCodes) == 0 {
			result.RiskCodes = []string{RiskReviewerEscalation}
		}
		return layer.report(ctx, request, result, nil)
	}
	return result, nil
}

// Escalate reports a security signal discovered after a command was approved.
func (layer *Layer) Escalate(ctx context.Context, request Request, reason string, riskCodes ...string) (Result, error) {
	if layer == nil || layer.reporter == nil {
		return Result{}, ErrInvalidConfiguration
	}
	if err := validateRequest(request); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	result := escalation(strings.TrimSpace(reason), riskCodes...)
	if !validResult(result) {
		return Result{}, ErrInvalidDecision
	}
	return layer.report(ctx, request, result, nil)
}

func (layer *Layer) report(ctx context.Context, request Request, result Result, cause error) (Result, error) {
	if err := layer.reporter.Report(ctx, cloneRequest(request), cloneResult(result)); err != nil {
		reportErr := fmt.Errorf("%w: %v", ErrReportFailed, err)
		if cause != nil {
			return result, errors.Join(cause, reportErr)
		}
		return result, reportErr
	}
	return result, cause
}

func validateRequest(request Request) error {
	required := []struct {
		name  string
		value string
	}{
		{name: "tenantId", value: request.TenantID},
		{name: "projectId", value: request.ProjectID},
		{name: "taskId", value: request.TaskID},
		{name: "agentId", value: request.AgentID},
		{name: "budgetAccountId", value: request.BudgetAccountID},
		{name: "dataClassification", value: request.DataClassification},
		{name: "executable", value: request.Executable},
		{name: "workingDir", value: request.WorkingDir},
		{name: "requestId", value: request.RequestID},
		{name: "idempotencyKey", value: request.IdempotencyKey},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" || len(field.value) > 4096 || !utf8.ValidString(field.value) || strings.ContainsAny(field.value, "\x00\r\n") {
			return fmt.Errorf("%s is required", field.name)
		}
	}
	switch request.DataClassification {
	case "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED":
	default:
		return errors.New("data classification is invalid")
	}
	if !filepath.IsAbs(request.WorkingDir) || filepath.Clean(request.WorkingDir) != request.WorkingDir || len(request.Arguments) > 256 {
		return errors.New("working directory or argument count is invalid")
	}
	if len(request.AllowedPaths) == 0 || len(request.AllowedPaths) > 256 || len(request.ForbiddenPaths) > 256 {
		return errors.New("workspace path boundaries are invalid")
	}
	for _, boundary := range append(append([]string(nil), request.AllowedPaths...), request.ForbiddenPaths...) {
		if strings.TrimSpace(boundary) == "" || len(boundary) > 4096 || !utf8.ValidString(boundary) || strings.ContainsAny(boundary, "\x00\r\n") {
			return errors.New("workspace path boundary is invalid")
		}
	}
	for _, argument := range request.Arguments {
		if len(argument) > 16<<10 || !utf8.ValidString(argument) || strings.ContainsRune(argument, '\x00') {
			return errors.New("command argument is invalid")
		}
	}
	if request.Timeout <= 0 || request.Timeout > time.Hour {
		return errors.New("timeout must be positive")
	}
	return nil
}

func validResult(result Result) bool {
	if result.Reason == "" || len(result.Reason) > 16<<10 || !utf8.ValidString(result.Reason) || len(result.RiskCodes) > 64 {
		return false
	}
	for _, riskCode := range result.RiskCodes {
		if riskCode == "" || len(riskCode) > 128 || !utf8.ValidString(riskCode) || strings.ContainsAny(riskCode, "\x00\r\n") {
			return false
		}
	}
	return result.Decision == DecisionApprove || result.Decision == DecisionEscalate
}

func cloneRequest(request Request) Request {
	request.Arguments = append([]string(nil), request.Arguments...)
	request.AllowedPaths = append([]string(nil), request.AllowedPaths...)
	request.ForbiddenPaths = append([]string(nil), request.ForbiddenPaths...)
	return request
}

func cloneResult(result Result) Result {
	result.RiskCodes = append([]string(nil), result.RiskCodes...)
	return result
}

func normalizedRiskCodes(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func escalation(reason string, riskCodes ...string) Result {
	return Result{Decision: DecisionEscalate, Reason: reason, RiskCodes: normalizedRiskCodes(riskCodes)}
}

func guardrailResult(request Request) (Result, bool) {
	executable := executableName(request.Executable)
	risks := make([]string, 0, 2)
	addRisk := func(risk string) {
		for _, current := range risks {
			if current == risk {
				return
			}
		}
		risks = append(risks, risk)
	}

	if executable == "sudo" || executable == "doas" {
		addRisk(RiskPrivilegeEscalation)
	}
	if executable == "docker" || executable == "podman" || executable == "kubectl" {
		addRisk(RiskHostControl)
	}
	if executable == "git" && gitSubcommand(request.Arguments) == "push" {
		addRisk(RiskRemoteMutation)
	}
	if networkCommand(executable, request.Arguments) {
		addRisk(RiskNetworkAccess)
	}
	if credentialArguments(request.Arguments) {
		addRisk(RiskCredentialExposure)
	}
	if executable == "rm" && destructiveRM(request.Arguments) {
		addRisk(RiskDestructiveFS)
	}
	if interpreterEvaluation(executable, request.Arguments) {
		addRisk(RiskInterpreterEval)
	}
	if destructiveDatabaseCommand(executable, request.Arguments) {
		addRisk(RiskDestructiveDatabase)
	}
	if workspaceEscape(request.WorkingDir, request.Arguments) {
		addRisk(RiskWorkspaceEscape)
	}
	if len(risks) == 0 {
		return Result{}, false
	}
	return escalation("the command matched a deterministic safety guardrail", risks...), true
}

func networkCommand(executable string, arguments []string) bool {
	switch executable {
	case "curl", "wget", "ssh", "scp", "sftp", "ftp", "nc", "netcat", "ncat", "socat", "telnet":
		return true
	case "git":
		switch gitSubcommand(arguments) {
		case "clone", "fetch", "pull", "push", "ls-remote":
			return true
		}
	}
	return false
}

func workspaceEscape(workingDir string, arguments []string) bool {
	for _, argument := range arguments {
		for _, candidate := range commandPathCandidates(argument) {
			candidate = strings.ReplaceAll(candidate, "\\", string(filepath.Separator))
			if filepath.IsAbs(candidate) {
				if pathOutsideWorkspace(workingDir, filepath.Clean(candidate)) {
					return true
				}
				if resolvedPathOutsideWorkspace(workingDir, candidate) {
					return true
				}
				continue
			}
			for _, part := range strings.Split(filepath.Clean(candidate), string(filepath.Separator)) {
				if part == ".." {
					return true
				}
			}
			if resolvedPathOutsideWorkspace(workingDir, filepath.Join(workingDir, candidate)) {
				return true
			}
		}
	}
	return false
}

func commandPathCandidates(argument string) []string {
	candidate := strings.TrimSpace(argument)
	if candidate == "" {
		return nil
	}
	lower := strings.ToLower(candidate)
	if strings.Contains(lower, "://") {
		parsed, err := url.Parse(candidate)
		if err != nil || !strings.EqualFold(parsed.Scheme, "file") || parsed.Path == "" {
			return nil
		}
		return []string{parsed.Path}
	}
	if _, value, found := strings.Cut(candidate, "="); found {
		candidate = strings.TrimSpace(value)
	} else if strings.HasPrefix(candidate, "-") {
		return nil
	}
	if candidate == "" {
		return nil
	}
	return []string{candidate}
}

func pathOutsideWorkspace(workingDir, candidate string) bool {
	relative, err := filepath.Rel(workingDir, candidate)
	return err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func resolvedPathOutsideWorkspace(workingDir, candidate string) bool {
	resolvedRoot, err := filepath.EvalSymlinks(workingDir)
	if err != nil {
		return false
	}
	current := filepath.Clean(candidate)
	for {
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr == nil {
			return pathOutsideWorkspace(resolvedRoot, resolved)
		}
		if !os.IsNotExist(resolveErr) {
			return true
		}
		parent := filepath.Dir(current)
		if parent == current || pathOutsideWorkspace(workingDir, parent) {
			return false
		}
		current = parent
	}
}

func credentialArguments(arguments []string) bool {
	for index, argument := range arguments {
		if credentials.Contains(argument) {
			return true
		}
		name, _, assigned := strings.Cut(argument, "=")
		if sensitiveArgumentName(name) && (assigned || index+1 < len(arguments)) {
			return true
		}
	}
	return false
}

func sensitiveArgumentName(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimLeft(value, "-")
	value = strings.ReplaceAll(value, "_", "-")
	switch value {
	case "access-key", "access-token", "api-key", "apikey", "auth-token", "client-secret", "password", "passwd", "refresh-token", "secret", "token":
		return true
	default:
		return false
	}
}

// RedactArguments removes credential-shaped command values before they leave
// the approval boundary.
func RedactArguments(arguments []string, replacement string) []string {
	redacted := append([]string(nil), arguments...)
	redactNext := false
	for index, argument := range redacted {
		if redactNext {
			redacted[index] = replacement
			redactNext = false
			continue
		}
		name, _, assigned := strings.Cut(argument, "=")
		if sensitiveArgumentName(name) {
			if assigned {
				redacted[index] = name + "=" + replacement
			} else {
				redactNext = true
			}
			continue
		}
		redacted[index], _ = credentials.Redact(argument, replacement)
	}
	return redacted
}

func executableName(value string) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), "\\", "/")
	value = strings.ToLower(path.Base(value))
	return strings.TrimSuffix(value, ".exe")
}

func gitSubcommand(arguments []string) string {
	optionsWithValue := map[string]struct{}{
		"-c": {}, "-C": {}, "--exec-path": {}, "--git-dir": {}, "--namespace": {}, "--super-prefix": {}, "--work-tree": {},
	}
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if _, consumesValue := optionsWithValue[argument]; consumesValue {
			index++
			continue
		}
		if strings.HasPrefix(argument, "-") {
			continue
		}
		return strings.ToLower(argument)
	}
	return ""
}

func destructiveRM(arguments []string) bool {
	recursive := false
	force := false
	noPreserveRoot := false
	dangerousTarget := false
	for _, argument := range arguments {
		switch argument {
		case "--recursive":
			recursive = true
		case "--force":
			force = true
		case "--no-preserve-root":
			noPreserveRoot = true
		case "/", "/*", ".", "..", "./", "../":
			dangerousTarget = true
		default:
			if strings.HasPrefix(argument, "-") && !strings.HasPrefix(argument, "--") {
				flags := strings.TrimLeft(argument, "-")
				recursive = recursive || strings.Contains(flags, "r") || strings.Contains(flags, "R")
				force = force || strings.Contains(flags, "f")
			}
		}
	}
	return noPreserveRoot || recursive && (force || dangerousTarget)
}

func interpreterEvaluation(executable string, arguments []string) bool {
	for _, argument := range arguments {
		lower := strings.ToLower(argument)
		switch executable {
		case "sh", "bash", "dash", "zsh", "ksh":
			if shortFlagContains(lower, "c") {
				return true
			}
		case "powershell", "pwsh":
			if lower == "-command" || lower == "--command" || lower == "-encodedcommand" || lower == "-enc" || lower == "-c" {
				return true
			}
		case "cmd":
			if lower == "/c" || lower == "/k" {
				return true
			}
		default:
			if strings.HasPrefix(executable, "python") && strings.HasPrefix(lower, "-c") {
				return true
			}
			if (executable == "node" || executable == "ruby" || executable == "perl" || executable == "lua") && (lower == "-e" || lower == "--eval") {
				return true
			}
			if executable == "php" && lower == "-r" {
				return true
			}
		}
	}
	return false
}

func shortFlagContains(argument, flag string) bool {
	return strings.HasPrefix(argument, "-") && !strings.HasPrefix(argument, "--") && strings.Contains(strings.TrimLeft(argument, "-"), flag)
}

func destructiveDatabaseCommand(executable string, arguments []string) bool {
	switch executable {
	case "dropdb", "dropuser":
		return true
	case "psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "mongosh", "mongo", "redis-cli", "mysqladmin":
	default:
		return false
	}

	statement := strings.ToUpper(strings.Join(strings.Fields(strings.Join(arguments, " ")), " "))
	destructive := []string{
		"DROP DATABASE", "DROP SCHEMA", "DROP TABLE", "DROP COLLECTION", "DROPDATABASE(",
		"TRUNCATE ", "DELETE FROM", "FLUSHALL", "FLUSHDB", "MYSQLADMIN DROP", "SHUTDOWN",
	}
	for _, marker := range destructive {
		if strings.Contains(statement, marker) {
			return true
		}
	}
	return executable == "mysqladmin" && containsArgument(arguments, "drop")
}

func containsArgument(arguments []string, expected string) bool {
	for _, argument := range arguments {
		if strings.EqualFold(argument, expected) {
			return true
		}
	}
	return false
}

// MockReviewer is deterministic and intentionally narrow. It approves common
// read, build, and test commands and escalates everything else.
type MockReviewer struct{}

func (MockReviewer) Review(_ context.Context, request Request) (Result, error) {
	executable := executableName(request.Executable)
	subcommand := firstNonOption(request.Arguments)
	allowed := false
	switch executable {
	case "cat", "echo", "head", "ls", "pwd", "rg", "tail", "wc":
		allowed = true
	case "git":
		allowed = containsString([]string{"diff", "log", "ls-files", "rev-parse", "show", "status"}, gitSubcommand(request.Arguments))
	case "go":
		allowed = containsString([]string{"build", "list", "test", "vet"}, subcommand)
	case "cargo":
		allowed = containsString([]string{"build", "check", "test"}, subcommand)
	case "dotnet":
		allowed = containsString([]string{"build", "test"}, subcommand)
	}
	if !allowed {
		return escalation("the mock reviewer requires explicit review for this command", RiskMockReviewRequired), nil
	}
	return Result{Decision: DecisionApprove, Reason: "approved by the deterministic mock reviewer"}, nil
}

func firstNonOption(arguments []string) string {
	for _, argument := range arguments {
		if !strings.HasPrefix(argument, "-") {
			return strings.ToLower(argument)
		}
	}
	return ""
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
