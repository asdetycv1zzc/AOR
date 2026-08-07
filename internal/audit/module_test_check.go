package audit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/pkg/contracts"
)

const moduleTestOutputLimit = 1 << 20

// ModuleTestCheck runs one deployment-configured argv against the immutable
// submission commit. The command is never interpreted by a shell.
type ModuleTestCheck struct {
	repositoryRoot string
	workRoot       string
	argv           []string
	timeout        time.Duration
}

func NewModuleTestCheck(repositoryRoot, workRoot string, argv []string, timeout time.Duration) (*ModuleTestCheck, error) {
	if !validAbsoluteDirectoryRoot(repositoryRoot) || !validAbsoluteDirectoryRoot(workRoot) || filepath.Clean(repositoryRoot) == filepath.Clean(workRoot) || len(argv) == 0 || argv[0] == "" || timeout <= 0 {
		return nil, ErrInvalidInput
	}
	if isModuleTestShell(argv[0]) {
		return nil, ErrInvalidInput
	}
	for _, value := range argv {
		if value == "" || strings.ContainsRune(value, '\x00') {
			return nil, ErrInvalidInput
		}
	}
	return &ModuleTestCheck{repositoryRoot: repositoryRoot, workRoot: workRoot, argv: append([]string(nil), argv...), timeout: timeout}, nil
}

func (check *ModuleTestCheck) ID() string { return "module-tests" }

func (check *ModuleTestCheck) Run(ctx context.Context, input DeterministicInput) CheckResult {
	if check == nil || ctx == nil || ctx.Err() != nil || !commitID(input.Manifest.HeadCommit) || input.Manifest.ProjectID == "" || input.TenantID == "" {
		return moduleTestFailure(StatusError, "invalid module test input", "module-test-input")
	}
	if pathResult := (pathCheck{}).Run(ctx, cloneDeterministicInput(input)); pathResult.Status != StatusPass {
		return moduleTestFailure(StatusFail, "submission changes paths outside the module ownership boundary", "module-test-path-ownership")
	}
	if commitResult := (commitCheck{}).Run(ctx, cloneDeterministicInput(input)); commitResult.Status != StatusPass {
		return moduleTestFailure(StatusFail, "submission is not bound to distinct immutable commits", "module-test-commit-integrity")
	}
	repositoryPath, err := repository.ProjectRepositoryPath(check.repositoryRoot, input.TenantID, input.Manifest.ProjectID)
	if err != nil {
		return moduleTestFailure(StatusError, "project repository is unavailable", "module-test-repository")
	}
	if err := os.MkdirAll(check.workRoot, 0o700); err != nil {
		return moduleTestFailure(StatusError, "module test work root is unavailable", "module-test-work-root")
	}
	environment := moduleTestEnvironment(check.workRoot)
	root, err := os.MkdirTemp(check.workRoot, "aor-module-test-")
	if err != nil {
		return moduleTestFailure(StatusError, "module test workspace could not be created", "module-test-workspace")
	}
	defer os.RemoveAll(root)
	workspace := filepath.Join(root, "checkout")
	cloneCommand := exec.CommandContext(ctx, "git", "-c", "protocol.file.allow=always", "--no-pager", "--no-replace-objects", "clone", "--no-hardlinks", "--no-checkout", "--quiet", repositoryPath, workspace)
	cloneCommand.Env = environment
	cloneOutput := &moduleTestOutput{}
	cloneCommand.Stdout, cloneCommand.Stderr = cloneOutput, cloneOutput
	if err := cloneCommand.Run(); err != nil {
		return moduleTestFailure(StatusError, "submission commit could not be checked out", "module-test-checkout")
	}
	resolved, err := runModuleGitOutput(ctx, workspace, environment, "rev-parse", "--verify", input.Manifest.HeadCommit+"^{commit}")
	if err != nil || strings.TrimSpace(resolved) != input.Manifest.HeadCommit {
		return moduleTestFailure(StatusError, "submission commit could not be verified", "module-test-commit")
	}
	if err := runModuleGit(ctx, workspace, environment, "checkout", "--detach", "--quiet", input.Manifest.HeadCommit); err != nil {
		return moduleTestFailure(StatusError, "submission commit could not be checked out", "module-test-checkout")
	}

	testContext, cancel := context.WithTimeout(ctx, check.timeout)
	defer cancel()
	command := exec.CommandContext(testContext, check.argv[0], check.argv[1:]...)
	command.Dir = workspace
	command.Env = environment
	var stdout, stderr moduleTestOutput
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	status := StatusPass
	if runErr != nil {
		status = StatusFail
		if testContext.Err() != nil {
			status = StatusError
		}
	}
	if stdout.overflow || stderr.overflow {
		status = StatusError
		runErr = errors.New("module test output exceeded the configured limit")
	}
	encodedResult, marshalErr := json.Marshal(struct {
		Command  []string `json:"command"`
		ExitCode int      `json:"exitCode"`
		Status   string   `json:"status"`
	}{Command: append([]string(nil), check.argv...), ExitCode: moduleTestExitCode(runErr), Status: string(status)})
	if marshalErr != nil {
		return moduleTestFailure(StatusError, "module test result could not be encoded", "module-test-result")
	}
	checkResult := CheckResult{Status: status, Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Result: encodedResult}
	if status != StatusPass {
		reason := "configured module test failed"
		if testContext.Err() != nil {
			reason = testContext.Err().Error()
		}
		checkResult.Findings = []contracts.AuditFinding{deterministicFinding(contracts.FindingHigh, "TEST", check.ID(), "", "module-test", "test-failed", "the configured module test passes", reason, "fix the implementation and rerun the configured test")}
	}
	return checkResult
}

func validAbsoluteDirectoryRoot(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.ContainsRune(value, '\x00')
}

func isModuleTestShell(value string) bool {
	base := strings.ToLower(filepath.Base(value))
	switch base {
	case "sh", "bash", "dash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe":
		return true
	default:
		return false
	}
}

func runModuleGit(ctx context.Context, directory string, environment []string, arguments ...string) error {
	command := exec.CommandContext(ctx, "git", append([]string{"--no-pager", "--no-replace-objects", "-C", directory}, arguments...)...)
	command.Env = environment
	command.Stdout = &moduleTestOutput{}
	command.Stderr = &moduleTestOutput{}
	return command.Run()
}

func runModuleGitOutput(ctx context.Context, directory string, environment []string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, "git", append([]string{"--no-pager", "--no-replace-objects", "-C", directory}, arguments...)...)
	command.Env = environment
	var stdout, stderr moduleTestOutput
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return "", err
	}
	return string(stdout.Bytes()), nil
}

func moduleTestEnvironment(workRoot string) []string {
	pathValue := os.Getenv("PATH")
	environment := []string{"HOME=" + workRoot, "TMPDIR=" + workRoot, "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1", "GIT_PROTOCOL_FROM_USER=0", "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly", "GOMAXPROCS=1", "GOMEMLIMIT=384MiB"}
	if pathValue != "" {
		environment = append(environment, "PATH="+pathValue)
	}
	return environment
}

func moduleTestExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func moduleTestFailure(status CheckStatus, reason, code string) CheckResult {
	return CheckResult{Status: status, Findings: []contracts.AuditFinding{deterministicFinding(contracts.FindingHigh, "TEST", "module-tests", "", "module-test", code, "the configured module test can run against the immutable submission", reason, "repair the test environment or implementation")}}
}

type moduleTestOutput struct {
	data     []byte
	overflow bool
}

func (output *moduleTestOutput) Write(value []byte) (int, error) {
	remaining := moduleTestOutputLimit - len(output.data)
	if remaining > len(value) {
		remaining = len(value)
	}
	if remaining > 0 {
		output.data = append(output.data, value[:remaining]...)
	}
	output.overflow = output.overflow || remaining < len(value)
	return len(value), nil
}

func (output *moduleTestOutput) Bytes() []byte {
	return append([]byte(nil), output.data...)
}
