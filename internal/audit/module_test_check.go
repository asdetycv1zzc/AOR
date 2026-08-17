package audit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/toolchain"
	"github.com/akimisaka/aor/pkg/contracts"
)

const moduleTestOutputLimit = 1 << 20

// ModuleTestCheck runs the plan-owned verification entrypoint from the
// immutable submission commit.
type ModuleTestCheck struct {
	repositoryRoot string
	workRoot       string
	toolchains     toolchain.Resolver
	timeout        time.Duration
}

func NewModuleTestCheck(repositoryRoot, workRoot string, toolchains toolchain.Resolver, timeout time.Duration) (*ModuleTestCheck, error) {
	if !validAbsoluteDirectoryRoot(repositoryRoot) || !validAbsoluteDirectoryRoot(workRoot) || filepath.Clean(repositoryRoot) == filepath.Clean(workRoot) || toolchains == nil || timeout <= 0 {
		return nil, ErrInvalidInput
	}
	return &ModuleTestCheck{repositoryRoot: repositoryRoot, workRoot: workRoot, toolchains: toolchains, timeout: timeout}, nil
}

func (check *ModuleTestCheck) ID() string { return "module-tests" }

func (check *ModuleTestCheck) Run(ctx context.Context, input DeterministicInput) CheckResult {
	if check == nil || ctx == nil || ctx.Err() != nil || !commitID(input.Manifest.HeadCommit) || input.Manifest.ProjectID == "" || input.TenantID == "" || input.ModuleSpec == nil || input.ModuleSpec.Validate() != nil || input.ModuleSpec.VerificationEntrypoint == "" || len(input.ModuleSpec.ToolchainIDs) == 0 {
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
	tools, err := check.toolchains.Resolve(ctx, input.ModuleSpec.ToolchainIDs)
	if err != nil {
		return moduleTestFailure(StatusError, "selected module toolchains are unavailable", "module-test-toolchains")
	}
	if err := toolchain.ValidateResolved(tools, input.ModuleSpec.Toolchains); err != nil {
		return moduleTestFailure(StatusError, "selected module toolchain versions no longer match the approved specification", "module-test-toolchain-version")
	}
	binPaths, err := toolchain.BinPaths(check.toolchains.Root(), tools)
	if err != nil {
		return moduleTestFailure(StatusError, "selected module toolchains are invalid", "module-test-toolchains")
	}
	environment := moduleTestEnvironment(check.workRoot, check.toolchains.Root(), binPaths)
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

	entrypoint := filepath.Join(workspace, filepath.FromSlash(input.ModuleSpec.VerificationEntrypoint))
	entrypointInfo, err := os.Lstat(entrypoint)
	if err != nil || !entrypointInfo.Mode().IsRegular() || entrypointInfo.Mode()&os.ModeSymlink != 0 {
		return moduleTestFailure(StatusFail, "planned verification entrypoint is missing from the submission", "module-test-entrypoint")
	}
	argv, err := moduleTestCommand(input.Platform, input.ModuleSpec.VerificationEntrypoint)
	if err != nil {
		return moduleTestFailure(StatusError, "planned verification entrypoint cannot run on this worker", "module-test-platform")
	}
	testContext, cancel := context.WithTimeout(ctx, check.timeout)
	defer cancel()
	command := exec.CommandContext(testContext, argv[0], argv[1:]...)
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
	exitCode := moduleTestExitCode(runErr)
	encodedResult, marshalErr := json.Marshal(struct {
		Command    []string                  `json:"command"`
		Toolchains []contracts.VersionedTool `json:"toolchains"`
		ExitCode   int                       `json:"exitCode"`
		Status     string                    `json:"status"`
	}{Command: append([]string(nil), argv...), Toolchains: append([]contracts.VersionedTool(nil), input.ModuleSpec.Toolchains...), ExitCode: exitCode, Status: string(status)})
	if marshalErr != nil {
		return moduleTestFailure(StatusError, "module test result could not be encoded", "module-test-result")
	}
	checkResult := CheckResult{Status: status, Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Result: encodedResult}
	if status != StatusPass {
		reason := "planned module verification failed with exit code " + strconv.Itoa(exitCode)
		if testContext.Err() != nil {
			reason = testContext.Err().Error()
		}
		checkResult.Findings = []contracts.AuditFinding{deterministicFinding(contracts.FindingHigh, "TEST", check.ID(), input.ModuleSpec.VerificationEntrypoint, "module-test", "test-failed", "the planned module verification passes", reason, "fix the implementation or verification framework and rerun the audit")}
	}
	return checkResult
}

func validAbsoluteDirectoryRoot(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.ContainsRune(value, '\x00')
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

func moduleTestEnvironment(workRoot, toolchainRoot string, toolchainBinPaths []string) []string {
	pathValue := os.Getenv("PATH")
	environment := []string{"HOME=" + workRoot, "TMPDIR=" + workRoot, "LC_ALL=C", "AOR_TOOLCHAIN_ROOT=" + toolchainRoot, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1", "GIT_PROTOCOL_FROM_USER=0"}
	pathParts := append([]string(nil), toolchainBinPaths...)
	if pathValue != "" {
		pathParts = append(pathParts, pathValue)
	}
	if len(pathParts) != 0 {
		environment = append(environment, "PATH="+strings.Join(pathParts, string(os.PathListSeparator)))
	}
	return environment
}

func moduleTestCommand(platform contracts.ExecutionPlatform, entrypoint string) ([]string, error) {
	switch platform {
	case contracts.PlatformLinux:
		if !strings.HasSuffix(strings.ToLower(entrypoint), ".sh") {
			return nil, ErrInvalidInput
		}
		return []string{"/bin/sh", entrypoint}, nil
	case contracts.PlatformWindows:
		if !strings.HasSuffix(strings.ToLower(entrypoint), ".ps1") {
			return nil, ErrInvalidInput
		}
		return []string{"powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", entrypoint}, nil
	default:
		return nil, ErrInvalidInput
	}
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
	return CheckResult{Status: status, Findings: []contracts.AuditFinding{deterministicFinding(contracts.FindingHigh, "TEST", "module-tests", "", "module-test", code, "the planned module verification can run against the immutable submission", reason, "repair the verification framework, toolchain inventory, or implementation")}}
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
