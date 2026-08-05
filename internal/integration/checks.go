package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

const checkOutputLimit = 1 << 20

type CheckCommand struct {
	Kind        CheckKind
	Executable  string
	Arguments   []string
	Environment []string
	Timeout     time.Duration
	OwnerTaskID string
	Tasks       []string
}

type CommandVerifierConfig struct {
	RepositoryPath string
	WorkRoot       string
	Commands       []CheckCommand
	Clock          func() time.Time
}

// CommandVerifier checks an immutable integration commit in a temporary Git
// worktree. Commands are argv arrays and are never evaluated by a shell.
type CommandVerifier struct {
	repositoryPath string
	workRoot       string
	commands       []CheckCommand
	clock          func() time.Time
	mu             sync.Mutex
}

func NewCommandVerifier(config CommandVerifierConfig) (*CommandVerifier, error) {
	repositoryPath, err := verifiedDirectory(config.RepositoryPath)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	workRoot, err := verifiedDirectory(config.WorkRoot)
	if err != nil || repositoryPath == workRoot {
		return nil, ErrInvalidRequest
	}
	commands := append([]CheckCommand(nil), config.Commands...)
	seen := make(map[CheckKind]struct{}, len(commands))
	for index := range commands {
		command := &commands[index]
		command.Arguments = append([]string(nil), command.Arguments...)
		command.Environment = append([]string(nil), command.Environment...)
		command.Tasks = append([]string(nil), command.Tasks...)
		if !validCheckKind(command.Kind) || command.Executable == "" || strings.ContainsRune(command.Executable, '\x00') || command.Timeout <= 0 || command.Timeout > 24*time.Hour {
			return nil, ErrInvalidRequest
		}
		if _, duplicate := seen[command.Kind]; duplicate {
			return nil, ErrInvalidRequest
		}
		seen[command.Kind] = struct{}{}
		for _, value := range append(append([]string(nil), command.Arguments...), command.Environment...) {
			if strings.ContainsRune(value, '\x00') {
				return nil, ErrInvalidRequest
			}
		}
	}
	if len(seen) != len(requiredCheckKinds) {
		return nil, ErrInvalidRequest
	}
	ordered := make([]CheckCommand, 0, len(requiredCheckKinds))
	for _, kind := range requiredCheckKinds {
		for _, command := range commands {
			if command.Kind == kind {
				ordered = append(ordered, command)
				break
			}
		}
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if _, err := NewGitMerger(repositoryPath); err != nil {
		return nil, ErrInvalidRequest
	}
	return &CommandVerifier{repositoryPath: repositoryPath, workRoot: workRoot, commands: ordered, clock: config.Clock}, nil
}

func (verifier *CommandVerifier) Verify(ctx context.Context, input MergeVerificationInput) ([]CheckResult, error) {
	if verifier == nil || ctx == nil || ctx.Err() != nil || input.TenantID == "" || input.ProjectID == "" || input.IntegrationID == "" || !commitID(input.IntegrationCommit) || !commitID(input.BaseCommit) || len(input.Candidates) == 0 {
		return nil, ErrInvalidRequest
	}
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	root, err := os.MkdirTemp(verifier.workRoot, "aor-integration-")
	if err != nil {
		return nil, err
	}
	worktree := filepath.Join(root, "checkout")
	if err := verifier.git(ctx, "worktree", "add", "--detach", worktree, input.IntegrationCommit); err != nil {
		_ = os.Remove(root)
		return nil, err
	}
	checks := make([]CheckResult, 0, len(verifier.commands))
	for _, command := range verifier.commands {
		if ctx.Err() != nil {
			cleanupErr := verifier.cleanup(worktree, root)
			return checks, errors.Join(ctx.Err(), cleanupErr)
		}
		checks = append(checks, verifier.run(ctx, worktree, input, command))
	}
	if err := verifier.cleanup(worktree, root); err != nil {
		return checks, err
	}
	return checks, nil
}

func (verifier *CommandVerifier) run(ctx context.Context, worktree string, input MergeVerificationInput, command CheckCommand) CheckResult {
	started := verifier.clock().UTC()
	checkContext, cancel := context.WithTimeout(ctx, command.Timeout)
	defer cancel()
	process := exec.CommandContext(checkContext, command.Executable, command.Arguments...)
	process.Dir = worktree
	process.Env = commandEnvironment(command.Environment)
	var stdout, stderr boundedCheckOutput
	process.Stdout = &stdout
	process.Stderr = &stderr
	runErr := process.Run()
	completed := verifier.clock().UTC()
	status := CheckPassed
	summary := "integration check passed"
	exitCode := 0
	if runErr != nil {
		status = CheckFailed
		summary = "integration check failed"
		exitCode = -1
		var exitError *exec.ExitError
		if errors.As(runErr, &exitError) {
			exitCode = exitError.ExitCode()
		}
		if checkContext.Err() != nil {
			status = CheckError
			summary = checkContext.Err().Error()
		}
	}
	result := CheckResult{
		Kind: command.Kind, Status: status, Summary: summary, OwnerTaskID: command.OwnerTaskID,
		Tasks: append([]string(nil), command.Tasks...), StartedAt: started, CompletedAt: completed,
	}
	evidence, err := json.Marshal(struct {
		TenantID          string    `json:"tenantId"`
		ProjectID         string    `json:"projectId"`
		IntegrationID     string    `json:"integrationId"`
		IntegrationCommit string    `json:"integrationCommit"`
		Kind              CheckKind `json:"kind"`
		Executable        string    `json:"executable"`
		Arguments         []string  `json:"arguments"`
		ExitCode          int       `json:"exitCode"`
		Stdout            string    `json:"stdout"`
		Stderr            string    `json:"stderr"`
		StartedAt         time.Time `json:"startedAt"`
		CompletedAt       time.Time `json:"completedAt"`
	}{input.TenantID, input.ProjectID, input.IntegrationID, input.IntegrationCommit, command.Kind, command.Executable, command.Arguments, exitCode, stdout.String(), stderr.String(), started, completed})
	if err != nil {
		result.Status = CheckError
		result.Summary = err.Error()
		return result
	}
	result.EvidenceSHA256, err = canonicaljson.Digest(evidence)
	if err != nil {
		result.Status = CheckError
		result.Summary = err.Error()
	}
	return result
}

func (verifier *CommandVerifier) cleanup(worktree, root string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	removeErr := verifier.git(ctx, "worktree", "remove", "--force", worktree)
	rootErr := os.Remove(root)
	return errors.Join(removeErr, rootErr)
}

func (verifier *CommandVerifier) git(ctx context.Context, arguments ...string) error {
	command := exec.CommandContext(ctx, "git", append([]string{"--no-pager", "--no-replace-objects", "--git-dir", verifier.repositoryPath, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"}, arguments...)...)
	command.Dir = verifier.repositoryPath
	command.Env = commandEnvironment(nil)
	var stdout, stderr boundedCheckOutput
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return nil
}

func verifiedDirectory(raw string) (string, error) {
	if raw == "" || !filepath.IsAbs(raw) || filepath.Clean(raw) != raw {
		return "", ErrInvalidRequest
	}
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil || resolved != raw {
		return "", ErrInvalidRequest
	}
	info, err := os.Lstat(raw)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrInvalidRequest
	}
	return raw, nil
}

func commandEnvironment(extra []string) []string {
	environment := []string{
		"LC_ALL=C",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_NO_LAZY_FETCH=1",
		"GIT_PROTOCOL_FROM_USER=0",
	}
	if pathValue := os.Getenv("PATH"); pathValue != "" {
		environment = append(environment, "PATH="+pathValue)
	}
	for _, value := range extra {
		separator := strings.IndexByte(value, '=')
		if separator <= 0 {
			continue
		}
		key := value[:separator]
		if key == "PATH" || key == "LC_ALL" || strings.HasPrefix(key, "GIT_") {
			continue
		}
		environment = append(environment, value)
	}
	return environment
}

type boundedCheckOutput struct {
	data      []byte
	discarded int64
}

func (output *boundedCheckOutput) Write(value []byte) (int, error) {
	remaining := checkOutputLimit - len(output.data)
	if remaining > len(value) {
		remaining = len(value)
	}
	if remaining > 0 {
		output.data = append(output.data, value[:remaining]...)
	}
	output.discarded += int64(len(value) - remaining)
	return len(value), nil
}

func (output *boundedCheckOutput) String() string {
	if output.discarded == 0 {
		return string(output.data)
	}
	return string(output.data) + "\n[truncated " + strconv.FormatInt(output.discarded, 10) + " bytes]"
}

var _ MergeVerifier = (*CommandVerifier)(nil)
