package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/akimisaka/aor/internal/sandbox"
	"github.com/akimisaka/aor/pkg/canonicaljson"
)

const (
	sandboxCheckOutputLimit = 1 << 20
	sandboxCopyTimeout      = 2 * time.Minute
	sandboxWallTimeOverhead = 30 * time.Second
	sandboxMaximumWallTime  = 30 * time.Minute
	sandboxCleanupTimeout   = 30 * time.Second
	sandboxMaximumArguments = 128
	sandboxMaximumArgBytes  = 64 << 10
	sandboxMaximumValueSize = 16 << 10
)

const copyRepositoryCommand = "mkdir -p /workspace/repository && cp -R /workspace/inputs/repository/. /workspace/repository/ && rm -f /workspace/repository/.git"

type SandboxVerifierConfig struct {
	RepositoryPath      string
	WorkRoot            string
	DependencyCachePath string
	Provider            sandbox.SandboxProvider
	ImageDigest         string
	DeploymentProfile   sandbox.DeploymentProfile
	Commands            []CheckCommand
	Clock               func() time.Time
}

// SandboxVerifier runs integration checks in a fresh, network-isolated Linux
// container. Git only creates and removes the trusted detached worktree on the
// worker; candidate-controlled build and test processes never run there.
type SandboxVerifier struct {
	repositoryPath      string
	workRoot            string
	dependencyCachePath string
	provider            sandbox.SandboxProvider
	imageDigest         string
	deploymentProfile   sandbox.DeploymentProfile
	commands            []CheckCommand
	wallTime            time.Duration
	clock               func() time.Time
	mu                  sync.Mutex
}

func NewSandboxVerifier(config SandboxVerifierConfig) (*SandboxVerifier, error) {
	if config.Provider == nil || !digestPattern(config.ImageDigest) ||
		config.DeploymentProfile != sandbox.ProfileLocal && config.DeploymentProfile != sandbox.ProfileProduction {
		return nil, ErrInvalidRequest
	}
	repositoryPath, err := verifiedDirectory(config.RepositoryPath)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	workRoot, err := verifiedDirectory(config.WorkRoot)
	if err != nil || repositoryPath == workRoot {
		return nil, ErrInvalidRequest
	}
	dependencyCachePath, err := verifiedDependencyCache(config.DependencyCachePath)
	if err != nil || dependencyCachePath == repositoryPath || dependencyCachePath == workRoot {
		return nil, ErrInvalidRequest
	}
	commands, wallTime, err := validatedSandboxCommands(config.Commands)
	if err != nil {
		return nil, err
	}
	if _, err := NewGitMerger(repositoryPath); err != nil {
		return nil, ErrInvalidRequest
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &SandboxVerifier{
		repositoryPath:      repositoryPath,
		workRoot:            workRoot,
		dependencyCachePath: dependencyCachePath,
		provider:            config.Provider,
		imageDigest:         config.ImageDigest,
		deploymentProfile:   config.DeploymentProfile,
		commands:            commands,
		wallTime:            wallTime,
		clock:               config.Clock,
	}, nil
}

func (verifier *SandboxVerifier) Verify(ctx context.Context, input MergeVerificationInput) (checks []CheckResult, resultErr error) {
	if verifier == nil || verifier.provider == nil || ctx == nil || ctx.Err() != nil ||
		!canonicalUUID(input.TenantID) || !canonicalUUID(input.ProjectID) || !canonicalUUID(input.IntegrationID) ||
		!commitID(input.IntegrationCommit) || !commitID(input.BaseCommit) || len(input.Candidates) == 0 || !validStoredCandidates(input.Candidates) {
		return nil, ErrInvalidRequest
	}

	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	root, err := os.MkdirTemp(verifier.workRoot, "aor-integration-")
	if err != nil {
		return nil, err
	}
	worktree := filepath.Join(root, "checkout")
	worktreeAdded := false
	sandboxID := ""
	defer func() {
		resultErr = errors.Join(resultErr, verifier.cleanup(ctx, sandboxID, worktree, root, worktreeAdded))
	}()

	if err := verifier.git(ctx, "worktree", "add", "--detach", worktree, input.IntegrationCommit); err != nil {
		return nil, err
	}
	worktreeAdded = true
	if _, err := verifiedDirectory(worktree); err != nil {
		return nil, ErrInvalidRequest
	}

	spec := verifier.sandboxSpec(input, worktree, filepath.Base(root))
	if err := spec.Validate(); err != nil {
		return nil, errors.Join(ErrInvalidRequest, err)
	}
	handle, err := verifier.provider.Create(ctx, spec)
	if err != nil {
		return nil, err
	}
	sandboxID = spec.SandboxID
	if !validIntegrationSandboxHandle(spec, handle) {
		return nil, sandbox.ErrAttestationFailed
	}

	copyDigest, err := verifier.copyRepository(ctx, handle, input)
	if err != nil {
		return nil, err
	}
	checks = make([]CheckResult, 0, len(verifier.commands))
	for _, command := range verifier.commands {
		if ctx.Err() != nil {
			return checks, ctx.Err()
		}
		checks = append(checks, verifier.runCheck(ctx, handle, input, copyDigest, command))
		if ctx.Err() != nil {
			return checks, ctx.Err()
		}
	}
	return checks, nil
}

func (verifier *SandboxVerifier) sandboxSpec(input MergeVerificationInput, worktree, nonce string) sandbox.SandboxSpec {
	allowed := make([]string, 0, len(verifier.commands)+1)
	allowed = append(allowed, "/bin/sh")
	for _, command := range verifier.commands {
		if !containsString(allowed, command.Executable) {
			allowed = append(allowed, command.Executable)
		}
	}
	wallTimeSeconds := int((verifier.wallTime + time.Second - 1) / time.Second)
	return sandbox.SandboxSpec{
		SandboxID:       stableIntegrationSandboxID(input, nonce),
		TenantID:        input.TenantID,
		ProjectID:       input.ProjectID,
		TaskID:          input.IntegrationID,
		Role:            sandbox.RoleAuditor,
		Platform:        sandbox.PlatformLinux,
		IsolationLevel:  sandbox.IsolationContainer,
		ImageDigest:     verifier.imageDigest,
		CPULimit:        "2",
		MemoryBytes:     2 * 1024 * 1024 * 1024,
		PIDsLimit:       256,
		DiskBytes:       2 * 1024 * 1024 * 1024,
		WallTimeSeconds: wallTimeSeconds,
		NetworkPolicy:   sandbox.NetworkPolicy{Mode: "DENY_ALL"},
		Mounts: []sandbox.Mount{
			{Source: worktree, Target: "/workspace/inputs/repository", Mode: "RO"},
			{Source: verifier.dependencyCachePath, Target: "/workspace/inputs/go-mod", Mode: "RO"},
		},
		AllowedExecutables:       allowed,
		EnvironmentAllowlist:     []string{},
		WorkloadTrust:            sandbox.TrustUntrusted,
		DeploymentProfile:        verifier.deploymentProfile,
		RequiresNetworkIsolation: true,
	}
}

func verifiedDependencyCache(raw string) (string, error) {
	if raw == "" || !filepath.IsAbs(raw) || filepath.Clean(raw) != raw {
		return "", ErrInvalidRequest
	}
	parent, err := verifiedDirectory(filepath.Dir(raw))
	if err != nil {
		return "", ErrInvalidRequest
	}
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil {
		return "", ErrInvalidRequest
	}
	relative, err := filepath.Rel(parent, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", ErrInvalidRequest
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrInvalidRequest
	}
	return resolved, nil
}

func (verifier *SandboxVerifier) copyRepository(ctx context.Context, handle sandbox.SandboxHandle, input MergeVerificationInput) (string, error) {
	started := verifier.clock().UTC()
	result, runErr := verifier.provider.Exec(ctx, handle.ID, sandbox.ExecRequest{
		Executable: "/bin/sh",
		Arguments:  []string{"-c", copyRepositoryCommand},
		Timeout:    sandboxCopyTimeout,
	})
	completed := verifier.completedAt(started)
	digest, digestErr := sandboxExecutionDigest(sandboxExecutionEvidence{
		TenantID:           input.TenantID,
		ProjectID:          input.ProjectID,
		IntegrationID:      input.IntegrationID,
		IntegrationCommit:  input.IntegrationCommit,
		Operation:          "COPY_REPOSITORY",
		Executable:         "/bin/sh",
		Arguments:          []string{"-c", copyRepositoryCommand},
		ExitCode:           result.ExitCode,
		Error:              boundedError(runErr),
		StdoutSHA256:       bytesDigest(result.Stdout),
		StdoutBytes:        len(result.Stdout),
		StderrSHA256:       bytesDigest(result.Stderr),
		StderrBytes:        len(result.Stderr),
		StartedAt:          started,
		CompletedAt:        completed,
		SandboxID:          handle.ID,
		SandboxCreatedAt:   handle.CreatedAt,
		SandboxAttestation: handle.Attestation,
	})
	if digestErr != nil {
		return "", digestErr
	}
	if runErr != nil {
		return "", errors.Join(ErrChecksFailed, runErr)
	}
	if result.ExitCode != 0 || len(result.Stdout) > sandboxCheckOutputLimit || len(result.Stderr) > sandboxCheckOutputLimit {
		return "", ErrChecksFailed
	}
	return digest, nil
}

func (verifier *SandboxVerifier) runCheck(ctx context.Context, handle sandbox.SandboxHandle, input MergeVerificationInput, copyDigest string, command CheckCommand) CheckResult {
	started := verifier.clock().UTC()
	execution, runErr := verifier.provider.Exec(ctx, handle.ID, sandbox.ExecRequest{
		Executable: command.Executable,
		Arguments:  append([]string(nil), command.Arguments...),
		WorkingDir: "repository",
		Timeout:    command.Timeout,
	})
	completed := verifier.completedAt(started)
	status := CheckPassed
	summary := "integration check passed"
	if execution.ExitCode != 0 {
		status = CheckFailed
		summary = "integration check exited with status " + strconv.Itoa(execution.ExitCode)
	}
	if runErr != nil {
		status = CheckError
		summary = sandboxExecutionSummary(runErr)
	}
	if len(execution.Stdout) > sandboxCheckOutputLimit || len(execution.Stderr) > sandboxCheckOutputLimit {
		status = CheckError
		summary = "integration check output exceeded limit"
	}

	result := CheckResult{
		Kind:        command.Kind,
		Status:      status,
		Summary:     summary,
		OwnerTaskID: command.OwnerTaskID,
		Tasks:       append([]string(nil), command.Tasks...),
		StartedAt:   started,
		CompletedAt: completed,
	}
	evidence, err := sandboxExecutionDigest(sandboxExecutionEvidence{
		TenantID:             input.TenantID,
		ProjectID:            input.ProjectID,
		IntegrationID:        input.IntegrationID,
		IntegrationCommit:    input.IntegrationCommit,
		BaseCommit:           input.BaseCommit,
		CandidateCommits:     candidateCommits(input.Candidates),
		Operation:            string(command.Kind),
		Executable:           command.Executable,
		Arguments:            append([]string(nil), command.Arguments...),
		ExitCode:             execution.ExitCode,
		Error:                boundedError(runErr),
		StdoutSHA256:         bytesDigest(execution.Stdout),
		StdoutBytes:          len(execution.Stdout),
		StderrSHA256:         bytesDigest(execution.Stderr),
		StderrBytes:          len(execution.Stderr),
		StartedAt:            started,
		CompletedAt:          completed,
		SandboxID:            handle.ID,
		SandboxCreatedAt:     handle.CreatedAt,
		SandboxAttestation:   handle.Attestation,
		RepositoryCopySHA256: copyDigest,
	})
	if err != nil {
		result.Status = CheckError
		result.Summary = "integration check evidence failed"
		return result
	}
	result.EvidenceSHA256 = evidence
	return result
}

func (verifier *SandboxVerifier) completedAt(started time.Time) time.Time {
	completed := verifier.clock().UTC()
	if completed.Before(started) {
		return started
	}
	return completed
}

func (verifier *SandboxVerifier) cleanup(parent context.Context, sandboxID, worktree, root string, worktreeAdded bool) error {
	var destroyErr error
	if sandboxID != "" {
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(parent), sandboxCleanupTimeout)
		destroyErr = verifier.provider.Destroy(cleanupContext, sandboxID)
		cancel()
	}
	var worktreeErr error
	if worktreeAdded {
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(parent), sandboxCleanupTimeout)
		worktreeErr = verifier.git(cleanupContext, "worktree", "remove", "--force", worktree)
		cancel()
	}
	rootErr := os.Remove(root)
	if destroyErr != nil || worktreeErr != nil || rootErr != nil {
		return errors.Join(sandbox.ErrCleanupFailed, destroyErr, worktreeErr, rootErr)
	}
	return nil
}

func (verifier *SandboxVerifier) git(ctx context.Context, arguments ...string) error {
	base := []string{"--no-pager", "--no-replace-objects", "--git-dir", verifier.repositoryPath, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"}
	command := exec.CommandContext(ctx, "git", append(base, arguments...)...)
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

func validatedSandboxCommands(input []CheckCommand) ([]CheckCommand, time.Duration, error) {
	if len(input) != len(requiredCheckKinds) {
		return nil, 0, ErrInvalidRequest
	}
	byKind := make(map[CheckKind]CheckCommand, len(input))
	total := sandboxCopyTimeout + sandboxWallTimeOverhead
	for _, original := range input {
		command := original
		command.Arguments = append([]string(nil), original.Arguments...)
		command.Tasks = append([]string(nil), original.Tasks...)
		if !validCheckKind(command.Kind) || !validExecutable(command.Executable) || len(command.Environment) != 0 ||
			command.Timeout <= 0 || command.Timeout > sandboxMaximumWallTime || !validTaskBinding(command.OwnerTaskID, command.Tasks) {
			return nil, 0, ErrInvalidRequest
		}
		if _, duplicate := byKind[command.Kind]; duplicate || !validArguments(command.Arguments) {
			return nil, 0, ErrInvalidRequest
		}
		byKind[command.Kind] = command
		total += command.Timeout
	}
	if total > sandboxMaximumWallTime {
		return nil, 0, ErrInvalidRequest
	}
	ordered := make([]CheckCommand, 0, len(requiredCheckKinds))
	for _, kind := range requiredCheckKinds {
		command, exists := byKind[kind]
		if !exists {
			return nil, 0, ErrInvalidRequest
		}
		ordered = append(ordered, command)
	}
	return ordered, total, nil
}

func validExecutable(value string) bool {
	if value == "" || len(value) > sandboxMaximumValueSize || shellExecutable(value) {
		return false
	}
	return safeArgumentValue(value)
}

func shellExecutable(value string) bool {
	switch strings.ToLower(filepath.Base(value)) {
	case "sh", "bash", "dash", "ash", "ksh", "zsh", "csh", "tcsh", "fish", "pwsh", "powershell", "cmd", "cmd.exe":
		return true
	default:
		return false
	}
}

func validArguments(arguments []string) bool {
	if len(arguments) > sandboxMaximumArguments {
		return false
	}
	total := 0
	for _, argument := range arguments {
		if len(argument) > sandboxMaximumValueSize || !safeArgumentValue(argument) {
			return false
		}
		total += len(argument)
		if total > sandboxMaximumArgBytes {
			return false
		}
	}
	return true
}

func safeArgumentValue(value string) bool {
	for _, character := range value {
		if character == 0 || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validTaskBinding(ownerTaskID string, tasks []string) bool {
	if len(tasks) > 1024 || ownerTaskID != "" && !safeBoundedText(ownerTaskID, 256) {
		return false
	}
	seen := make(map[string]struct{}, len(tasks))
	for _, taskID := range tasks {
		if !safeBoundedText(taskID, 256) {
			return false
		}
		if _, duplicate := seen[taskID]; duplicate {
			return false
		}
		seen[taskID] = struct{}{}
	}
	return ownerTaskID == "" || containsString(tasks, ownerTaskID)
}

func safeBoundedText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && safeArgumentValue(value)
}

func stableIntegrationSandboxID(input MergeVerificationInput, nonce string) string {
	digest := sha256.Sum256([]byte(input.TenantID + "\x00" + input.ProjectID + "\x00" + input.IntegrationID + "\x00" + input.IntegrationCommit + "\x00" + nonce))
	return "integration-sandbox-" + hex.EncodeToString(digest[:])
}

func validIntegrationSandboxHandle(spec sandbox.SandboxSpec, handle sandbox.SandboxHandle) bool {
	profileDigest, err := sandbox.SecurityProfileDigest(spec)
	attestation := handle.Attestation
	return err == nil && handle.ID == spec.SandboxID && handle.Platform == sandbox.PlatformLinux && handle.IsolationLevel == sandbox.IsolationContainer &&
		attestation.SecurityProfileSHA256 == profileDigest && attestation.ImageDigest == spec.ImageDigest && attestation.Runtime != "" &&
		attestation.NonRoot && (attestation.Rootless || attestation.UserNamespace) && attestation.ReadOnlyRootFS &&
		attestation.CapabilitiesDropped && attestation.SeccompEnabled && attestation.MandatoryPolicy && attestation.CgroupsV2 &&
		attestation.Tmpfs && attestation.WorkdirReadWrite && !attestation.HostDevices && !attestation.HostPID && !attestation.HostNetwork &&
		!attestation.Privileged && !attestation.RuntimeSocket
}

type sandboxExecutionEvidence struct {
	TenantID             string              `json:"tenantId"`
	ProjectID            string              `json:"projectId"`
	IntegrationID        string              `json:"integrationId"`
	IntegrationCommit    string              `json:"integrationCommit"`
	BaseCommit           string              `json:"baseCommit,omitempty"`
	CandidateCommits     []string            `json:"candidateCommits,omitempty"`
	Operation            string              `json:"operation"`
	Executable           string              `json:"executable"`
	Arguments            []string            `json:"arguments"`
	ExitCode             int                 `json:"exitCode"`
	Error                string              `json:"error,omitempty"`
	StdoutSHA256         string              `json:"stdoutSha256"`
	StdoutBytes          int                 `json:"stdoutBytes"`
	StderrSHA256         string              `json:"stderrSha256"`
	StderrBytes          int                 `json:"stderrBytes"`
	StartedAt            time.Time           `json:"startedAt"`
	CompletedAt          time.Time           `json:"completedAt"`
	SandboxID            string              `json:"sandboxId"`
	SandboxCreatedAt     time.Time           `json:"sandboxCreatedAt"`
	SandboxAttestation   sandbox.Attestation `json:"sandboxAttestation"`
	RepositoryCopySHA256 string              `json:"repositoryCopySha256,omitempty"`
}

func sandboxExecutionDigest(evidence sandboxExecutionEvidence) (string, error) {
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func bytesDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) > 1024 {
		return value[:1024]
	}
	return value
}

func sandboxExecutionSummary(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "integration check timed out"
	case errors.Is(err, context.Canceled):
		return "integration check canceled"
	case errors.Is(err, sandbox.ErrOutputLimit):
		return "integration check output exceeded limit"
	default:
		return "integration check runtime failed"
	}
}

func candidateCommits(candidates []Candidate) []string {
	commits := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		commits = append(commits, candidate.SubmissionCommit)
	}
	sort.Strings(commits)
	return commits
}

var _ MergeVerifier = (*SandboxVerifier)(nil)
