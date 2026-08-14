package servicebootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/sandbox"
	"github.com/akimisaka/aor/internal/toolchain"
	"github.com/akimisaka/aor/pkg/contracts"
)

const (
	commandSandboxCopyTimeout       = 2 * time.Minute
	commandSandboxCleanupTimeout    = 30 * time.Second
	commandSandboxRepositoryInput   = "/workspace/inputs/repository"
	commandSandboxToolchainInput    = "/workspace/inputs/toolchains"
	commandSandboxDependencyInput   = "/workspace/inputs/go-mod"
	commandSandboxWorkingDirectory  = "repository"
	commandSandboxCopyExecutable    = "/bin/sh"
	commandSandboxEnvironmentBinary = "/usr/bin/env"
)

const commandSandboxCopyScript = "mkdir -p /workspace/repository && cp -R /workspace/inputs/repository/. /workspace/repository/ && rm -f /workspace/repository/.git"

type sandboxCommandRunner struct {
	provider        sandbox.SandboxProvider
	toolchains      toolchain.Resolver
	imageDigest     string
	dependencyCache string
	profile         sandbox.DeploymentProfile
}

func newSandboxCommandRunner(provider sandbox.SandboxProvider, toolchains toolchain.Resolver, imageDigest, dependencyCache, deploymentProfile string) (*sandboxCommandRunner, error) {
	if provider == nil || toolchains == nil || !validCommandRoot(toolchains.Root()) || !strings.HasPrefix(imageDigest, "sha256:") || len(imageDigest) != len("sha256:")+64 {
		return nil, ErrWorkerConfiguration
	}
	if dependencyCache != "" && !validCommandRoot(dependencyCache) {
		return nil, ErrWorkerConfiguration
	}
	profile := sandbox.ProfileLocal
	if deploymentProfile == "PREPRODUCTION" || deploymentProfile == "PRODUCTION" {
		profile = sandbox.ProfileProduction
	}
	return &sandboxCommandRunner{provider: provider, toolchains: toolchains, imageDigest: imageDigest, dependencyCache: dependencyCache, profile: profile}, nil
}

func (runner *sandboxCommandRunner) Run(ctx context.Context, request commandRunRequest) (result commandRunResult, resultErr error) {
	if runner == nil || runner.provider == nil || runner.toolchains == nil || ctx == nil || request.Timeout <= 0 || request.Timeout > time.Hour ||
		!validCommandRoot(request.Directory) || request.Module.Validate() != nil || request.Module.ExecutionPlatform != contracts.PlatformLinux || request.Module.SandboxLevel != contracts.IsolationContainer ||
		request.TenantID == "" || request.ProjectID == "" || request.TaskID == "" || request.InvocationID == "" {
		return commandRunResult{}, repository.ErrInvalidRequest
	}
	installed, err := runner.toolchains.Resolve(ctx, request.Module.ToolchainIDs)
	if err != nil || toolchain.ValidateResolved(installed, request.Module.Toolchains) != nil {
		return commandRunResult{}, repository.ErrInvalidRequest
	}
	binPaths, err := toolchain.BinPaths(runner.toolchains.Root(), installed)
	if err != nil {
		return commandRunResult{}, repository.ErrInvalidRequest
	}
	spec, environment, err := runner.spec(request, binPaths)
	if err != nil {
		return commandRunResult{}, err
	}
	if err := spec.Validate(); err != nil {
		return commandRunResult{}, repository.ErrInvalidRequest
	}
	handle, err := runner.provider.Create(ctx, spec)
	if err != nil {
		return commandRunResult{}, err
	}
	defer func() {
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), commandSandboxCleanupTimeout)
		defer cancel()
		if err := runner.provider.Destroy(cleanupContext, handle.ID); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	if !validCommandSandboxHandle(spec, handle) {
		return commandRunResult{}, sandbox.ErrAttestationFailed
	}
	copyResult, err := runner.provider.Exec(ctx, handle.ID, sandbox.ExecRequest{
		Executable: commandSandboxCopyExecutable, Arguments: []string{"-c", commandSandboxCopyScript}, Timeout: commandSandboxCopyTimeout,
	})
	if err != nil || copyResult.ExitCode != 0 || len(copyResult.Stdout) > commandToolOutputLimit || len(copyResult.Stderr) > commandToolOutputLimit {
		if err != nil {
			return commandRunResult{}, err
		}
		return commandRunResult{}, repository.ErrInvalidRequest
	}
	execArguments := append(environment, "--", request.Executable)
	execArguments = append(execArguments, request.Arguments...)
	execution, err := runner.provider.Exec(ctx, handle.ID, sandbox.ExecRequest{
		Executable: commandSandboxEnvironmentBinary, Arguments: execArguments,
		WorkingDir: commandSandboxWorkingDirectory, Timeout: request.Timeout,
	})
	result = commandRunResult{ExitCode: execution.ExitCode}
	result.Stdout, result.StdoutTruncated = boundedCommandOutput(execution.Stdout)
	result.Stderr, result.StderrTruncated = boundedCommandOutput(execution.Stderr)
	if err == nil {
		return result, nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) && ctx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		return result, nil
	}
	if errors.Is(err, sandbox.ErrOutputLimit) {
		result.StdoutTruncated = true
		result.StderrTruncated = true
		return result, nil
	}
	return result, err
}

func (runner *sandboxCommandRunner) spec(request commandRunRequest, binPaths []string) (sandbox.SandboxSpec, []string, error) {
	containerBinPaths := make([]string, 0, len(binPaths)+1)
	for _, binPath := range binPaths {
		relative, err := filepath.Rel(runner.toolchains.Root(), binPath)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return sandbox.SandboxSpec{}, nil, repository.ErrInvalidRequest
		}
		containerBinPaths = append(containerBinPaths, path.Join(commandSandboxToolchainInput, filepath.ToSlash(relative)))
	}
	containerBinPaths = append(containerBinPaths, "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	environment := []string{
		"HOME=/tmp", "TMPDIR=/tmp", "LC_ALL=C", "PATH=" + strings.Join(containerBinPaths, ":"),
		"AOR_TOOLCHAIN_ROOT=" + commandSandboxToolchainInput,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1", "GIT_PROTOCOL_FROM_USER=0",
		"GOPROXY=off", "GOSUMDB=off", "GONOSUMDB=*", "NPM_CONFIG_OFFLINE=true", "YARN_ENABLE_NETWORK=0", "PIP_NO_INDEX=1", "CARGO_NET_OFFLINE=true",
	}
	mounts := []sandbox.Mount{
		{Source: request.Directory, Target: commandSandboxRepositoryInput, Mode: "RO"},
		{Source: runner.toolchains.Root(), Target: commandSandboxToolchainInput, Mode: "RO"},
	}
	if runner.dependencyCache != "" {
		mounts = append(mounts, sandbox.Mount{Source: runner.dependencyCache, Target: commandSandboxDependencyInput, Mode: "RO"})
		environment = append(environment, "GOMODCACHE="+commandSandboxDependencyInput, "GOFLAGS=-mod=readonly")
	}
	trust := sandbox.TrustUntrusted
	if request.Module.WorkloadProfile.Trust == contracts.WorkloadTrusted {
		trust = sandbox.TrustTrusted
	}
	wallTime := commandSandboxCopyTimeout + request.Timeout + commandSandboxCleanupTimeout
	return sandbox.SandboxSpec{
		SandboxID: stableCommandSandboxID(request), TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		Role: sandbox.RoleExecutor, Platform: sandbox.PlatformLinux, IsolationLevel: sandbox.IsolationContainer,
		ImageDigest: runner.imageDigest, CPULimit: "2", MemoryBytes: 2 << 30, PIDsLimit: 256, DiskBytes: 2 << 30,
		WallTimeSeconds: int((wallTime + time.Second - 1) / time.Second), NetworkPolicy: sandbox.NetworkPolicy{Mode: "DENY_ALL"},
		Mounts: mounts, AllowedExecutables: []string{commandSandboxCopyExecutable, commandSandboxEnvironmentBinary},
		EnvironmentAllowlist: []string{}, WorkloadTrust: trust, DeploymentProfile: runner.profile,
		RequiresNetworkIsolation: true, HostileMultiTenant: request.Module.WorkloadProfile.HostileMultiTenant,
	}, environment, nil
}

func stableCommandSandboxID(request commandRunRequest) string {
	digest := sha256.Sum256([]byte(request.TenantID + "\x00" + request.ProjectID + "\x00" + request.TaskID + "\x00" + request.InvocationID))
	return "aor-command-" + hex.EncodeToString(digest[:])
}

func validCommandSandboxHandle(spec sandbox.SandboxSpec, handle sandbox.SandboxHandle) bool {
	profileDigest, err := sandbox.SecurityProfileDigest(spec)
	attestation := handle.Attestation
	return err == nil && handle.ID == spec.SandboxID && handle.Platform == spec.Platform && handle.IsolationLevel == spec.IsolationLevel &&
		attestation.SecurityProfileSHA256 == profileDigest && attestation.ImageDigest == spec.ImageDigest && attestation.Runtime != "" &&
		attestation.NonRoot && (attestation.Rootless || attestation.UserNamespace) && attestation.ReadOnlyRootFS &&
		attestation.CapabilitiesDropped && attestation.SeccompEnabled && attestation.MandatoryPolicy && attestation.CgroupsV2 &&
		attestation.Tmpfs && attestation.WorkdirReadWrite && !attestation.HostDevices && !attestation.HostPID && !attestation.HostNetwork &&
		!attestation.Privileged && !attestation.RuntimeSocket
}

func validCommandRoot(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value && value != string(filepath.Separator) && !strings.ContainsAny(value, "\x00\r\n")
}

func boundedCommandOutput(value []byte) (string, bool) {
	truncated := len(value) > commandToolOutputLimit
	if truncated {
		value = value[:commandToolOutputLimit]
	}
	for !utf8.Valid(value) && len(value) > 0 {
		value = value[:len(value)-1]
		truncated = true
	}
	return string(value), truncated
}

var _ commandRunner = (*sandboxCommandRunner)(nil)
