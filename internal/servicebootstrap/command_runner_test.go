package servicebootstrap

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/sandbox"
	"github.com/akimisaka/aor/internal/toolchain"
	"github.com/akimisaka/aor/pkg/contracts"
)

type commandToolchainResolver struct {
	root string
	tool toolchain.InstalledTool
}

func (resolver commandToolchainResolver) Root() string { return resolver.root }

func (resolver commandToolchainResolver) Snapshot(context.Context) (toolchain.Inventory, error) {
	return toolchain.Inventory{Tools: []toolchain.InstalledTool{resolver.tool}}, nil
}

func (resolver commandToolchainResolver) Resolve(context.Context, []string) ([]toolchain.InstalledTool, error) {
	return []toolchain.InstalledTool{resolver.tool}, nil
}

type commandSandboxProviderRecorder struct {
	spec       sandbox.SandboxSpec
	executions []sandbox.ExecRequest
	result     sandbox.ExecResult
	destroyed  string
}

func (provider *commandSandboxProviderRecorder) Create(_ context.Context, spec sandbox.SandboxSpec) (sandbox.SandboxHandle, error) {
	provider.spec = spec
	profileDigest, err := sandbox.SecurityProfileDigest(spec)
	if err != nil {
		return sandbox.SandboxHandle{}, err
	}
	return sandbox.SandboxHandle{
		ID: spec.SandboxID, Platform: spec.Platform, IsolationLevel: spec.IsolationLevel, CreatedAt: time.Now(),
		Attestation: sandbox.Attestation{
			Runtime: "runc", ImageDigest: spec.ImageDigest, SecurityProfileSHA256: profileDigest,
			NonRoot: true, Rootless: true, ReadOnlyRootFS: true, CapabilitiesDropped: true,
			SeccompEnabled: true, MandatoryPolicy: true, CgroupsV2: true, Tmpfs: true, WorkdirReadWrite: true,
		},
	}, nil
}

func (provider *commandSandboxProviderRecorder) Exec(_ context.Context, _ string, request sandbox.ExecRequest) (sandbox.ExecResult, error) {
	provider.executions = append(provider.executions, request)
	if len(provider.executions) == 1 {
		return sandbox.ExecResult{ExitCode: 0}, nil
	}
	return provider.result, nil
}

func (*commandSandboxProviderRecorder) Export(context.Context, string, []string) ([]sandbox.ArtifactRef, error) {
	return nil, sandbox.ErrUnsupported
}

func (*commandSandboxProviderRecorder) Snapshot(context.Context, string) (sandbox.SnapshotRef, error) {
	return sandbox.SnapshotRef{}, sandbox.ErrUnsupported
}

func (*commandSandboxProviderRecorder) Terminate(context.Context, string, string) error { return nil }

func (provider *commandSandboxProviderRecorder) Destroy(_ context.Context, id string) error {
	provider.destroyed = id
	return nil
}

func TestSandboxCommandRunnerUsesDenyAllDisposableWorkspace(t *testing.T) {
	toolRoot := t.TempDir()
	binDirectory := filepath.Join(toolRoot, "go-1", "bin")
	if err := os.MkdirAll(binDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	installed := toolchain.InstalledTool{
		SchemaVersion: 1, ID: "go-1", Kind: contracts.ToolchainCompiler, Name: "go", Version: "1.26.5",
		Platform: contracts.PlatformLinux, Architecture: "amd64", Languages: []string{"go"}, BinDirs: []string{"bin"},
		Executables: []toolchain.Executable{{Name: "go", Path: "bin/go"}},
	}
	pinned := contracts.VersionedTool{
		InventoryID: installed.ID, Kind: installed.Kind, Name: installed.Name, Version: installed.Version,
		Platform: installed.Platform, Architecture: installed.Architecture, Source: contracts.ToolchainInstalled,
	}
	module := dependencyBaseModule("module-command", "modules/command/**")
	module.VerificationEntrypoint = "modules/command/verify.sh"
	module.ToolchainIDs = []string{installed.ID}
	module.Toolchains = []contracts.VersionedTool{pinned}
	if err := module.Validate(); err != nil {
		t.Fatal(err)
	}
	provider := &commandSandboxProviderRecorder{result: sandbox.ExecResult{ExitCode: 1, Stdout: []byte("test output"), Stderr: []byte("failed")}}
	runner, err := newSandboxCommandRunner(provider, commandToolchainResolver{root: toolRoot, tool: installed}, "sha256:"+strings.Repeat("a", 64), t.TempDir(), "PRODUCTION")
	if err != nil {
		t.Fatal(err)
	}
	request := commandRunRequest{
		TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", InvocationID: "invocation-1",
		Executable: "go", Arguments: []string{"test", "./..."}, Directory: t.TempDir(), Timeout: time.Minute, Module: module,
	}
	result, err := runner.Run(context.Background(), request)
	if err != nil || result.ExitCode != 1 || result.Stdout != "test output" || result.Stderr != "failed" {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	if provider.spec.NetworkPolicy.Mode != "DENY_ALL" || !provider.spec.RequiresNetworkIsolation || provider.spec.IsolationLevel != sandbox.IsolationContainer || provider.spec.DeploymentProfile != sandbox.ProfileProduction {
		t.Fatalf("sandbox spec=%#v", provider.spec)
	}
	if len(provider.spec.Mounts) != 3 || provider.spec.Mounts[0].Source != request.Directory || provider.spec.Mounts[0].Target != commandSandboxRepositoryInput {
		t.Fatalf("sandbox mounts=%#v", provider.spec.Mounts)
	}
	for _, mount := range provider.spec.Mounts {
		if mount.Mode != "RO" {
			t.Fatalf("writable sandbox mount=%#v", mount)
		}
	}
	if len(provider.executions) != 2 || provider.executions[0].Executable != commandSandboxCopyExecutable || !reflect.DeepEqual(provider.executions[0].Arguments, []string{"-c", commandSandboxCopyScript}) {
		t.Fatalf("copy execution=%#v", provider.executions)
	}
	command := provider.executions[1]
	if command.Executable != commandSandboxEnvironmentBinary || command.WorkingDir != commandSandboxWorkingDirectory || !containsCommandArgument(command.Arguments, "go") || !containsCommandArgument(command.Arguments, "GOPROXY=off") {
		t.Fatalf("command execution=%#v", command)
	}
	if provider.destroyed != provider.spec.SandboxID {
		t.Fatalf("destroyed=%q sandbox=%q", provider.destroyed, provider.spec.SandboxID)
	}
}

func containsCommandArgument(arguments []string, expected string) bool {
	for _, argument := range arguments {
		if argument == expected {
			return true
		}
	}
	return false
}
