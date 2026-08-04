package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

type scriptedCommand struct {
	stdout string
	exit   int
	err    error
}

type scriptedRunner struct {
	commands []scriptedCommand
	args     [][]string
}

func (r *scriptedRunner) Run(_ context.Context, _ string, args []string, stdout, _ io.Writer) (int, error) {
	r.args = append(r.args, append([]string(nil), args...))
	if len(r.commands) == 0 {
		return -1, errors.New("unexpected command")
	}
	command := r.commands[0]
	r.commands = r.commands[1:]
	_, _ = io.WriteString(stdout, command.stdout)
	return command.exit, command.err
}

func TestDockerBackendCreatesAndInspectsHardenedContainer(t *testing.T) {
	spec := linuxSpec()
	runner := hardenedDockerScript(t, spec, false)
	backend, err := NewDockerBackend(DockerBackendOptions{RuntimeName: "runc", SeccompProfile: "/etc/aor/seccomp.json", MandatoryPolicy: "apparmor=aor-sandbox", Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	provider := NewLinuxProvider(backend, "runc", nil)
	handle, err := provider.Create(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if handle.Attestation.SecurityProfileSHA256 == "" || handle.Attestation.RiskDisclosure == "" {
		t.Fatalf("attestation = %#v", handle.Attestation)
	}
	create := runner.args[2]
	for _, required := range [][]string{{"--read-only"}, {"--cap-drop", "ALL"}, {"--network", "none"}, {"--tmpfs", "/tmp:rw,noexec,nosuid,nodev"}, {"--tmpfs", "/workspace:rw,nosuid,nodev,size=4096"}} {
		if !containsSequence(create, required) {
			t.Fatalf("create args missing %v: %v", required, create)
		}
	}
}

func TestDockerBackendRejectsEngineWithoutRootlessMode(t *testing.T) {
	info := dockerInfo{OSType: "linux", CgroupVersion: "2", DefaultRuntime: "runc", SecurityOptions: []string{"name=apparmor"}}
	encoded, _ := json.Marshal(info)
	runner := &scriptedRunner{commands: []scriptedCommand{{stdout: string(encoded)}}}
	backend, err := NewDockerBackend(DockerBackendOptions{RuntimeName: "runc", SeccompProfile: "/etc/aor/seccomp.json", MandatoryPolicy: "apparmor=aor-sandbox", Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Create(context.Background(), linuxSpec()); !errors.Is(err, ErrBackendDrift) || !strings.Contains(err.Error(), "rootless engine required") {
		t.Fatalf("rootful engine = %v", err)
	}
	if len(runner.args) != 1 {
		t.Fatalf("commands after failed probe = %d", len(runner.args))
	}
}

func TestDockerBackendReadyPinsManifestAndUsesDedicatedEndpoint(t *testing.T) {
	digest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	imageID := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	reference := "golang:1.26@" + digest
	info, _ := json.Marshal(hardenedDockerInfo())
	image, _ := json.Marshal([]map[string]any{{"Id": imageID, "RepoDigests": []string{"golang@" + digest}}})
	runner := &scriptedRunner{commands: []scriptedCommand{{stdout: string(info)}, {stdout: string(image)}}}
	backend, err := NewDockerBackend(DockerBackendOptions{
		Endpoint:        "unix:///run/aor-sandbox/engine.sock",
		RuntimeName:     "runc",
		ImageReference:  reference,
		SeccompProfile:  "builtin",
		MandatoryPolicy: "apparmor=aor-sandbox",
		Runner:          runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(runner.args[0][:2], []string{"--host", "unix:///run/aor-sandbox/engine.sock"}) || !slices.Equal(runner.args[1][2:], []string{"image", "inspect", reference}) {
		t.Fatalf("runtime commands = %v", runner.args)
	}
}

func TestDockerBackendCreatesOnlyConfiguredImmutableImage(t *testing.T) {
	spec := linuxSpec()
	spec.ImageDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	imageID := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	reference := "golang:1.26@" + spec.ImageDigest
	info, _ := json.Marshal(hardenedDockerInfo())
	image, _ := json.Marshal([]map[string]any{{"Id": imageID, "RepoDigests": []string{"golang@" + spec.ImageDigest}}})
	inspection := hardenedInspection(spec, imageID, false)
	encodedInspection, _ := json.Marshal([]dockerInspection{inspection})
	runner := &scriptedRunner{commands: []scriptedCommand{{stdout: string(info)}, {stdout: string(image)}, {stdout: "container-id\n"}, {}, {stdout: string(encodedInspection)}}}
	backend, err := NewDockerBackend(DockerBackendOptions{RuntimeName: "runc", ImageReference: reference, SeccompProfile: "/etc/aor/seccomp.json", MandatoryPolicy: "apparmor=aor-sandbox", Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	provider := NewLinuxProvider(backend, "runc", nil)
	handle, err := provider.Create(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if handle.Attestation.ImageDigest != spec.ImageDigest || !containsSequence(runner.args[2], []string{reference}) {
		t.Fatalf("attestation=%#v create=%v", handle.Attestation, runner.args[2])
	}
}

func TestDockerBackendRejectsMutableOrUnconfinedRuntimeConfiguration(t *testing.T) {
	for _, options := range []DockerBackendOptions{
		{RuntimeName: "runc", ImageReference: "golang:latest", SeccompProfile: "builtin", MandatoryPolicy: "apparmor=aor-sandbox"},
		{RuntimeName: "runc", ImageReference: "golang@sha256:1111111111111111111111111111111111111111111111111111111111111111", SeccompProfile: "unconfined", MandatoryPolicy: "apparmor=aor-sandbox"},
		{RuntimeName: "runc", ImageReference: "golang@sha256:1111111111111111111111111111111111111111111111111111111111111111", SeccompProfile: "Unconfined", MandatoryPolicy: "apparmor=aor-sandbox"},
		{RuntimeName: "runc", ImageReference: "golang@sha256:1111111111111111111111111111111111111111111111111111111111111111", SeccompProfile: "builtin", MandatoryPolicy: "apparmor=unconfined"},
		{Endpoint: "unix:///var/run/docker.sock", RuntimeName: "runc", ImageReference: "golang@sha256:1111111111111111111111111111111111111111111111111111111111111111", SeccompProfile: "builtin", MandatoryPolicy: "apparmor=aor-sandbox"},
		{Endpoint: "unix:////var/run/docker.sock", RuntimeName: "runc", ImageReference: "golang@sha256:1111111111111111111111111111111111111111111111111111111111111111", SeccompProfile: "builtin", MandatoryPolicy: "apparmor=aor-sandbox"},
		{Endpoint: "unix:///run/aor-sandbox/engine.sock\n", RuntimeName: "runc", ImageReference: "golang@sha256:1111111111111111111111111111111111111111111111111111111111111111", SeccompProfile: "builtin", MandatoryPolicy: "apparmor=aor-sandbox"},
		{RuntimeName: "runc\n", ImageReference: "golang@sha256:1111111111111111111111111111111111111111111111111111111111111111", SeccompProfile: "builtin", MandatoryPolicy: "apparmor=aor-sandbox"},
		{RuntimeName: "runc", ImageReference: "golang@sha256:1111111111111111111111111111111111111111111111111111111111111111", SeccompProfile: "builtin", MandatoryPolicy: "apparmor=aor-sandbox", HoldCommand: []string{"relative"}},
	} {
		if _, err := NewDockerBackend(options); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("options %#v error = %v", options, err)
		}
	}
}

func TestDockerBackendRejectsEngineWithoutResourceLimitEnforcement(t *testing.T) {
	info := hardenedDockerInfo()
	info.PidsLimit = false
	encoded, _ := json.Marshal(info)
	runner := &scriptedRunner{commands: []scriptedCommand{{stdout: string(encoded)}}}
	backend, err := NewDockerBackend(DockerBackendOptions{RuntimeName: "runc", SeccompProfile: "builtin", MandatoryPolicy: "apparmor=aor-sandbox", Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Ready(context.Background()); !errors.Is(err, ErrBackendDrift) || !strings.Contains(err.Error(), "limit enforcement") {
		t.Fatalf("engine without PID limits = %v", err)
	}
}

func TestDockerBackendCleansUpAttestationDrift(t *testing.T) {
	spec := linuxSpec()
	runner := hardenedDockerScript(t, spec, true)
	backend, err := NewDockerBackend(DockerBackendOptions{RuntimeName: "runc", SeccompProfile: "/etc/aor/seccomp.json", MandatoryPolicy: "apparmor=aor-sandbox", Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Create(context.Background(), spec); !errors.Is(err, ErrBackendDrift) {
		t.Fatalf("privileged inspection = %v", err)
	}
	if len(runner.args) != 6 || !slices.Equal(runner.args[5], []string{"rm", "--force", "--volumes", spec.SandboxID}) {
		t.Fatalf("cleanup args = %v", runner.args)
	}
}

func hardenedDockerScript(t *testing.T, spec SandboxSpec, privileged bool) *scriptedRunner {
	t.Helper()
	info := hardenedDockerInfo()
	inspection := hardenedInspection(spec, spec.ImageDigest, privileged)
	encodedInfo, _ := json.Marshal(info)
	encodedInspect, _ := json.Marshal([]dockerInspection{inspection})
	encodedImage, _ := json.Marshal([]map[string]string{{"Id": spec.ImageDigest}})
	return &scriptedRunner{commands: []scriptedCommand{{stdout: string(encodedInfo)}, {stdout: string(encodedImage)}, {stdout: "container-id\n"}, {}, {stdout: string(encodedInspect)}, {}}}
}

func hardenedDockerInfo() dockerInfo {
	return dockerInfo{OSType: "linux", CgroupVersion: "2", DefaultRuntime: "runc", SecurityOptions: []string{"name=rootless", "name=apparmor"}, MemoryLimit: true, PidsLimit: true, CPUCfsQuota: true}
}

func hardenedInspection(spec SandboxSpec, imageID string, privileged bool) dockerInspection {
	inspection := dockerInspection{Image: imageID}
	inspection.Config.User = "65532:65532"
	inspection.Config.WorkingDir = "/workspace"
	inspection.HostConfig.ReadonlyRootfs = true
	inspection.HostConfig.Privileged = privileged
	inspection.HostConfig.NetworkMode = "none"
	inspection.HostConfig.CapDrop = []string{"ALL"}
	inspection.HostConfig.SecurityOpt = []string{"no-new-privileges:true", "seccomp=/etc/aor/seccomp.json", "apparmor=aor-sandbox"}
	inspection.HostConfig.PidsLimit = int64(spec.PIDsLimit)
	inspection.HostConfig.Memory = spec.MemoryBytes
	inspection.HostConfig.NanoCPUs = 2_000_000_000
	inspection.HostConfig.Tmpfs = map[string]string{"/tmp": "rw", "/workspace": "rw"}
	return inspection
}

func containsSequence(values, wanted []string) bool {
	if len(wanted) == 0 || len(wanted) > len(values) {
		return false
	}
	for index := 0; index <= len(values)-len(wanted); index++ {
		if slices.Equal(values[index:index+len(wanted)], wanted) {
			return true
		}
	}
	return false
}
