package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
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
	if _, err := backend.Create(context.Background(), linuxSpec()); !errors.Is(err, ErrBackendDrift) {
		t.Fatalf("rootful engine = %v", err)
	}
	if len(runner.args) != 1 {
		t.Fatalf("commands after failed probe = %d", len(runner.args))
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
	info := dockerInfo{OSType: "linux", CgroupVersion: "2", DefaultRuntime: "runc", SecurityOptions: []string{"name=rootless", "name=apparmor"}}
	inspection := dockerInspection{Image: spec.ImageDigest}
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
	encodedInfo, _ := json.Marshal(info)
	encodedInspect, _ := json.Marshal([]dockerInspection{inspection})
	encodedImage, _ := json.Marshal([]map[string]string{{"Id": spec.ImageDigest}})
	return &scriptedRunner{commands: []scriptedCommand{{stdout: string(encodedInfo)}, {stdout: string(encodedImage)}, {stdout: "container-id\n"}, {}, {stdout: string(encodedInspect)}, {}}}
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
