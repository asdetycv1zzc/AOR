package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxCapturedOutput = 1 << 20

var (
	ErrBackendUnavailable = errors.New("sandbox backend unavailable")
	ErrBackendDrift       = errors.New("sandbox backend security configuration drift")
	ErrOutputLimit        = errors.New("sandbox output exceeded inline limit")
)

type CommandRunner interface {
	Run(ctx context.Context, executable string, args []string, stdout, stderr io.Writer) (int, error)
}

type OSCommandRunner struct{}

func (OSCommandRunner) Run(ctx context.Context, executable string, args []string, stdout, stderr io.Writer) (int, error) {
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if err == nil {
		return 0, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode(), err
	}
	return -1, err
}

type StoredBlob struct {
	URI    string
	SHA256 string
	Size   int64
}

type BlobStore interface {
	Put(ctx context.Context, mediaType string, encrypted bool, produce func(io.Writer) error) (StoredBlob, error)
}

type DockerBackendOptions struct {
	Binary               string
	RuntimeName          string
	SeccompProfile       string
	MandatoryPolicy      string
	HoldCommand          []string
	Runner               CommandRunner
	BlobStore            BlobStore
	MaxInlineOutputBytes int
}

type DockerBackend struct {
	binary          string
	runtime         string
	seccomp         string
	mandatoryPolicy string
	holdCommand     []string
	runner          CommandRunner
	blobs           BlobStore
	maxOutput       int
}

func NewDockerBackend(options DockerBackendOptions) (*DockerBackend, error) {
	if options.Binary == "" {
		options.Binary = "docker"
	}
	if options.RuntimeName == "" || options.SeccompProfile == "" || options.MandatoryPolicy == "" || options.MandatoryPolicy == "unconfined" || strings.ContainsAny(options.MandatoryPolicy, "\r\n") {
		return nil, ErrInvalidSpec
	}
	if options.Runner == nil {
		options.Runner = OSCommandRunner{}
	}
	if len(options.HoldCommand) == 0 {
		options.HoldCommand = []string{"/aor/runtime/hold"}
	}
	if options.MaxInlineOutputBytes <= 0 || options.MaxInlineOutputBytes > maxCapturedOutput {
		options.MaxInlineOutputBytes = maxCapturedOutput
	}
	return &DockerBackend{binary: options.Binary, runtime: options.RuntimeName, seccomp: options.SeccompProfile, mandatoryPolicy: options.MandatoryPolicy, holdCommand: append([]string(nil), options.HoldCommand...), runner: options.Runner, blobs: options.BlobStore, maxOutput: options.MaxInlineOutputBytes}, nil
}

func (b *DockerBackend) Create(ctx context.Context, spec SandboxSpec) (attestation Attestation, err error) {
	if spec.Platform != PlatformLinux || spec.NetworkPolicy.Mode != "DENY_ALL" {
		return Attestation{}, ErrUnsupported
	}
	info, err := b.inspectEngine(ctx)
	if err != nil {
		return Attestation{}, err
	}
	if err := b.verifyImage(ctx, spec.ImageDigest); err != nil {
		return Attestation{}, err
	}
	args, err := b.createArgs(spec)
	if err != nil {
		return Attestation{}, err
	}
	created := false
	defer func() {
		if err != nil && created {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, _, _ = b.capture(cleanupContext, []string{"rm", "--force", "--volumes", spec.SandboxID})
			cancel()
		}
	}()
	_, output, err := b.capture(ctx, args)
	if err != nil || strings.TrimSpace(output) == "" {
		return Attestation{}, backendError(err)
	}
	created = true
	if _, _, err = b.capture(ctx, []string{"start", spec.SandboxID}); err != nil {
		return Attestation{}, backendError(err)
	}
	inspection, err := b.inspectContainer(ctx, spec.SandboxID)
	if err != nil {
		return Attestation{}, err
	}
	attestation, err = b.attest(spec, info, inspection)
	if err != nil {
		return Attestation{}, err
	}
	return attestation, nil
}

func (b *DockerBackend) Exec(ctx context.Context, id string, request ExecRequest) (ExecResult, error) {
	args := []string{"exec"}
	if request.WorkingDir != "" {
		args = append(args, "--workdir", "/workspace/"+request.WorkingDir)
	} else {
		args = append(args, "--workdir", "/workspace")
	}
	args = append(args, id, request.Executable)
	args = append(args, request.Arguments...)
	stdout := newCappedBuffer(b.maxOutput)
	stderr := newCappedBuffer(b.maxOutput)
	started := time.Now().UTC()
	exitCode, err := b.runner.Run(ctx, b.binary, args, stdout, stderr)
	finished := time.Now().UTC()
	result := ExecResult{ExitCode: exitCode, Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), StartedAt: started, FinishedAt: finished}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	var exitError *exec.ExitError
	if err != nil && !errors.As(err, &exitError) {
		return result, ErrBackendUnavailable
	}
	if stdout.Truncated() || stderr.Truncated() {
		return result, ErrOutputLimit
	}
	return result, nil
}

func (b *DockerBackend) Export(ctx context.Context, id string, paths []string) ([]ArtifactRef, error) {
	if b.blobs == nil {
		return nil, ErrUnsupported
	}
	artifacts := make([]ArtifactRef, 0, len(paths))
	for _, artifactPath := range paths {
		stored, err := b.blobs.Put(ctx, "application/vnd.aor.sandbox-export.v1.tar", false, func(destination io.Writer) error {
			return b.stream(ctx, []string{"cp", id + ":/workspace/" + artifactPath, "-"}, destination)
		})
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, ArtifactRef{Path: artifactPath, URI: stored.URI, SHA256: stored.SHA256, Size: stored.Size})
	}
	return artifacts, nil
}

func (b *DockerBackend) Snapshot(ctx context.Context, id string) (SnapshotRef, error) {
	if b.blobs == nil {
		return SnapshotRef{}, ErrUnsupported
	}
	stored, err := b.blobs.Put(ctx, "application/vnd.oci.image.layer.v1.tar", true, func(destination io.Writer) error {
		return b.stream(ctx, []string{"export", id}, destination)
	})
	if err != nil {
		return SnapshotRef{}, err
	}
	return SnapshotRef{URI: stored.URI, SHA256: stored.SHA256}, nil
}

func (b *DockerBackend) Terminate(ctx context.Context, id, _ string) error {
	_, _, err := b.capture(ctx, []string{"stop", "--time", "10", id})
	return backendError(err)
}

func (b *DockerBackend) Destroy(ctx context.Context, id string) error {
	_, _, err := b.capture(ctx, []string{"rm", "--force", "--volumes", id})
	return backendError(err)
}

type dockerInfo struct {
	OSType          string   `json:"OSType"`
	CgroupVersion   string   `json:"CgroupVersion"`
	DefaultRuntime  string   `json:"DefaultRuntime"`
	SecurityOptions []string `json:"SecurityOptions"`
}

type dockerInspection struct {
	Image  string `json:"Image"`
	Config struct {
		User       string `json:"User"`
		WorkingDir string `json:"WorkingDir"`
	} `json:"Config"`
	HostConfig struct {
		ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
		Privileged     bool              `json:"Privileged"`
		NetworkMode    string            `json:"NetworkMode"`
		PidMode        string            `json:"PidMode"`
		CapDrop        []string          `json:"CapDrop"`
		SecurityOpt    []string          `json:"SecurityOpt"`
		PidsLimit      int64             `json:"PidsLimit"`
		Memory         int64             `json:"Memory"`
		NanoCPUs       int64             `json:"NanoCpus"`
		Tmpfs          map[string]string `json:"Tmpfs"`
		Devices        []json.RawMessage `json:"Devices"`
		Binds          []string          `json:"Binds"`
	} `json:"HostConfig"`
}

func (b *DockerBackend) inspectEngine(ctx context.Context) (dockerInfo, error) {
	var info dockerInfo
	if err := b.captureJSON(ctx, []string{"info", "--format", "{{json .}}"}, &info); err != nil {
		return info, err
	}
	rootless := includesFold(info.SecurityOptions, "rootless")
	mandatory := includesFold(info.SecurityOptions, "apparmor") || includesFold(info.SecurityOptions, "selinux")
	if info.OSType != "linux" || info.CgroupVersion != "2" || info.DefaultRuntime != b.runtime || !rootless || !mandatory {
		return info, ErrBackendDrift
	}
	return info, nil
}

func (b *DockerBackend) verifyImage(ctx context.Context, digest string) error {
	var images []struct {
		ID string `json:"Id"`
	}
	if err := b.captureJSON(ctx, []string{"image", "inspect", digest}, &images); err != nil {
		return err
	}
	if len(images) != 1 || images[0].ID != digest {
		return ErrBackendDrift
	}
	return nil
}

func (b *DockerBackend) inspectContainer(ctx context.Context, id string) (dockerInspection, error) {
	var inspections []dockerInspection
	if err := b.captureJSON(ctx, []string{"inspect", id}, &inspections); err != nil {
		return dockerInspection{}, err
	}
	if len(inspections) != 1 {
		return dockerInspection{}, ErrBackendDrift
	}
	return inspections[0], nil
}

func (b *DockerBackend) createArgs(spec SandboxSpec) ([]string, error) {
	if !sandboxIDPattern.MatchString(spec.SandboxID) || strings.ContainsAny(b.seccomp, "\r\n") {
		return nil, ErrInvalidSpec
	}
	cpus, err := strconv.ParseFloat(spec.CPULimit, 64)
	if err != nil || cpus <= 0 {
		return nil, ErrInvalidSpec
	}
	args := []string{"create", "--name", spec.SandboxID, "--pull", "never", "--read-only", "--user", "65532:65532", "--init", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--security-opt", "seccomp=" + b.seccomp, "--security-opt", b.mandatoryPolicy, "--pids-limit", strconv.Itoa(spec.PIDsLimit), "--memory", strconv.FormatInt(spec.MemoryBytes, 10), "--cpus", spec.CPULimit, "--network", "none", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev", "--tmpfs", "/workspace:rw,nosuid,nodev,size=" + strconv.FormatInt(spec.DiskBytes, 10), "--workdir", "/workspace"}
	for _, mount := range spec.Mounts {
		if strings.ContainsAny(mount.Source+mount.Target, ",\r\n") || mount.Mode != "RO" {
			return nil, ErrUnsafeWorkload
		}
		args = append(args, "--mount", "type=bind,src="+mount.Source+",dst="+mount.Target+",readonly")
	}
	args = append(args, spec.ImageDigest)
	args = append(args, b.holdCommand...)
	return args, nil
}

func (b *DockerBackend) attest(spec SandboxSpec, info dockerInfo, inspection dockerInspection) (Attestation, error) {
	expectedCPUs, _ := strconv.ParseFloat(spec.CPULimit, 64)
	expectedNanoCPUs := int64(expectedCPUs * 1_000_000_000)
	nonRoot := inspection.Config.User != "" && inspection.Config.User != "0" && inspection.Config.User != "root" && !strings.HasPrefix(inspection.Config.User, "0:")
	security := inspection.HostConfig.SecurityOpt
	valid := inspection.Image == spec.ImageDigest && inspection.Config.WorkingDir == "/workspace" && nonRoot && inspection.HostConfig.ReadonlyRootfs && !inspection.HostConfig.Privileged && inspection.HostConfig.NetworkMode == "none" && inspection.HostConfig.PidMode == "" && includesExactFold(inspection.HostConfig.CapDrop, "ALL") && includesFold(security, "no-new-privileges") && includesFold(security, "seccomp="+b.seccomp) && includesFold(security, b.mandatoryPolicy) && inspection.HostConfig.PidsLimit == int64(spec.PIDsLimit) && inspection.HostConfig.Memory == spec.MemoryBytes && inspection.HostConfig.NanoCPUs == expectedNanoCPUs && len(inspection.HostConfig.Devices) == 0 && hasTmpfs(inspection.HostConfig.Tmpfs, "/tmp") && hasTmpfs(inspection.HostConfig.Tmpfs, "/workspace") && !containsRuntimeSocket(inspection.HostConfig.Binds)
	if !valid {
		return Attestation{}, ErrBackendDrift
	}
	digest, err := SecurityProfileDigest(spec)
	if err != nil {
		return Attestation{}, err
	}
	return Attestation{SecurityProfileSHA256: digest, ImageDigest: spec.ImageDigest, Runtime: info.DefaultRuntime, NonRoot: true, Rootless: true, ReadOnlyRootFS: true, CapabilitiesDropped: true, SeccompEnabled: true, MandatoryPolicy: true, CgroupsV2: true, Tmpfs: true, WorkdirReadWrite: true}, nil
}

func (b *DockerBackend) captureJSON(ctx context.Context, args []string, target any) error {
	_, output, err := b.capture(ctx, args)
	if err != nil {
		return backendError(err)
	}
	if err := json.Unmarshal([]byte(output), target); err != nil {
		return ErrBackendDrift
	}
	return nil
}

func (b *DockerBackend) capture(ctx context.Context, args []string) (int, string, error) {
	stdout := newCappedBuffer(maxCapturedOutput)
	stderr := newCappedBuffer(4096)
	exitCode, err := b.runner.Run(ctx, b.binary, args, stdout, stderr)
	if stdout.Truncated() || stderr.Truncated() {
		return exitCode, "", ErrOutputLimit
	}
	if err != nil || exitCode != 0 {
		return exitCode, "", errOrBackend(err)
	}
	return exitCode, string(stdout.Bytes()), nil
}

func (b *DockerBackend) stream(ctx context.Context, args []string, destination io.Writer) error {
	stderr := newCappedBuffer(4096)
	exitCode, err := b.runner.Run(ctx, b.binary, args, destination, stderr)
	if err != nil || exitCode != 0 || stderr.Truncated() {
		return backendError(err)
	}
	return nil
}

func backendError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrBackendUnavailable
}

func errOrBackend(err error) error {
	if err != nil {
		return err
	}
	return ErrBackendUnavailable
}

func includesFold(values []string, wanted string) bool {
	wanted = strings.ToLower(wanted)
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), wanted) {
			return true
		}
	}
	return false
}

func includesExactFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

func hasTmpfs(values map[string]string, mount string) bool {
	_, exists := values[mount]
	return exists
}

func containsRuntimeSocket(binds []string) bool {
	for _, bind := range binds {
		lower := strings.ToLower(bind)
		if strings.Contains(lower, "docker.sock") || strings.Contains(lower, "containerd.sock") || strings.Contains(lower, "podman.sock") {
			return true
		}
	}
	return false
}

var sandboxIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

type cappedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func newCappedBuffer(limit int) *cappedBuffer { return &cappedBuffer{limit: limit} }

func (b *cappedBuffer) Write(value []byte) (int, error) {
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		amount := len(value)
		if amount > remaining {
			amount = remaining
		}
		_, _ = b.buffer.Write(value[:amount])
	}
	if len(value) > remaining {
		b.truncated = true
	}
	return len(value), nil
}

func (b *cappedBuffer) Bytes() []byte   { return append([]byte(nil), b.buffer.Bytes()...) }
func (b *cappedBuffer) Truncated() bool { return b.truncated }

var _ Backend = (*DockerBackend)(nil)

func (b *DockerBackend) String() string {
	return fmt.Sprintf("docker/%s", b.runtime)
}
