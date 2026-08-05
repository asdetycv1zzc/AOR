package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"path"
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
	Endpoint             string
	RuntimeName          string
	ImageReference       string
	SeccompProfile       string
	MandatoryPolicy      string
	HoldCommand          []string
	Runner               CommandRunner
	BlobStore            BlobStore
	MaxInlineOutputBytes int
}

type DockerBackend struct {
	binary          string
	endpoint        string
	runtime         string
	imageReference  string
	imageDigest     string
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
	if options.Endpoint != "" && !validDockerEndpoint(options.Endpoint) {
		return nil, ErrInvalidSpec
	}
	imageDigest := ""
	if options.ImageReference != "" {
		var valid bool
		imageDigest, valid = immutableImageDigest(options.ImageReference)
		if !valid {
			return nil, ErrInvalidSpec
		}
	}
	if len(options.HoldCommand) == 0 {
		options.HoldCommand = []string{"/aor/runtime/hold"}
	}
	if !validRuntimeName(options.RuntimeName) || options.SeccompProfile == "" || strings.EqualFold(options.SeccompProfile, "unconfined") || strings.ContainsAny(options.SeccompProfile, "\r\n\x00") || !validMandatoryPolicy(options.MandatoryPolicy) || !validHoldCommand(options.HoldCommand) {
		return nil, ErrInvalidSpec
	}
	if options.Runner == nil {
		options.Runner = OSCommandRunner{}
	}
	if options.MaxInlineOutputBytes <= 0 || options.MaxInlineOutputBytes > maxCapturedOutput {
		options.MaxInlineOutputBytes = maxCapturedOutput
	}
	return &DockerBackend{binary: options.Binary, endpoint: options.Endpoint, runtime: options.RuntimeName, imageReference: options.ImageReference, imageDigest: imageDigest, seccomp: options.SeccompProfile, mandatoryPolicy: options.MandatoryPolicy, holdCommand: append([]string(nil), options.HoldCommand...), runner: options.Runner, blobs: options.BlobStore, maxOutput: options.MaxInlineOutputBytes}, nil
}

// Ready performs a non-mutating engine and security capability probe. It does
// not create a container or pull an image.
func (b *DockerBackend) Ready(ctx context.Context) error {
	if b == nil || ctx == nil {
		return ErrBackendUnavailable
	}
	if _, err := b.inspectEngine(ctx); err != nil {
		return err
	}
	if b.imageReference != "" {
		_, err := b.verifyImage(ctx, b.imageDigest)
		return err
	}
	return nil
}

func (b *DockerBackend) Create(ctx context.Context, spec SandboxSpec) (attestation Attestation, err error) {
	if spec.Platform != PlatformLinux || spec.NetworkPolicy.Mode != "DENY_ALL" {
		return Attestation{}, ErrUnsupported
	}
	info, err := b.inspectEngine(ctx)
	if err != nil {
		return Attestation{}, err
	}
	imageID, err := b.verifyImage(ctx, spec.ImageDigest)
	if err != nil {
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
	attestation, err = b.attest(spec, imageID, info, inspection)
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
	exitCode, err := b.runner.Run(ctx, b.binary, b.commandArgs(args), stdout, stderr)
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
	MemoryLimit     bool     `json:"MemoryLimit"`
	PidsLimit       bool     `json:"PidsLimit"`
	CPUCfsQuota     bool     `json:"CPUCfsQuota"`
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
	Mounts []dockerMount `json:"Mounts"`
}

// dockerMount is the daemon's effective mount table. HostConfig.Binds only
// describes legacy bind syntax; --mount entries (the syntax used by AOR) are
// represented here. Attestation must inspect both views so a daemon or
// runtime cannot add a mount that was absent from the requested spec.
type dockerMount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Mode        string `json:"Mode"`
	RW          bool   `json:"RW"`
}

func (b *DockerBackend) inspectEngine(ctx context.Context) (dockerInfo, error) {
	var info dockerInfo
	if err := b.captureJSON(ctx, []string{"info", "--format", "{{json .}}"}, &info); err != nil {
		return info, err
	}
	rootless := includesFold(info.SecurityOptions, "rootless")
	if info.OSType != "linux" {
		return info, backendDrift("Linux OCI engine required")
	}
	if info.CgroupVersion != "2" {
		return info, backendDrift("cgroups v2 required")
	}
	if info.DefaultRuntime != b.runtime {
		return info, backendDrift("configured OCI runtime is not the engine default")
	}
	if !rootless {
		return info, backendDrift("rootless engine required")
	}
	if !mandatoryPolicyAvailable(info.SecurityOptions, b.mandatoryPolicy) {
		return info, backendDrift("configured mandatory access-control policy is unavailable")
	}
	if !info.MemoryLimit || !info.PidsLimit || !info.CPUCfsQuota {
		return info, backendDrift("memory, PID, and CPU limit enforcement required")
	}
	return info, nil
}

func (b *DockerBackend) verifyImage(ctx context.Context, digest string) (string, error) {
	var images []struct {
		ID          string   `json:"Id"`
		RepoDigests []string `json:"RepoDigests"`
	}
	target := digest
	if b.imageReference != "" {
		if digest != b.imageDigest {
			return "", backendDrift("sandbox image digest does not match the configured immutable image")
		}
		target = b.imageReference
	}
	if err := b.captureJSON(ctx, []string{"image", "inspect", target}, &images); err != nil {
		return "", err
	}
	if len(images) != 1 || !validDigest(images[0].ID) {
		return "", backendDrift("sandbox image inspection is invalid")
	}
	if b.imageReference == "" {
		if images[0].ID != digest {
			return "", backendDrift("sandbox image content ID does not match the requested digest")
		}
		return images[0].ID, nil
	}
	for _, repoDigest := range images[0].RepoDigests {
		if strings.HasSuffix(repoDigest, "@"+digest) {
			return images[0].ID, nil
		}
	}
	return "", backendDrift("configured sandbox image manifest digest is not installed")
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
	args := []string{"create", "--name", spec.SandboxID, "--pull", "never", "--read-only", "--user", "65532:65532", "--env", "HOME=/tmp", "--init", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--security-opt", "seccomp=" + b.seccomp, "--security-opt", b.mandatoryPolicy, "--pids-limit", strconv.Itoa(spec.PIDsLimit), "--memory", strconv.FormatInt(spec.MemoryBytes, 10), "--cpus", spec.CPULimit, "--network", "none", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev", "--tmpfs", "/workspace:rw,nosuid,nodev,size=" + strconv.FormatInt(spec.DiskBytes, 10), "--workdir", "/workspace"}
	for _, mount := range spec.Mounts {
		if strings.ContainsAny(mount.Source+mount.Target, ",\r\n") || mount.Mode != "RO" {
			return nil, ErrUnsafeWorkload
		}
		args = append(args, "--mount", "type=bind,src="+mount.Source+",dst="+mount.Target+",readonly")
	}
	image := spec.ImageDigest
	if b.imageReference != "" {
		if spec.ImageDigest != b.imageDigest {
			return nil, ErrUnsafeWorkload
		}
		image = b.imageReference
	}
	args = append(args, image)
	args = append(args, b.holdCommand...)
	return args, nil
}

func (b *DockerBackend) attest(spec SandboxSpec, imageID string, info dockerInfo, inspection dockerInspection) (Attestation, error) {
	expectedCPUs, _ := strconv.ParseFloat(spec.CPULimit, 64)
	expectedNanoCPUs := int64(expectedCPUs * 1_000_000_000)
	nonRoot := inspection.Config.User != "" && inspection.Config.User != "0" && inspection.Config.User != "root" && !strings.HasPrefix(inspection.Config.User, "0:")
	security := inspection.HostConfig.SecurityOpt
	valid := inspection.Image == imageID && inspection.Config.WorkingDir == "/workspace" && nonRoot && inspection.HostConfig.ReadonlyRootfs && !inspection.HostConfig.Privileged && inspection.HostConfig.NetworkMode == "none" && inspection.HostConfig.PidMode == "" && includesExactFold(inspection.HostConfig.CapDrop, "ALL") && includesFold(security, "no-new-privileges") && includesFold(security, "seccomp="+b.seccomp) && includesFold(security, b.mandatoryPolicy) && inspection.HostConfig.PidsLimit == int64(spec.PIDsLimit) && inspection.HostConfig.Memory == spec.MemoryBytes && inspection.HostConfig.NanoCPUs == expectedNanoCPUs && len(inspection.HostConfig.Devices) == 0 && validateTmpfsOptions(spec, inspection.HostConfig.Tmpfs) && validateDockerMounts(spec, inspection)
	if !valid {
		return Attestation{}, ErrBackendDrift
	}
	digest, err := SecurityProfileDigest(spec)
	if err != nil {
		return Attestation{}, err
	}
	return Attestation{SecurityProfileSHA256: digest, ImageDigest: spec.ImageDigest, Runtime: info.DefaultRuntime, NonRoot: true, Rootless: true, ReadOnlyRootFS: true, CapabilitiesDropped: true, SeccompEnabled: true, MandatoryPolicy: true, CgroupsV2: true, Tmpfs: true, WorkdirReadWrite: true}, nil
}

// validateTmpfsOptions checks the effective daemon options, rather than only
// checking that the two expected destinations exist. Extra options such as
// exec, suid, or dev would weaken the sandbox's temporary filesystems.
func validateTmpfsOptions(spec SandboxSpec, values map[string]string) bool {
	if len(values) != 2 {
		return false
	}
	tmpOptions, ok := values["/tmp"]
	if !ok || !hasTmpfsOption(tmpOptions, "rw") || !hasTmpfsOption(tmpOptions, "noexec") || !hasTmpfsOption(tmpOptions, "nosuid") || !hasTmpfsOption(tmpOptions, "nodev") || hasTmpfsOption(tmpOptions, "exec") || hasTmpfsOption(tmpOptions, "suid") || hasTmpfsOption(tmpOptions, "dev") {
		return false
	}
	workspaceOptions, ok := values["/workspace"]
	if !ok || !hasTmpfsOption(workspaceOptions, "rw") || !hasTmpfsOption(workspaceOptions, "nosuid") || !hasTmpfsOption(workspaceOptions, "nodev") || hasTmpfsOption(workspaceOptions, "suid") || hasTmpfsOption(workspaceOptions, "dev") || !hasTmpfsSize(workspaceOptions, spec.DiskBytes) {
		return false
	}
	return true
}

func hasTmpfsOption(options, wanted string) bool {
	for _, option := range strings.Split(strings.ToLower(options), ",") {
		if strings.TrimSpace(option) == wanted {
			return true
		}
	}
	return false
}

func hasTmpfsSize(options string, expected int64) bool {
	wanted := "size=" + strconv.FormatInt(expected, 10)
	for _, option := range strings.Split(strings.ToLower(options), ",") {
		if strings.TrimSpace(option) == wanted {
			return true
		}
	}
	return false
}

// validateDockerMounts compares the daemon's complete effective mount table
// with the requested spec. HostConfig.Binds is rejected outright because AOR
// creates all user mounts with --mount and must never accept an unaccounted
// legacy bind. The two internal tmpfs mounts and every requested read-only
// bind must appear exactly once; volumes, tmpfs destinations, and bind
// sources not in the spec fail closed.
func validateDockerMounts(spec SandboxSpec, inspection dockerInspection) bool {
	if len(inspection.HostConfig.Binds) != 0 || containsRuntimeSocket(inspection.HostConfig.Binds) {
		return false
	}
	type expectedMount struct {
		kind   string
		source string
	}
	expected := map[string]expectedMount{
		"/tmp":       {kind: "tmpfs"},
		"/workspace": {kind: "tmpfs"},
	}
	for _, requested := range spec.Mounts {
		target := path.Clean(strings.ReplaceAll(requested.Target, "\\", "/"))
		if target == "." || target == "/" {
			return false
		}
		if _, duplicate := expected[target]; duplicate || requested.Mode != "RO" {
			return false
		}
		expected[target] = expectedMount{kind: "bind", source: requested.Source}
	}
	if len(inspection.Mounts) != len(expected) {
		return false
	}
	seen := make(map[string]struct{}, len(inspection.Mounts))
	for _, actual := range inspection.Mounts {
		target := path.Clean(strings.ReplaceAll(actual.Destination, "\\", "/"))
		if target == "." || actual.Destination == "" {
			return false
		}
		if _, duplicate := seen[target]; duplicate {
			return false
		}
		seen[target] = struct{}{}
		requirement, found := expected[target]
		if !found || !strings.EqualFold(actual.Type, requirement.kind) || containsRuntimeSocket([]string{actual.Source, actual.Destination}) {
			return false
		}
		if requirement.kind == "tmpfs" {
			if !actual.RW {
				return false
			}
			continue
		}
		if actual.Source != requirement.source || actual.RW || !hasMountOption(actual.Mode, "ro") {
			return false
		}
	}
	return len(seen) == len(expected)
}

func hasMountOption(options, wanted string) bool {
	for _, option := range strings.Split(strings.ToLower(options), ",") {
		if strings.TrimSpace(option) == wanted {
			return true
		}
	}
	return false
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
	exitCode, err := b.runner.Run(ctx, b.binary, b.commandArgs(args), stdout, stderr)
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
	exitCode, err := b.runner.Run(ctx, b.binary, b.commandArgs(args), destination, stderr)
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

func (b *DockerBackend) commandArgs(args []string) []string {
	if b.endpoint == "" {
		return args
	}
	result := make([]string, 0, len(args)+2)
	result = append(result, "--host", b.endpoint)
	return append(result, args...)
}

func immutableImageDigest(reference string) (string, bool) {
	separator := strings.LastIndex(reference, "@")
	if separator <= 0 || separator == len(reference)-1 || strings.ContainsAny(reference, "\r\n\x00") {
		return "", false
	}
	digest := reference[separator+1:]
	return digest, validDigest(digest)
}

func validDockerEndpoint(value string) bool {
	if !strings.HasPrefix(value, "unix:///") || strings.ContainsAny(value, "\r\n\x00%") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "unix" || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasPrefix(parsed.Path, "/") || parsed.Path == "/" || strings.Contains(parsed.Path, "//") {
		return false
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return parsed.Path != "/var/run/docker.sock" && parsed.Path != "/run/docker.sock"
}

func validRuntimeName(value string) bool {
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\r\n\x00/\\") {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validHoldCommand(command []string) bool {
	if len(command) == 0 || len(command) > 16 || !strings.HasPrefix(command[0], "/") {
		return false
	}
	for _, argument := range command {
		if argument == "" || len(argument) > 4096 || strings.ContainsAny(argument, "\r\n\x00") {
			return false
		}
	}
	return true
}

func validMandatoryPolicy(policy string) bool {
	if policy == "" || strings.ContainsAny(policy, "\r\n\x00") || strings.Contains(strings.ToLower(policy), "unconfined") {
		return false
	}
	return (strings.HasPrefix(policy, "apparmor=") && len(strings.TrimPrefix(policy, "apparmor=")) > 0) || (strings.HasPrefix(policy, "label=type:") && len(strings.TrimPrefix(policy, "label=type:")) > 0)
}

func mandatoryPolicyAvailable(securityOptions []string, policy string) bool {
	switch {
	case strings.HasPrefix(policy, "apparmor="):
		return includesFold(securityOptions, "apparmor")
	case strings.HasPrefix(policy, "label=type:"):
		return includesFold(securityOptions, "selinux")
	default:
		return false
	}
}

func backendDrift(reason string) error {
	return fmt.Errorf("%w: %s", ErrBackendDrift, reason)
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
