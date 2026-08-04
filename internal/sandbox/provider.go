package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidSpec       = errors.New("invalid sandbox specification")
	ErrUnsupported       = errors.New("unsupported sandbox capability")
	ErrUnsafeWorkload    = errors.New("unsafe workload for sandbox provider")
	ErrSandboxNotFound   = errors.New("sandbox not found")
	ErrSandboxTerminated = errors.New("sandbox terminated")
	ErrAttestationFailed = errors.New("sandbox attestation failed")
	ErrCleanupFailed     = errors.New("sandbox cleanup failed")
)

type sandboxState struct {
	mu         sync.Mutex
	controlMu  sync.Mutex
	spec       SandboxSpec
	handle     SandboxHandle
	creating   bool
	terminated bool
	destroyed  bool
}

type Provider struct {
	mu       sync.Mutex
	platform Platform
	backend  Backend
	runtime  string
	clock    func() time.Time
	states   map[string]*sandboxState
	mounts   []string
}

// Ready verifies that the backing execution runtime is available and still
// advertises the security profile required by this provider. A worker must
// fail closed when this check cannot complete.
func (p *Provider) Ready(ctx context.Context) error {
	if p == nil || p.backend == nil || ctx == nil {
		return ErrBackendUnavailable
	}
	if checker, ok := p.backend.(interface{ Ready(context.Context) error }); ok {
		return checker.Ready(ctx)
	}
	if p.platform == PlatformWindows {
		return nil
	}
	return ErrBackendUnavailable
}

func NewLinuxProvider(backend Backend, runtimeName string, clock func() time.Time) *Provider {
	return NewLinuxProviderWithOptions(backend, LinuxProviderOptions{RuntimeName: runtimeName}, clock)
}

func NewLinuxProviderWithOptions(backend Backend, options LinuxProviderOptions, clock func() time.Time) *Provider {
	provider := newProvider(PlatformLinux, backend, options.RuntimeName, clock)
	provider.mounts = append([]string(nil), options.AllowedMountRoots...)
	return provider
}

func NewWindowsProvider(backend Backend, clock func() time.Time) *Provider {
	return newProvider(PlatformWindows, backend, "native-process", clock)
}

func newProvider(platform Platform, backend Backend, runtimeName string, clock func() time.Time) *Provider {
	if clock == nil {
		clock = time.Now
	}
	return &Provider{platform: platform, backend: backend, runtime: runtimeName, clock: clock, states: make(map[string]*sandboxState)}
}

func (p *Provider) Create(ctx context.Context, spec SandboxSpec) (SandboxHandle, error) {
	if p.backend == nil || spec.Platform != p.platform {
		return SandboxHandle{}, ErrUnsupported
	}
	if err := spec.Validate(); err != nil {
		return SandboxHandle{}, err
	}
	if err := p.validateMounts(spec); err != nil {
		return SandboxHandle{}, err
	}
	if spec.Platform == PlatformWindows {
		if spec.WorkloadTrust == TrustUntrusted && spec.DeploymentProfile == ProfileProduction || spec.RequiresHiddenTests || spec.RequiresNetworkIsolation || spec.HostileMultiTenant || spec.DeploymentProfile == ProfileProduction && (!spec.TrustedSingleTenant || spec.WorkloadTrust != TrustTrusted) && spec.RiskAcceptanceApprovalID == "" {
			return SandboxHandle{}, ErrUnsafeWorkload
		}
	}
	state := &sandboxState{spec: cloneSpec(spec), creating: true}
	p.mu.Lock()
	if _, exists := p.states[spec.SandboxID]; exists {
		p.mu.Unlock()
		return SandboxHandle{}, ErrInvalidSpec
	}
	p.states[spec.SandboxID] = state
	p.mu.Unlock()
	attestation, err := p.backend.Create(ctx, cloneSpec(spec))
	if err != nil {
		p.removeFailedCreate(spec.SandboxID, state)
		return SandboxHandle{}, err
	}
	attestation, err = p.validateAttestation(spec, attestation)
	if err != nil {
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		cleanupErr := p.backend.Destroy(cleanupContext, spec.SandboxID)
		cancel()
		if cleanupErr != nil {
			state.mu.Lock()
			state.creating = false
			state.terminated = true
			state.mu.Unlock()
			return SandboxHandle{}, errors.Join(err, ErrCleanupFailed)
		}
		p.removeFailedCreate(spec.SandboxID, state)
		return SandboxHandle{}, err
	}
	handle := SandboxHandle{ID: spec.SandboxID, Platform: spec.Platform, IsolationLevel: spec.IsolationLevel, Attestation: attestation, CreatedAt: p.clock().UTC()}
	state.mu.Lock()
	state.handle = handle
	state.creating = false
	state.mu.Unlock()
	return handle, nil
}

func (p *Provider) Exec(ctx context.Context, id string, req ExecRequest) (ExecResult, error) {
	state, err := p.active(id)
	if err != nil {
		return ExecResult{}, err
	}
	state.mu.Lock()
	spec := cloneSpec(state.spec)
	handle := state.handle
	state.mu.Unlock()
	if req.Executable == "" || req.Timeout <= 0 || req.Timeout > time.Duration(spec.WallTimeSeconds)*time.Second || !contains(spec.AllowedExecutables, req.Executable) {
		return ExecResult{}, ErrInvalidSpec
	}
	if req.WorkingDir != "" && !validRelativePath(req.WorkingDir) {
		return ExecResult{}, ErrInvalidSpec
	}
	remaining := handle.CreatedAt.Add(time.Duration(spec.WallTimeSeconds) * time.Second).Sub(p.clock())
	if remaining <= 0 {
		return ExecResult{}, ErrSandboxTerminated
	}
	timeout := req.Timeout
	if remaining < timeout {
		timeout = remaining
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return p.backend.Exec(execCtx, id, cloneExec(req))
}

func (p *Provider) Export(ctx context.Context, id string, paths []string) ([]ArtifactRef, error) {
	_, err := p.active(id)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, ErrInvalidSpec
	}
	seen := make(map[string]bool, len(paths))
	cleaned := make([]string, 0, len(paths))
	for _, candidate := range paths {
		clean, ok := cleanRelativePath(candidate)
		if !ok || seen[clean] {
			return nil, ErrInvalidSpec
		}
		seen[clean] = true
		cleaned = append(cleaned, clean)
	}
	artifacts, err := p.backend.Export(ctx, id, cleaned)
	if err != nil {
		return nil, err
	}
	if err := validateArtifacts(cleaned, artifacts); err != nil {
		return nil, err
	}
	return artifacts, nil
}

func (p *Provider) Snapshot(ctx context.Context, id string) (SnapshotRef, error) {
	state, err := p.active(id)
	if err != nil {
		return SnapshotRef{}, err
	}
	state.mu.Lock()
	handle := state.handle
	state.mu.Unlock()
	snapshot, err := p.backend.Snapshot(ctx, id)
	if err != nil {
		return SnapshotRef{}, err
	}
	if !validArtifactURI(snapshot.URI, snapshot.SHA256) {
		return SnapshotRef{}, ErrInvalidSpec
	}
	snapshot.IsolationLevel = handle.IsolationLevel
	snapshot.Attestation = handle.Attestation
	return snapshot, nil
}

func (p *Provider) Terminate(ctx context.Context, id, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return ErrInvalidSpec
	}
	state := p.lookup(id)
	if state == nil {
		return ErrSandboxNotFound
	}
	state.controlMu.Lock()
	defer state.controlMu.Unlock()
	state.mu.Lock()
	if state.creating || state.destroyed {
		state.mu.Unlock()
		return ErrSandboxNotFound
	}
	if state.terminated {
		state.mu.Unlock()
		return nil
	}
	state.terminated = true
	state.mu.Unlock()
	if err := p.backend.Terminate(ctx, id, reason); err != nil {
		state.mu.Lock()
		state.terminated = false
		state.mu.Unlock()
		return err
	}
	return nil
}

func (p *Provider) Destroy(ctx context.Context, id string) error {
	state := p.lookup(id)
	if state == nil {
		return nil
	}
	state.controlMu.Lock()
	defer state.controlMu.Unlock()
	state.mu.Lock()
	if state.destroyed {
		state.mu.Unlock()
		return nil
	}
	if state.creating {
		state.mu.Unlock()
		return ErrSandboxNotFound
	}
	state.destroyed = true
	state.mu.Unlock()
	if err := p.backend.Destroy(ctx, id); err != nil {
		state.mu.Lock()
		state.destroyed = false
		state.mu.Unlock()
		return err
	}
	return nil
}

func (p *Provider) lookup(id string) *sandboxState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.states[id]
}

func (p *Provider) active(id string) (*sandboxState, error) {
	state := p.lookup(id)
	if state == nil {
		return nil, ErrSandboxNotFound
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.creating || state.destroyed {
		return nil, ErrSandboxNotFound
	}
	if state.terminated {
		return nil, ErrSandboxTerminated
	}
	return state, nil
}

func (p *Provider) removeFailedCreate(id string, state *sandboxState) {
	p.mu.Lock()
	if p.states[id] == state {
		delete(p.states, id)
	}
	p.mu.Unlock()
}

func (p *Provider) validateAttestation(spec SandboxSpec, actual Attestation) (Attestation, error) {
	if spec.Platform == PlatformWindows {
		if actual.Runtime != "native-process" {
			return Attestation{}, ErrAttestationFailed
		}
		return Attestation{Runtime: "native-process", RiskDisclosure: "NONE: native host process; no filesystem, network, process, credential, or kernel isolation"}, nil
	}
	profileDigest, err := SecurityProfileDigest(spec)
	if err != nil || actual.SecurityProfileSHA256 != profileDigest || actual.ImageDigest != spec.ImageDigest || actual.Runtime == "" || actual.Runtime != p.runtime || !actual.NonRoot || !actual.ReadOnlyRootFS || !actual.CapabilitiesDropped || !actual.SeccompEnabled || !actual.MandatoryPolicy || !actual.CgroupsV2 || !actual.Tmpfs || !actual.WorkdirReadWrite || actual.HostDevices || actual.HostPID || actual.HostNetwork || actual.Privileged || actual.RuntimeSocket {
		return Attestation{}, ErrAttestationFailed
	}
	if !actual.Rootless && !actual.UserNamespace {
		return Attestation{}, ErrAttestationFailed
	}
	actual.RiskDisclosure = "CONTAINER: OCI container shares the host kernel and is not a VM boundary"
	return actual, nil
}

func (s SandboxSpec) Validate() error {
	if !sandboxIDPattern.MatchString(s.SandboxID) || s.TenantID == "" || s.ProjectID == "" || s.TaskID == "" || strings.ContainsAny(s.TenantID+s.ProjectID+s.TaskID, "\x00\r\n") || s.WallTimeSeconds <= 0 || s.Role != RoleExecutor && s.Role != RoleAuditor || s.WorkloadTrust != TrustTrusted && s.WorkloadTrust != TrustUntrusted || s.DeploymentProfile != ProfileLocal && s.DeploymentProfile != ProfileProduction {
		return ErrInvalidSpec
	}
	if s.Platform == PlatformLinux {
		if s.IsolationLevel != IsolationContainer || !validDigest(s.ImageDigest) || s.CPULimit == "" || s.MemoryBytes <= 0 || s.PIDsLimit <= 0 || s.DiskBytes <= 0 || s.NetworkPolicy.Mode != "DENY_ALL" && s.NetworkPolicy.Mode != "ALLOWLIST" || s.Role == RoleAuditor && s.NetworkPolicy.Mode != "DENY_ALL" {
			return ErrInvalidSpec
		}
		if s.NetworkPolicy.Mode == "DENY_ALL" && len(s.NetworkPolicy.Destinations) != 0 || s.NetworkPolicy.Mode == "ALLOWLIST" && !validDestinations(s.NetworkPolicy.Destinations) {
			return ErrInvalidSpec
		}
	} else if s.Platform == PlatformWindows {
		if s.IsolationLevel != IsolationNone || s.ImageDigest != "" {
			return ErrInvalidSpec
		}
	} else {
		return ErrInvalidSpec
	}
	for _, mount := range s.Mounts {
		if mount.Source == "" || mount.Target == "" || mount.Mode != "RO" && mount.Mode != "RW" || !filepath.IsAbs(mount.Source) || !path.IsAbs(strings.ReplaceAll(mount.Target, "\\", "/")) || strings.ContainsAny(mount.Source+mount.Target, "\x00\r\n") || containsRuntimeSocket([]string{mount.Source}) {
			return ErrInvalidSpec
		}
	}
	for _, executable := range s.AllowedExecutables {
		if strings.TrimSpace(executable) == "" || strings.ContainsAny(executable, "\x00\r\n") {
			return ErrInvalidSpec
		}
	}
	for _, name := range s.EnvironmentAllowlist {
		if !environmentNamePattern.MatchString(name) || credentialEnvironmentPattern.MatchString(name) {
			return ErrInvalidSpec
		}
	}
	return nil
}

func (p *Provider) validateMounts(spec SandboxSpec) error {
	if spec.Platform == PlatformWindows && len(spec.Mounts) > 0 {
		return ErrUnsafeWorkload
	}
	for _, mount := range spec.Mounts {
		if len(p.mounts) == 0 || !allowedMountSource(mount.Source, p.mounts) {
			return ErrUnsafeWorkload
		}
		target := path.Clean(strings.ReplaceAll(mount.Target, "\\", "/"))
		switch {
		case strings.HasPrefix(target, "/workspace/inputs/"):
			if mount.Mode != "RO" {
				return ErrUnsafeWorkload
			}
		case target == "/knowledge" || strings.HasPrefix(target, "/knowledge/"):
			if mount.Mode != "RO" {
				return ErrUnsafeWorkload
			}
		case target == "/audit" || strings.HasPrefix(target, "/audit/"):
			if spec.Role != RoleAuditor || mount.Mode != "RO" {
				return ErrUnsafeWorkload
			}
		default:
			return ErrUnsafeWorkload
		}
	}
	return nil
}

func allowedMountSource(source string, roots []string) bool {
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil {
		return false
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() && !info.IsDir() {
		return false
	}
	for _, root := range roots {
		resolvedRoot, rootErr := filepath.EvalSymlinks(root)
		if rootErr != nil || resolvedRoot == string(filepath.Separator) {
			continue
		}
		relative, relErr := filepath.Rel(resolvedRoot, resolved)
		if relErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func validDestinations(destinations []string) bool {
	if len(destinations) == 0 {
		return false
	}
	for _, destination := range destinations {
		if strings.Contains(destination, "*") {
			return false
		}
		parsed, err := url.Parse(destination)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
			return false
		}
		host := strings.ToLower(parsed.Hostname())
		if host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "metadata.google.internal" {
			return false
		}
		if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
			return false
		}
	}
	return true
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validDigest(value string) bool { return digestPattern.MatchString(value) }

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func cleanRelativePath(value string) (string, bool) {
	if value == "" || strings.ContainsRune(value, 0) {
		return "", false
	}
	normalized := strings.ReplaceAll(value, "\\", "/")
	clean := path.Clean(normalized)
	if clean == "." || strings.HasPrefix(clean, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return clean, true
}

func validRelativePath(value string) bool {
	_, ok := cleanRelativePath(value)
	return ok
}

func validateArtifacts(requested []string, artifacts []ArtifactRef) error {
	if len(artifacts) != len(requested) {
		return ErrInvalidSpec
	}
	seen := make(map[string]bool, len(artifacts))
	for _, artifact := range artifacts {
		clean, ok := cleanRelativePath(artifact.Path)
		if !ok || !contains(requested, clean) || seen[clean] || artifact.Size < 0 || !validArtifactURI(artifact.URI, artifact.SHA256) {
			return ErrInvalidSpec
		}
		seen[clean] = true
	}
	return nil
}

func validArtifactURI(uri, digest string) bool {
	return validHexDigest(digest) && uri == "artifact://sha256/"+digest
}

var hexDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

var environmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var credentialEnvironmentPattern = regexp.MustCompile(`(?i)(^|_)(secret|token|password|credential|private_key|access_key|api_key)($|_)`)

func validHexDigest(value string) bool { return hexDigestPattern.MatchString(value) }

func SecurityProfileDigest(spec SandboxSpec) (string, error) {
	profile := struct {
		SandboxID            string
		ImageDigest          string
		CPULimit             string
		MemoryBytes          int64
		PIDsLimit            int
		DiskBytes            int64
		NetworkPolicy        NetworkPolicy
		Mounts               []Mount
		AllowedExecutables   []string
		EnvironmentAllowlist []string
	}{spec.SandboxID, spec.ImageDigest, spec.CPULimit, spec.MemoryBytes, spec.PIDsLimit, spec.DiskBytes, spec.NetworkPolicy, spec.Mounts, spec.AllowedExecutables, spec.EnvironmentAllowlist}
	encoded, err := json.Marshal(profile)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func cloneSpec(value SandboxSpec) SandboxSpec {
	value.NetworkPolicy.Destinations = append([]string(nil), value.NetworkPolicy.Destinations...)
	value.Mounts = append([]Mount(nil), value.Mounts...)
	value.AllowedExecutables = append([]string(nil), value.AllowedExecutables...)
	value.EnvironmentAllowlist = append([]string(nil), value.EnvironmentAllowlist...)
	return value
}

func cloneExec(value ExecRequest) ExecRequest {
	value.Arguments = append([]string(nil), value.Arguments...)
	return value
}

func (s SandboxSpec) String() string {
	return fmt.Sprintf("%s/%s", s.Platform, s.IsolationLevel)
}
