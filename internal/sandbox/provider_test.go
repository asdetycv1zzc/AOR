package sandbox

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeBackend struct {
	created     SandboxSpec
	attestation Attestation
	destroyed   int
}

func (b *fakeBackend) Create(_ context.Context, spec SandboxSpec) (Attestation, error) {
	b.created = spec
	if spec.Platform == PlatformWindows {
		return Attestation{Runtime: "native-process"}, nil
	}
	if b.attestation.Runtime == "" {
		b.attestation = hardenedAttestation(spec.ImageDigest)
	}
	return b.attestation, nil
}

func hardenedAttestation(digest string) Attestation {
	spec := linuxSpec()
	spec.ImageDigest = digest
	profileDigest, _ := SecurityProfileDigest(spec)
	return Attestation{SecurityProfileSHA256: profileDigest, ImageDigest: digest, Runtime: "runc", NonRoot: true, Rootless: true, ReadOnlyRootFS: true, CapabilitiesDropped: true, SeccompEnabled: true, MandatoryPolicy: true, CgroupsV2: true, Tmpfs: true, WorkdirReadWrite: true}
}
func (b *fakeBackend) Exec(context.Context, string, ExecRequest) (ExecResult, error) {
	return ExecResult{ExitCode: 0}, nil
}
func (b *fakeBackend) Export(_ context.Context, _ string, paths []string) ([]ArtifactRef, error) {
	return []ArtifactRef{{Path: paths[0]}}, nil
}
func (b *fakeBackend) Snapshot(context.Context, string) (SnapshotRef, error) {
	return SnapshotRef{URI: "snapshot://one"}, nil
}
func (b *fakeBackend) Terminate(context.Context, string, string) error { return nil }
func (b *fakeBackend) Destroy(context.Context, string) error           { b.destroyed++; return nil }

func linuxSpec() SandboxSpec {
	return SandboxSpec{SandboxID: "sbx", TenantID: "ten", ProjectID: "prj", TaskID: "task", Role: RoleExecutor, Platform: PlatformLinux, IsolationLevel: IsolationContainer, ImageDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000", CPULimit: "2", MemoryBytes: 1024, PIDsLimit: 64, DiskBytes: 4096, WallTimeSeconds: 60, NetworkPolicy: NetworkPolicy{Mode: "DENY_ALL"}, AllowedExecutables: []string{"go"}, WorkloadTrust: TrustUntrusted, DeploymentProfile: ProfileProduction}
}

func TestLinuxProviderPinsHardenedAttestation(t *testing.T) {
	backend := &fakeBackend{}
	backend.attestation = hardenedAttestation(linuxSpec().ImageDigest)
	backend.attestation.Runtime = "runc-1.4"
	provider := NewLinuxProvider(backend, "runc-1.4", func() time.Time { return time.Unix(0, 0) })
	handle, err := provider.Create(context.Background(), linuxSpec())
	if err != nil {
		t.Fatal(err)
	}
	if handle.IsolationLevel != IsolationContainer || !handle.Attestation.Rootless || !handle.Attestation.ReadOnlyRootFS || !handle.Attestation.CapabilitiesDropped || !handle.Attestation.SeccompEnabled || handle.Attestation.Privileged || handle.Attestation.HostPID || handle.Attestation.HostNetwork || handle.Attestation.RuntimeSocket {
		t.Fatalf("attestation = %#v", handle.Attestation)
	}
	if err := provider.Destroy(context.Background(), "sbx"); err != nil {
		t.Fatal(err)
	}
	if err := provider.Destroy(context.Background(), "sbx"); err != nil || backend.destroyed != 1 {
		t.Fatalf("destroy = %v calls=%d", err, backend.destroyed)
	}
}

func TestWindowsProviderReportsNoneAndRejectsUnsafeWork(t *testing.T) {
	provider := NewWindowsProvider(&fakeBackend{}, time.Now)
	spec := linuxSpec()
	spec.Platform = PlatformWindows
	spec.IsolationLevel = IsolationNone
	spec.ImageDigest = ""
	spec.CPULimit = ""
	spec.MemoryBytes = 0
	spec.PIDsLimit = 0
	spec.DiskBytes = 0
	_, err := provider.Create(context.Background(), spec)
	if !errors.Is(err, ErrUnsafeWorkload) {
		t.Fatalf("unsafe Windows create = %v", err)
	}
	spec.WorkloadTrust = TrustTrusted
	spec.DeploymentProfile = ProfileLocal
	handle, err := provider.Create(context.Background(), spec)
	if err != nil || handle.IsolationLevel != IsolationNone || handle.Attestation.RiskDisclosure == "" {
		t.Fatalf("Windows handle = %#v err=%v", handle, err)
	}
}

func TestExportRejectsTraversal(t *testing.T) {
	provider := NewLinuxProvider(&fakeBackend{}, "runc", time.Now)
	if _, err := provider.Create(context.Background(), linuxSpec()); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Export(context.Background(), "sbx", []string{"../secret"}); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("traversal = %v", err)
	}
	if _, err := provider.Export(context.Background(), "sbx", []string{`..\secret`}); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("Windows traversal = %v", err)
	}
}

func TestLinuxProviderRejectsUnverifiedHardening(t *testing.T) {
	backend := &fakeBackend{attestation: hardenedAttestation(linuxSpec().ImageDigest)}
	backend.attestation.SeccompEnabled = false
	provider := NewLinuxProvider(backend, "runc", time.Now)
	if _, err := provider.Create(context.Background(), linuxSpec()); !errors.Is(err, ErrAttestationFailed) {
		t.Fatalf("attestation = %v", err)
	}
	if backend.destroyed != 1 {
		t.Fatalf("failed sandbox cleanup calls = %d", backend.destroyed)
	}
}

func TestSandboxSpecRejectsFailOpenNetworkAndUnknownClassification(t *testing.T) {
	spec := linuxSpec()
	spec.NetworkPolicy.Mode = "OPEN"
	if !errors.Is(spec.Validate(), ErrInvalidSpec) {
		t.Fatal("open network mode accepted")
	}
	spec = linuxSpec()
	spec.WorkloadTrust = ""
	if !errors.Is(spec.Validate(), ErrInvalidSpec) {
		t.Fatal("unknown workload trust accepted")
	}
}

func TestWindowsRejectsHostileAndIsolationDependentWork(t *testing.T) {
	provider := NewWindowsProvider(&fakeBackend{}, time.Now)
	spec := linuxSpec()
	spec.Platform = PlatformWindows
	spec.IsolationLevel = IsolationNone
	spec.ImageDigest = ""
	spec.CPULimit = ""
	spec.MemoryBytes = 0
	spec.PIDsLimit = 0
	spec.DiskBytes = 0
	spec.WorkloadTrust = TrustTrusted
	spec.DeploymentProfile = ProfileProduction
	spec.TrustedSingleTenant = true
	spec.HostileMultiTenant = true
	if _, err := provider.Create(context.Background(), spec); !errors.Is(err, ErrUnsafeWorkload) {
		t.Fatalf("hostile workload = %v", err)
	}
}

type lifecycleBackend struct {
	execStarted chan struct{}
	releaseExec chan struct{}
	releaseOnce sync.Once
	destroys    atomic.Int32
}

func (b *lifecycleBackend) Create(_ context.Context, spec SandboxSpec) (Attestation, error) {
	return hardenedAttestation(spec.ImageDigest), nil
}
func (b *lifecycleBackend) Exec(context.Context, string, ExecRequest) (ExecResult, error) {
	close(b.execStarted)
	<-b.releaseExec
	return ExecResult{}, nil
}
func (b *lifecycleBackend) Export(context.Context, string, []string) ([]ArtifactRef, error) {
	return nil, ErrUnsupported
}
func (b *lifecycleBackend) Snapshot(context.Context, string) (SnapshotRef, error) {
	return SnapshotRef{}, ErrUnsupported
}
func (b *lifecycleBackend) Terminate(context.Context, string, string) error {
	b.releaseOnce.Do(func() { close(b.releaseExec) })
	return nil
}
func (b *lifecycleBackend) Destroy(context.Context, string) error {
	b.destroys.Add(1)
	b.releaseOnce.Do(func() { close(b.releaseExec) })
	return nil
}

func TestTerminateCanInterruptInFlightExecution(t *testing.T) {
	backend := &lifecycleBackend{execStarted: make(chan struct{}), releaseExec: make(chan struct{})}
	provider := NewLinuxProvider(backend, "runc", time.Now)
	if _, err := provider.Create(context.Background(), linuxSpec()); err != nil {
		t.Fatal(err)
	}
	execDone := make(chan error, 1)
	go func() {
		_, err := provider.Exec(context.Background(), "sbx", ExecRequest{Executable: "go", Timeout: time.Second})
		execDone <- err
	}()
	<-backend.execStarted
	if err := provider.Terminate(context.Background(), "sbx", "test termination"); err != nil {
		t.Fatal(err)
	}
	if err := <-execDone; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentDestroyCallsBackendOnce(t *testing.T) {
	backend := &lifecycleBackend{execStarted: make(chan struct{}), releaseExec: make(chan struct{})}
	provider := NewLinuxProvider(backend, "runc", time.Now)
	if _, err := provider.Create(context.Background(), linuxSpec()); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := provider.Destroy(context.Background(), "sbx"); err != nil {
				t.Errorf("destroy: %v", err)
			}
		}()
	}
	wait.Wait()
	if backend.destroys.Load() != 1 {
		t.Fatalf("destroy calls = %d", backend.destroys.Load())
	}
}
