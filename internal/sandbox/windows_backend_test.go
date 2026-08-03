package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestWindowsNativeBackendRejectsNonWindowsHost(t *testing.T) {
	_, err := NewWindowsNativeBackend(WindowsBackendOptions{WorkRoot: t.TempDir()})
	if runtime.GOOS != "windows" && !errors.Is(err, ErrUnsupported) {
		t.Fatalf("non-Windows constructor = %v", err)
	}
}

func TestWindowsNativeBackendLifecycleKeepsNoneSemantics(t *testing.T) {
	root := t.TempDir()
	backend, err := newWindowsNativeBackend(WindowsBackendOptions{WorkRoot: root}, "windows")
	if err != nil {
		t.Fatal(err)
	}
	spec := linuxSpec()
	spec.Platform = PlatformWindows
	spec.IsolationLevel = IsolationNone
	spec.ImageDigest = ""
	spec.CPULimit = ""
	spec.MemoryBytes = 0
	spec.PIDsLimit = 0
	spec.DiskBytes = 0
	spec.WorkloadTrust = TrustTrusted
	spec.DeploymentProfile = ProfileLocal
	attestation, err := backend.Create(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if attestation.Runtime != "native-process" || attestation.Rootless || attestation.ReadOnlyRootFS {
		t.Fatalf("native attestation = %#v", attestation)
	}
	workdir := filepath.Join(root, spec.SandboxID)
	if _, err := os.Stat(workdir); err != nil {
		t.Fatal(err)
	}
	if err := backend.Destroy(context.Background(), spec.SandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(workdir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workdir remains: %v", err)
	}
}

func TestAllowedEnvironmentIsCaseInsensitiveAndMinimal(t *testing.T) {
	got := allowedEnvironment([]string{"path", "SystemRoot"}, []string{"PATH=one", "TOKEN=secret", "SYSTEMROOT=two"})
	want := []string{"PATH=one", "SYSTEMROOT=two"}
	if !slices.Equal(got, want) {
		t.Fatalf("environment = %v", got)
	}
}
