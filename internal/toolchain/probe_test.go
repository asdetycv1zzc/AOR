package toolchain

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestUnixProbeServerChecksVersion(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("unix probe is deployed on Linux")
	}
	workRoot := t.TempDir()
	root := filepath.Join(workRoot, "candidate")
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "bin", "tool")
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, content, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(filepath.Dir(workRoot), func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return os.Chmod(path, 0o755)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "probe.sock")
	server, err := NewProbeServer(socket, workRoot)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	for deadline := time.Now().Add(time.Second); server.Ready() != nil && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	client, err := NewUnixProbeClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	request := ProbeRequest{Root: root, ExpectedVersion: "PASS", Commands: []ProbeCommand{{Name: "g++", Path: "bin/tool", Args: []string{"-test.v", "-test.run=^$"}}}}
	if err := client.Probe(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.ExpectedVersion = "2.0.0"
	if err := client.Probe(context.Background(), request); err != ErrToolchainVersion {
		t.Fatalf("expected version mismatch, got %v", err)
	}
	cancel()
	_ = server.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
