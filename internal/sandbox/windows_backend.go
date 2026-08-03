package sandbox

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type WindowsBackendOptions struct {
	WorkRoot             string
	BlobStore            BlobStore
	MaxInlineOutputBytes int
}

type windowsProcessState struct {
	mu         sync.Mutex
	spec       SandboxSpec
	directory  string
	terminated bool
	processes  map[*exec.Cmd]struct{}
}

type WindowsNativeBackend struct {
	mu        sync.Mutex
	workRoot  string
	blobs     BlobStore
	maxOutput int
	states    map[string]*windowsProcessState
}

func NewWindowsNativeBackend(options WindowsBackendOptions) (*WindowsNativeBackend, error) {
	return newWindowsNativeBackend(options, runtime.GOOS)
}

func newWindowsNativeBackend(options WindowsBackendOptions, operatingSystem string) (*WindowsNativeBackend, error) {
	if operatingSystem != "windows" || !filepath.IsAbs(options.WorkRoot) {
		return nil, ErrUnsupported
	}
	info, err := os.Lstat(options.WorkRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidSpec
	}
	resolved, err := filepath.EvalSymlinks(options.WorkRoot)
	if err != nil || filepath.Clean(resolved) == filepath.VolumeName(resolved)+string(filepath.Separator) {
		return nil, ErrInvalidSpec
	}
	if options.MaxInlineOutputBytes <= 0 || options.MaxInlineOutputBytes > maxCapturedOutput {
		options.MaxInlineOutputBytes = maxCapturedOutput
	}
	return &WindowsNativeBackend{workRoot: resolved, blobs: options.BlobStore, maxOutput: options.MaxInlineOutputBytes, states: make(map[string]*windowsProcessState)}, nil
}

func (b *WindowsNativeBackend) Create(_ context.Context, spec SandboxSpec) (Attestation, error) {
	if spec.Platform != PlatformWindows || spec.IsolationLevel != IsolationNone || !sandboxIDPattern.MatchString(spec.SandboxID) {
		return Attestation{}, ErrInvalidSpec
	}
	directory := filepath.Join(b.workRoot, spec.SandboxID)
	if !withinRoot(b.workRoot, directory) {
		return Attestation{}, ErrInvalidSpec
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.states[spec.SandboxID]; exists {
		return Attestation{}, ErrInvalidSpec
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return Attestation{}, ErrBackendUnavailable
	}
	b.states[spec.SandboxID] = &windowsProcessState{spec: cloneSpec(spec), directory: directory, processes: make(map[*exec.Cmd]struct{})}
	return Attestation{Runtime: "native-process"}, nil
}

func (b *WindowsNativeBackend) Exec(ctx context.Context, id string, request ExecRequest) (ExecResult, error) {
	state := b.state(id)
	if state == nil {
		return ExecResult{}, ErrSandboxNotFound
	}
	directory := state.directory
	if request.WorkingDir != "" {
		directory = filepath.Join(directory, filepath.FromSlash(request.WorkingDir))
	}
	if !withinRoot(state.directory, directory) {
		return ExecResult{}, ErrInvalidSpec
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ExecResult{}, ErrInvalidSpec
	}
	command := exec.CommandContext(ctx, request.Executable, request.Arguments...)
	command.Dir = directory
	command.Env = allowedEnvironment(state.spec.EnvironmentAllowlist, os.Environ())
	stdout := newCappedBuffer(b.maxOutput)
	stderr := newCappedBuffer(b.maxOutput)
	command.Stdout = stdout
	command.Stderr = stderr
	started := time.Now().UTC()
	state.mu.Lock()
	if state.terminated {
		state.mu.Unlock()
		return ExecResult{}, ErrSandboxTerminated
	}
	if err := command.Start(); err != nil {
		state.mu.Unlock()
		return ExecResult{}, ErrBackendUnavailable
	}
	state.processes[command] = struct{}{}
	state.mu.Unlock()
	err = command.Wait()
	state.mu.Lock()
	delete(state.processes, command)
	state.mu.Unlock()
	result := ExecResult{ExitCode: command.ProcessState.ExitCode(), Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), StartedAt: started, FinishedAt: time.Now().UTC()}
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

func (b *WindowsNativeBackend) Export(ctx context.Context, id string, paths []string) ([]ArtifactRef, error) {
	state := b.state(id)
	if state == nil {
		return nil, ErrSandboxNotFound
	}
	if b.blobs == nil {
		return nil, ErrUnsupported
	}
	artifacts := make([]ArtifactRef, 0, len(paths))
	for _, artifactPath := range paths {
		stored, err := b.blobs.Put(ctx, "application/vnd.aor.sandbox-export.v1.tar", false, func(destination io.Writer) error {
			return writeTar(state.directory, artifactPath, destination)
		})
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, ArtifactRef{Path: artifactPath, URI: stored.URI, SHA256: stored.SHA256, Size: stored.Size})
	}
	return artifacts, nil
}

func (b *WindowsNativeBackend) Snapshot(ctx context.Context, id string) (SnapshotRef, error) {
	state := b.state(id)
	if state == nil {
		return SnapshotRef{}, ErrSandboxNotFound
	}
	if b.blobs == nil {
		return SnapshotRef{}, ErrUnsupported
	}
	stored, err := b.blobs.Put(ctx, "application/vnd.aor.windows-workdir.v1.tar", true, func(destination io.Writer) error {
		return writeTar(state.directory, ".", destination)
	})
	if err != nil {
		return SnapshotRef{}, err
	}
	return SnapshotRef{URI: stored.URI, SHA256: stored.SHA256}, nil
}

func (b *WindowsNativeBackend) Terminate(_ context.Context, id, _ string) error {
	state := b.state(id)
	if state == nil {
		return ErrSandboxNotFound
	}
	state.mu.Lock()
	state.terminated = true
	processes := make([]*exec.Cmd, 0, len(state.processes))
	for process := range state.processes {
		processes = append(processes, process)
	}
	state.mu.Unlock()
	var failed bool
	for _, process := range processes {
		if process.Process != nil && process.Process.Kill() != nil {
			failed = true
		}
	}
	if failed {
		return ErrBackendUnavailable
	}
	return nil
}

func (b *WindowsNativeBackend) Destroy(ctx context.Context, id string) error {
	state := b.state(id)
	if state == nil {
		return nil
	}
	if err := b.Terminate(ctx, id, "destroy"); err != nil {
		return err
	}
	if err := os.RemoveAll(state.directory); err != nil {
		return ErrBackendUnavailable
	}
	b.mu.Lock()
	delete(b.states, id)
	b.mu.Unlock()
	return nil
}

func (b *WindowsNativeBackend) state(id string) *windowsProcessState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.states[id]
}

func allowedEnvironment(allowlist, environment []string) []string {
	result := make([]string, 0, len(allowlist))
	for _, entry := range environment {
		name, _, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		for _, allowed := range allowlist {
			if strings.EqualFold(name, allowed) {
				result = append(result, entry)
				break
			}
		}
	}
	return result
}

func withinRoot(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func writeTar(root, requested string, destination io.Writer) error {
	clean, ok := cleanRelativePath(requested)
	if requested == "." {
		clean, ok = ".", true
	}
	if !ok {
		return ErrInvalidSpec
	}
	base := filepath.Join(root, filepath.FromSlash(clean))
	if !withinRoot(root, base) {
		return ErrInvalidSpec
	}
	archive := tar.NewWriter(destination)
	defer archive.Close()
	return filepath.WalkDir(base, func(pathName string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return ErrBackendUnavailable
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return ErrUnsafeWorkload
		}
		info, err := entry.Info()
		if err != nil {
			return ErrBackendUnavailable
		}
		relative, err := filepath.Rel(root, pathName)
		if err != nil || !withinRoot(root, pathName) {
			return ErrUnsafeWorkload
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return ErrBackendUnavailable
		}
		header.Name = filepath.ToSlash(relative)
		if err := archive.WriteHeader(header); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		file, err := os.Open(pathName)
		if err != nil {
			return ErrBackendUnavailable
		}
		_, copyErr := io.Copy(archive, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}

var _ Backend = (*WindowsNativeBackend)(nil)
