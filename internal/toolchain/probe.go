package toolchain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maximumProbeRequestBytes = int64(64 << 10)
	maximumProbeCommands     = 16
	defaultProbeTimeout      = 2 * time.Minute
)

type ProbeCommand struct {
	Name string   `json:"name"`
	Path string   `json:"path"`
	Args []string `json:"args"`
}

type ProbeRequest struct {
	Root            string         `json:"root"`
	ExpectedVersion string         `json:"expectedVersion"`
	Commands        []ProbeCommand `json:"commands"`
}

type ProbeResult struct {
	OK      bool   `json:"ok"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type ExecutableProber interface {
	Probe(context.Context, ProbeRequest) error
}

type LocalExecutableProber struct{}

func (LocalExecutableProber) Probe(ctx context.Context, request ProbeRequest) error {
	return runProbe(ctx, request)
}

type UnixProbeClient struct {
	socketPath string
}

func NewUnixProbeClient(socketPath string) (*UnixProbeClient, error) {
	if !validProbeSocketPath(socketPath) {
		return nil, ErrInvalidInventory
	}
	return &UnixProbeClient{socketPath: socketPath}, nil
}

func (client *UnixProbeClient) Probe(ctx context.Context, request ProbeRequest) error {
	if client == nil || ctx == nil || validateProbeRequest(request, "") != nil {
		return ErrInvalidInventory
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", client.socketPath)
	if err != nil {
		return err
	}
	defer connection.Close()
	deadline := time.Now().Add(10 * time.Minute)
	if contextDeadline, found := ctx.Deadline(); found && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return err
	}
	var result ProbeResult
	decoder := json.NewDecoder(io.LimitReader(connection, maximumProbeRequestBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return err
	}
	if result.OK {
		return nil
	}
	switch result.Code {
	case "VERSION_MISMATCH":
		return ErrToolchainVersion
	case "NOT_PORTABLE":
		if result.Message != "" {
			return fmt.Errorf("%w: %s", ErrToolchainNotPortable, result.Message)
		}
		return ErrToolchainNotPortable
	case "LIMIT_EXCEEDED":
		return ErrArchiveLimit
	default:
		if result.Message != "" {
			return fmt.Errorf("%w: %s", ErrUnsupportedTool, result.Message)
		}
		return ErrUnsupportedTool
	}
}

type ProbeServer struct {
	socketPath string
	workRoot   string
	running    atomic.Bool
	listener   *net.UnixListener
	mutex      sync.Mutex
}

func NewProbeServer(socketPath, workRoot string) (*ProbeServer, error) {
	if !validProbeSocketPath(socketPath) || !validInstallerRoot(workRoot) {
		return nil, ErrInvalidInventory
	}
	return &ProbeServer{socketPath: socketPath, workRoot: workRoot}, nil
}

func (server *ProbeServer) Ready() error {
	if server == nil || !server.running.Load() {
		return ErrProvisionerUnavailable
	}
	return nil
}

func (server *ProbeServer) Run(ctx context.Context) error {
	if server == nil || ctx == nil || !server.running.CompareAndSwap(false, true) {
		return ErrProvisionerUnavailable
	}
	defer server.running.Store(false)
	if err := os.MkdirAll(filepath.Dir(server.socketPath), 0o770); err != nil {
		return err
	}
	if info, err := os.Lstat(server.socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return ErrInvalidInventory
		}
		if err := os.Remove(server.socketPath); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: server.socketPath, Net: "unix"})
	if err != nil {
		return err
	}
	server.mutex.Lock()
	server.listener = listener
	server.mutex.Unlock()
	defer func() {
		_ = listener.Close()
		_ = os.Remove(server.socketPath)
		server.mutex.Lock()
		server.listener = nil
		server.mutex.Unlock()
	}()
	if err := os.Chmod(server.socketPath, 0o666); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return acceptErr
		}
		go server.handle(ctx, connection)
	}
}

func (server *ProbeServer) Close() error {
	if server == nil {
		return nil
	}
	server.mutex.Lock()
	listener := server.listener
	server.mutex.Unlock()
	if listener == nil {
		return nil
	}
	return listener.Close()
}

func (server *ProbeServer) handle(ctx context.Context, connection *net.UnixConn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Minute))
	decoder := json.NewDecoder(io.LimitReader(connection, maximumProbeRequestBytes+1))
	decoder.DisallowUnknownFields()
	var request ProbeRequest
	result := ProbeResult{}
	if err := decoder.Decode(&request); err != nil || validateProbeRequest(request, server.workRoot) != nil {
		result.Code = "INVALID_REQUEST"
		result.Message = "invalid toolchain probe request"
	} else {
		probeContext, cancel := context.WithTimeout(ctx, 10*time.Minute)
		err := runProbe(probeContext, request)
		cancel()
		if err == nil {
			result.OK = true
		} else {
			result.Code, result.Message = probeFailure(err)
		}
	}
	_ = json.NewEncoder(connection).Encode(result)
}

func probeFailure(err error) (string, string) {
	switch {
	case errors.Is(err, ErrToolchainVersion):
		return "VERSION_MISMATCH", "toolchain version probe mismatch"
	case errors.Is(err, ErrArchiveLimit):
		return "LIMIT_EXCEEDED", "toolchain probe output limit exceeded"
	default:
		return "NOT_PORTABLE", provisioningErrorMessage(err)
	}
}

func validateProbeRequest(request ProbeRequest, workRoot string) error {
	if request.Root == "" || !filepath.IsAbs(request.Root) || filepath.Clean(request.Root) != request.Root ||
		!exactText(request.ExpectedVersion, 256) || len(request.Commands) < 1 || len(request.Commands) > maximumProbeCommands {
		return ErrInvalidInventory
	}
	if workRoot != "" {
		resolvedRoot, err := filepath.EvalSymlinks(request.Root)
		if err != nil {
			return ErrInvalidInventory
		}
		relative, err := filepath.Rel(workRoot, resolvedRoot)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return ErrInvalidInventory
		}
		request.Root = resolvedRoot
	}
	for _, command := range request.Commands {
		if !safeToken(command.Name, 128) || len(command.Args) > 16 {
			return ErrInvalidInventory
		}
		path, err := containedPath(request.Root, command.Path)
		if err != nil {
			return ErrInvalidInventory
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return ErrInvalidInventory
		}
		for _, argument := range command.Args {
			if argument == "" || len(argument) > 128 || strings.ContainsAny(argument, "\r\n\x00") {
				return ErrInvalidInventory
			}
		}
	}
	return nil
}

func runProbe(ctx context.Context, request ProbeRequest) error {
	if err := validateProbeRequest(request, ""); err != nil {
		return err
	}
	temporaryRoot, err := os.MkdirTemp("", "aor-toolchain-probe-")
	if err != nil {
		return fmt.Errorf("create probe temporary directory: %w", err)
	}
	defer os.RemoveAll(temporaryRoot)
	for _, probe := range request.Commands {
		commandContext, cancel := context.WithTimeout(ctx, defaultProbeTimeout)
		path, err := containedPath(request.Root, probe.Path)
		if err != nil {
			cancel()
			return ErrToolchainNotPortable
		}
		command := exec.CommandContext(commandContext, path, probe.Args...)
		command.Dir = request.Root
		command.Env = probeEnvironment(request.Root, temporaryRoot)
		output, runErr := limitedCombinedOutput(command, defaultProbeLimit)
		cancel()
		if runErr != nil {
			return fmt.Errorf("%w: %s: %v", ErrToolchainNotPortable, probe.Name, runErr)
		}
		if !exactVersionInOutput(string(output), request.ExpectedVersion) {
			return fmt.Errorf("%w: %s", ErrToolchainVersion, probe.Name)
		}
	}
	return nil
}

func probeEnvironment(root, temporaryRoot string) []string {
	paths := []string{filepath.Join(root, "bin")}
	if systemPath := os.Getenv("PATH"); systemPath != "" {
		paths = append(paths, systemPath)
	}
	return []string{
		"HOME=" + temporaryRoot,
		"TMPDIR=" + temporaryRoot,
		"XDG_CACHE_HOME=" + filepath.Join(temporaryRoot, "cache"),
		"LANG=C",
		"LC_ALL=C",
		"PATH=" + strings.Join(paths, string(os.PathListSeparator)),
	}
}

func probeRequest(root string, executables []Executable, profile toolProfile, version string) ProbeRequest {
	commands := make([]ProbeCommand, 0, len(executables))
	for index, executable := range executables {
		commands = append(commands, ProbeCommand{Name: executable.Name, Path: executable.Path, Args: append([]string(nil), profile.executables[index].versionArgs...)})
	}
	return ProbeRequest{Root: root, ExpectedVersion: version, Commands: commands}
}

func validProbeSocketPath(value string) bool {
	return value != "" && len(value) <= 100 && filepath.IsAbs(value) && filepath.Clean(value) == value && value != string(filepath.Separator) && !strings.ContainsAny(value, "\r\n\x00")
}
