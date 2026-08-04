package servicebootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/credentials"
	"github.com/akimisaka/aor/internal/runtimeclient"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	"github.com/akimisaka/aor/internal/sandbox"
	aorworkflow "github.com/akimisaka/aor/internal/workflow"
)

var (
	ErrWorkerConfiguration = errors.New("invalid worker configuration")
	ErrWorkerUnavailable   = errors.New("worker execution provider unavailable")
)

// sandboxActivityInput is intentionally narrow: workflow code can only ask a
// worker to execute a validated sandbox command. Network, model, repository,
// and tool operations remain controlled by their dedicated services.
type sandboxActivityInput struct {
	Action          string               `json:"action"`
	Spec            sandbox.SandboxSpec  `json:"spec"`
	Lease           authz.LeaseReference `json:"lease"`
	AgentInstanceID string               `json:"agentInstanceId"`
	BudgetAccountID string               `json:"budgetAccountId"`
	Executable      string               `json:"executable"`
	Arguments       []string             `json:"arguments,omitempty"`
	WorkingDir      string               `json:"workingDir,omitempty"`
	TimeoutSeconds  int                  `json:"timeoutSeconds"`
	ExportPaths     []string             `json:"exportPaths,omitempty"`
}

type sandboxActivityEffect struct {
	provider   sandbox.SandboxProvider
	authorizer sandboxExecutionAuthorizer
}

func (effect sandboxActivityEffect) Execute(ctx context.Context, key string, payload json.RawMessage) (output json.RawMessage, resultErr error) {
	if effect.provider == nil || effect.authorizer == nil || ctx == nil || strings.TrimSpace(key) == "" {
		return nil, ErrWorkerUnavailable
	}
	var input sandboxActivityInput
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, aorworkflow.ErrInvalidExecution
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, aorworkflow.ErrInvalidExecution
	}
	if input.Action != authz.ActionSandboxExec || input.TimeoutSeconds <= 0 || input.TimeoutSeconds > 24*60*60 || input.Executable == "" || input.Lease.ID == "" || input.Lease.PolicyVersion == "" || input.Lease.FencingToken < 1 || input.Lease.ExpiresAt.IsZero() || input.AgentInstanceID == "" || input.BudgetAccountID == "" || len(input.Arguments) > 256 || len(input.ExportPaths) > 256 {
		return nil, aorworkflow.ErrInvalidExecution
	}
	execution, found := aorworkflow.ExecutionInputFromContext(ctx)
	if !found || input.Spec.TenantID != execution.TenantID || input.Spec.ProjectID != execution.ProjectID || input.Spec.TaskID != execution.TaskID {
		return nil, aorworkflow.ErrInvalidExecution
	}
	if err := input.Spec.Validate(); err != nil {
		return nil, err
	}
	if input.TimeoutSeconds > input.Spec.WallTimeSeconds {
		return nil, aorworkflow.ErrInvalidExecution
	}
	if err := effect.authorizer.Authorize(ctx, execution, input); err != nil {
		return nil, err
	}
	handle, err := effect.provider.Create(ctx, input.Spec)
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		cleanupErr := effect.provider.Destroy(cleanupCtx, handle.ID)
		cancel()
		if cleanupErr != nil {
			output = nil
			resultErr = errors.Join(resultErr, sandbox.ErrCleanupFailed, cleanupErr)
		}
	}()
	if err := effect.authorizer.Authorize(ctx, execution, input); err != nil {
		return nil, err
	}
	result, err := effect.provider.Exec(ctx, handle.ID, sandbox.ExecRequest{
		Executable: input.Executable,
		Arguments:  append([]string(nil), input.Arguments...),
		WorkingDir: input.WorkingDir,
		Timeout:    time.Duration(input.TimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, err
	}
	var artifacts []sandbox.ArtifactRef
	if len(input.ExportPaths) > 0 {
		if err := effect.authorizer.Authorize(ctx, execution, input); err != nil {
			return nil, err
		}
		artifacts, err = effect.provider.Export(ctx, handle.ID, input.ExportPaths)
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(struct {
		Key         string                `json:"idempotencyKey"`
		ExitCode    int                   `json:"exitCode"`
		Stdout      []byte                `json:"stdout"`
		Stderr      []byte                `json:"stderr"`
		StartedAt   time.Time             `json:"startedAt"`
		FinishedAt  time.Time             `json:"finishedAt"`
		Artifacts   []sandbox.ArtifactRef `json:"artifacts,omitempty"`
		Attestation sandbox.Attestation   `json:"attestation"`
	}{Key: key, ExitCode: result.ExitCode, Stdout: append([]byte(nil), result.Stdout...), Stderr: append([]byte(nil), result.Stderr...), StartedAt: result.StartedAt, FinishedAt: result.FinishedAt, Artifacts: append([]sandbox.ArtifactRef(nil), artifacts...), Attestation: handle.Attestation})
}

type workerHandler struct {
	runtime *aorworkflow.TemporalWorker
}

func (handler *workerHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if request.Method != http.MethodGet || request.URL.Path != "/" {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	if err := handler.runtime.Ready(); err != nil {
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (handler *workerHandler) Close() error {
	if handler != nil && handler.runtime != nil {
		handler.runtime.Stop()
	}
	return nil
}

func (handler *workerHandler) Ready() error {
	if handler == nil || handler.runtime == nil {
		return ErrWorkerUnavailable
	}
	return handler.runtime.Ready()
}

// Worker constructs and starts the Temporal worker before exposing the
// process. Provider readiness is checked first so an unsafe or unavailable
// execution backend cannot result in a polling worker that fails open.
func Worker(config runtimeconfig.Config, clients *runtimeclient.Clients) (http.Handler, error) {
	if config.Component != "aor-worker" || clients == nil || clients.Temporal() == nil || clients.Database() == nil {
		return nil, ErrWorkerConfiguration
	}
	provider, err := newExecutionProvider(config)
	if err != nil {
		return nil, err
	}
	probeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := provider.Ready(probeCtx); err != nil {
		return nil, errors.Join(ErrWorkerUnavailable, err)
	}
	secretResolver := credentials.NewSecretResolver(os.Getenv("AOR_SECRET_ROOT"))
	leaseKey, err := secretResolver.Resolve(probeCtx, config.LeaseSigningKeyRef)
	if err != nil {
		return nil, ErrWorkerConfiguration
	}
	leaseSigner, err := authz.NewHMACSigner(leaseKey)
	for index := range leaseKey {
		leaseKey[index] = 0
	}
	if err != nil {
		return nil, ErrWorkerConfiguration
	}
	leaseStore, err := authz.NewPostgresLeaseStore(clients.Database())
	if err != nil {
		return nil, ErrWorkerConfiguration
	}
	leaseManager, err := authz.NewLeaseManager(authz.LeaseManagerConfig{Store: leaseStore, Signer: leaseSigner, Clock: time.Now, HeartbeatInterval: 30 * time.Second})
	if err != nil {
		return nil, ErrWorkerConfiguration
	}
	scopes, err := newPostgresSandboxExecutionScopeResolver(clients.Database())
	if err != nil {
		return nil, err
	}
	authorizer, err := newLeaseBoundSandboxAuthorizer(config, scopes, leaseManager)
	if err != nil {
		return nil, err
	}
	activityResults, err := aorworkflow.NewPostgresActivityResultStore(clients.Database())
	if err != nil {
		return nil, err
	}
	activities, err := aorworkflow.NewActivitiesWithStore(sandboxActivityEffect{provider: provider, authorizer: authorizer}, activityResults)
	if err != nil {
		return nil, err
	}
	runtimeWorker, err := aorworkflow.NewTemporalWorker(clients.Temporal(), config.Temporal.TaskQueue, os.Getenv("AOR_WORKER_BUILD_ID"), activities)
	if err != nil {
		return nil, err
	}
	if err := runtimeWorker.Start(); err != nil {
		return nil, err
	}
	return &workerHandler{runtime: runtimeWorker}, nil
}

func newExecutionProvider(config runtimeconfig.Config) (*sandbox.Provider, error) {
	switch runtime.GOOS {
	case "linux":
		if config.Sandbox.EngineEndpoint == "" || config.Sandbox.ImageReference == "" || len(config.Sandbox.AllowedMountRoots) == 0 {
			return nil, ErrWorkerConfiguration
		}
		backend, err := sandbox.NewDockerBackend(sandbox.DockerBackendOptions{
			Binary:          "docker",
			Endpoint:        config.Sandbox.EngineEndpoint,
			RuntimeName:     config.Sandbox.RuntimeName,
			ImageReference:  config.Sandbox.ImageReference,
			SeccompProfile:  config.Sandbox.SeccompProfile,
			MandatoryPolicy: config.Sandbox.MandatoryPolicy,
			HoldCommand:     append([]string(nil), config.Sandbox.HoldCommand...),
		})
		if err != nil {
			return nil, errors.Join(ErrWorkerConfiguration, err)
		}
		return sandbox.NewLinuxProviderWithOptions(backend, sandbox.LinuxProviderOptions{
			RuntimeName:       config.Sandbox.RuntimeName,
			AllowedMountRoots: append([]string(nil), config.Sandbox.AllowedMountRoots...),
		}, time.Now), nil
	case "windows":
		workRoot := strings.TrimSpace(os.Getenv("AOR_SANDBOX_WINDOWS_WORK_ROOT"))
		if workRoot == "" {
			return nil, ErrWorkerConfiguration
		}
		backend, err := sandbox.NewWindowsNativeBackend(sandbox.WindowsBackendOptions{WorkRoot: workRoot})
		if err != nil {
			return nil, errors.Join(ErrWorkerConfiguration, err)
		}
		return sandbox.NewWindowsProvider(backend, time.Now), nil
	default:
		return nil, ErrWorkerUnavailable
	}
}
