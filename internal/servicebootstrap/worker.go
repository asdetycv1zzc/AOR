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

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/credentials"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/execution"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/knowledge"
	"github.com/akimisaka/aor/internal/leaseauthority"
	"github.com/akimisaka/aor/internal/policy"
	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/runtimeclient"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	"github.com/akimisaka/aor/internal/sandbox"
	"github.com/akimisaka/aor/internal/toolbroker"
	aorworkflow "github.com/akimisaka/aor/internal/workflow"
)

var (
	ErrWorkerConfiguration = errors.New("invalid worker configuration")
	ErrWorkerUnavailable   = errors.New("worker execution provider unavailable")
)

const ExecutionActivityAction = "execution.execute"

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

type executionActivityInput struct {
	Action      string `json:"action"`
	ExecutionID string `json:"executionId"`
}

type workerActivityEffect struct {
	sandbox   sandboxActivityEffect
	execution *execution.Service
}

func (effect workerActivityEffect) Execute(ctx context.Context, key string, payload json.RawMessage) (json.RawMessage, error) {
	var route struct {
		Action string `json:"action"`
	}
	if json.Unmarshal(payload, &route) != nil {
		return nil, aorworkflow.ErrInvalidExecution
	}
	if route.Action == authz.ActionSandboxExec {
		return effect.sandbox.Execute(ctx, key, payload)
	}
	if route.Action != ExecutionActivityAction || effect.execution == nil {
		return nil, aorworkflow.ErrInvalidExecution
	}
	var input executionActivityInput
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil {
		return nil, aorworkflow.ErrInvalidExecution
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || input.Action != ExecutionActivityAction || strings.TrimSpace(input.ExecutionID) != input.ExecutionID || input.ExecutionID == "" || len(input.ExecutionID) > 256 {
		return nil, aorworkflow.ErrInvalidExecution
	}
	scope, found := aorworkflow.ExecutionInputFromContext(ctx)
	if !found {
		return nil, aorworkflow.ErrInvalidExecution
	}
	result, err := effect.execution.Execute(ctx, execution.Request{
		ExecutionID: input.ExecutionID, TenantID: scope.TenantID,
		ProjectID: scope.ProjectID, TaskID: scope.TaskID,
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
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
	closer  io.Closer
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
	var closeErr error
	if handler != nil && handler.runtime != nil {
		handler.runtime.Stop()
	}
	if handler != nil && handler.closer != nil {
		closeErr = handler.closer.Close()
	}
	return closeErr
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
	if config.Component != "aor-worker" || clients == nil || clients.Temporal() == nil || clients.Database() == nil || clients.JetStream() == nil || clients.S3() == nil {
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
	repositoryKey := deriveRepositorySigningKey(leaseKey)
	leaseSigner, err := authz.NewHMACSigner(leaseKey)
	repositorySigner, repositorySignerErr := repository.NewHMACSigner(repositoryKey)
	for index := range leaseKey {
		leaseKey[index] = 0
	}
	for index := range repositoryKey {
		repositoryKey[index] = 0
	}
	if err != nil || repositorySignerErr != nil {
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
	executionService, host, err := configuredWorkerExecution(config, clients, leaseManager, leaseSigner, repositorySigner, secretResolver)
	if err != nil {
		return nil, err
	}
	activities, err := aorworkflow.NewActivitiesWithStore(workerActivityEffect{
		sandbox: sandboxActivityEffect{provider: provider, authorizer: authorizer}, execution: executionService,
	}, activityResults)
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	runtimeWorker, err := aorworkflow.NewTemporalWorker(clients.Temporal(), config.Temporal.TaskQueue, os.Getenv("AOR_WORKER_BUILD_ID"), activities)
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	if err := runtimeWorker.Start(); err != nil {
		_ = host.Close()
		return nil, err
	}
	return &workerHandler{runtime: runtimeWorker, closer: host}, nil
}

func configuredWorkerExecution(config runtimeconfig.Config, clients *runtimeclient.Clients, leaseManager *authz.LeaseManager, leaseSigner authz.Signer, repositorySigner repository.Signer, secretResolver *credentials.SecretResolver) (*execution.Service, *toolbroker.Host, error) {
	if clients == nil || leaseManager == nil || leaseSigner == nil || repositorySigner == nil || secretResolver == nil {
		return nil, nil, ErrWorkerConfiguration
	}
	policyClient, err := policy.NewOPAClient(config.OPA.URL)
	if err != nil {
		return nil, nil, err
	}
	toolScopes, err := toolbroker.NewPostgresScopeResolver(toolbroker.PostgresScopeResolverConfig{Database: clients.Database(), DeploymentProfile: config.DeploymentProfile})
	if err != nil {
		return nil, nil, err
	}
	leaseChecker := toolbroker.AuthzLeaseChecker{Manager: leaseManager, Scopes: toolScopes}
	policyEvaluator := toolbroker.OPAPolicyEvaluator{Policy: policyClient, Scopes: toolScopes, Clock: time.Now}
	streamRecorder, err := toolbroker.NewJetStreamInvocationRecorder(clients.JetStream(), config.NATS.Stream)
	if err != nil {
		return nil, nil, err
	}
	durableRecorder, err := toolbroker.NewPostgresInvocationRecorder(clients.Database())
	if err != nil {
		return nil, nil, err
	}
	recorder, err := toolbroker.NewCompositeInvocationRecorder(durableRecorder, streamRecorder)
	if err != nil {
		return nil, nil, err
	}
	artifactCatalog, err := artifact.NewPostgresS3Catalog(clients.Database(), clients.S3(), config.S3.Bucket, time.Now)
	if err != nil {
		return nil, nil, err
	}
	artifactPublisher, err := toolbroker.NewArtifactPublisher(artifactCatalog)
	if err != nil {
		return nil, nil, err
	}
	broker := toolbroker.New(leaseChecker, policyEvaluator, nil, artifactPublisher, recorder, policyEvaluator.Revalidate, time.Now)
	host, err := toolbroker.NewHost(broker)
	if err != nil {
		return nil, nil, err
	}
	repositoryClient, err := newRepositoryMCPClient(config.RepositoryRoot, clients.Database(), leaseChecker, repositorySigner, time.Now)
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	loadContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = host.AddServerWithPolicies(loadContext, repositoryMCPServerID, repositoryMCPVersion, repositoryClient, repositoryMCPPolicies())
	cancel()
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}

	leaseScopes, err := leaseauthority.NewPostgresScopeResolver(clients.Database(), config.DeploymentProfile)
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	leaseService, err := leaseauthority.New(leaseauthority.Config{Manager: leaseManager, Policy: policyClient, Scopes: leaseScopes, Clock: time.Now})
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	toolResolver, err := leaseauthority.NewDescriptorToolResolver(host.Broker().List())
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	runtimeAuthority, err := leaseauthority.NewRuntimeOperationAuthority(leaseService, 5*time.Minute, toolResolver)
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	slots, err := agentruntime.NewSlotPool(agentruntime.MaximumActiveAgentLimit, time.Now)
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	resolveContext, resolveCancel := context.WithTimeout(context.Background(), 10*time.Second)
	gateway, err := configuredModelGatewayClient(resolveContext, config, secretResolver)
	resolveCancel()
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	agentRuntime, err := agentruntime.New(runtimeAuthority, gateway, host.Broker(), slots, time.Now)
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}

	store := eventing.NewPostgresStore(clients.Database())
	tasks, err := execution.NewOrchestratorTaskAuthority(store, clients.Database(), leaseSigner, leaseManager, time.Now)
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	artifacts, err := goalplan.NewEventArtifactStore(store, time.Now)
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	specs, err := execution.NewArtifactModuleSpecs(artifacts)
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	assignments, err := execution.NewPostgresAssignmentAuthority(clients.Database())
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	knowledgeRepository, err := knowledge.NewFileRepository(config.KnowledgeRoot)
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	knowledgeScopes, err := knowledge.NewEventingScopeResolver(store)
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	knowledgeService, err := knowledge.NewService(knowledge.ServiceConfig{Repository: knowledgeRepository, Authorizer: policyClient, Scopes: knowledgeScopes, Clock: time.Now})
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	route := config.Execution.Route
	preparer, err := execution.NewExecutorRuntimePreparer(execution.ExecutorRuntimePreparerConfig{
		Knowledge: execution.KnowledgeServiceContextSource{Service: knowledgeService}, Leases: leaseService,
		Assignments: assignments, Tools: host.Broker().List(),
		Route: goalplan.ModelRoute{Provider: route.Provider, Model: route.Model, MaxOutputTokens: route.MaxOutputTokens,
			Temperature: route.Temperature, Seed: route.Seed, ProviderPolicy: route.ProviderPolicy,
			CachePolicy: route.CachePolicy, WorstCaseCostMicros: route.WorstCaseCostMicros, MaxAttempts: route.MaxAttempts},
		LeaseTTL: 5 * time.Minute, MaxToolRounds: config.Execution.MaxToolRounds, Clock: time.Now,
	})
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	submissionStore, err := repository.NewPostgresSubmissionStore(clients.Database())
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	submissions, err := execution.NewVerifiedSubmissions(submissionStore, repositorySigner)
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	service, err := execution.New(execution.Config{Tasks: tasks, Specs: specs, Assignments: assignments, Preparer: preparer, Runtime: agentRuntime, Bases: repositoryClient.service, Submissions: submissions})
	if err != nil {
		_ = host.Close()
		return nil, nil, err
	}
	return service, host, nil
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
