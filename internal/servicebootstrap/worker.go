package servicebootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/internal/audit"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/credentials"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/execution"
	"github.com/akimisaka/aor/internal/globalaudit"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/integration"
	"github.com/akimisaka/aor/internal/knowledge"
	"github.com/akimisaka/aor/internal/leaseauthority"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/policy"
	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/runtimeclient"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	"github.com/akimisaka/aor/internal/sandbox"
	"github.com/akimisaka/aor/internal/toolbroker"
	aorworkflow "github.com/akimisaka/aor/internal/workflow"
	"github.com/google/uuid"
)

var (
	ErrWorkerConfiguration = errors.New("invalid worker configuration")
	ErrWorkerUnavailable   = errors.New("worker execution provider unavailable")
)

const ExecutionActivityAction = aorworkflow.ExecutionActivityAction

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
	Recovery    bool   `json:"recovery,omitempty"`
}

type globalAuditActivityInput struct {
	Action string `json:"action"`
	RunID  string `json:"runId"`
}

type integrationActivityInput struct {
	Action        string `json:"action"`
	IntegrationID string `json:"integrationId"`
}

type moduleAuditActivityInput struct {
	Action string `json:"action"`
	RunID  string `json:"runId"`
}

type moduleAuditActivity struct {
	service     *audit.ModuleAuditService
	provider    sandbox.SandboxProvider
	imageDigest string
	profile     sandbox.DeploymentProfile
	local       bool
}

type workerActivityEffect struct {
	sandbox       sandboxActivityEffect
	execution     *execution.Service
	moduleAuditor *moduleAuditActivity
	globalAuditor *globalaudit.Service
	integration   *integrationActivity
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
	if route.Action == aorworkflow.ModuleAuditActivityAction {
		if effect.moduleAuditor == nil {
			return nil, aorworkflow.ErrInvalidExecution
		}
		var input moduleAuditActivityInput
		decoder := json.NewDecoder(strings.NewReader(string(payload)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil {
			return nil, aorworkflow.ErrInvalidExecution
		}
		var trailing struct{}
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || input.Action != aorworkflow.ModuleAuditActivityAction || strings.TrimSpace(input.RunID) != input.RunID || input.RunID == "" || len(input.RunID) > 256 {
			return nil, aorworkflow.ErrInvalidExecution
		}
		executionInput, found := aorworkflow.ExecutionInputFromContext(ctx)
		if !found {
			return nil, aorworkflow.ErrInvalidExecution
		}
		principalContext, err := authn.ContextWithPrincipal(ctx, authn.Principal{
			ID: "aor-module-audit-service", Type: authn.PrincipalService, Role: authn.RoleService,
			TenantID: executionInput.TenantID, ProjectID: executionInput.ProjectID,
		})
		if err != nil {
			return nil, err
		}
		result, err := effect.moduleAuditor.Run(principalContext, executionInput, input.RunID)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	if route.Action == aorworkflow.GlobalAuditActivityAction {
		if effect.globalAuditor == nil {
			return nil, aorworkflow.ErrInvalidExecution
		}
		var input globalAuditActivityInput
		decoder := json.NewDecoder(strings.NewReader(string(payload)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil {
			return nil, aorworkflow.ErrInvalidExecution
		}
		var trailing struct{}
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || input.Action != aorworkflow.GlobalAuditActivityAction || strings.TrimSpace(input.RunID) != input.RunID || input.RunID == "" || len(input.RunID) > 256 {
			return nil, aorworkflow.ErrInvalidExecution
		}
		executionInput, found := aorworkflow.ExecutionInputFromContext(ctx)
		if !found || input.RunID != executionInput.TaskID {
			return nil, aorworkflow.ErrInvalidExecution
		}
		principalContext, err := authn.ContextWithPrincipal(ctx, authn.Principal{
			ID: "aor-global-audit-service", Type: authn.PrincipalService, Role: authn.RoleService,
			TenantID: executionInput.TenantID, ProjectID: executionInput.ProjectID,
		})
		if err != nil {
			return nil, err
		}
		result, err := effect.globalAuditor.Run(principalContext, globalaudit.Request{
			RunID: input.RunID, TenantID: executionInput.TenantID, ProjectID: executionInput.ProjectID,
		})
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	if route.Action == aorworkflow.IntegrationActivityAction {
		if effect.integration == nil {
			return nil, aorworkflow.ErrInvalidExecution
		}
		var input integrationActivityInput
		decoder := json.NewDecoder(strings.NewReader(string(payload)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil {
			return nil, aorworkflow.ErrInvalidExecution
		}
		var trailing struct{}
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || input.Action != aorworkflow.IntegrationActivityAction || strings.TrimSpace(input.IntegrationID) != input.IntegrationID || input.IntegrationID == "" || len(input.IntegrationID) > 256 {
			return nil, aorworkflow.ErrInvalidExecution
		}
		executionInput, found := aorworkflow.ExecutionInputFromContext(ctx)
		if !found || input.IntegrationID != executionInput.TaskID {
			return nil, aorworkflow.ErrInvalidExecution
		}
		principalContext, err := authn.ContextWithPrincipal(ctx, authn.Principal{
			ID: integrationServicePrincipalID, Type: authn.PrincipalService, Role: authn.RoleService,
			TenantID: executionInput.TenantID, ProjectID: executionInput.ProjectID,
		})
		if err != nil {
			return nil, err
		}
		result, err := effect.integration.Run(principalContext, executionInput.TenantID, executionInput.ProjectID, input.IntegrationID)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
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

func (activity *moduleAuditActivity) Run(ctx context.Context, input aorworkflow.ExecutionInput, runID string) (result audit.ModuleAuditResult, resultErr error) {
	parsedRunID, parseErr := uuid.Parse(runID)
	if activity == nil || activity.service == nil || !activity.local && activity.provider == nil || ctx == nil || ctx.Err() != nil || parseErr != nil || parsedRunID.Version() != 7 || parsedRunID.String() != runID {
		return audit.ModuleAuditResult{}, ErrWorkerUnavailable
	}
	if activity.local {
		return activity.service.Run(ctx, audit.ModuleAuditRequest{
			AuditRunID: runID, TenantID: input.TenantID, ProjectID: input.ProjectID,
			TaskID: input.TaskID, SandboxID: stableModuleAuditRuntimeID(input, runID),
		})
	}
	spec, err := activity.sandboxSpec(input, runID)
	if err != nil {
		return audit.ModuleAuditResult{}, err
	}
	handle, err := activity.provider.Create(ctx, spec)
	if err != nil {
		return audit.ModuleAuditResult{}, err
	}
	defer func() {
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		cleanupErr := activity.provider.Destroy(cleanupContext, handle.ID)
		cancel()
		if cleanupErr != nil {
			result = audit.ModuleAuditResult{}
			resultErr = errors.Join(resultErr, sandbox.ErrCleanupFailed, cleanupErr)
		}
	}()
	if handle.ID != spec.SandboxID || handle.Platform != spec.Platform || handle.IsolationLevel != spec.IsolationLevel ||
		spec.Platform == sandbox.PlatformLinux && handle.Attestation.ImageDigest != spec.ImageDigest ||
		spec.Platform == sandbox.PlatformWindows && handle.Attestation.Runtime != "native-process" {
		return audit.ModuleAuditResult{}, ErrWorkerUnavailable
	}
	return activity.service.Run(ctx, audit.ModuleAuditRequest{
		AuditRunID: runID, TenantID: input.TenantID, ProjectID: input.ProjectID, TaskID: input.TaskID, SandboxID: handle.ID,
	})
}

func (activity *moduleAuditActivity) sandboxSpec(input aorworkflow.ExecutionInput, runID string) (sandbox.SandboxSpec, error) {
	base := sandbox.SandboxSpec{
		SandboxID: stableModuleAuditRuntimeID(input, runID), TenantID: input.TenantID,
		ProjectID: input.ProjectID, TaskID: input.TaskID, Role: sandbox.RoleAuditor,
		WallTimeSeconds: 1800, AllowedExecutables: []string{}, EnvironmentAllowlist: []string{},
		DeploymentProfile: activity.profile,
	}
	switch runtime.GOOS {
	case "linux":
		base.Platform = sandbox.PlatformLinux
		base.IsolationLevel = sandbox.IsolationContainer
		base.ImageDigest = activity.imageDigest
		base.CPULimit = "1"
		base.MemoryBytes = 512 * 1024 * 1024
		base.PIDsLimit = 128
		base.DiskBytes = 1024 * 1024 * 1024
		base.NetworkPolicy = sandbox.NetworkPolicy{Mode: "DENY_ALL"}
		base.WorkloadTrust = sandbox.TrustUntrusted
		base.RequiresHiddenTests = true
		base.RequiresNetworkIsolation = true
	case "windows":
		base.Platform = sandbox.PlatformWindows
		base.IsolationLevel = sandbox.IsolationNone
		base.WorkloadTrust = sandbox.TrustTrusted
		base.TrustedSingleTenant = true
	default:
		return sandbox.SandboxSpec{}, ErrWorkerUnavailable
	}
	if err := base.Validate(); err != nil {
		return sandbox.SandboxSpec{}, errors.Join(ErrWorkerConfiguration, err)
	}
	return base, nil
}

func stableModuleAuditRuntimeID(input aorworkflow.ExecutionInput, runID string) string {
	digest := sha256.Sum256([]byte(input.TenantID + "\x00" + input.ProjectID + "\x00" + input.TaskID + "\x00" + runID))
	return "module-audit-runtime-" + hex.EncodeToString(digest[:])
}

func workerExecutableDigest() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

type workerExecutionServices struct {
	execution         *execution.Service
	host              *toolbroker.Host
	agentRuntime      *agentruntime.Runtime
	tasks             *execution.OrchestratorTaskAuthority
	leaseService      *leaseauthority.Service
	artifactCatalog   *artifact.PostgresS3Catalog
	artifactPublisher *artifact.CapabilityPublisher
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
	var provider sandbox.SandboxProvider
	probeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if config.DeploymentProfile != "TEST" {
		configuredProvider, err := newExecutionProvider(config)
		if err != nil {
			return nil, err
		}
		if err := configuredProvider.Ready(probeCtx); err != nil {
			return nil, errors.Join(ErrWorkerUnavailable, err)
		}
		provider = configuredProvider
	}
	secretResolver := credentials.NewSecretResolver(os.Getenv("AOR_SECRET_ROOT"))
	leaseKey, err := secretResolver.Resolve(probeCtx, config.LeaseSigningKeyRef)
	if err != nil {
		return nil, ErrWorkerConfiguration
	}
	repositoryKey := deriveRepositorySigningKey(leaseKey)
	moduleAuditKey := deriveModuleAuditSigningKey(leaseKey)
	globalAuditKey := deriveGlobalAuditSigningKey(leaseKey)
	leaseSigner, err := authz.NewHMACSigner(leaseKey)
	repositorySigner, repositorySignerErr := repository.NewHMACSigner(repositoryKey)
	moduleAuditSigner, moduleAuditSignerErr := audit.NewHMACSigner(moduleAuditKey)
	globalAuditSigner, globalAuditSignerErr := audit.NewHMACSigner(globalAuditKey)
	for index := range leaseKey {
		leaseKey[index] = 0
	}
	for index := range repositoryKey {
		repositoryKey[index] = 0
	}
	for index := range moduleAuditKey {
		moduleAuditKey[index] = 0
	}
	for index := range globalAuditKey {
		globalAuditKey[index] = 0
	}
	if err != nil || repositorySignerErr != nil || moduleAuditSignerErr != nil || globalAuditSignerErr != nil {
		return nil, ErrWorkerConfiguration
	}
	leaseStore, err := authz.NewPostgresLeaseStore(clients.Database())
	if err != nil {
		return nil, ErrWorkerConfiguration
	}
	leaseManager, err := authz.NewLeaseManager(authz.LeaseManagerConfig{Store: leaseStore, Signer: leaseSigner, DefaultTTL: 5 * time.Minute, MaxTTL: 35 * time.Minute, HeartbeatInterval: 30 * time.Second})
	if err != nil {
		return nil, ErrWorkerConfiguration
	}
	var authorizer sandboxExecutionAuthorizer
	if provider != nil {
		scopes, err := newPostgresSandboxExecutionScopeResolver(clients.Database())
		if err != nil {
			return nil, err
		}
		authorizer, err = newLeaseBoundSandboxAuthorizer(config, scopes, leaseManager)
		if err != nil {
			return nil, err
		}
	}
	activityResults, err := aorworkflow.NewPostgresActivityResultStore(clients.Database())
	if err != nil {
		return nil, err
	}
	services, err := configuredWorkerExecution(config, clients, leaseManager, leaseSigner, repositorySigner, secretResolver)
	if err != nil {
		return nil, err
	}
	moduleAuditor, err := configuredModuleAudit(config, clients, provider, services, repositorySigner, moduleAuditSigner)
	if err != nil {
		_ = services.host.Close()
		return nil, err
	}
	var globalAuditor *globalaudit.Service
	var integrationRuntime *integrationActivity
	if config.DeploymentProfile != "TEST" {
		globalAuditor, err = configuredGlobalAudit(config, clients, provider, services, globalAuditSigner, secretResolver)
		if err != nil {
			_ = services.host.Close()
			return nil, err
		}
		integrationRuntime, err = configuredIntegration(config, clients, provider, services, leaseManager, repositorySigner, moduleAuditSigner)
		if err != nil {
			_ = services.host.Close()
			return nil, err
		}
	}
	activities, err := aorworkflow.NewActivitiesWithStore(workerActivityEffect{
		sandbox: sandboxActivityEffect{provider: provider, authorizer: authorizer}, execution: services.execution,
		moduleAuditor: moduleAuditor, globalAuditor: globalAuditor, integration: integrationRuntime,
	}, activityResults)
	if err != nil {
		_ = services.host.Close()
		return nil, err
	}
	runtimeWorker, err := aorworkflow.NewTemporalWorker(clients.Temporal(), config.Temporal.TaskQueue, os.Getenv("AOR_WORKER_BUILD_ID"), activities)
	if err != nil {
		_ = services.host.Close()
		return nil, err
	}
	if err := runtimeWorker.Start(); err != nil {
		_ = services.host.Close()
		return nil, err
	}
	return &workerHandler{runtime: runtimeWorker, closer: services.host}, nil
}

func configuredModuleAudit(config runtimeconfig.Config, clients *runtimeclient.Clients, provider sandbox.SandboxProvider, services *workerExecutionServices, repositorySigner repository.Signer, signer *audit.HMACSigner) (*moduleAuditActivity, error) {
	local := config.DeploymentProfile == "TEST"
	if clients == nil || !local && provider == nil || services == nil || services.agentRuntime == nil || services.leaseService == nil || services.artifactCatalog == nil || services.artifactPublisher == nil || repositorySigner == nil || signer == nil {
		return nil, ErrWorkerConfiguration
	}
	policyClient, err := policy.NewOPAClient(config.OPA.URL)
	if err != nil {
		return nil, err
	}
	principal := authn.Principal{ID: "aor-module-audit-service", Type: authn.PrincipalService, Role: authn.RoleService}
	store := eventing.NewPostgresStore(clients.Database())
	tasks, err := audit.NewOrchestratorTaskAuthority(store, policyClient, principal, time.Now)
	if err != nil {
		return nil, err
	}
	references, err := audit.NewStateModuleAuditReferenceSource(tasks)
	if err != nil {
		return nil, err
	}
	submissions, err := repository.NewPostgresSubmissionStore(clients.Database())
	if err != nil {
		return nil, err
	}
	artifacts, err := goalplan.NewEventArtifactStore(store, time.Now)
	if err != nil {
		return nil, err
	}
	var facts audit.SandboxFactsSource
	if local {
		runtimeDigest, digestErr := workerExecutableDigest()
		if digestErr != nil {
			return nil, ErrWorkerConfiguration
		}
		facts, err = audit.NewWorkerContainerFacts(runtimeDigest)
	} else {
		facts, err = audit.NewSnapshotSandboxFacts(provider)
	}
	if err != nil {
		return nil, err
	}
	inputs, err := audit.NewAuthoritativeInputSource(submissions, repositorySigner, artifacts, policyClient, principal, facts)
	if err != nil {
		return nil, err
	}
	evidence, err := audit.NewArtifactEvidenceStore(services.artifactPublisher, services.artifactCatalog)
	if err != nil {
		return nil, err
	}
	pipelineArtifacts, err := audit.NewCatalogArtifactPublisher(services.artifactPublisher)
	if err != nil {
		return nil, err
	}
	runs, err := audit.NewPostgresAuditRunStore(clients.Database())
	if err != nil {
		return nil, err
	}
	checkpoints, err := audit.NewPostgresCoordinationStore(clients.Database())
	if err != nil {
		return nil, err
	}
	tools, err := moduleAuditToolDefinitions(services.host.Broker().List())
	if err != nil {
		return nil, err
	}
	routeConfig := config.ModuleAuditRoute
	if routeConfig.Provider == "" {
		var found bool
		routeConfig, found = config.GoalPlan.Routes[string(agentruntime.RoleModuleAuditor)]
		if !found {
			routeConfig = config.Execution.Route
		}
	}
	route := goalplan.ModelRoute{
		Provider: routeConfig.Provider, Model: routeConfig.Model, MaxOutputTokens: routeConfig.MaxOutputTokens,
		Temperature: routeConfig.Temperature, Seed: routeConfig.Seed, ProviderPolicy: routeConfig.ProviderPolicy,
		CachePolicy: routeConfig.CachePolicy, WorstCaseCostMicros: routeConfig.WorstCaseCostMicros, MaxAttempts: routeConfig.MaxAttempts,
	}
	auditors, err := audit.NewRuntimeAuditorFactory(audit.RuntimeAuditorFactoryConfig{
		Runtime: services.agentRuntime, References: references, Leases: services.leaseService,
		Routes: route, Tools: tools, LeaseTTL: 5 * time.Minute, MaxToolRounds: config.Execution.MaxToolRounds, Clock: time.Now,
	})
	if err != nil {
		return nil, err
	}
	pipeline, err := audit.NewPersistentPipeline(nil, auditors, signer, evidence, pipelineArtifacts, runs, "1.0.0", time.Now)
	if err != nil {
		return nil, err
	}
	service, err := audit.NewModuleAuditService(audit.ModuleAuditServiceConfig{
		Tasks: tasks, Inputs: inputs, Pipeline: pipeline, Evidence: evidence, Signer: signer, Checkpoints: checkpoints,
	})
	if err != nil {
		return nil, err
	}
	profile := sandbox.ProfileLocal
	if config.DeploymentProfile == "PREPRODUCTION" || config.DeploymentProfile == "PRODUCTION" {
		profile = sandbox.ProfileProduction
	}
	return &moduleAuditActivity{service: service, provider: provider, imageDigest: configuredImageDigest(config.Sandbox.ImageReference), profile: profile, local: local}, nil
}

func moduleAuditToolDefinitions(descriptors []toolbroker.ToolDescriptor) ([]modelgateway.ToolDefinition, error) {
	allowed := map[string]struct{}{
		"artifact.read": {}, "knowledge.read_range": {}, "knowledge.search": {}, repositoryReadTool: {},
	}
	tools := make([]modelgateway.ToolDefinition, 0, len(allowed))
	seen := make(map[string]struct{}, len(allowed))
	for _, descriptor := range descriptors {
		if _, ok := allowed[descriptor.ToolID]; !ok {
			continue
		}
		if _, duplicate := seen[descriptor.ToolID]; duplicate || descriptor.Validate() != nil || descriptor.SideEffect != toolbroker.SideEffectNone ||
			descriptor.FilesystemAccess != toolbroker.FilesystemNone && descriptor.FilesystemAccess != toolbroker.FilesystemRead ||
			!repositoryRoleAllowed(descriptor.AllowedRoles, string(agentruntime.RoleModuleAuditor)) {
			return nil, ErrWorkerConfiguration
		}
		seen[descriptor.ToolID] = struct{}{}
		tools = append(tools, modelgateway.ToolDefinition{Name: descriptor.ToolID, Version: descriptor.Version, Schema: append(json.RawMessage(nil), descriptor.InputSchema...)})
	}
	if _, found := seen[repositoryReadTool]; !found {
		return nil, ErrWorkerConfiguration
	}
	sort.Slice(tools, func(left, right int) bool { return tools[left].Name < tools[right].Name })
	return tools, nil
}

func configuredWorkerExecution(config runtimeconfig.Config, clients *runtimeclient.Clients, leaseManager *authz.LeaseManager, leaseSigner authz.Signer, repositorySigner repository.Signer, secretResolver *credentials.SecretResolver) (*workerExecutionServices, error) {
	if clients == nil || leaseManager == nil || leaseSigner == nil || repositorySigner == nil || secretResolver == nil {
		return nil, ErrWorkerConfiguration
	}
	policyClient, err := policy.NewOPAClient(config.OPA.URL)
	if err != nil {
		return nil, err
	}
	toolScopes, err := toolbroker.NewPostgresScopeResolver(toolbroker.PostgresScopeResolverConfig{Database: clients.Database(), DeploymentProfile: config.DeploymentProfile})
	if err != nil {
		return nil, err
	}
	leaseChecker := toolbroker.AuthzLeaseChecker{Manager: leaseManager, Scopes: toolScopes}
	policyEvaluator := toolbroker.OPAPolicyEvaluator{Policy: policyClient, Scopes: toolScopes, Clock: time.Now}
	streamRecorder, err := toolbroker.NewJetStreamInvocationRecorder(clients.JetStream(), config.NATS.Stream)
	if err != nil {
		return nil, err
	}
	durableRecorder, err := toolbroker.NewPostgresInvocationRecorder(clients.Database())
	if err != nil {
		return nil, err
	}
	recorder, err := toolbroker.NewCompositeInvocationRecorder(durableRecorder, streamRecorder)
	if err != nil {
		return nil, err
	}
	artifactCatalog, err := artifact.NewPostgresS3Catalog(clients.Database(), clients.S3(), config.S3.Bucket, time.Now)
	if err != nil {
		return nil, err
	}
	capabilityPublisher, err := artifact.NewCapabilityPublisher(artifact.CapabilityPublisherConfig{
		Catalog: artifactCatalog, Leases: leaseManager, Policy: policyClient,
		ServiceID: "aor-worker-artifact-service", DeploymentProfile: config.DeploymentProfile,
	})
	if err != nil {
		return nil, err
	}
	artifactPublisher, err := toolbroker.NewArtifactPublisher(capabilityPublisher)
	if err != nil {
		return nil, err
	}
	broker := toolbroker.New(leaseChecker, policyEvaluator, nil, artifactPublisher, recorder, policyEvaluator.Revalidate, time.Now)
	host, err := toolbroker.NewHost(broker)
	if err != nil {
		return nil, err
	}
	repositoryClient, err := newRepositoryMCPClient(config.RepositoryRoot, clients.Database(), leaseChecker, repositorySigner, time.Now)
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	loadContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = host.AddServerWithPolicies(loadContext, repositoryMCPServerID, repositoryMCPVersion, repositoryClient, repositoryMCPPolicies())
	cancel()
	if err != nil {
		_ = host.Close()
		return nil, err
	}

	leaseScopes, err := leaseauthority.NewPostgresScopeResolver(clients.Database(), config.DeploymentProfile)
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	leaseService, err := leaseauthority.New(leaseauthority.Config{Manager: leaseManager, Policy: policyClient, Scopes: leaseScopes, Clock: time.Now})
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	toolResolver, err := leaseauthority.NewDescriptorToolResolver(host.Broker().List())
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	runtimeAuthority, err := leaseauthority.NewRuntimeOperationAuthority(leaseService, 5*time.Minute, toolResolver)
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	slots, err := agentruntime.NewSlotPool(agentruntime.MaximumActiveAgentLimit, time.Now)
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	resolveContext, resolveCancel := context.WithTimeout(context.Background(), 10*time.Second)
	gateway, err := configuredModelGatewayClient(resolveContext, config, secretResolver)
	resolveCancel()
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	agentRuntime, err := agentruntime.New(runtimeAuthority, gateway, host.Broker(), slots, time.Now)
	if err != nil {
		_ = host.Close()
		return nil, err
	}

	store := eventing.NewPostgresStore(clients.Database())
	tasks, err := execution.NewOrchestratorTaskAuthority(store, clients.Database(), leaseSigner, leaseManager, time.Now)
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	artifacts, err := goalplan.NewEventArtifactStore(store, time.Now)
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	specs, err := execution.NewArtifactModuleSpecs(artifacts)
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	assignments, err := execution.NewPostgresAssignmentAuthority(clients.Database())
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	knowledgeRepository, err := knowledge.NewFileRepository(config.KnowledgeRoot)
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	knowledgeScopes, err := knowledge.NewEventingScopeResolver(store)
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	knowledgeService, err := knowledge.NewService(knowledge.ServiceConfig{Repository: knowledgeRepository, Authorizer: policyClient, Scopes: knowledgeScopes, Clock: time.Now})
	if err != nil {
		_ = host.Close()
		return nil, err
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
		return nil, err
	}
	submissionStore, err := repository.NewPostgresSubmissionStore(clients.Database())
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	submissions, err := execution.NewVerifiedSubmissions(submissionStore, repositorySigner)
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	service, err := execution.New(execution.Config{Tasks: tasks, Specs: specs, Assignments: assignments, Preparer: preparer, Runtime: agentRuntime, Bases: repositoryClient.service, Submissions: submissions})
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	return &workerExecutionServices{
		execution: service, host: host, agentRuntime: agentRuntime, tasks: tasks,
		leaseService: leaseService, artifactCatalog: artifactCatalog, artifactPublisher: capabilityPublisher,
	}, nil
}

func configuredGlobalAudit(config runtimeconfig.Config, clients *runtimeclient.Clients, provider sandbox.SandboxProvider, services *workerExecutionServices, signer *audit.HMACSigner, secretResolver *credentials.SecretResolver) (*globalaudit.Service, error) {
	if clients == nil || provider == nil || services == nil || services.agentRuntime == nil || services.tasks == nil || services.leaseService == nil || services.artifactCatalog == nil || services.artifactPublisher == nil || signer == nil || secretResolver == nil || runtime.GOOS != "linux" {
		return nil, ErrWorkerConfiguration
	}
	routeConfig := config.GlobalAuditRoute
	if routeConfig.Provider == "" {
		var found bool
		routeConfig, found = config.GoalPlan.Routes[string(agentruntime.RoleGlobalAuditor)]
		if !found {
			routeConfig = config.Execution.Route
		}
	}
	if routeConfig.Provider == "" {
		routeConfig = config.Execution.Route
	}
	route := goalplan.ModelRoute{
		Provider: routeConfig.Provider, Model: routeConfig.Model, MaxOutputTokens: routeConfig.MaxOutputTokens,
		Temperature: routeConfig.Temperature, Seed: routeConfig.Seed, ProviderPolicy: routeConfig.ProviderPolicy,
		CachePolicy: routeConfig.CachePolicy, WorstCaseCostMicros: routeConfig.WorstCaseCostMicros, MaxAttempts: routeConfig.MaxAttempts,
	}
	inputs, err := globalaudit.NewPostgresInputSource(clients.Database())
	if err != nil {
		return nil, err
	}
	agents, err := globalaudit.NewPostgresAgentRegistry(clients.Database())
	if err != nil {
		return nil, err
	}
	profile := sandbox.ProfileLocal
	if config.DeploymentProfile == "PREPRODUCTION" || config.DeploymentProfile == "PRODUCTION" {
		profile = sandbox.ProfileProduction
	}
	environment, err := globalaudit.NewSandboxEnvironment(globalaudit.SandboxEnvironmentConfig{
		Provider: provider, ImageDigest: configuredImageDigest(config.Sandbox.ImageReference), DeploymentProfile: profile,
	})
	if err != nil {
		return nil, err
	}
	preparer, err := globalaudit.NewAuthoritativePreparer(globalaudit.PreparerConfig{
		Inputs: inputs, Agents: agents, Environment: environment, Leases: services.leaseService,
		Tools: services.host.Broker().List(), Route: route, LeaseTTL: 5 * time.Minute,
		MaxToolRounds: config.Execution.MaxToolRounds, Clock: time.Now,
	})
	if err != nil {
		return nil, err
	}
	store, err := globalaudit.NewPostgresStore(clients.Database(), services.artifactPublisher, signer)
	if err != nil {
		return nil, err
	}
	events := eventing.NewPostgresStore(clients.Database())
	integrationStore, err := integration.NewPostgresStore(clients.Database())
	if err != nil {
		return nil, err
	}
	followups, err := globalaudit.NewPostgresFollowupCreator(
		clients.Database(), events, integrationStore,
		authn.Principal{ID: "aor-global-audit-service", Type: authn.PrincipalService, Role: authn.RoleService}, time.Now,
	)
	if err != nil {
		return nil, err
	}
	return globalaudit.New(globalaudit.Config{
		Projects: services.tasks, Preparer: preparer, Runtime: services.agentRuntime,
		Store: store, Signer: signer, Followups: followups, PipelineVersion: "1.0.0",
	})
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
