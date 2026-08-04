package servicebootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/credentials"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/policy"
	"github.com/akimisaka/aor/internal/runtimeclient"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	openaicompatible "github.com/akimisaka/aor/model-adapters/openai-compatible"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

const (
	modelGatewayReservationTTL = 24 * time.Hour
	modelGatewayRequestTimeout = 2 * time.Minute
)

// ModelGateway constructs the authenticated, policy-authorized model service.
// Provider credentials are resolved only while constructing adapters and are
// never included in the returned handler or any authorization input.
func ModelGateway(config runtimeconfig.Config, clients *runtimeclient.Clients) (http.Handler, error) {
	if clients == nil || clients.Database() == nil || len(config.ModelGateway.Providers) < 2 {
		return nil, runtimeclient.ErrInvalidClientConfig
	}
	authenticator, err := oidcAuthenticator(config)
	if err != nil {
		return nil, err
	}
	opaClient, err := policy.NewOPAClient(config.OPA.URL)
	if err != nil {
		return nil, err
	}
	resolver := credentials.NewSecretResolver(os.Getenv("AOR_SECRET_ROOT"))
	resolveContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	replayKey, err := resolver.Resolve(resolveContext, config.ModelGateway.ReplayKeyRef)
	if err != nil {
		return nil, runtimeclient.ErrDependencyUnavailable
	}
	ledger, ledgerErr := modelgateway.NewPostgresBudgetLedgerWithReplay(clients.Database(), time.Now, modelGatewayReservationTTL, modelgateway.ReplayStoreConfig{
		KeyID:         config.ModelGateway.ReplayKeyID,
		EncryptionKey: replayKey,
		TTL:           time.Duration(config.ModelGateway.ReplayTTLHours) * time.Hour,
	})
	clearBytes(replayKey)
	if ledgerErr != nil {
		return nil, ledgerErr
	}
	allowed := make(map[string]map[string]struct{}, len(config.ModelGateway.Providers))
	var authorizer *modelGatewayAuthorizer
	gateway := modelgateway.NewGatewayWithConfig(ledger, time.Now, modelgateway.GatewayConfig{
		ProviderPolicies: map[string]modelgateway.ProviderPolicy{
			"default": configuredProviderPolicy(config.ModelGateway.Providers),
		},
		ProviderEligibility: func(ctx context.Context, input modelgateway.ProviderEligibilityInput) error {
			return authorizeProviderCandidate(ctx, authorizer, input)
		},
	})
	for _, provider := range config.ModelGateway.Providers {
		credential, resolveErr := resolver.Resolve(resolveContext, provider.APIKeyRef)
		if resolveErr != nil {
			return nil, runtimeclient.ErrDependencyUnavailable
		}
		adapter, adapterErr := newConfiguredAdapter(provider, credential)
		clearBytes(credential)
		if adapterErr != nil {
			return nil, runtimeclient.ErrInvalidClientConfig
		}
		providerNames := []string{provider.ID}
		if provider.Provider != provider.ID {
			providerNames = append(providerNames, provider.Provider)
		}
		for _, providerName := range providerNames {
			models := allowed[providerName]
			if models == nil {
				models = make(map[string]struct{}, len(provider.Models))
				allowed[providerName] = models
			}
			for _, model := range provider.Models {
				if err := gateway.Register(providerName, model, adapter, modelgateway.Pricing{
					InputMicrosPerToken: provider.InputMicrosPerToken, OutputMicrosPerToken: provider.OutputMicrosPerToken,
				}); err != nil {
					return nil, runtimeclient.ErrInvalidClientConfig
				}
				models[model] = struct{}{}
			}
		}
	}
	authorizer = &modelGatewayAuthorizer{
		db: clients.Database(), opa: opaClient, allowed: allowed, clock: time.Now,
		allowHuman:        config.Environment == runtimeconfig.EnvironmentDevelopment || config.Environment == runtimeconfig.EnvironmentTest,
		deploymentProfile: deploymentProfileForEnvironment(config.Environment), providerPolicy: "default",
	}
	service, err := modelgateway.NewHTTPService(gateway, authorizer, modelgateway.HTTPConfig{})
	if err != nil {
		return nil, err
	}
	protected, err := authn.NewHTTPMiddleware(authenticator, service.Handler())
	if err != nil {
		return nil, err
	}
	return protected, nil
}

func configuredProviderPolicy(providers []runtimeconfig.ProviderConfig) modelgateway.ProviderPolicy {
	candidates := make([]modelgateway.ProviderCandidate, 0)
	for _, provider := range providers {
		classes := append([]string(nil), provider.AllowedDataClassifications...)
		if len(classes) == 0 {
			classes = []string{"PUBLIC"}
		}
		residency := append([]string(nil), provider.DataResidency...)
		if len(residency) == 0 {
			residency = []string{"provider-defined"}
		}
		retention := provider.RetentionPolicy
		if retention == "" {
			retention = "provider-defined"
		}
		for _, model := range provider.Models {
			candidates = append(candidates, modelgateway.ProviderCandidate{
				Provider: provider.ID, Model: model, CapabilityRank: 100,
				AllowedDataClassifications: append([]string(nil), classes...), AllowedDataResidencies: append([]string(nil), residency...), RetentionPolicy: retention,
			})
		}
	}
	return modelgateway.ProviderPolicy{Candidates: candidates, MinimumCapabilityRank: 100}
}

func authorizeProviderCandidate(ctx context.Context, authorizer *modelGatewayAuthorizer, input modelgateway.ProviderEligibilityInput) error {
	if authorizer == nil {
		return modelgateway.ErrAuthorizationDenied
	}
	authorization, err := authorizer.AuthorizeModel(ctx, modelgateway.ModelAuthorizationRequest{
		Operation: input.Operation, Provider: input.Candidate.Provider, Model: input.Candidate.Model,
		DataClassification: input.Request.DataClassification,
		RequestID:          input.Request.RequestID, AccountID: input.AccountID, ReservationID: input.ReservationID,
		ProjectID: input.Request.ProjectID, TaskID: input.Request.TaskID,
		AgentInstanceID: input.Request.AgentInstanceID, Role: input.Request.Role,
	})
	if err != nil || authorization.TenantID != input.Request.TenantID || authorization.ProjectID != input.Request.ProjectID ||
		authorization.TaskID != input.Request.TaskID || authorization.AgentInstanceID != input.Request.AgentInstanceID ||
		authorization.Role != input.Request.Role || authorization.Provider != input.Candidate.Provider || authorization.AccountID != input.AccountID || authorization.DataClassification != input.Request.DataClassification || authorization.ProviderPolicy != input.Request.ProviderPolicy || authorization.PolicyDigest != input.Request.PolicyDigest {
		return modelgateway.ErrAuthorizationDenied
	}
	return nil
}

func newConfiguredAdapter(provider runtimeconfig.ProviderConfig, credential []byte) (modelgateway.ModelAdapter, error) {
	endpoint, err := chatCompletionsEndpoint(provider.BaseURL)
	if err != nil || len(credential) == 0 {
		return nil, modelgateway.ErrInvalidRequest
	}
	capabilities := modelgateway.ModelCapabilities{
		SupportsStreaming:     provider.SupportsStreaming,
		SupportsToolCalls:     provider.SupportsToolCalls,
		SupportsJSONSchema:    provider.SupportsJSONSchema,
		SupportsSeed:          provider.SupportsSeed,
		SupportsPromptCaching: provider.SupportsPromptCaching,
		MaxInputTokens:        provider.MaxInputTokens,
		MaxOutputTokens:       provider.MaxOutputTokens,
		DataResidency:         append([]string(nil), provider.DataResidency...),
		RetentionPolicy:       provider.RetentionPolicy,
		Modalities:            append([]string(nil), provider.Modalities...),
		ActualModelVersion:    "NON_REPRODUCIBLE_PROVIDER",
	}
	models := make(map[string]modelgateway.ModelCapabilities, len(provider.Models))
	for _, model := range provider.Models {
		models[model] = capabilities
	}
	return openaicompatible.New(openaicompatible.Config{
		Endpoint: endpoint, Credential: string(credential), Models: models, RequestTimeout: modelGatewayRequestTimeout,
	})
}

func chatCompletionsEndpoint(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Scheme == "http" && !loopbackHost(parsed.Hostname()) {
		return "", modelgateway.ErrInvalidRequest
	}
	path := strings.TrimRight(parsed.Path, "/")
	if !strings.HasSuffix(path, "/chat/completions") {
		path += "/chat/completions"
	}
	parsed.Path, parsed.RawPath = path, ""
	return parsed.String(), nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	parsed := net.ParseIP(host)
	return parsed != nil && parsed.IsLoopback()
}

type modelGatewayAuthorizer struct {
	db                *sql.DB
	opa               authz.PolicyEvaluator
	allowed           map[string]map[string]struct{}
	clock             func() time.Time
	allowHuman        bool
	deploymentProfile string
	providerPolicy    string
}

func (authorizer *modelGatewayAuthorizer) AuthorizeModel(ctx context.Context, request modelgateway.ModelAuthorizationRequest) (modelgateway.ModelAuthorization, error) {
	if authorizer == nil || authorizer.db == nil || authorizer.opa == nil || ctx == nil {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	principal, ok := authn.PrincipalFromContext(ctx)
	if !ok || principal.TenantID == "" || principal.Role == "" || !validModelOperation(request.Operation) {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	if (principal.Type == authn.PrincipalUser || principal.Type == authn.PrincipalBreakGlassAdmin) && !authorizer.allowHuman {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	if principal.Type != authn.PrincipalUser && principal.Type != authn.PrincipalService && principal.Type != authn.PrincipalAgentRuntime && principal.Type != authn.PrincipalAgentInstance && principal.Type != authn.PrincipalBreakGlassAdmin {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	if request.Operation == "reconcile" && principal.Type != authn.PrincipalService {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	if _, err := uuid.Parse(principal.TenantID); err != nil {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	if request.Provider == "" || request.Model == "" {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	models, found := authorizer.allowed[request.Provider]
	if !found {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	if _, found = models[request.Model]; !found {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	projectID := request.ProjectID
	if projectID == "" {
		projectID = principal.ProjectID
	}
	if projectID == "" || principal.ProjectID != "" && principal.ProjectID != projectID {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	if _, err := uuid.Parse(projectID); err != nil {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	if request.TaskID != "" {
		if _, err := uuid.Parse(request.TaskID); err != nil {
			return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
		}
	}
	role := request.Role
	if role == "" {
		role = principal.Role
	}
	if principal.Type != authn.PrincipalService && principal.Type != authn.PrincipalAgentRuntime && role != principal.Role {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	if !validModelRole(role) {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	agentInstanceID := request.AgentInstanceID
	if agentInstanceID == "" && principal.Type == authn.PrincipalAgentInstance {
		agentInstanceID = principal.ID
	}
	if request.Operation != "capabilities" && agentInstanceID == "" {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	if principal.Type == authn.PrincipalAgentInstance && agentInstanceID != principal.ID {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}

	project, task, account, reservation, err := authorizer.loadScope(ctx, principal.TenantID, projectID, request.TaskID, request.AccountID, request.ReservationID, request.RequestID)
	if err != nil {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	if project.Classification == "" {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	reservationStateAllowed := reservation.State == string(modelgateway.ReservationOpen)
	if request.Operation == "reconcile" {
		reservationStateAllowed = reservation.State == string(modelgateway.ReservationReconcile) || reservation.State == string(modelgateway.ReservationSettled)
	}
	reservationAvailable := account.ID == request.AccountID && modelAccountScopeMatches(account.ScopeType, account.ScopeID, projectID, request.TaskID) && reservation.AccountID == request.AccountID && reservation.RequestID == request.RequestID && reservationStateAllowed
	budgetAvailable := account.Available || reservationAvailable
	if request.Operation != "capabilities" && (request.AccountID == "" || !budgetAvailable) {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	if request.Operation == "reconcile" && (!reservationAvailable || request.ReceiptSHA256 == "") {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	if request.Operation == "cancel" && (request.ProviderRequestID == "" || reservation.AccountID != request.AccountID || reservation.RequestID != request.RequestID || reservation.State != string(modelgateway.ReservationOpen)) {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	if request.Operation == "cancel" && request.RequestID == "" {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}

	action := modelAction(request.Operation)
	digest, err := canonicaljson.Digest(mustJSON(modelAuthorizationDigest{
		Operation: request.Operation, Provider: request.Provider, Model: request.Model, RequestID: request.RequestID,
		ProjectID: projectID, TaskID: request.TaskID, AgentInstanceID: agentInstanceID, Role: role, DataClassification: project.Classification,
		ProviderPolicy: authorizer.providerPolicy, ReceiptSHA256: request.ReceiptSHA256,
	}))
	if err != nil {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	input := authz.PolicyInput{
		Principal:       principal,
		Project:         authz.ProjectScope{TenantID: principal.TenantID, ID: projectID, State: project.State, StateVersion: project.Version, Classification: project.Classification},
		Action:          action,
		Resource:        authz.Resource{Type: "model", ID: request.Provider + "/" + request.Model, Attributes: map[string]string{"operation": request.Operation, "provider": request.Provider, "model": request.Model}},
		ParameterDigest: digest,
		Budget:          authz.BudgetScope{AccountID: request.AccountID, Available: budgetAvailable},
	}
	if task.ID != "" {
		input.Task = task
	}
	decision, err := authorizer.opa.Evaluate(ctx, input)
	if err != nil || !decision.Decision.Allowed() {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	if decision.PolicyVersion == "" {
		return modelgateway.ModelAuthorization{}, modelgateway.ErrAuthorizationDenied
	}
	return modelgateway.ModelAuthorization{TenantID: principal.TenantID, ProjectID: projectID, TaskID: task.ID, AgentInstanceID: agentInstanceID, Role: role, Provider: request.Provider, AccountID: request.AccountID, DataClassification: project.Classification, ProviderPolicy: authorizer.providerPolicy, PolicyDigest: decision.PolicyVersion}, nil
}

type modelAuthorizationDigest struct {
	Operation          string `json:"operation"`
	Provider           string `json:"provider"`
	Model              string `json:"model"`
	RequestID          string `json:"requestId"`
	ProjectID          string `json:"projectId"`
	TaskID             string `json:"taskId"`
	AgentInstanceID    string `json:"agentInstanceId"`
	Role               string `json:"role"`
	DataClassification string `json:"dataClassification"`
	ProviderPolicy     string `json:"providerPolicy"`
	ReceiptSHA256      string `json:"receiptSha256,omitempty"`
}

type modelProjectProjection struct {
	State          string
	Version        int64
	Classification string
}

type modelTaskProjection struct {
	authz.TaskScope
}

type modelAccountProjection struct {
	ID        string
	ScopeType string
	ScopeID   string
	Available bool
}

type modelReservationProjection struct {
	AccountID string
	RequestID string
	State     string
}

func (authorizer *modelGatewayAuthorizer) loadScope(ctx context.Context, tenantID, projectID, taskID, accountID, reservationID, requestID string) (modelProjectProjection, authz.TaskScope, modelAccountProjection, modelReservationProjection, error) {
	tx, err := authorizer.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return modelProjectProjection{}, authz.TaskScope{}, modelAccountProjection{}, modelReservationProjection{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setModelTenant(ctx, tx, tenantID); err != nil {
		return modelProjectProjection{}, authz.TaskScope{}, modelAccountProjection{}, modelReservationProjection{}, err
	}
	var project modelProjectProjection
	if err := tx.QueryRowContext(ctx, `SELECT state, state_version, data_classification FROM projects WHERE tenant_id = $1::uuid AND id = $2::uuid`, tenantID, projectID).Scan(&project.State, &project.Version, &project.Classification); err != nil {
		return modelProjectProjection{}, authz.TaskScope{}, modelAccountProjection{}, modelReservationProjection{}, err
	}
	var task authz.TaskScope
	if taskID != "" {
		task.TenantID, task.ProjectID, task.ID = tenantID, projectID, taskID
		var specDigest, platform, isolation string
		var moduleJSON []byte
		if err := tx.QueryRowContext(ctx, `SELECT t.state, t.state_version, ms.content_sha256, ms.execution_platform, ms.isolation_level, ms.content_jsonb FROM module_tasks t JOIN module_specs ms ON ms.tenant_id = t.tenant_id AND ms.id = t.module_spec_id WHERE t.tenant_id = $1::uuid AND t.project_id = $2::uuid AND t.id = $3::uuid`, tenantID, projectID, taskID).Scan(&task.State, &task.StateVersion, &specDigest, &platform, &isolation, &moduleJSON); err != nil {
			return modelProjectProjection{}, authz.TaskScope{}, modelAccountProjection{}, modelReservationProjection{}, err
		}
		var module contracts.ModuleSpec
		if err := json.Unmarshal(moduleJSON, &module); err != nil || module.ProjectID != projectID || string(module.ExecutionPlatform) != platform || string(module.SandboxLevel) != isolation {
			return modelProjectProjection{}, authz.TaskScope{}, modelAccountProjection{}, modelReservationProjection{}, modelgateway.ErrAuthorizationDenied
		}
		task.SpecDigest, task.ExecutionPlatform, task.SandboxLevel = specDigest, platform, isolation
		task.WorkloadTrust = string(module.WorkloadProfile.Trust)
		task.DeploymentProfile = authorizer.deploymentProfile
		task.HostileMultiTenant = module.WorkloadProfile.HostileMultiTenant
		task.RequiresNetworkIsolation = module.WorkloadProfile.RequiresNetworkIsolation
		task.RequiresHiddenConfidentiality = module.WorkloadProfile.RequiresHiddenTestConfidentiality
	}
	var account modelAccountProjection
	if accountID != "" {
		var hardLimit, spent, reserved int64
		if err := tx.QueryRowContext(ctx, `SELECT id, scope_type, scope_id, hard_limit_micros, spent_micros, reserved_micros FROM budget_accounts WHERE tenant_id = $1::uuid AND id = $2`, tenantID, accountID).Scan(&account.ID, &account.ScopeType, &account.ScopeID, &hardLimit, &spent, &reserved); err != nil {
			return modelProjectProjection{}, authz.TaskScope{}, modelAccountProjection{}, modelReservationProjection{}, err
		}
		account.Available = hardLimit >= 0 && spent >= 0 && reserved >= 0 && hardLimit >= spent && hardLimit-spent >= reserved && hardLimit-spent-reserved > 0 && modelAccountScopeMatches(account.ScopeType, account.ScopeID, projectID, taskID)
	}
	var reservation modelReservationProjection
	if reservationID != "" {
		if err := tx.QueryRowContext(ctx, `SELECT account_id, request_id, state FROM budget_reservations WHERE tenant_id = $1::uuid AND id = $2`, tenantID, reservationID).Scan(&reservation.AccountID, &reservation.RequestID, &reservation.State); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return modelProjectProjection{}, authz.TaskScope{}, modelAccountProjection{}, modelReservationProjection{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return modelProjectProjection{}, authz.TaskScope{}, modelAccountProjection{}, modelReservationProjection{}, err
	}
	return project, task, account, reservation, nil
}

func setModelTenant(ctx context.Context, tx *sql.Tx, tenantID string) error {
	var superuser, bypassRLS bool
	if err := tx.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS); err != nil || superuser || bypassRLS {
		return errors.New("model authorization database role is not tenant isolated")
	}
	_, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID)
	return err
}

func modelAccountScopeMatches(scopeType, scopeID, projectID, taskID string) bool {
	switch scopeType {
	case "PROJECT":
		return scopeID == projectID
	case "TASK":
		return taskID != "" && scopeID == taskID
	default:
		return false
	}
}

func modelAction(operation string) string {
	switch operation {
	case "generate":
		return authz.ActionModelGenerate
	case "stream":
		return authz.ActionModelStream
	case "cancel":
		return authz.ActionModelCancel
	case "reconcile":
		return authz.ActionModelReconcile
	default:
		return authz.ActionModelCapabilities
	}
}

func validModelOperation(operation string) bool {
	return operation == "generate" || operation == "stream" || operation == "cancel" || operation == "reconcile" || operation == "capabilities"
}

func validModelRole(role string) bool {
	switch role {
	case authn.RoleGoalProposer, authn.RoleGoalChallenger, authn.RolePlanSupervisor, authn.RoleModulePlanner,
		authn.RoleExecutor, authn.RoleAuditor, "MODULE_AUDITOR", "GLOBAL_AUDITOR", authn.RoleKnowledgeCurator,
		authn.RoleService, authn.RoleUser, authn.RoleBreakGlassAdmin:
		return true
	default:
		return false
	}
}

func deploymentProfileForEnvironment(environment string) string {
	switch environment {
	case runtimeconfig.EnvironmentDevelopment:
		return "LOCAL"
	case runtimeconfig.EnvironmentTest:
		return "TEST"
	case runtimeconfig.EnvironmentPreproduction:
		return "PREPRODUCTION"
	default:
		return "PRODUCTION"
	}
}

func mustJSON(value any) []byte {
	encoded, err := jsonMarshal(value)
	if err != nil {
		return nil
	}
	return encoded
}

func jsonMarshal(value any) ([]byte, error) {
	return json.Marshal(value)
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ modelgateway.HTTPAuthorizer = (*modelGatewayAuthorizer)(nil)
