package controlapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type ModelProvider struct {
	ID                         string         `json:"id"`
	Provider                   string         `json:"provider"`
	Models                     []string       `json:"models"`
	ModelContextWindowTokens   map[string]int `json:"modelContextWindowTokens,omitempty"`
	ModelMaxOutputTokens       map[string]int `json:"modelMaxOutputTokens,omitempty"`
	InputMicrosPerToken        int64          `json:"inputMicrosPerToken"`
	OutputMicrosPerToken       int64          `json:"outputMicrosPerToken"`
	SupportsStreaming          bool           `json:"supportsStreaming"`
	SupportsToolCalls          bool           `json:"supportsToolCalls"`
	SupportsJSONSchema         bool           `json:"supportsJsonSchema"`
	SupportsSeed               bool           `json:"supportsSeed"`
	SupportsPromptCaching      bool           `json:"supportsPromptCaching"`
	MaxInputTokens             int            `json:"maxInputTokens"`
	MaxOutputTokens            int            `json:"maxOutputTokens"`
	AllowedDataClassifications []string       `json:"allowedDataClassifications"`
	DataResidency              []string       `json:"dataResidency"`
	RetentionPolicy            string         `json:"retentionPolicy"`
	Modalities                 []string       `json:"modalities"`
}

type modelProviderPage struct {
	Items []ModelProvider `json:"items"`
}

type modelRouteSettingsResource struct {
	ModelRoutes map[string]state.ProjectModelRoute `json:"modelRoutes"`
	Version     int64                              `json:"version"`
}

type modelRouteSettingsBody struct {
	ModelRoutes map[string]state.ProjectModelRoute `json:"modelRoutes"`
}

type modelRouteSettingsStore interface {
	Get(context.Context, string) (map[string]state.ProjectModelRoute, int64, bool, error)
	Put(context.Context, string, map[string]state.ProjectModelRoute) (map[string]state.ProjectModelRoute, int64, error)
}

func validatedModelConfiguration(providers []ModelProvider, routes map[string]state.ProjectModelRoute) ([]ModelProvider, map[string]state.ProjectModelRoute, error) {
	if len(providers) == 0 && len(routes) == 0 {
		return nil, nil, nil
	}
	if len(providers) == 0 || state.ValidateProjectModelRoutes(routes) != nil {
		return nil, nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "model configuration"})
	}
	clonedProviders := cloneModelProviders(providers)
	if validateModelProviders(clonedProviders) != nil || validateRoutesAgainstProviders(routes, clonedProviders) != nil {
		return nil, nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "model configuration"})
	}
	return clonedProviders, cloneModelRoutes(routes), nil
}

func validateModelProviders(providers []ModelProvider) error {
	seenProviders := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		if !safeModelValue(provider.ID, 128) || !safeModelValue(provider.Provider, 128) || len(provider.Models) == 0 ||
			provider.InputMicrosPerToken < 0 || provider.OutputMicrosPerToken < 0 || provider.MaxInputTokens < 1 || provider.MaxOutputTokens < 1 ||
			!safeModelValue(provider.RetentionPolicy, 256) ||
			len(provider.AllowedDataClassifications) == 0 || len(provider.DataResidency) == 0 || len(provider.Modalities) == 0 {
			return errors.New("invalid model provider")
		}
		if _, duplicate := seenProviders[provider.ID]; duplicate {
			return errors.New("duplicate model provider")
		}
		seenProviders[provider.ID] = struct{}{}
		if !uniqueModelValues(provider.Models, 256) || !uniqueModelValues(provider.AllowedDataClassifications, 64) ||
			!uniqueModelValues(provider.DataResidency, 128) || !uniqueModelValues(provider.Modalities, 128) {
			return errors.New("invalid model provider metadata")
		}
		for model, maximum := range provider.ModelMaxOutputTokens {
			if !safeModelValue(model, 256) || maximum < 1 || maximum > provider.MaxOutputTokens {
				return errors.New("invalid model output limit")
			}
		}
		for model, window := range provider.ModelContextWindowTokens {
			if !safeModelValue(model, 256) || window < 1 || window > 10_000_000 {
				return errors.New("invalid model context window")
			}
		}
		if len(provider.ModelContextWindowTokens) > 0 && len(provider.ModelContextWindowTokens) != len(provider.Models) {
			return errors.New("incomplete model context windows")
		}
		for _, model := range provider.Models {
			if window := provider.ModelContextWindowTokens[model]; len(provider.ModelContextWindowTokens) > 0 && window < 1 {
				return errors.New("missing model context window")
			}
		}
	}
	return nil
}

func validateRoutesAgainstProviders(routes map[string]state.ProjectModelRoute, providers []ModelProvider) error {
	if state.ValidateProjectModelRoutes(routes) != nil {
		return errors.New("invalid model routes")
	}
	byID := make(map[string]ModelProvider, len(providers))
	for _, provider := range providers {
		byID[provider.ID] = provider
	}
	for role, route := range routes {
		provider, found := byID[route.Provider]
		maximum := provider.MaxOutputTokens
		contextWindow := provider.MaxInputTokens
		if modelMaximum, known := provider.ModelMaxOutputTokens[route.Model]; known {
			maximum = modelMaximum
		}
		if modelWindow, known := provider.ModelContextWindowTokens[route.Model]; known {
			contextWindow = modelWindow
		}
		if route.ContextWindowTokens == 0 {
			route.ContextWindowTokens = contextWindow
		}
		if !found || !safeModelValue(route.Model, 256) || route.Model == "*" || route.MaxOutputTokens > maximum ||
			route.ContextWindowTokens > contextWindow || route.MaxOutputTokens >= route.ContextWindowTokens ||
			route.Seed != nil && !provider.SupportsSeed || !provider.SupportsJSONSchema || routeUsesTools(role) && !provider.SupportsToolCalls {
			return errors.New("model route is not supported by provider")
		}
		routes[role] = route
	}
	return nil
}

func routeUsesTools(role string) bool {
	return role == "EXECUTOR" || role == "MODULE_AUDITOR" || role == "GLOBAL_AUDITOR"
}

func uniqueModelValues(values []string, maximum int) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !safeModelValue(value, maximum) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func safeModelValue(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func cloneModelProviders(providers []ModelProvider) []ModelProvider {
	cloned := append([]ModelProvider(nil), providers...)
	for index := range cloned {
		cloned[index].Models = append([]string(nil), providers[index].Models...)
		cloned[index].ModelContextWindowTokens = cloneTokenLimits(providers[index].ModelContextWindowTokens)
		cloned[index].ModelMaxOutputTokens = cloneModelOutputLimits(providers[index].ModelMaxOutputTokens)
		cloned[index].AllowedDataClassifications = append([]string(nil), providers[index].AllowedDataClassifications...)
		cloned[index].DataResidency = append([]string(nil), providers[index].DataResidency...)
		cloned[index].Modalities = append([]string(nil), providers[index].Modalities...)
	}
	return cloned
}

func cloneModelOutputLimits(limits map[string]int) map[string]int {
	if limits == nil {
		return nil
	}
	cloned := make(map[string]int, len(limits))
	for model, maximum := range limits {
		cloned[model] = maximum
	}
	return cloned
}

func cloneModelRoutes(routes map[string]state.ProjectModelRoute) map[string]state.ProjectModelRoute {
	if routes == nil {
		return nil
	}
	cloned := make(map[string]state.ProjectModelRoute, len(routes))
	for role, route := range routes {
		if route.Seed != nil {
			seed := *route.Seed
			route.Seed = &seed
		}
		cloned[role] = route
	}
	return cloned
}

func (handler *Handler) resolveProjectModelRoutes(ctx context.Context, tenantID string, supplied map[string]state.ProjectModelRoute) (map[string]state.ProjectModelRoute, error) {
	providers, err := handler.tenantModelProviders(ctx, tenantID)
	if err != nil {
		return nil, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, map[string]any{"scope": "model provider settings"})
	}
	if supplied != nil {
		supplied = normalizeModelProviderAliases(supplied)
		if validateRoutesAgainstProviders(supplied, providers) != nil {
			return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "project model routes"})
		}
		return cloneModelRoutes(supplied), nil
	}
	routes, _, found, err := handler.modelRouteSettings.Get(ctx, tenantID)
	if err != nil {
		return nil, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, map[string]any{"scope": "model route settings"})
	}
	if !found {
		routes = handler.defaultModelRoutes
	}
	routes = normalizeModelProviderAliases(routes)
	if validateRoutesAgainstProviders(routes, providers) != nil {
		return nil, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "model route configuration"})
	}
	return cloneModelRoutes(routes), nil
}

func (handler *Handler) listModelProviders(response http.ResponseWriter, request *http.Request, principal authn.Principal) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "model provider query"}))
		return
	}
	if err := handler.authorizeTenantModelResource(request.Context(), principal, authz.ActionSettingsRead, "model-provider-list", ""); err != nil {
		writeError(response, request, err)
		return
	}
	providers, err := handler.tenantModelProviders(request.Context(), principal.TenantID)
	if err != nil {
		writeError(response, request, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, map[string]any{"scope": "model provider catalog"}))
		return
	}
	if len(providers) == 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "model provider catalog"}))
		return
	}
	writeJSON(response, http.StatusOK, modelProviderPage{Items: providers})
}

func (handler *Handler) getModelRouteSettings(response http.ResponseWriter, request *http.Request, principal authn.Principal) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "model route settings query"}))
		return
	}
	if err := handler.authorizeTenantModelResource(request.Context(), principal, authz.ActionSettingsRead, "model-route-settings", ""); err != nil {
		writeError(response, request, err)
		return
	}
	routes, version, found, err := handler.modelRouteSettings.Get(request.Context(), principal.TenantID)
	if err != nil {
		writeError(response, request, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, map[string]any{"scope": "model route settings"}))
		return
	}
	if !found {
		routes = handler.defaultModelRoutes
		version = 0
	}
	routes = normalizeModelProviderAliases(routes)
	providers, providerErr := handler.tenantModelProviders(request.Context(), principal.TenantID)
	if providerErr != nil {
		writeError(response, request, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", providerErr, map[string]any{"scope": "model provider settings"}))
		return
	}
	if validateRoutesAgainstProviders(routes, providers) != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "model route configuration"}))
		return
	}
	writeModelRouteSettings(response, http.StatusOK, routes, version)
}

func (handler *Handler) putModelRouteSettings(response http.ResponseWriter, request *http.Request, principal authn.Principal) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "model route settings query"}))
		return
	}
	var body modelRouteSettingsBody
	if decodeJSON(request, &body) != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "model route settings"}))
		return
	}
	body.ModelRoutes = normalizeModelProviderAliases(body.ModelRoutes)
	providers, providerErr := handler.tenantModelProviders(request.Context(), principal.TenantID)
	if providerErr != nil {
		writeError(response, request, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", providerErr, map[string]any{"scope": "model provider settings"}))
		return
	}
	if validateRoutesAgainstProviders(body.ModelRoutes, providers) != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "model route settings"}))
		return
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "model route settings"}))
		return
	}
	digest, err := canonicaljson.Digest(encoded)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "model route settings"}))
		return
	}
	if err := handler.authorizeTenantModelResource(request.Context(), principal, authz.ActionSettingsWrite, "model-route-settings", digest); err != nil {
		writeError(response, request, err)
		return
	}
	if err := handler.ensureTenant(request.Context(), principal.TenantID); err != nil {
		writeError(response, request, err)
		return
	}
	routes, version, err := handler.modelRouteSettings.Put(request.Context(), principal.TenantID, body.ModelRoutes)
	if err != nil {
		writeError(response, request, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, map[string]any{"scope": "model route settings"}))
		return
	}
	writeModelRouteSettings(response, http.StatusOK, routes, version)
}

func (handler *Handler) tenantModelProviders(ctx context.Context, tenantID string) ([]ModelProvider, error) {
	providers := cloneModelProviders(handler.modelProviders)
	if handler.providerSettings == nil {
		return providers, nil
	}
	settings, err := handler.providerSettings.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	known := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		known[provider.ID] = struct{}{}
	}
	for _, setting := range settings {
		if !setting.Custom {
			continue
		}
		if _, duplicate := known[setting.ID]; duplicate {
			continue
		}
		known[setting.ID] = struct{}{}
		providers = append(providers, ModelProvider{
			ID: setting.ID, Provider: setting.Provider, Models: append([]string(nil), setting.Models...),
			ModelMaxOutputTokens:     modelOutputLimits(setting.Models, setting.MaxOutputTokens),
			ModelContextWindowTokens: cloneTokenLimits(setting.ModelContextWindowTokens),
			InputMicrosPerToken:      setting.InputMicrosPerToken, OutputMicrosPerToken: setting.OutputMicrosPerToken,
			SupportsStreaming: setting.SupportsStreaming, SupportsToolCalls: setting.SupportsToolCalls,
			SupportsJSONSchema: setting.SupportsJSONSchema, SupportsSeed: setting.SupportsSeed,
			SupportsPromptCaching: setting.SupportsPromptCaching, MaxInputTokens: setting.MaxInputTokens,
			MaxOutputTokens:            setting.MaxOutputTokens,
			AllowedDataClassifications: append([]string(nil), setting.AllowedDataClassifications...),
			DataResidency:              append([]string(nil), setting.DataResidency...), RetentionPolicy: setting.RetentionPolicy,
			Modalities: append([]string(nil), setting.Modalities...),
		})
	}
	return providers, nil
}

func cloneTokenLimits(values map[string]int) map[string]int {
	cloned := make(map[string]int, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func modelOutputLimits(models []string, maximum int) map[string]int {
	limits := make(map[string]int, len(models))
	for _, model := range models {
		limits[model] = maximum
	}
	return limits
}

func normalizeModelProviderAliases(routes map[string]state.ProjectModelRoute) map[string]state.ProjectModelRoute {
	normalized := cloneModelRoutes(routes)
	for role, route := range normalized {
		switch route.Provider {
		case "openai-primary":
			route.Provider = "openai"
		case "deepseek-audit":
			route.Provider = "deepseek"
		}
		normalized[role] = route
	}
	return normalized
}

func (handler *Handler) authorizeTenantModelResource(ctx context.Context, principal authn.Principal, action, resourceType, parameterDigest string) error {
	input := authz.PolicyInput{
		Principal: principal,
		Project: authz.ProjectScope{
			TenantID: principal.TenantID, ID: principal.TenantID, State: "CREATED", StateVersion: 0, Classification: "INTERNAL",
		},
		Action: action, Resource: authz.Resource{Type: resourceType, ID: principal.TenantID},
		ParameterDigest: parameterDigest, Budget: authz.BudgetScope{AccountID: "control-plane", Available: true},
	}
	decision, err := handler.authorizer.Evaluate(ctx, input)
	if err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	if !decision.Decision.Allowed() {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": decision.PolicyVersion, "ruleId": decision.RuleID})
	}
	return nil
}

func writeModelRouteSettings(response http.ResponseWriter, status int, routes map[string]state.ProjectModelRoute, version int64) {
	response.Header().Set("ETag", entityTag(version))
	writeJSON(response, status, modelRouteSettingsResource{ModelRoutes: cloneModelRoutes(routes), Version: version})
}

func newModelRouteSettingsStore(database *sql.DB) modelRouteSettingsStore {
	if database == nil {
		return &memoryModelRouteSettingsStore{settings: make(map[string]modelRouteSettingsResource)}
	}
	return &postgresModelRouteSettingsStore{database: database}
}

type memoryModelRouteSettingsStore struct {
	mutex    sync.Mutex
	settings map[string]modelRouteSettingsResource
}

func (store *memoryModelRouteSettingsStore) Get(_ context.Context, tenantID string) (map[string]state.ProjectModelRoute, int64, bool, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	setting, found := store.settings[tenantID]
	return cloneModelRoutes(setting.ModelRoutes), setting.Version, found, nil
}

func (store *memoryModelRouteSettingsStore) Put(_ context.Context, tenantID string, routes map[string]state.ProjectModelRoute) (map[string]state.ProjectModelRoute, int64, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	setting, found := store.settings[tenantID]
	if found && reflect.DeepEqual(setting.ModelRoutes, routes) {
		return cloneModelRoutes(setting.ModelRoutes), setting.Version, nil
	}
	version := int64(1)
	if found {
		version = setting.Version + 1
	}
	setting = modelRouteSettingsResource{ModelRoutes: cloneModelRoutes(routes), Version: version}
	store.settings[tenantID] = setting
	return cloneModelRoutes(setting.ModelRoutes), setting.Version, nil
}

type postgresModelRouteSettingsStore struct {
	database *sql.DB
}

func (store *postgresModelRouteSettingsStore) Get(ctx context.Context, tenantID string) (map[string]state.ProjectModelRoute, int64, bool, error) {
	tx, err := store.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, 0, false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		return nil, 0, false, err
	}
	var encoded []byte
	var version int64
	err = tx.QueryRowContext(ctx, `
SELECT model_routes_jsonb, version
FROM tenant_model_route_settings
WHERE tenant_id = $1::uuid`, tenantID).Scan(&encoded, &version)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return nil, 0, false, err
		}
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	var routes map[string]state.ProjectModelRoute
	if json.Unmarshal(encoded, &routes) != nil {
		return nil, 0, false, errors.New("invalid persisted model route settings")
	}
	for role, route := range routes {
		if route.ReasoningEffort == "" {
			route.ReasoningEffort = state.DefaultModelReasoningEffort(route.Provider)
			routes[role] = route
		}
	}
	if state.ValidateProjectModelRoutes(routes) != nil || version < 1 {
		return nil, 0, false, errors.New("invalid persisted model route settings")
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, false, err
	}
	return cloneModelRoutes(routes), version, true, nil
}

func (store *postgresModelRouteSettingsStore) Put(ctx context.Context, tenantID string, routes map[string]state.ProjectModelRoute) (map[string]state.ProjectModelRoute, int64, error) {
	encoded, err := json.Marshal(routes)
	if err != nil {
		return nil, 0, err
	}
	tx, err := store.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		return nil, 0, err
	}
	var version int64
	err = tx.QueryRowContext(ctx, `
INSERT INTO tenant_model_route_settings (tenant_id, model_routes_jsonb, version)
VALUES ($1::uuid, $2::jsonb, 1)
ON CONFLICT (tenant_id) DO UPDATE
SET model_routes_jsonb = EXCLUDED.model_routes_jsonb,
    version = CASE
      WHEN tenant_model_route_settings.model_routes_jsonb = EXCLUDED.model_routes_jsonb THEN tenant_model_route_settings.version
      ELSE tenant_model_route_settings.version + 1
    END,
    updated_at = CASE
      WHEN tenant_model_route_settings.model_routes_jsonb = EXCLUDED.model_routes_jsonb THEN tenant_model_route_settings.updated_at
      ELSE transaction_timestamp()
    END
RETURNING version`, tenantID, encoded).Scan(&version)
	if err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return cloneModelRoutes(routes), version, nil
}
