package modelproviders

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/modelgateway"
	openaicompatible "github.com/akimisaka/aor/model-adapters/openai-compatible"
)

func newAdapter(factory AdapterFactory, provider string, protocol Protocol, baseURL, apiKey string, models []string) (modelgateway.ModelAdapter, error) {
	if apiKey == "" || validateURL(baseURL) != nil || len(models) == 0 {
		return nil, ErrInvalidSettings
	}
	catalog, found := findCatalog(provider)
	if !found || !validProtocol(catalog, protocol) {
		return nil, ErrInvalidSettings
	}
	capabilities := make(map[string]modelgateway.ModelCapabilities, len(models))
	for _, model := range models {
		definition, found := findModel(catalog.ID, model)
		if !found {
			return nil, ErrInvalidSettings
		}
		capabilities[model] = modelCapabilities(definition)
	}
	if factory.RequestTimeout == 0 {
		factory.RequestTimeout = 90 * time.Second
	}
	switch protocol {
	case ProtocolAnthropic:
		return newAnthropicAdapter(anthropicConfig{
			BaseURL: baseURL, APIKey: apiKey, Models: capabilities,
			HTTPClient: factory.HTTPClient, RequestTimeout: factory.RequestTimeout,
		})
	case ProtocolOpenAICompatible:
		endpoint, err := openAIEndpoint(baseURL)
		if err != nil {
			return nil, err
		}
		adapter, err := openaicompatible.New(openaicompatible.Config{
			Endpoint: endpoint, Credential: apiKey, Models: capabilities,
			HTTPClient: factory.HTTPClient, RequestTimeout: factory.RequestTimeout,
		})
		if err != nil {
			return nil, err
		}
		return adapter, nil
	default:
		return nil, ErrInvalidSettings
	}
}

func openAIEndpoint(raw string) (string, error) {
	parsed, err := parseProviderURL(raw)
	if err != nil {
		return "", err
	}
	path := strings.TrimRight(parsed.Path, "/")
	if !strings.HasSuffix(path, "/chat/completions") {
		path += "/chat/completions"
	}
	parsed.Path, parsed.RawPath = path, ""
	return parsed.String(), nil
}

func parseProviderURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, ErrInvalidSettings
	}
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return nil, ErrInvalidSettings
	}
	return parsed, nil
}

// DynamicAdapter resolves the encrypted provider settings on each tenant's
// first call and refreshes the concrete adapter whenever the row version
// changes. A saved WebUI setting therefore applies to the next invocation
// without restarting the model gateway process.
type DynamicAdapter struct {
	provider string
	model    string
	store    SettingsStore
	factory  AdapterFactory

	mu      sync.Mutex
	current map[string]dynamicAdapterEntry
}

type dynamicAdapterEntry struct {
	version int64
	adapter modelgateway.ModelAdapter
}

func NewDynamicAdapter(provider, model string, store SettingsStore, factory AdapterFactory) (*DynamicAdapter, error) {
	if _, found := findModel(provider, model); !found || store == nil {
		return nil, ErrInvalidSettings
	}
	return &DynamicAdapter{provider: provider, model: model, store: store, factory: factory, current: make(map[string]dynamicAdapterEntry)}, nil
}

func (adapter *DynamicAdapter) Capabilities(ctx context.Context, model string) (modelgateway.ModelCapabilities, error) {
	if model != adapter.model {
		return modelgateway.ModelCapabilities{}, modelgateway.ErrProviderNotAllowed
	}
	tenantID, err := tenantFromContext(ctx)
	if err != nil {
		return modelgateway.ModelCapabilities{}, err
	}
	_, concrete, err := adapter.resolve(ctx, tenantID)
	if err != nil {
		return modelgateway.ModelCapabilities{}, err
	}
	return concrete.Capabilities(ctx, adapter.model)
}

func (adapter *DynamicAdapter) CountTokens(ctx context.Context, request modelgateway.NormalizedRequest) (modelgateway.TokenEstimate, error) {
	concrete, err := adapter.concrete(ctx, request.TenantID)
	if err != nil {
		return modelgateway.TokenEstimate{}, err
	}
	return concrete.CountTokens(ctx, request)
}

func (adapter *DynamicAdapter) Generate(ctx context.Context, request modelgateway.NormalizedRequest) (modelgateway.NormalizedResponse, error) {
	concrete, err := adapter.concrete(ctx, request.TenantID)
	if err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	return concrete.Generate(ctx, request)
}

func (adapter *DynamicAdapter) Stream(ctx context.Context, request modelgateway.NormalizedRequest) (modelgateway.ResponseStream, error) {
	concrete, err := adapter.concrete(ctx, request.TenantID)
	if err != nil {
		return nil, err
	}
	return concrete.Stream(ctx, request)
}

func (adapter *DynamicAdapter) Cancel(ctx context.Context, providerRequestID string) error {
	if ctx == nil || providerRequestID == "" {
		return modelgateway.ErrInvalidRequest
	}
	adapter.mu.Lock()
	entries := make([]modelgateway.ModelAdapter, 0, len(adapter.current))
	for _, entry := range adapter.current {
		entries = append(entries, entry.adapter)
	}
	adapter.mu.Unlock()
	for _, concrete := range entries {
		if err := concrete.Cancel(ctx, providerRequestID); err == nil {
			return nil
		}
	}
	return nil
}

func (adapter *DynamicAdapter) NormalizeUsage(raw any) (modelgateway.Usage, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	for _, entry := range adapter.current {
		return entry.adapter.NormalizeUsage(raw)
	}
	return modelgateway.Usage{}, modelgateway.ErrProviderNotAllowed
}

func (adapter *DynamicAdapter) concrete(ctx context.Context, tenantID string) (modelgateway.ModelAdapter, error) {
	if ctx == nil || tenantID == "" {
		return nil, modelgateway.ErrInvalidRequest
	}
	_, concrete, err := adapter.resolve(ctx, tenantID)
	return concrete, err
}

func (adapter *DynamicAdapter) resolve(ctx context.Context, tenantID string) (ResolvedSettings, modelgateway.ModelAdapter, error) {
	resolved, found, err := adapter.store.Resolve(ctx, tenantID, adapter.provider)
	if err != nil {
		return ResolvedSettings{}, nil, modelgateway.ErrProviderUnavailable
	}
	if !found || !contains(resolved.Models, adapter.model) {
		return ResolvedSettings{}, nil, modelgateway.ErrProviderNotAllowed
	}
	adapter.mu.Lock()
	if entry, found := adapter.current[tenantID]; found && entry.version == resolved.Version {
		adapter.mu.Unlock()
		return resolved, entry.adapter, nil
	}
	concrete, err := adapter.factory.NewWithProtocol(resolved.Provider, resolved.Protocol, resolved.BaseURL, resolved.APIKey, resolved.Models)
	if err == nil {
		adapter.current[tenantID] = dynamicAdapterEntry{version: resolved.Version, adapter: concrete}
	}
	adapter.mu.Unlock()
	if err != nil {
		return ResolvedSettings{}, nil, modelgateway.ErrProviderUnavailable
	}
	return resolved, concrete, nil
}

func tenantFromContext(ctx context.Context) (string, error) {
	if ctx == nil {
		return "", modelgateway.ErrInvalidRequest
	}
	principal, found := authn.PrincipalFromContext(ctx)
	if !found || principal.TenantID == "" {
		return "", modelgateway.ErrAuthorizationDenied
	}
	return principal.TenantID, nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
