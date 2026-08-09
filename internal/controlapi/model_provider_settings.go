package controlapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/modelproviders"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
	"github.com/google/uuid"
)

const modelProviderTestTimeout = 20 * time.Second

type modelProviderSettingsResource struct {
	ID               string   `json:"id"`
	Provider         string   `json:"provider"`
	DisplayName      string   `json:"displayName,omitempty"`
	BaseURL          string   `json:"baseUrl"`
	Protocol         string   `json:"protocol"`
	Protocols        []string `json:"protocols,omitempty"`
	Models           []string `json:"models"`
	APIKeyConfigured bool     `json:"apiKeyConfigured"`
	Enabled          bool     `json:"enabled"`
	Version          int64    `json:"version"`
}

type modelProviderSettingsPage struct {
	Items []modelProviderSettingsResource `json:"items"`
}

type modelProviderSettingsBody struct {
	BaseURL  string `json:"baseUrl"`
	Protocol string `json:"protocol"`
	APIKey   string `json:"apiKey,omitempty"`
	Enabled  bool   `json:"enabled"`
}

type modelProviderTestBody struct {
	BaseURL  string `json:"baseUrl"`
	Protocol string `json:"protocol"`
	APIKey   string `json:"apiKey,omitempty"`
	Model    string `json:"model"`
}

type modelProviderTestResource struct {
	OK        bool   `json:"ok"`
	Model     string `json:"model"`
	LatencyMS int64  `json:"latencyMs,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

func (handler *Handler) getModelProviderSettings(response http.ResponseWriter, request *http.Request, principal authn.Principal) {
	response.Header().Set("Cache-Control", "no-store")
	if len(request.URL.Query()) != 0 {
		writeError(response, request, invalidModelProviderSettings("model provider settings query"))
		return
	}
	if err := handler.authorizeTenantModelResource(request.Context(), principal, authz.ActionSettingsRead, "model-provider-settings", ""); err != nil {
		writeError(response, request, err)
		return
	}
	if handler.providerSettings == nil {
		writeError(response, request, unavailableModelProviderSettings(nil))
		return
	}
	settings, err := handler.providerSettings.List(request.Context(), principal.TenantID)
	if err != nil {
		writeError(response, request, unavailableModelProviderSettings(err))
		return
	}
	byID := make(map[string]modelproviders.ProviderSettings, len(settings))
	for _, setting := range settings {
		byID[setting.ID] = setting
	}
	catalog := modelproviders.Catalog()
	items := make([]modelProviderSettingsResource, 0, len(catalog))
	for _, provider := range catalog {
		items = append(items, modelProviderSettingsResourceFrom(provider, byID[provider.ID]))
	}
	writeJSON(response, http.StatusOK, modelProviderSettingsPage{Items: items})
}

func (handler *Handler) putModelProviderSettings(response http.ResponseWriter, request *http.Request, principal authn.Principal, providerID string) {
	response.Header().Set("Cache-Control", "no-store")
	if len(request.URL.Query()) != 0 {
		writeError(response, request, invalidModelProviderSettings("model provider settings query"))
		return
	}
	catalog, found := modelProviderCatalog(providerID)
	if !found {
		writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
		return
	}
	var body modelProviderSettingsBody
	if decodeJSON(request, &body) != nil || !modelProviderCatalogHasProtocol(catalog, body.Protocol) {
		writeError(response, request, invalidModelProviderSettings("model provider settings"))
		return
	}
	digest, err := modelProviderSettingsDigest(providerID, body.BaseURL, body.Protocol, body.Enabled, "")
	if err != nil {
		writeError(response, request, invalidModelProviderSettings("model provider settings"))
		return
	}
	if err := handler.authorizeTenantModelResource(request.Context(), principal, authz.ActionSettingsWrite, "model-provider-settings", digest); err != nil {
		writeError(response, request, err)
		return
	}
	if handler.providerSettings == nil {
		writeError(response, request, unavailableModelProviderSettings(nil))
		return
	}
	if err := handler.ensureTenant(request.Context(), principal.TenantID); err != nil {
		writeError(response, request, err)
		return
	}
	setting, err := handler.providerSettings.Put(request.Context(), principal.TenantID, providerID, modelproviders.PutRequest{
		BaseURL: body.BaseURL, Protocol: modelproviders.Protocol(body.Protocol), APIKey: body.APIKey, Enabled: body.Enabled,
	})
	if err != nil {
		writeError(response, request, mapModelProviderSettingsError(err))
		return
	}
	writeJSON(response, http.StatusOK, modelProviderSettingsResourceFrom(catalog, setting))
}

func (handler *Handler) testModelProvider(response http.ResponseWriter, request *http.Request, principal authn.Principal, providerID string) {
	response.Header().Set("Cache-Control", "no-store")
	if len(request.URL.Query()) != 0 {
		writeError(response, request, invalidModelProviderSettings("model provider test query"))
		return
	}
	catalog, found := modelProviderCatalog(providerID)
	if !found {
		writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
		return
	}
	var body modelProviderTestBody
	if decodeJSON(request, &body) != nil || !modelProviderCatalogHasProtocol(catalog, body.Protocol) || !modelProviderCatalogHasModel(catalog, body.Model) || !validModelProviderAPIKey(body.APIKey) {
		writeError(response, request, invalidModelProviderSettings("model provider test"))
		return
	}
	digest, err := modelProviderSettingsDigest(providerID, body.BaseURL, body.Protocol, true, body.Model)
	if err != nil {
		writeError(response, request, invalidModelProviderSettings("model provider test"))
		return
	}
	if err := handler.authorizeTenantModelResource(request.Context(), principal, authz.ActionSettingsWrite, "model-provider-test", digest); err != nil {
		writeError(response, request, err)
		return
	}
	apiKey := body.APIKey
	if apiKey == "" {
		if handler.providerSettings == nil {
			writeError(response, request, unavailableModelProviderSettings(nil))
			return
		}
		resolved, configured, resolveErr := handler.providerSettings.Resolve(request.Context(), principal.TenantID, providerID)
		if resolveErr != nil {
			writeError(response, request, mapModelProviderSettingsError(resolveErr))
			return
		}
		if !configured || resolved.APIKey == "" {
			writeError(response, request, invalidModelProviderSettings("model provider API key"))
			return
		}
		apiKey = resolved.APIKey
	}
	adapter, err := handler.providerAdapter.NewWithProtocol(providerID, modelproviders.Protocol(body.Protocol), body.BaseURL, apiKey, []string{body.Model})
	apiKey = ""
	if err != nil {
		writeError(response, request, invalidModelProviderSettings("model provider test"))
		return
	}
	testContext, cancel := context.WithTimeout(request.Context(), modelProviderTestTimeout)
	defer cancel()
	started := time.Now()
	_, err = adapter.Generate(testContext, modelgateway.NormalizedRequest{
		RequestID: uuid.NewString(), TenantID: principal.TenantID, Role: "MODEL_PROVIDER_TEST", Model: body.Model,
		Messages:        []modelgateway.Message{{Role: "user", Content: "Reply with OK."}},
		MaxOutputTokens: 8, Temperature: 0,
	})
	latency := time.Since(started).Milliseconds()
	if err != nil {
		writeJSON(response, http.StatusOK, modelProviderTestResource{OK: false, Model: body.Model, LatencyMS: latency, Detail: "connection failed"})
		return
	}
	writeJSON(response, http.StatusOK, modelProviderTestResource{OK: true, Model: body.Model, LatencyMS: latency, Detail: "connection succeeded"})
}

func modelProviderSettingsPath(path string) (string, bool, bool) {
	const prefix = "/v1/settings/model-providers/"
	if !strings.HasPrefix(path, prefix) {
		return "", false, false
	}
	value := strings.TrimPrefix(path, prefix)
	test := strings.HasSuffix(value, ":test")
	if test {
		value = strings.TrimSuffix(value, ":test")
	}
	if value == "" || strings.Contains(value, "/") || !safeModelValue(value, 128) {
		return "", false, false
	}
	return value, test, true
}

func modelProviderCatalog(providerID string) (modelproviders.ProviderCatalog, bool) {
	for _, provider := range modelproviders.Catalog() {
		if provider.ID == providerID {
			return provider, true
		}
	}
	return modelproviders.ProviderCatalog{}, false
}

func modelProviderCatalogModels(provider modelproviders.ProviderCatalog) []string {
	models := make([]string, 0, len(provider.Models))
	for _, model := range provider.Models {
		models = append(models, model.ID)
	}
	return models
}

func modelProviderCatalogHasModel(provider modelproviders.ProviderCatalog, modelID string) bool {
	for _, model := range provider.Models {
		if model.ID == modelID {
			return true
		}
	}
	return false
}

func modelProviderCatalogHasProtocol(provider modelproviders.ProviderCatalog, protocol string) bool {
	for _, candidate := range provider.Protocols {
		if string(candidate) == protocol {
			return true
		}
	}
	return false
}

func validModelProviderAPIKey(value string) bool {
	return value == "" || len(value) <= 64*1024 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func modelProviderSettingsResourceFrom(catalog modelproviders.ProviderCatalog, setting modelproviders.ProviderSettings) modelProviderSettingsResource {
	protocol := string(catalog.Protocol)
	if setting.Protocol != "" {
		protocol = string(setting.Protocol)
	}
	protocols := make([]string, 0, len(catalog.Protocols))
	for _, candidate := range catalog.Protocols {
		protocols = append(protocols, string(candidate))
	}
	models := setting.Models
	if len(models) == 0 {
		models = modelProviderCatalogModels(catalog)
	}
	return modelProviderSettingsResource{
		ID: catalog.ID, Provider: catalog.ID, DisplayName: catalog.DisplayName,
		BaseURL: setting.BaseURL, Protocol: protocol, Protocols: protocols,
		Models: append([]string(nil), models...), APIKeyConfigured: setting.APIKeyConfigured,
		Enabled: setting.Enabled, Version: setting.Version,
	}
}

func modelProviderSettingsDigest(providerID, baseURL, protocol string, enabled bool, model string) (string, error) {
	encoded, err := json.Marshal(struct {
		ProviderID string `json:"providerId"`
		BaseURL    string `json:"baseUrl"`
		Protocol   string `json:"protocol"`
		Enabled    bool   `json:"enabled"`
		Model      string `json:"model,omitempty"`
	}{ProviderID: providerID, BaseURL: baseURL, Protocol: protocol, Enabled: enabled, Model: model})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func mapModelProviderSettingsError(err error) error {
	if errors.Is(err, modelproviders.ErrInvalidSettings) || errors.Is(err, modelproviders.ErrProviderNotFound) || errors.Is(err, modelproviders.ErrAPIKeyUnavailable) {
		return invalidModelProviderSettings("model provider settings")
	}
	return unavailableModelProviderSettings(err)
}

func invalidModelProviderSettings(scope string) error {
	return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": scope})
}

func unavailableModelProviderSettings(err error) error {
	if err == nil {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "model provider settings"})
	}
	return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, map[string]any{"scope": "model provider settings"})
}
