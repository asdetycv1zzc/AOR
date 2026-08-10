package controlapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/modelproviders"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
	"github.com/google/uuid"
)

const modelProviderTestTimeout = 20 * time.Second

type modelProviderSettingsResource struct {
	ID               string   `json:"id"`
	Provider         string   `json:"provider"`
	DisplayName      string   `json:"displayName,omitempty"`
	Custom           bool     `json:"custom"`
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
	DisplayName string   `json:"displayName,omitempty"`
	BaseURL     string   `json:"baseUrl"`
	Protocol    string   `json:"protocol"`
	APIKey      string   `json:"apiKey,omitempty"`
	Models      []string `json:"models,omitempty"`
	Enabled     bool     `json:"enabled"`
}

type modelProviderTestBody struct {
	BaseURL         string `json:"baseUrl"`
	Protocol        string `json:"protocol"`
	APIKey          string `json:"apiKey,omitempty"`
	Model           string `json:"model"`
	ReasoningEffort string `json:"reasoningEffort"`
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
	items := make([]modelProviderSettingsResource, 0, len(settings))
	for _, setting := range settings {
		items = append(items, modelProviderSettingsResourceFrom(setting))
	}
	writeJSON(response, http.StatusOK, modelProviderSettingsPage{Items: items})
}

func (handler *Handler) putModelProviderSettings(response http.ResponseWriter, request *http.Request, principal authn.Principal, providerID string) {
	response.Header().Set("Cache-Control", "no-store")
	if len(request.URL.Query()) != 0 {
		writeError(response, request, invalidModelProviderSettings("model provider settings query"))
		return
	}
	var body modelProviderSettingsBody
	if decodeJSON(request, &body) != nil || !validModelProviderProtocol(body.Protocol) {
		writeError(response, request, invalidModelProviderSettings("model provider settings"))
		return
	}
	digest, err := modelProviderSettingsDigest(providerID, body.DisplayName, body.BaseURL, body.Protocol, body.Models, body.Enabled, "", "")
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
		DisplayName: body.DisplayName, BaseURL: body.BaseURL, Protocol: modelproviders.Protocol(body.Protocol), APIKey: body.APIKey, Models: body.Models, Enabled: body.Enabled,
	})
	if err != nil {
		writeError(response, request, mapModelProviderSettingsError(err))
		return
	}
	writeJSON(response, http.StatusOK, modelProviderSettingsResourceFrom(setting))
}

func (handler *Handler) testModelProvider(response http.ResponseWriter, request *http.Request, principal authn.Principal, providerID string) {
	response.Header().Set("Cache-Control", "no-store")
	if len(request.URL.Query()) != 0 {
		writeError(response, request, invalidModelProviderSettings("model provider test query"))
		return
	}
	var body modelProviderTestBody
	if decodeJSON(request, &body) != nil || !validModelProviderProtocol(body.Protocol) || !safeModelValue(body.Model, 256) || body.Model == "*" || !state.ValidModelReasoningEffort(providerID, body.ReasoningEffort) || !validModelProviderAPIKey(body.APIKey) {
		writeError(response, request, invalidModelProviderSettings("model provider test"))
		return
	}
	digest, err := modelProviderSettingsDigest(providerID, "", body.BaseURL, body.Protocol, nil, true, body.Model, body.ReasoningEffort)
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
	stream, err := adapter.Stream(testContext, modelgateway.NormalizedRequest{
		RequestID: uuid.NewString(), TenantID: principal.TenantID, Role: "MODEL_PROVIDER_TEST", Model: body.Model,
		Messages:        []modelgateway.Message{{Role: "user", Content: `Return exactly {"ok":true}.`}},
		MaxOutputTokens: 256, Temperature: 0, ReasoningEffort: body.ReasoningEffort,
		ResponseSchema: json.RawMessage(`{"type":"object","required":["ok"],"properties":{"ok":{"const":true}},"additionalProperties":false}`),
	})
	if err == nil && stream == nil {
		err = modelgateway.ErrOutputSchema
	}
	if err == nil {
		defer stream.Close()
		deltaCount := 0
		for {
			_, receiveErr := stream.Recv(testContext)
			if errors.Is(receiveErr, io.EOF) {
				break
			}
			if receiveErr != nil {
				err = receiveErr
				break
			}
			deltaCount++
		}
		contentStream, contentOK := stream.(modelgateway.FinalContentAwareStream)
		usageStream, usageOK := stream.(modelgateway.UsageAwareStream)
		content, contentReady := json.RawMessage(nil), false
		if contentOK {
			content, contentReady = contentStream.FinalContent()
		}
		_, usageReady := modelgateway.Usage{}, false
		if usageOK {
			_, usageReady = usageStream.FinalUsage()
		}
		if err == nil && (deltaCount == 0 || !contentReady || !json.Valid(content) || !usageReady) {
			err = modelgateway.ErrOutputSchema
		}
	}
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

func validModelProviderProtocol(protocol string) bool {
	return protocol == string(modelproviders.ProtocolOpenAICompatible) || protocol == string(modelproviders.ProtocolOpenAIResponses) || protocol == string(modelproviders.ProtocolAnthropic)
}

func validModelProviderAPIKey(value string) bool {
	return value == "" || len(value) <= 64*1024 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func modelProviderSettingsResourceFrom(setting modelproviders.ProviderSettings) modelProviderSettingsResource {
	protocols := make([]string, 0, len(setting.Protocols))
	for _, candidate := range setting.Protocols {
		protocols = append(protocols, string(candidate))
	}
	return modelProviderSettingsResource{
		ID: setting.ID, Provider: setting.Provider, DisplayName: setting.DisplayName, Custom: setting.Custom,
		BaseURL: setting.BaseURL, Protocol: string(setting.Protocol), Protocols: protocols,
		Models: append([]string(nil), setting.Models...), APIKeyConfigured: setting.APIKeyConfigured,
		Enabled: setting.Enabled, Version: setting.Version,
	}
}

func modelProviderSettingsDigest(providerID, displayName, baseURL, protocol string, models []string, enabled bool, model, reasoningEffort string) (string, error) {
	encoded, err := json.Marshal(struct {
		ProviderID      string   `json:"providerId"`
		DisplayName     string   `json:"displayName,omitempty"`
		BaseURL         string   `json:"baseUrl"`
		Protocol        string   `json:"protocol"`
		Models          []string `json:"models,omitempty"`
		Enabled         bool     `json:"enabled"`
		Model           string   `json:"model,omitempty"`
		ReasoningEffort string   `json:"reasoningEffort,omitempty"`
	}{ProviderID: providerID, DisplayName: displayName, BaseURL: baseURL, Protocol: protocol, Models: models, Enabled: enabled, Model: model, ReasoningEffort: reasoningEffort})
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
