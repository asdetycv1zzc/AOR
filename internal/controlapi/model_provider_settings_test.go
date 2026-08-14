package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/modelproviders"
)

type recordingModelProviderSettingsStore struct {
	putCalls   int
	providerID string
	request    modelproviders.PutRequest
}

func (store *recordingModelProviderSettingsStore) List(context.Context, string) ([]modelproviders.ProviderSettings, error) {
	return nil, nil
}

func (store *recordingModelProviderSettingsStore) Get(context.Context, string, string) (modelproviders.ProviderSettings, bool, error) {
	return modelproviders.ProviderSettings{}, false, nil
}

func (store *recordingModelProviderSettingsStore) Resolve(context.Context, string, string) (modelproviders.ResolvedSettings, bool, error) {
	return modelproviders.ResolvedSettings{}, false, nil
}

func (store *recordingModelProviderSettingsStore) Put(_ context.Context, _ string, providerID string, request modelproviders.PutRequest) (modelproviders.ProviderSettings, error) {
	store.putCalls++
	store.providerID = providerID
	store.request = request
	return modelproviders.ProviderSettings{
		ID: providerID, Provider: providerID, DisplayName: "OpenAI", BaseURL: request.BaseURL,
		Protocol: request.Protocol, Protocols: []modelproviders.Protocol{request.Protocol},
		Models: []string{"gpt-test"}, ModelContextWindowTokens: map[string]int{"gpt-test": 400_000},
		APIKeyConfigured: !request.ClearAPIKey, Enabled: request.Enabled, Version: 2,
	}, nil
}

func TestPutModelProviderSettingsClearsAPIKeyAndDisablesProvider(t *testing.T) {
	settings := &recordingModelProviderSettingsStore{}
	authorizer := &recordingAuthorizer{}
	handler := &Handler{authorizer: authorizer, providerSettings: settings}
	request := httptest.NewRequest(http.MethodPut, "/v1/settings/model-providers/openai", strings.NewReader(`{"baseUrl":"https://api.openai.com/v1","protocol":"openai-responses","clearApiKey":true,"enabled":true}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	principal := authn.Principal{ID: "user-1", Type: authn.PrincipalUser, Role: authn.RoleUser, TenantID: testTenantID}

	handler.putModelProviderSettings(response, request, principal, "openai")

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if settings.putCalls != 1 || settings.providerID != "openai" || !settings.request.ClearAPIKey || settings.request.Enabled || settings.request.APIKey != "" {
		t.Fatalf("put calls=%d provider=%q request=%#v", settings.putCalls, settings.providerID, settings.request)
	}
	var resource modelProviderSettingsResource
	if err := json.Unmarshal(response.Body.Bytes(), &resource); err != nil {
		t.Fatal(err)
	}
	if resource.APIKeyConfigured || resource.Enabled {
		t.Fatalf("resource=%#v", resource)
	}
	withoutClear, err := modelProviderSettingsDigest("openai", "", "https://api.openai.com/v1", "openai-responses", nil, nil, false, false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(authorizer.inputs) != 1 || authorizer.inputs[0].ParameterDigest == "" || authorizer.inputs[0].ParameterDigest == withoutClear {
		t.Fatalf("authorization inputs=%#v", authorizer.inputs)
	}
}

func TestPutModelProviderSettingsRejectsClearWithReplacementKey(t *testing.T) {
	settings := &recordingModelProviderSettingsStore{}
	authorizer := &recordingAuthorizer{}
	handler := &Handler{authorizer: authorizer, providerSettings: settings}
	request := httptest.NewRequest(http.MethodPut, "/v1/settings/model-providers/openai", strings.NewReader(`{"baseUrl":"https://api.openai.com/v1","protocol":"openai-responses","apiKey":"replacement","clearApiKey":true,"enabled":false}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	principal := authn.Principal{ID: "user-1", Type: authn.PrincipalUser, Role: authn.RoleUser, TenantID: testTenantID}

	handler.putModelProviderSettings(response, request, principal, "openai")

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if settings.putCalls != 0 || len(authorizer.inputs) != 0 {
		t.Fatalf("put calls=%d authorization inputs=%#v", settings.putCalls, authorizer.inputs)
	}
}
