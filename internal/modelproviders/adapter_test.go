package modelproviders

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/akimisaka/aor/internal/modelgateway"
)

const adapterTestTenant = "11111111-1111-4111-8111-111111111111"

func TestAnthropicAdapterUsesMessagesProtocol(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/v1/messages" || request.Header.Get("x-api-key") != "test-key" || request.Header.Get("anthropic-version") != anthropicVersion {
			t.Errorf("unexpected Anthropic request path=%q", request.URL.Path)
		}
		var body anthropicRequest
		if json.NewDecoder(request.Body).Decode(&body) != nil || body.ToolChoice == nil || body.ToolChoice.Name != "aor_response" || len(body.Tools) != 1 {
			t.Error("structured response tool was not configured")
		}
		return jsonResponse(`{"id":"msg-1","model":"claude-sonnet-4-6","role":"assistant","content":[{"type":"tool_use","id":"tool-1","name":"aor_response","input":{"ok":true}}],"stop_reason":"tool_use","usage":{"input_tokens":12,"output_tokens":4}}`), nil
	})}
	adapter, err := AdapterFactory{HTTPClient: client}.NewWithProtocol(
		ProviderClaude, ProtocolAnthropic, "https://api.anthropic.test", "test-key", []string{"claude-sonnet-4-6"},
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := adapter.Generate(context.Background(), modelgateway.NormalizedRequest{
		RequestID: "request-1", TenantID: adapterTestTenant, Model: "claude-sonnet-4-6",
		Messages: []modelgateway.Message{{Role: "user", Content: "Return JSON."}}, MaxOutputTokens: 128,
		ResponseSchema: json.RawMessage(`{"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Content) != `{"ok":true}` || len(result.ToolCalls) != 0 || result.Usage.InputTokens != 12 {
		t.Fatalf("result = %#v", result)
	}
}

func TestDynamicAdapterRefreshesAfterSettingsVersionChanges(t *testing.T) {
	var firstCalls, secondCalls int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Host {
		case "first.example":
			firstCalls++
		case "second.example":
			secondCalls++
		default:
			t.Errorf("unexpected host %q", request.URL.Host)
		}
		return jsonResponse(`{"id":"response-1","model":"gpt-5.4","choices":[{"message":{"role":"assistant","content":"{\"ok\":true}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":3}}`), nil
	})}
	store := &memorySettingsStore{resolved: resolvedTestSettings("https://first.example/v1", "first-key", 1)}
	adapter, err := NewDynamicAdapter(ProviderOpenAI, "gpt-5.4", store, AdapterFactory{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	request := modelgateway.NormalizedRequest{
		RequestID: "request-1", TenantID: adapterTestTenant, Model: "gpt-5.4",
		Messages: []modelgateway.Message{{Role: "user", Content: "hello"}}, MaxOutputTokens: 32,
	}
	if _, err := adapter.Generate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	store.set(resolvedTestSettings("https://second.example/v1", "second-key", 2))
	request.RequestID = "request-2"
	if _, err := adapter.Generate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if firstCalls != 1 || secondCalls != 1 {
		t.Fatalf("calls = first:%d second:%d", firstCalls, secondCalls)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func jsonResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func resolvedTestSettings(baseURL, apiKey string, version int64) ResolvedSettings {
	catalog, _ := findCatalog(ProviderOpenAI)
	settings := defaultSettings(catalog)
	settings.BaseURL = baseURL
	settings.Protocol = ProtocolOpenAICompatible
	settings.Enabled = true
	settings.APIKeyConfigured = true
	settings.Models = []string{"gpt-5.4"}
	settings.Version = version
	return ResolvedSettings{ProviderSettings: settings, APIKey: apiKey}
}

type memorySettingsStore struct {
	mu       sync.Mutex
	resolved ResolvedSettings
}

func (store *memorySettingsStore) set(value ResolvedSettings) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.resolved = value
}

func (store *memorySettingsStore) Resolve(context.Context, string, string) (ResolvedSettings, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.resolved, true, nil
}

func (store *memorySettingsStore) List(context.Context, string) ([]ProviderSettings, error) {
	return nil, nil
}

func (store *memorySettingsStore) Get(context.Context, string, string) (ProviderSettings, bool, error) {
	return ProviderSettings{}, false, nil
}

func (store *memorySettingsStore) Put(context.Context, string, string, PutRequest) (ProviderSettings, error) {
	return ProviderSettings{}, nil
}
