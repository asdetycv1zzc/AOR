package openaicompatible

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/modelgateway"
)

const testCredential = "credential-test-0123456789"

func TestGenerateUsesChatCompletionsWithoutCredentialLeakage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/chat/completions" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer "+testCredential {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		var payload struct {
			Model     string `json:"model"`
			MaxTokens int    `json:"max_tokens"`
			Tools     []struct {
				Type string `json:"type"`
			} `json:"tools"`
			ResponseFormat struct {
				Type string `json:"type"`
			} `json:"response_format"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Model != "gpt-test" || payload.MaxTokens != 16 || len(payload.Tools) != 1 || payload.Tools[0].Type != "function" || payload.ResponseFormat.Type != "json_schema" {
			t.Fatalf("payload = %#v", payload)
		}
		_, _ = writer.Write([]byte(`{"id":"chatcmpl-1","model":"gpt-test-2026-08","choices":[{"message":{"content":"{\"ok\":true}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":3,"total_tokens":14}}`))
	}))
	defer server.Close()

	adapter := testAdapter(t, server.URL+"/v1/chat/completions", Config{})
	response, err := adapter.Generate(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if response.RequestID != "request-1" || response.ProviderRequestID != "chatcmpl-1" || response.ModelVersion != "gpt-test-2026-08" || string(response.Content) != `{"ok":true}` {
		t.Fatalf("response = %#v", response)
	}
	if response.Usage.InputTokens != 11 || response.Usage.OutputTokens != 3 || response.Usage.CostMicros != 0 {
		t.Fatalf("usage = %#v", response.Usage)
	}
	if strings.Contains(response.ProviderRequestID+response.ModelVersion+string(response.Content), testCredential) {
		t.Fatal("credential leaked into response")
	}
	count, err := adapter.CountTokens(context.Background(), testRequest())
	if err != nil || count.InputTokens <= 0 {
		t.Fatalf("token estimate = %#v, %v", count, err)
	}
}

func TestGenerateClassifiesHTTPAndNetworkFailuresWithoutProviderBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusTooManyRequests)
		_, _ = writer.Write([]byte(`{"error":{"message":"` + testCredential + `"}}`))
	}))
	defer server.Close()
	adapter := testAdapter(t, server.URL, Config{})
	_, err := adapter.Generate(context.Background(), testRequest())
	var failure *modelgateway.ProviderFailure
	if !errors.As(err, &failure) || !failure.Retryable || !failure.OutcomeKnown || strings.Contains(err.Error(), testCredential) {
		t.Fatalf("http failure = %#v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	adapter = testAdapter(t, endpoint, Config{RequestTimeout: time.Second})
	_, err = adapter.Generate(context.Background(), testRequest())
	if !errors.As(err, &failure) || failure.OutcomeKnown || !failure.Retryable || strings.Contains(err.Error(), testCredential) {
		t.Fatalf("network failure = %#v", err)
	}
}

func TestStreamParsesSSEAndCancelStopsTheRequest(t *testing.T) {
	cancelled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+testCredential {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write([]byte("data: {\"id\":\"chatcmpl-stream\",\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n"))
		writer.(http.Flusher).Flush()
		<-request.Context().Done()
		close(cancelled)
	}))
	defer server.Close()
	adapter := testAdapter(t, server.URL, Config{})
	stream, err := adapter.Stream(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	event, err := stream.Recv(context.Background())
	if err != nil || !strings.Contains(string(event), "chatcmpl-stream") {
		t.Fatalf("stream event = %s, %v", event, err)
	}
	if err := adapter.Cancel(context.Background(), "chatcmpl-stream"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("stream request was not cancelled")
	}
	if _, err := stream.Recv(context.Background()); err == nil {
		t.Fatal("cancelled stream returned an event")
	}
}

func TestGenerateBoundsResponseAndHonorsCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(started)
		select {
		case <-request.Context().Done():
		case <-release:
		}
		_ = writer
	}))
	defer server.Close()
	adapter := testAdapter(t, server.URL, Config{RequestTimeout: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := adapter.Generate(ctx, testRequest())
		result <- err
	}()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	close(release)

	overflow := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("x", 65)))
	}))
	defer overflow.Close()
	adapter = testAdapter(t, overflow.URL, Config{MaxResponseBytes: 64})
	_, err := adapter.Generate(context.Background(), testRequest())
	var failure *modelgateway.ProviderFailure
	if !errors.As(err, &failure) || failure.OutcomeKnown || !errors.Is(failure, modelgateway.ErrOutputTooLarge) {
		t.Fatalf("overflow failure = %#v", err)
	}
}

func TestNormalizeUsageRejectsCredentialValues(t *testing.T) {
	adapter := testAdapter(t, "http://127.0.0.1", Config{})
	usage, err := adapter.NormalizeUsage(chatUsage{PromptTokens: 7, CompletionTokens: 2})
	if err != nil || usage.InputTokens != 7 || usage.OutputTokens != 2 {
		t.Fatalf("usage = %#v, %v", usage, err)
	}
	usage, err = adapter.NormalizeUsage(map[string]any{"prompt_tokens": float64(5), "completion_tokens": float64(4)})
	if err != nil || usage.InputTokens != 5 || usage.OutputTokens != 4 {
		t.Fatalf("map usage = %#v, %v", usage, err)
	}
	if _, err := adapter.NormalizeUsage(modelgateway.Usage{ProviderRequestID: testCredential}); !errors.Is(err, modelgateway.ErrInvalidRequest) {
		t.Fatalf("credential usage error = %v", err)
	}
	if _, err := adapter.Capabilities(context.Background(), "unknown"); !errors.Is(err, modelgateway.ErrProviderNotAllowed) {
		t.Fatalf("unknown capabilities = %v", err)
	}
}

func testAdapter(t *testing.T, endpoint string, overrides Config) *Adapter {
	t.Helper()
	config := Config{
		Endpoint: endpoint, Credential: testCredential, RequestTimeout: time.Second,
		Models: map[string]modelgateway.ModelCapabilities{"gpt-test": {
			SupportsStreaming: true, SupportsToolCalls: true, SupportsJSONSchema: true, SupportsSeed: true,
			MaxInputTokens: 4096, MaxOutputTokens: 128, ActualModelVersion: "gpt-test-configured",
		}},
	}
	if overrides.RequestTimeout != 0 {
		config.RequestTimeout = overrides.RequestTimeout
	}
	if overrides.MaxResponseBytes != 0 {
		config.MaxResponseBytes = overrides.MaxResponseBytes
	}
	adapter, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func testRequest() modelgateway.NormalizedRequest {
	return modelgateway.NormalizedRequest{
		RequestID: "request-1", TenantID: "tenant-1", ProjectID: "project-1", AgentInstanceID: "agent-1", Role: "EXECUTOR",
		Model: "gpt-test", PromptBundleVersion: "v1", Messages: []modelgateway.Message{{Role: "system", Content: "rules"}, {Role: "user", Content: "answer"}},
		Tools:          []modelgateway.ToolDefinition{{Name: "repo.read", Description: "read", Schema: json.RawMessage(`{"type":"object"}`)}},
		ResponseSchema: json.RawMessage(`{"type":"object"}`), MaxOutputTokens: 16, Temperature: 0.2, DataClassification: "INTERNAL",
	}
}
