package openaicompatible

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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
		if request.Header.Get("Accept") != "application/json" {
			t.Fatalf("accept = %q", request.Header.Get("Accept"))
		}
		if request.Method != http.MethodPost || request.URL.Path != "/v1/chat/completions" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer "+testCredential {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		var payload struct {
			Model           string `json:"model"`
			MaxTokens       int    `json:"max_tokens"`
			ReasoningEffort string `json:"reasoning_effort"`
			Tools           []struct {
				Type string `json:"type"`
			} `json:"tools"`
			ResponseFormat struct {
				Type string `json:"type"`
			} `json:"response_format"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Model != "gpt-test" || payload.MaxTokens != 16 || payload.ReasoningEffort != "low" || len(payload.Tools) != 1 || payload.Tools[0].Type != "function" || payload.ResponseFormat.Type != "json_schema" {
			t.Fatalf("payload = %#v", payload)
		}
		_, _ = writer.Write([]byte(`{"id":"chatcmpl-1","model":"gpt-test-2026-08","choices":[{"message":{"content":"{\"ok\":true}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":3,"total_tokens":14}}`))
	}))
	defer server.Close()

	adapter := testAdapter(t, server.URL+"/v1/chat/completions", Config{SupportsReasoningEffort: true})
	request := testRequest()
	request.ReasoningEffort = "low"
	response, err := adapter.Generate(context.Background(), request)
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

func TestGenerateDoesNotForceStreamingForChatCompletions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var payload struct {
			Stream bool `json:"stream"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Stream {
			t.Fatal("Generate unexpectedly requested an SSE response")
		}
		_, _ = writer.Write([]byte(`{"id":"chatcmpl-json","model":"gpt-test-v1","choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer server.Close()
	adapter := testAdapter(t, server.URL, Config{})
	request := streamingTestRequest()
	if _, err := adapter.Generate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateUsesResponsesAndPreservesToolHistory(t *testing.T) {
	providerCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		providerCalls++
		if request.Method != http.MethodPost || request.URL.Path != "/v1/responses" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		var payload responsesRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Model != "gpt-test" || payload.MaxOutputTokens != 16 || payload.Reasoning == nil || payload.Reasoning.Effort != "high" || payload.Temperature != nil || payload.TopP != nil || len(payload.Tools) != 1 || payload.Text == nil || payload.Text.Format.Type != "json_schema" {
			t.Fatalf("payload = %#v", payload)
		}
		switch providerCalls {
		case 1:
			if len(payload.Input) != 2 || payload.Input[0].Role != "system" || payload.Input[1].Role != "user" {
				t.Fatalf("first input = %#v", payload.Input)
			}
			_, _ = writer.Write([]byte(`{"id":"resp-1","model":"gpt-test-2026-08","status":"completed","output":[{"type":"reasoning","id":"rs-1","encrypted_content":"opaque-reasoning"},{"type":"function_call","id":"fc-1","call_id":"call-1","name":"repo.read","arguments":"{\"path\":\"README.md\"}"}],"usage":{"input_tokens":12,"output_tokens":5,"total_tokens":17}}`))
		case 2:
			if len(payload.Input) != 5 || payload.Input[2].Type != "reasoning" || payload.Input[2].EncryptedContent != "opaque-reasoning" {
				t.Fatalf("continued input = %#v", payload.Input)
			}
			call, result := payload.Input[3], payload.Input[4]
			if call.Type != "function_call" || call.ID != "fc-1" || call.CallID != "call-1" || call.Name != "repo.read" || call.Arguments != `{"path":"README.md"}` {
				t.Fatalf("function call input = %#v", call)
			}
			if result.Type != "function_call_output" || result.CallID != "call-1" || result.Output != `{"content":"README"}` {
				t.Fatalf("function output input = %#v", result)
			}
			_, _ = writer.Write([]byte(`{"id":"resp-2","model":"gpt-test-2026-08","status":"completed","output":[{"type":"reasoning","id":"rs-2"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"{\"ok\":true}"}]}],"usage":{"input_tokens":20,"output_tokens":4,"total_tokens":24}}`))
		default:
			t.Fatalf("provider calls = %d", providerCalls)
		}
	}))
	defer server.Close()

	adapter := testAdapter(t, server.URL+"/v1/responses", Config{WireFormat: WireFormatResponses, SupportsReasoningEffort: true})
	request := testRequest()
	request.ReasoningEffort = "high"
	request.TopP = 0.8
	response, err := adapter.Generate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Content) != 0 || len(response.ToolCalls) != 1 || response.ToolCalls[0].ID != "call-1" || response.ToolCalls[0].Name != "repo.read" || response.Usage.InputTokens != 12 || response.Usage.OutputTokens != 5 {
		t.Fatalf("tool response = %#v", response)
	}
	request.RequestID = "request-2"
	request.Messages = append(request.Messages,
		modelgateway.Message{Role: "assistant", ToolCalls: response.ToolCalls},
		modelgateway.Message{Role: "tool", ToolCallID: "call-1", Content: `{"content":"README"}`},
	)
	response, err = adapter.Generate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Content) != `{"ok":true}` || len(response.ToolCalls) != 0 || response.FinishReason != "stop" || response.ProviderRequestID != "resp-2" || response.Usage.InputTokens != 20 || response.Usage.OutputTokens != 4 {
		t.Fatalf("final response = %#v", response)
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

func TestGenerateRequiresAuthoritativeProviderUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"id":"chatcmpl-missing-usage","model":"gpt-test-v1","choices":[{"message":{"content":"{\"ok\":true}"},"finish_reason":"stop"}]}`))
	}))
	defer server.Close()
	adapter := testAdapter(t, server.URL, Config{})
	_, err := adapter.Generate(context.Background(), testRequest())
	var failure *modelgateway.ProviderFailure
	if !errors.As(err, &failure) || failure.OutcomeKnown || !errors.Is(failure, modelgateway.ErrOutputSchema) {
		t.Fatalf("missing usage failure = %#v", err)
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
	stream, err := adapter.Stream(context.Background(), streamingTestRequest())
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

func TestStreamAggregatesDeltasAndRequestsAuthoritativeUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var payload struct {
			Stream        bool `json:"stream"`
			StreamOptions struct {
				IncludeUsage bool `json:"include_usage"`
			} `json:"stream_options"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if !payload.Stream || !payload.StreamOptions.IncludeUsage {
			t.Fatalf("stream request options = %#v", payload)
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write([]byte("data: {\"id\":\"chatcmpl-aggregate\",\"model\":\"gpt-test-v2\",\"choices\":[{\"delta\":{\"content\":\"{\\\"ok\\\"\"}}]}\n\n"))
		_, _ = writer.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\":true}\"}}]}\n\n"))
		_, _ = writer.Write([]byte("data: {\"id\":\"chatcmpl-aggregate\",\"model\":\"gpt-test-v2\",\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":2,\"total_tokens\":9}}\n\n"))
		_, _ = writer.Write([]byte("data: [DONE]\n\n"))
	}))
	defer server.Close()
	adapter := testAdapter(t, server.URL, Config{})
	stream, err := adapter.Stream(context.Background(), streamingTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := stream.Recv(context.Background()); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	contentStream, ok := stream.(modelgateway.FinalContentAwareStream)
	if !ok {
		t.Fatal("stream does not expose final content")
	}
	content, ready := contentStream.FinalContent()
	if !ready || string(content) != `{"ok":true}` {
		t.Fatalf("final content=%s ready=%v", content, ready)
	}
	usageStream, ok := stream.(modelgateway.UsageAwareStream)
	if !ok {
		t.Fatal("stream does not expose final usage")
	}
	usage, ready := usageStream.FinalUsage()
	if !ready || usage.InputTokens != 7 || usage.OutputTokens != 2 || usage.ProviderRequestID != "chatcmpl-aggregate" || usage.ModelVersion != "gpt-test-v2" {
		t.Fatalf("final usage=%#v ready=%v", usage, ready)
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

func TestGenerateTransportsNativeToolCallsAndResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var payload chatRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if len(payload.Messages) != 3 {
			t.Fatalf("messages = %#v", payload.Messages)
		}
		assistant := payload.Messages[1]
		if assistant.Content != nil || len(assistant.ToolCalls) != 1 || assistant.ToolCalls[0].ID != "call-1" || assistant.ToolCalls[0].Function.Name != "repo.read" || assistant.ToolCalls[0].Function.Arguments != `{"path":"README.md"}` {
			t.Fatalf("assistant message = %#v", assistant)
		}
		toolResult := payload.Messages[2]
		if toolResult.ToolCallID != "call-1" || toolResult.Content == nil || *toolResult.Content != `{"content":"README"}` {
			t.Fatalf("tool result = %#v", toolResult)
		}
		_, _ = writer.Write([]byte(`{"id":"chatcmpl-tool","model":"gpt-test-v2","choices":[{"message":{"content":null,"tool_calls":[{"id":"call-2","type":"function","function":{"name":"repo.read","arguments":"{\"path\":\"SPEC.md\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":17,"completion_tokens":4,"total_tokens":21}}`))
	}))
	defer server.Close()

	request := testRequest()
	request.Messages = []modelgateway.Message{
		{Role: "user", Content: "read files"},
		{Role: "assistant", ToolCalls: []modelgateway.ToolCall{{ID: "call-1", Name: "repo.read", Arguments: json.RawMessage(`{"path":"README.md"}`)}}},
		{Role: "tool", ToolCallID: "call-1", Content: `{"content":"README"}`},
	}
	response, err := testAdapter(t, server.URL, Config{}).Generate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Content) != 0 || len(response.ToolCalls) != 1 || response.ToolCalls[0].ID != "call-2" || response.ToolCalls[0].Name != "repo.read" || string(response.ToolCalls[0].Arguments) != `{"path":"SPEC.md"}` {
		t.Fatalf("response = %#v", response)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip modelgateway.NormalizedResponse
	if err := json.Unmarshal(encoded, &roundTrip); err != nil || len(roundTrip.ToolCalls) != 1 || string(roundTrip.ToolCalls[0].Arguments) != `{"path":"SPEC.md"}` {
		t.Fatalf("round trip = %#v, %v", roundTrip, err)
	}
}

func TestGenerateRejectsInvalidNativeToolCallResponses(t *testing.T) {
	adapter := testAdapter(t, "http://127.0.0.1", Config{})
	capabilities, err := adapter.Capabilities(context.Background(), "gpt-test")
	if err != nil {
		t.Fatal(err)
	}
	toolCall := func(id, name, arguments string) map[string]any {
		return map[string]any{"id": id, "type": "function", "function": map[string]any{"name": name, "arguments": arguments}}
	}
	for _, test := range []struct {
		name     string
		content  any
		calls    []map[string]any
		expected error
	}{
		{name: "content and calls", content: `{"ok":true}`, calls: []map[string]any{toolCall("call-1", "repo.read", `{}`)}, expected: modelgateway.ErrOutputSchema},
		{name: "unknown tool", calls: []map[string]any{toolCall("call-1", "repo.write", `{}`)}, expected: modelgateway.ErrOutputSchema},
		{name: "malformed arguments", calls: []map[string]any{toolCall("call-1", "repo.read", `{`)}, expected: modelgateway.ErrOutputSchema},
		{name: "credential", calls: []map[string]any{toolCall("call-1", "repo.read", `{"token":"`+testCredential+`"}`)}, expected: modelgateway.ErrCredentialDetected},
		{name: "oversized arguments", calls: []map[string]any{toolCall("call-1", "repo.read", `{"value":"`+strings.Repeat("x", modelgateway.MaximumToolArgumentsBytes)+`"}`)}, expected: modelgateway.ErrOutputSchema},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, marshalErr := json.Marshal(map[string]any{
				"id": "chatcmpl-tool", "model": "gpt-test-v2",
				"choices": []any{map[string]any{"message": map[string]any{"content": test.content, "tool_calls": test.calls}, "finish_reason": "tool_calls"}},
				"usage":   map[string]any{"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
			})
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			_, decodeErr := adapter.decodeResponse(testRequest(), capabilities, payload)
			var failure *modelgateway.ProviderFailure
			if !errors.As(decodeErr, &failure) || !errors.Is(failure, test.expected) {
				t.Fatalf("decode error = %#v", decodeErr)
			}
		})
	}
}

func TestStreamRejectsNativeTools(t *testing.T) {
	adapter := testAdapter(t, "http://127.0.0.1", Config{})
	if _, err := adapter.Stream(context.Background(), testRequest()); !errors.Is(err, modelgateway.ErrProviderNotAllowed) {
		t.Fatalf("stream error = %v", err)
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
	config.WireFormat = overrides.WireFormat
	config.SupportsReasoningEffort = overrides.SupportsReasoningEffort
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

func streamingTestRequest() modelgateway.NormalizedRequest {
	request := testRequest()
	request.Tools = nil
	return request
}
