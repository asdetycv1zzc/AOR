package modelproviders

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/modelgateway"
)

const anthropicTestKey = "anthropic-test-key"

func TestAnthropicStreamEmitsDeltasAndFinalState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/messages" || request.Header.Get("x-api-key") != anthropicTestKey || request.Header.Get("anthropic-version") != anthropicVersion || request.Header.Get("Accept") != "text/event-stream" {
			t.Errorf("unexpected request path=%q headers=%v", request.URL.Path, request.Header)
		}
		var payload anthropicRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Error(err)
			return
		}
		if !payload.Stream {
			t.Error("stream was not enabled")
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		writeAnthropicTestEvent(writer, "message_start", `{"type":"message_start","message":{"id":"msg_test","model":"claude-test-v1","role":"assistant","content":[],"stop_reason":null,"usage":{"input_tokens":7,"output_tokens":0}}}`)
		writeAnthropicTestEvent(writer, "content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
		writeAnthropicTestEvent(writer, "content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}`)
		writeAnthropicTestEvent(writer, "content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" world"}}`)
		writeAnthropicTestEvent(writer, "content_block_stop", `{"type":"content_block_stop","index":0}`)
		writeAnthropicTestEvent(writer, "message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}`)
		writeAnthropicTestEvent(writer, "message_stop", `{"type":"message_stop"}`)
	}))
	defer server.Close()

	adapter := newAnthropicStreamTestAdapter(t, server.URL)
	stream, err := adapter.Stream(context.Background(), anthropicStreamTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	for index, expected := range []string{`{"delta":"hello"}`, `{"delta":" world"}`} {
		event, receiveErr := stream.Recv(context.Background())
		if receiveErr != nil || string(event) != expected {
			t.Fatalf("event %d = %s, %v", index, event, receiveErr)
		}
	}
	if _, err := stream.Recv(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal error = %v", err)
	}
	contentStream := stream.(modelgateway.FinalContentAwareStream)
	content, ready := contentStream.FinalContent()
	if !ready || string(content) != `"hello world"` {
		t.Fatalf("final content = %s, ready=%v", content, ready)
	}
	usageStream := stream.(modelgateway.UsageAwareStream)
	usage, ready := usageStream.FinalUsage()
	if !ready || usage.InputTokens != 7 || usage.OutputTokens != 2 || usage.ProviderRequestID != "msg_test" || usage.ModelVersion != "claude-test-v1" {
		t.Fatalf("final usage = %#v, ready=%v", usage, ready)
	}
}

func TestAnthropicStreamAssemblesStructuredResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var payload anthropicRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Error(err)
			return
		}
		if !payload.Stream || len(payload.Tools) != 1 || payload.Tools[0].Name != "aor_response" {
			t.Errorf("structured stream payload = %#v", payload)
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		writeAnthropicTestEvent(writer, "message_start", `{"type":"message_start","message":{"id":"msg_structured","model":"claude-test-v2","role":"assistant","content":[],"stop_reason":null,"usage":{"input_tokens":11,"output_tokens":0}}}`)
		writeAnthropicTestEvent(writer, "content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"tool_test","name":"aor_response","input":{}}}`)
		writeAnthropicTestEvent(writer, "content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"answer\""}}`)
		writeAnthropicTestEvent(writer, "content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":":\"ok\"}"}}`)
		writeAnthropicTestEvent(writer, "content_block_stop", `{"type":"content_block_stop","index":0}`)
		writeAnthropicTestEvent(writer, "message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":4}}`)
		writeAnthropicTestEvent(writer, "message_stop", `{"type":"message_stop"}`)
	}))
	defer server.Close()

	adapter := newAnthropicStreamTestAdapter(t, server.URL)
	request := anthropicStreamTestRequest()
	request.ResponseSchema = json.RawMessage(`{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"]}`)
	stream, err := adapter.Stream(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	var streamed strings.Builder
	for {
		event, receiveErr := stream.Recv(context.Background())
		if errors.Is(receiveErr, io.EOF) {
			break
		}
		if receiveErr != nil {
			t.Fatal(receiveErr)
		}
		var delta struct {
			Delta string `json:"delta"`
		}
		if json.Unmarshal(event, &delta) != nil {
			t.Fatalf("invalid normalized delta: %s", event)
		}
		streamed.WriteString(delta.Delta)
	}
	if streamed.String() != `{"answer":"ok"}` {
		t.Fatalf("streamed content = %q", streamed.String())
	}
	content, ready := stream.(modelgateway.FinalContentAwareStream).FinalContent()
	if !ready || string(content) != `{"answer":"ok"}` {
		t.Fatalf("final content = %s, ready=%v", content, ready)
	}
}

func TestAnthropicStreamBoundsSSELines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(writer, "data: "+strings.Repeat("x", modelgateway.MaximumResponseBytes+1)+"\n\n")
	}))
	defer server.Close()

	adapter := newAnthropicStreamTestAdapter(t, server.URL)
	stream, err := adapter.Stream(context.Background(), anthropicStreamTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_, err = stream.Recv(context.Background())
	var failure *modelgateway.ProviderFailure
	if !errors.As(err, &failure) || failure.OutcomeKnown || !errors.Is(err, modelgateway.ErrOutputTooLarge) {
		t.Fatalf("oversized line error = %#v", err)
	}
}

func TestAnthropicStreamPreservesReceiveCancellation(t *testing.T) {
	cancelled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		<-request.Context().Done()
		close(cancelled)
	}))
	defer server.Close()

	adapter := newAnthropicStreamTestAdapter(t, server.URL)
	stream, err := adapter.Stream(context.Background(), anthropicStreamTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	receiveContext, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := stream.Recv(receiveContext); !errors.Is(err, context.Canceled) {
		t.Fatalf("receive cancellation = %v", err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("provider request was not cancelled")
	}
}

func newAnthropicStreamTestAdapter(t *testing.T, baseURL string) *anthropicAdapter {
	t.Helper()
	adapter, err := newAnthropicAdapter(anthropicConfig{
		BaseURL: baseURL,
		APIKey:  anthropicTestKey,
		Models: map[string]modelgateway.ModelCapabilities{
			"claude-test": {
				SupportsStreaming:  true,
				SupportsToolCalls:  true,
				SupportsJSONSchema: true,
				MaxInputTokens:     4096,
				MaxOutputTokens:    1024,
				ActualModelVersion: "claude-test-fallback",
			},
		},
		RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func anthropicStreamTestRequest() modelgateway.NormalizedRequest {
	return modelgateway.NormalizedRequest{
		RequestID: "request-test", Model: "claude-test",
		Messages:        []modelgateway.Message{{Role: "user", Content: "hello"}},
		MaxOutputTokens: 128, Temperature: 0.5, TopP: 1,
	}
}

func writeAnthropicTestEvent(writer http.ResponseWriter, eventName, payload string) {
	_, _ = io.WriteString(writer, "event: "+eventName+"\n")
	_, _ = io.WriteString(writer, "data: "+payload+"\n\n")
	writer.(http.Flusher).Flush()
}
