package openaicompatible

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/akimisaka/aor/internal/modelgateway"
)

func TestResponsesStreamPreservesTerminalResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Accept") != "text/event-stream" {
			t.Fatalf("accept = %q", request.Header.Get("Accept"))
		}
		var payload responsesRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if !payload.Stream || payload.Text != nil || payload.Reasoning == nil || payload.Reasoning.Summary != "auto" {
			t.Fatal("Responses stream request did not enable streaming")
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		events := []string{
			`event: response.created
data: {"type":"response.created","response":{"id":"resp-stream","model":"gpt-test-v3","status":"in_progress","output":[]}}

`,
			`event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg-1","output_index":0,"content_index":0,"delta":"{\"ok\""}

`,
			`event: response.reasoning_summary_text.delta
data: {"type":"response.reasoning_summary_text.delta","item_id":"rs-1","output_index":0,"summary_index":0,"delta":"Checking constraints"}

`,
			`event: response.reasoning_summary_text.delta
data: {"type":"response.reasoning_summary_text.delta","item_id":"rs-1","output_index":0,"summary_index":1,"delta":"Selecting tools"}

`,
			`data: {"type":"response.output_text.delta","item_id":"msg-1","output_index":0,"content_index":0,"delta":":true}"}

`,
			`event: response.completed
data: {"type":"response.completed","response":{"id":"resp-stream","model":"gpt-test-v3","status":"completed","output":[{"type":"reasoning","id":"rs-1"},{"type":"message","id":"msg-1","role":"assistant","content":[{"type":"output_text","text":"{\"ok\":true}"}]}],"usage":{"input_tokens":9,"output_tokens":3,"total_tokens":12,"input_tokens_details":{"cached_tokens":6,"cache_write_tokens":1}}}}

`,
		}
		for _, event := range events {
			_, _ = writer.Write([]byte(event))
			writer.(http.Flusher).Flush()
		}
	}))
	defer server.Close()

	adapter := testAdapter(t, server.URL+"/v1/responses", Config{WireFormat: WireFormatResponses, SupportsReasoningEffort: true})
	request := streamingTestRequest()
	request.ReasoningEffort = "medium"
	stream, err := adapter.Stream(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	var events []json.RawMessage
	for {
		event, receiveErr := stream.Recv(context.Background())
		if errors.Is(receiveErr, io.EOF) {
			break
		}
		if receiveErr != nil {
			t.Fatal(receiveErr)
		}
		events = append(events, event)
	}
	if len(events) != 2 || string(events[0]) != `{"delta":"{\"ok\""}` || string(events[1]) != `{"delta":":true}"}` {
		t.Fatalf("events = %q", events)
	}

	contentStream, ok := stream.(modelgateway.FinalContentAwareStream)
	if !ok {
		t.Fatal("Responses stream does not expose final content")
	}
	content, ready := contentStream.FinalContent()
	if !ready || string(content) != `{"ok":true}` {
		t.Fatalf("final content = %s, ready = %v", content, ready)
	}
	usageStream, ok := stream.(modelgateway.UsageAwareStream)
	if !ok {
		t.Fatal("Responses stream does not expose final usage")
	}
	usage, ready := usageStream.FinalUsage()
	if !ready || usage.InputTokens != 9 || usage.OutputTokens != 3 || usage.ProviderRequestID != "resp-stream" || usage.ModelVersion != "gpt-test-v3" || usage.CacheReadTokens == nil || *usage.CacheReadTokens != 6 || usage.CacheWriteTokens == nil || *usage.CacheWriteTokens != 1 {
		t.Fatalf("final usage = %#v, ready = %v", usage, ready)
	}
	responsesStream := stream.(*responsesResponseStream)
	if responsesStream.summaryBytes != len("Checking constraints\n\nSelecting tools") || responsesStream.summaryIndex != 1 {
		t.Fatalf("reasoning summary bytes = %d", responsesStream.summaryBytes)
	}
	finishReason, ready := responsesStream.FinalFinishReason()
	if !ready || finishReason != "stop" {
		t.Fatalf("finish reason = %q, ready = %v", finishReason, ready)
	}
}

func TestResponsesStreamClassifiesProviderFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write([]byte("event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"server_error\",\"message\":\"secret provider detail\"}}}\n\n"))
	}))
	defer server.Close()

	adapter := testAdapter(t, server.URL+"/v1/responses", Config{WireFormat: WireFormatResponses})
	stream, err := adapter.Stream(context.Background(), streamingTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_, err = stream.Recv(context.Background())
	var failure *modelgateway.ProviderFailure
	if !errors.As(err, &failure) || !failure.OutcomeKnown || !failure.Retryable || strings.Contains(err.Error(), "secret provider detail") {
		t.Fatalf("failure = %v", err)
	}
}
