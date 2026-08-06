package modelgateway

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestNativeToolMessagesRoundTrip(t *testing.T) {
	messages := []Message{
		{Role: "assistant", ToolCalls: []ToolCall{{ID: "call-1", Name: "repo.read", Arguments: json.RawMessage(`{"path":"README.md"}`)}}},
		{Role: "tool", ToolCallID: "call-1", Content: `{"content":"read result"}`},
	}
	for _, message := range messages {
		if err := message.Validate(); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Message
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded, message) {
			t.Fatalf("decoded message = %#v", decoded)
		}
	}
}

func TestGatewayAcceptsAllowlistedToolCallsAndReplaysDeepCopy(t *testing.T) {
	gateway, adapter, ledger := newHardeningGateway(t, GatewayConfig{})
	adapter.response = NormalizedResponse{
		ToolCalls: []ToolCall{{ID: "call-1", Name: "repo.read", Arguments: json.RawMessage(`{"path":"README.md"}`)}},
		Usage:     Usage{InputTokens: 2, OutputTokens: 1, CostMicros: 3},
	}
	request := hardeningRequest("native-tool-call")
	request.Tools = []ToolDefinition{{Name: "repo.read", Schema: json.RawMessage(`{"type":"object"}`)}}
	request.ResponseSchema = json.RawMessage(`{"type":"object","required":["ok"]}`)
	request.ResponseSemanticValidator = func(json.RawMessage) error {
		return errors.New("tool calls must not run final-content validation")
	}
	options := GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "native-tool-reservation", MaxAttempts: 1}

	response, err := gateway.Generate(context.Background(), request, options)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Content) != 0 || len(response.ToolCalls) != 1 || response.ToolCalls[0].Name != "repo.read" {
		t.Fatalf("response = %#v", response)
	}
	expectedArguments := string(response.ToolCalls[0].Arguments)
	expectedDigest := responseOutputDigest(response)
	response.ToolCalls[0].Arguments[0] = '['

	replayed, err := gateway.Generate(context.Background(), request, options)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.Calls() != 1 || string(replayed.ToolCalls[0].Arguments) != expectedArguments {
		t.Fatalf("replay = %#v, provider calls = %d", replayed, adapter.Calls())
	}
	call, found := ledger.ModelCall("tenant", request.RequestID)
	if !found || call.OutputSHA256 != expectedDigest {
		t.Fatalf("model call = %#v, found = %t", call, found)
	}
}

func TestGatewayValidatesNativeToolCallBoundary(t *testing.T) {
	request := hardeningRequest("tool-validation")
	request.Tools = []ToolDefinition{{Name: "repo.read", Schema: json.RawMessage(`{"type":"object"}`)}}
	validCall := ToolCall{ID: "call-1", Name: "repo.read", Arguments: json.RawMessage(`{"path":"README.md"}`)}
	credential := "sk-" + strings.Repeat("x", 20)
	for _, test := range []struct {
		name     string
		response NormalizedResponse
		expected error
	}{
		{name: "content and calls", response: NormalizedResponse{Content: json.RawMessage(`{"ok":true}`), ToolCalls: []ToolCall{validCall}}, expected: ErrOutputSchema},
		{name: "unknown tool", response: NormalizedResponse{ToolCalls: []ToolCall{{ID: "call-1", Name: "repo.write", Arguments: json.RawMessage(`{}`)}}}, expected: ErrOutputSchema},
		{name: "credential", response: NormalizedResponse{ToolCalls: []ToolCall{{ID: "call-1", Name: "repo.read", Arguments: json.RawMessage(`{"token":"` + credential + `"}`)}}}, expected: ErrCredentialDetected},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateGeneratedResponse(request, test.response); !errors.Is(err, test.expected) {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}

func TestGatewayRejectsStreamingWithNativeTools(t *testing.T) {
	gateway, adapter, _ := newHardeningGateway(t, GatewayConfig{})
	request := hardeningRequest("streaming-tools")
	request.Tools = []ToolDefinition{{Name: "repo.read", Schema: json.RawMessage(`{"type":"object"}`)}}
	_, err := gateway.Stream(context.Background(), request, GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "streaming-tools-reservation", MaxAttempts: 1})
	if !errors.Is(err, ErrProviderNotAllowed) || adapter.StreamCalls() != 0 {
		t.Fatalf("stream error = %v, provider calls = %d", err, adapter.StreamCalls())
	}
}
