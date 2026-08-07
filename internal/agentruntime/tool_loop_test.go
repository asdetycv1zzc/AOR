package agentruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/toolbroker"
)

func TestRunToolLoopUsesDeclaredConversationAndBoundaries(t *testing.T) {
	clock := &mutableClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	authority := &fakeAuthority{clock: clock}
	gateway := &scriptedToolGateway{responses: []modelgateway.NormalizedResponse{
		{ToolCalls: []modelgateway.ToolCall{{ID: "call-1", Name: "repo.read", Arguments: json.RawMessage(`{"path":"README.md"}`)}}},
		{Content: json.RawMessage(`{"intent":"SUBMIT_IMPLEMENTATION"}`)},
	}}
	broker := &recordingToolBroker{result: toolbroker.ToolResult{InvocationID: "inv-1", Output: []byte(`{"content":"read result"}`), TrustLevel: "UNTRUSTED"}}
	runtime := newTestRuntime(t, clock, authority, gateway, broker)
	declaration := testDeclaration(RoleExecutor)
	startRun(t, runtime, declaration, testLease(clock.Now(), declaration))

	authority.mu.Lock()
	baselineValidations := len(authority.calls)
	authority.mu.Unlock()
	response, err := runtime.RunToolLoop(context.Background(), declaration.RunID, toolLoopTestCall(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Content) != `{"intent":"SUBMIT_IMPLEMENTATION"}` || len(response.ToolCalls) != 0 {
		t.Fatalf("final response = %#v", response)
	}
	requests, options := gateway.Captured()
	if len(requests) != 2 || len(options) != 2 {
		t.Fatalf("gateway calls = %d", len(requests))
	}
	for index, request := range requests {
		if request.ResponseSchemaRef != "" || len(request.ResponseSchema) != 0 || request.ResponseSemanticValidator != nil {
			t.Fatalf("tool round %d retained final response schema", index)
		}
	}
	runtime.mu.RLock()
	declaredMessages := cloneMessages(runtime.runs[declaration.RunID].prompt.Messages)
	runtime.mu.RUnlock()
	if !reflect.DeepEqual(requests[0].Messages, declaredMessages) {
		t.Fatal("first model call did not start from the declared prompt")
	}
	continued := requests[1].Messages
	if len(continued) != len(requests[0].Messages)+2 {
		t.Fatalf("continued messages = %#v", continued)
	}
	assistant, toolResult := continued[len(continued)-2], continued[len(continued)-1]
	if assistant.Role != "assistant" || len(assistant.ToolCalls) != 1 || assistant.ToolCalls[0].ID != "call-1" || assistant.ToolCalls[0].Name != "repo.read" || string(assistant.ToolCalls[0].Arguments) != `{"path":"README.md"}` {
		t.Fatalf("assistant message = %#v", assistant)
	}
	if toolResult.Role != "tool" || toolResult.ToolCallID != "call-1" || toolResult.Content != `{"content":"read result"}` {
		t.Fatalf("tool message = %#v", toolResult)
	}
	if requests[0].RequestID != "req-loop" || requests[1].RequestID != "req-loop.2" || options[0].ReservationID != "res-loop" || options[1].ReservationID != "res-loop.2" {
		t.Fatalf("round identifiers = %#v / %#v", requests, options)
	}
	toolRequests := broker.Captured()
	if len(toolRequests) != 1 || toolRequests[0].RequestID != "call-1" || toolRequests[0].ToolID != "repo.read" || toolRequests[0].Version != "1" || string(toolRequests[0].Parameters) != `{"path":"README.md"}` {
		t.Fatalf("tool requests = %#v", toolRequests)
	}
	authority.mu.Lock()
	validations := append([]LeaseOperation(nil), authority.calls[baselineValidations:]...)
	authority.mu.Unlock()
	expectedValidations := []LeaseOperation{
		LeaseOperationModel, LeaseOperationModel, LeaseOperationResult,
		LeaseOperationTool, LeaseOperationTool, LeaseOperationResult,
		LeaseOperationModel, LeaseOperationModel, LeaseOperationResult,
	}
	if !reflect.DeepEqual(validations, expectedValidations) {
		t.Fatalf("lease validations = %#v", validations)
	}
	if snapshot := runtime.slots.(*SlotPool).Snapshot(); snapshot.Active != 0 {
		t.Fatalf("active slots = %#v", snapshot)
	}
}

func TestRunToolLoopFailsClosed(t *testing.T) {
	validCall := func(id, name string) modelgateway.NormalizedResponse {
		return modelgateway.NormalizedResponse{ToolCalls: []modelgateway.ToolCall{{ID: id, Name: name, Arguments: json.RawMessage(`{"path":"README.md"}`)}}}
	}
	tests := []struct {
		name         string
		responses    []modelgateway.NormalizedResponse
		result       toolbroker.ToolResult
		maxRounds    int
		expected     error
		gatewayCalls int
		brokerCalls  int
	}{
		{name: "unknown tool", responses: []modelgateway.NormalizedResponse{validCall("call-1", "repo.write")}, maxRounds: 1, expected: toolbroker.ErrUnknownTool, gatewayCalls: 1},
		{name: "repeated call id", responses: []modelgateway.NormalizedResponse{validCall("call-1", "repo.read"), validCall("call-1", "repo.read")}, result: validLoopToolResult(), maxRounds: 2, expected: modelgateway.ErrOutputSchema, gatewayCalls: 2, brokerCalls: 1},
		{name: "rounds exhausted", responses: []modelgateway.NormalizedResponse{validCall("call-1", "repo.read"), validCall("call-2", "repo.read")}, result: validLoopToolResult(), maxRounds: 1, expected: ErrToolRoundsExhausted, gatewayCalls: 2, brokerCalls: 1},
		{name: "empty result", responses: []modelgateway.NormalizedResponse{validCall("call-1", "repo.read")}, result: toolbroker.ToolResult{}, maxRounds: 1, expected: ErrToolResultInvalid, gatewayCalls: 1, brokerCalls: 1},
		{name: "oversized result", responses: []modelgateway.NormalizedResponse{validCall("call-1", "repo.read")}, result: toolbroker.ToolResult{Output: bytes.Repeat([]byte("0"), modelgateway.MaximumToolResultBytes+1)}, maxRounds: 1, expected: ErrToolResultInvalid, gatewayCalls: 1, brokerCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := &mutableClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
			gateway := &scriptedToolGateway{responses: test.responses}
			broker := &recordingToolBroker{result: test.result}
			runtime := newTestRuntime(t, clock, &fakeAuthority{clock: clock}, gateway, broker)
			declaration := testDeclaration(RoleExecutor)
			startRun(t, runtime, declaration, testLease(clock.Now(), declaration))

			_, err := runtime.RunToolLoop(context.Background(), declaration.RunID, toolLoopTestCall(), test.maxRounds)
			if !errors.Is(err, test.expected) {
				t.Fatalf("error = %v", err)
			}
			if gateway.Calls() != test.gatewayCalls || broker.Calls() != test.brokerCalls {
				t.Fatalf("calls = gateway %d, broker %d", gateway.Calls(), broker.Calls())
			}
			if snapshot := runtime.slots.(*SlotPool).Snapshot(); snapshot.Active != 0 {
				t.Fatalf("active slots = %#v", snapshot)
			}
		})
	}
}

func TestDeclarationRequiresNativeToolVersion(t *testing.T) {
	clock := &mutableClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	runtime := newTestRuntime(t, clock, &fakeAuthority{clock: clock}, &scriptedToolGateway{}, &recordingToolBroker{})
	declaration := testDeclaration(RoleExecutor)
	declaration.Tools[0].Version = ""
	declaration.ToolSchemaDigest = DigestToolDefinitions(declaration.Tools)
	if err := runtime.Declare(declaration); !errors.Is(err, ErrInvalidDeclaration) {
		t.Fatalf("declare error = %v", err)
	}
}

func toolLoopTestCall() ModelCall {
	return ModelCall{RequestID: "req-loop", Provider: "provider", Model: "model", ReservationID: "res-loop", MaxOutputTokens: 128, ProviderPolicy: "default", CachePolicy: "local", MaxAttempts: 1}
}

func validLoopToolResult() toolbroker.ToolResult {
	return toolbroker.ToolResult{InvocationID: "inv-1", Output: []byte(`{"ok":true}`), TrustLevel: "UNTRUSTED"}
}

type scriptedToolGateway struct {
	mu        sync.Mutex
	responses []modelgateway.NormalizedResponse
	requests  []modelgateway.NormalizedRequest
	options   []modelgateway.GenerateOptions
}

func (g *scriptedToolGateway) Generate(_ context.Context, request modelgateway.NormalizedRequest, options modelgateway.GenerateOptions) (modelgateway.NormalizedResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	request.Messages = cloneMessages(request.Messages)
	g.requests = append(g.requests, request)
	g.options = append(g.options, options)
	if len(g.requests) > len(g.responses) {
		return modelgateway.NormalizedResponse{}, errors.New("unexpected model call")
	}
	return g.responses[len(g.requests)-1], nil
}

func (g *scriptedToolGateway) Captured() ([]modelgateway.NormalizedRequest, []modelgateway.GenerateOptions) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]modelgateway.NormalizedRequest(nil), g.requests...), append([]modelgateway.GenerateOptions(nil), g.options...)
}

func (g *scriptedToolGateway) Calls() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.requests)
}

type recordingToolBroker struct {
	mu       sync.Mutex
	result   toolbroker.ToolResult
	requests []toolbroker.ToolRequest
}

func (b *recordingToolBroker) Invoke(_ context.Context, request toolbroker.ToolRequest) (toolbroker.ToolResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	request.Parameters = append([]byte(nil), request.Parameters...)
	b.requests = append(b.requests, request)
	return b.result, nil
}

func (b *recordingToolBroker) Captured() []toolbroker.ToolRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]toolbroker.ToolRequest(nil), b.requests...)
}

func (b *recordingToolBroker) Calls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.requests)
}
