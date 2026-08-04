package toolbroker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/mcp"
)

type staticMCPClient struct {
	tools  []mcp.Tool
	result mcp.ToolCallResult
}

func (client *staticMCPClient) Initialize(context.Context) (mcp.InitializeResponse, error) {
	return mcp.InitializeResponse{ProtocolVersion: mcp.BaselineProtocolVersion, Capabilities: map[string]any{"tools": map[string]any{}}, ServerInfo: mcp.Implementation{Name: "static", Version: "1"}}, nil
}

func (client *staticMCPClient) ListTools(context.Context, string) (mcp.ToolListResult, error) {
	return mcp.ToolListResult{Tools: client.tools}, nil
}

func (client *staticMCPClient) CallTool(context.Context, string, map[string]any) (mcp.ToolCallResult, error) {
	return client.result, nil
}

func (*staticMCPClient) Close() error { return nil }

func TestHostRejectsDuplicateToolsWithoutPartialRegistration(t *testing.T) {
	broker := New(concurrentLease{}, testPolicy{}, nil, nil, &concurrentRecorder{}, nil, time.Now)
	host, err := NewHost(broker)
	if err != nil {
		t.Fatal(err)
	}
	tool := mcp.Tool{Name: "repo.read", InputSchema: map[string]any{"type": "object"}}
	client := &staticMCPClient{tools: []mcp.Tool{tool, tool}}
	if err := host.AddServer(context.Background(), "repository", "1.0.0", client); !errors.Is(err, ErrMCPConfig) {
		t.Fatalf("duplicate tools error = %v", err)
	}
	if descriptors := broker.List(); len(descriptors) != 0 {
		t.Fatalf("partial descriptors = %#v", descriptors)
	}
}

func TestHostRequiresObjectSchemasAndValidatesStructuredOutput(t *testing.T) {
	broker := New(concurrentLease{}, testPolicy{}, nil, nil, &concurrentRecorder{}, nil, time.Now)
	host, err := NewHost(broker)
	if err != nil {
		t.Fatal(err)
	}
	invalid := &staticMCPClient{tools: []mcp.Tool{{Name: "invalid", InputSchema: map[string]any{"type": "string"}}}}
	if err := host.AddServer(context.Background(), "invalid-server", "1.0.0", invalid); !errors.Is(err, ErrMCPConfig) {
		t.Fatalf("non-object input schema error = %v", err)
	}

	tool := mcp.Tool{Name: "repo.read", InputSchema: map[string]any{"type": "object"}, OutputSchema: map[string]any{"type": "object", "required": []any{"value"}, "properties": map[string]any{"value": map[string]any{"type": "string"}}}}
	client := &staticMCPClient{tools: []mcp.Tool{tool}, result: mcp.ToolCallResult{Content: []mcp.Content{{Type: "text", Text: "bad"}}, StructuredContent: map[string]any{"value": 42}}}
	policy := MCPToolPolicy{Risk: RiskLow, SideEffect: SideEffectNone, FilesystemAccess: FilesystemRead, RequiresApproval: ApprovalNever, AllowedRoles: []string{"EXECUTOR"}, RateLimit: "10/s", TimeoutSeconds: 10, MaxOutputBytes: maxOutputBytes}
	if err := host.AddServerWithPolicies(context.Background(), "repository", "1.0.0", client, map[string]MCPToolPolicy{"repo.read": policy}); err != nil {
		t.Fatal(err)
	}
	request := request()
	request.ToolID = "repo.read"
	request.Version = "1.0.0"
	if _, err := host.Invoke(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid structured output error = %v", err)
	}
}
