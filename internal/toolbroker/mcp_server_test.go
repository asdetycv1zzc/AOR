package toolbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/pkg/mcp"
)

type fakeMCPToolClient struct {
	started chan struct{}
	block   bool
}

func (client *fakeMCPToolClient) Initialize(context.Context) (mcp.InitializeResponse, error) {
	return mcp.InitializeResponse{ProtocolVersion: mcp.BaselineProtocolVersion, Capabilities: map[string]any{"tools": map[string]any{}}, ServerInfo: mcp.Implementation{Name: "fake", Version: "1"}}, nil
}

func (client *fakeMCPToolClient) ListTools(context.Context, string) (mcp.ToolListResult, error) {
	return mcp.ToolListResult{Tools: []mcp.Tool{{Name: "repo.read", Description: "read", InputSchema: map[string]any{"type": "object"}}}}, nil
}

func (client *fakeMCPToolClient) CallTool(ctx context.Context, _ string, _ map[string]any) (mcp.ToolCallResult, error) {
	if client.started != nil {
		select {
		case <-client.started:
		default:
			close(client.started)
		}
	}
	if client.block {
		<-ctx.Done()
		return mcp.ToolCallResult{}, ctx.Err()
	}
	return mcp.ToolCallResult{Content: []mcp.Content{{Type: "text", Text: "ok"}}}, nil
}

func (*fakeMCPToolClient) Close() error { return nil }

func testMCPServer(t *testing.T, client *fakeMCPToolClient) (*MCPServer, authn.Principal) {
	t.Helper()
	broker := New(concurrentLease{}, testPolicy{}, nil, nil, &concurrentRecorder{}, nil, time.Now)
	host, err := NewHost(broker)
	if err != nil {
		t.Fatal(err)
	}
	policy := MCPToolPolicy{Risk: RiskLow, SideEffect: SideEffectNone, FilesystemAccess: FilesystemRead, RequiresApproval: ApprovalNever, AllowedRoles: []string{"EXECUTOR"}, RateLimit: "100/s", TimeoutSeconds: 10, MaxOutputBytes: maxOutputBytes}
	if err := host.AddServerWithPolicies(context.Background(), "repository", "1.0.0", client, map[string]MCPToolPolicy{"repo.read": policy}); err != nil {
		t.Fatal(err)
	}
	server, err := NewMCPServer(MCPServerConfig{Host: host, ServerInfo: mcp.Implementation{Name: "aor-tool-broker", Version: "1"}, AllowedOrigins: []string{"https://client.example"}, RequireAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	principal := authn.Principal{ID: "agent-1", Type: authn.PrincipalAgentInstance, Role: authn.RoleExecutor, TenantID: "tenant-1", ProjectID: "project-1"}
	return server, principal
}

func TestMCPStreamableHTTPInitializeListAndCall(t *testing.T) {
	server, principal := testMCPServer(t, &fakeMCPToolClient{})
	initializeBody, _ := mcp.Request(json.RawMessage(`1`), "initialize", mcp.InitializeParams{ProtocolVersion: mcp.BaselineProtocolVersion, Capabilities: map[string]any{}, ClientInfo: mcp.Implementation{Name: "client", Version: "1"}})
	initialize := performMCPRequest(t, server, principal, initializeBody, "", "", "")
	if initialize.Code != http.StatusOK || initialize.Header().Get("MCP-Session-Id") == "" {
		t.Fatalf("initialize status=%d headers=%v body=%s", initialize.Code, initialize.Header(), initialize.Body.String())
	}
	sessionID := initialize.Header().Get("MCP-Session-Id")
	initializedBody, _ := mcp.Notification("notifications/initialized", map[string]any{})
	initialized := performMCPRequest(t, server, principal, initializedBody, sessionID, mcp.BaselineProtocolVersion, "")
	if initialized.Code != http.StatusAccepted {
		t.Fatalf("initialized status=%d body=%s", initialized.Code, initialized.Body.String())
	}
	listBody, _ := mcp.Request(json.RawMessage(`2`), "tools/list", map[string]any{})
	listed := performMCPRequest(t, server, principal, listBody, sessionID, mcp.BaselineProtocolVersion, "")
	message, err := mcp.Decode(listed.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var list mcp.ToolListResult
	if json.Unmarshal(message.Result, &list) != nil || len(list.Tools) != 1 || list.Tools[0].Name != "repo.read" {
		t.Fatalf("tools result=%s", listed.Body.String())
	}
	callBody := toolCallBody(t, 3)
	called := performMCPRequest(t, server, principal, callBody, sessionID, mcp.BaselineProtocolVersion, "")
	message, err = mcp.Decode(called.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var call mcp.ToolCallResult
	if json.Unmarshal(message.Result, &call) != nil || call.IsError || len(call.Content) != 1 || call.Content[0].Text != "ok" {
		t.Fatalf("call result=%s", called.Body.String())
	}
}

func TestMCPHTTPRejectsOriginAndMissingNegotiatedVersion(t *testing.T) {
	server, principal := testMCPServer(t, &fakeMCPToolClient{})
	initializeBody, _ := mcp.Request(json.RawMessage(`1`), "initialize", mcp.InitializeParams{ProtocolVersion: mcp.BaselineProtocolVersion, Capabilities: map[string]any{}, ClientInfo: mcp.Implementation{Name: "client", Version: "1"}})
	blocked := performMCPRequest(t, server, principal, initializeBody, "", "", "https://evil.example")
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("origin status=%d", blocked.Code)
	}
	initialized := performMCPRequest(t, server, principal, initializeBody, "", "", "")
	sessionID := initialized.Header().Get("MCP-Session-Id")
	listBody, _ := mcp.Request(json.RawMessage(`2`), "tools/list", map[string]any{})
	missingVersion := performMCPRequest(t, server, principal, listBody, sessionID, "", "")
	if missingVersion.Code != http.StatusBadRequest {
		t.Fatalf("missing version status=%d body=%s", missingVersion.Code, missingVersion.Body.String())
	}
}

func TestMCPHTTPRequiresJSONContentType(t *testing.T) {
	server, principal := testMCPServer(t, &fakeMCPToolClient{})
	body, _ := mcp.Request(json.RawMessage(`1`), "initialize", mcp.InitializeParams{ProtocolVersion: mcp.BaselineProtocolVersion, Capabilities: map[string]any{}, ClientInfo: mcp.Implementation{Name: "client", Version: "1"}})
	request := httptest.NewRequest(http.MethodPost, "https://broker.example/mcp", bytes.NewReader(body))
	request.Header.Set("Content-Type", "text/plain")
	request.Header.Set("Accept", "application/json, text/event-stream")
	ctx, err := authn.ContextWithPrincipal(request.Context(), principal)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request.WithContext(ctx))
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type status = %d", response.Code)
	}
}

func TestCallMetadataRequiresStableIdempotencyKey(t *testing.T) {
	metadata := json.RawMessage(`{"aor":{"tenantId":"tenant-1","projectId":"project-1","taskId":"task-1","policyVersion":"policy-1","budgetAccountId":"budget-1","lease":{"id":"lease-1","expiresAt":"2030-01-01T00:00:00Z","fencingToken":1}}}`)
	if _, err := callMetadata(metadata); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing idempotency key error = %v", err)
	}
}

func TestMCPCancellationStopsActiveToolCall(t *testing.T) {
	client := &fakeMCPToolClient{started: make(chan struct{}), block: true}
	server, principal := testMCPServer(t, client)
	initializeBody, _ := mcp.Request(json.RawMessage(`1`), "initialize", mcp.InitializeParams{ProtocolVersion: mcp.BaselineProtocolVersion, Capabilities: map[string]any{}, ClientInfo: mcp.Implementation{Name: "client", Version: "1"}})
	initialized := performMCPRequest(t, server, principal, initializeBody, "", "", "")
	sessionID := initialized.Header().Get("MCP-Session-Id")
	notification, _ := mcp.Notification("notifications/initialized", map[string]any{})
	_ = performMCPRequest(t, server, principal, notification, sessionID, mcp.BaselineProtocolVersion, "")
	result := make(chan *httptest.ResponseRecorder, 1)
	callBody := toolCallBody(t, 7)
	go func() {
		result <- performMCPRequest(t, server, principal, callBody, sessionID, mcp.BaselineProtocolVersion, "")
	}()
	select {
	case <-client.started:
	case <-time.After(2 * time.Second):
		t.Fatal("tool call did not start")
	}
	cancelBody, _ := mcp.Notification("notifications/cancelled", map[string]any{"requestId": 7, "reason": "test"})
	cancelled := performMCPRequest(t, server, principal, cancelBody, sessionID, mcp.BaselineProtocolVersion, "")
	if cancelled.Code != http.StatusAccepted {
		t.Fatalf("cancel status=%d", cancelled.Code)
	}
	select {
	case response := <-result:
		if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
			t.Fatalf("cancelled call status=%d body=%s", response.Code, response.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled call did not stop")
	}
}

func performMCPRequest(t *testing.T, server *MCPServer, principal authn.Principal, body []byte, sessionID, version, origin string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://broker.example/mcp", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		request.Header.Set("MCP-Session-Id", sessionID)
	}
	if version != "" {
		request.Header.Set("MCP-Protocol-Version", version)
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	ctx, err := authn.ContextWithPrincipal(request.Context(), principal)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request.WithContext(ctx))
	return response
}

func toolCallBody(t *testing.T, id int) []byte {
	t.Helper()
	params := map[string]any{
		"name":      "repo.read",
		"arguments": map[string]any{"path": "README.md"},
		"_meta": map[string]any{"aor": map[string]any{
			"idempotencyKey": "tool-call-stable-key",
			"tenantId":       "tenant-1", "projectId": "project-1", "taskId": "task-1",
			"policyVersion": "policy-1", "budgetAccountId": "budget-1",
			"lease": map[string]any{"id": "lease-1", "expiresAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "fencingToken": 1},
		}},
	}
	body, err := mcp.Request(json.RawMessage(strconv.Itoa(id)), "tools/call", params)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
