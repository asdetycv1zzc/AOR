package toolbroker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/pkg/mcp"
)

func TestStreamableHTTPClientNegotiatesAndCallsTools(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-token" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(request.Body)
		message, err := mcp.Decode(body)
		if err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if !accepts(request.Header.Get("Accept"), "application/json") || !accepts(request.Header.Get("Accept"), "text/event-stream") {
			response.WriteHeader(http.StatusNotAcceptable)
			return
		}
		if message.IsNotification() {
			response.WriteHeader(http.StatusAccepted)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		switch message.Method {
		case "initialize":
			response.Header().Set("MCP-Session-Id", "session-1")
			encoded, _ := mcp.Response(message.ID, mcp.InitializeResponse{ProtocolVersion: mcp.BaselineProtocolVersion, Capabilities: map[string]any{"tools": map[string]any{}}, ServerInfo: mcp.Implementation{Name: "server", Version: "1"}})
			_, _ = response.Write(encoded)
		case "tools/list":
			if request.Header.Get("MCP-Session-Id") != "session-1" || request.Header.Get("MCP-Protocol-Version") != mcp.BaselineProtocolVersion {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			encoded, _ := mcp.Response(message.ID, mcp.ToolListResult{Tools: []mcp.Tool{{Name: "repo.read", InputSchema: map[string]any{"type": "object"}}}})
			_, _ = response.Write(encoded)
		case "tools/call":
			encoded, _ := mcp.Response(message.ID, mcp.ToolCallResult{Content: []mcp.Content{{Type: "text", Text: "ok"}}})
			_, _ = response.Write(encoded)
		}
	}))
	defer server.Close()
	client, err := NewStreamableHTTPClient(StreamableHTTPClientConfig{Endpoint: server.URL + "/mcp", AllowHTTP: true, AllowPrivate: true, BearerToken: []byte("test-token")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	listed, err := client.ListTools(context.Background(), "")
	if err != nil || len(listed.Tools) != 1 || listed.Tools[0].Name != "repo.read" {
		t.Fatalf("list=%#v err=%v", listed, err)
	}
	result, err := client.CallTool(context.Background(), "repo.read", map[string]any{"path": "README.md"})
	if err != nil || len(result.Content) != 1 || result.Content[0].Text != "ok" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestStreamableHTTPClientSendsExplicitCancellation(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var raw json.RawMessage
		_ = json.NewDecoder(request.Body).Decode(&raw)
		message, err := mcp.Decode(raw)
		if err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if message.Method == "notifications/initialized" {
			response.WriteHeader(http.StatusAccepted)
			return
		}
		if message.Method == "notifications/cancelled" {
			select {
			case cancelled <- struct{}{}:
			default:
			}
			response.WriteHeader(http.StatusAccepted)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		if message.Method == "initialize" {
			response.Header().Set("MCP-Session-Id", "session-1")
			encoded, _ := mcp.Response(message.ID, mcp.InitializeResponse{ProtocolVersion: mcp.BaselineProtocolVersion, Capabilities: map[string]any{"tools": map[string]any{}}, ServerInfo: mcp.Implementation{Name: "server", Version: "1"}})
			_, _ = response.Write(encoded)
			return
		}
		close(started)
		<-request.Context().Done()
	}))
	defer server.Close()
	client, err := NewStreamableHTTPClient(StreamableHTTPClientConfig{Endpoint: server.URL + "/mcp", AllowHTTP: true, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.CallTool(ctx, "repo.read", map[string]any{})
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("call did not start")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled call succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("call did not stop")
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("explicit cancellation notification was not sent")
	}
}

func TestStreamableHTTPClientRejectsPrivateAndInsecureProductionEndpoints(t *testing.T) {
	for _, config := range []StreamableHTTPClientConfig{
		{Endpoint: "https://127.0.0.1/mcp"},
		{Endpoint: "https://169.254.169.254/mcp"},
		{Endpoint: "http://public.example/mcp", AllowHTTP: false},
	} {
		if _, err := NewStreamableHTTPClient(config); err == nil {
			t.Fatalf("endpoint %s was accepted", config.Endpoint)
		}
	}
}

func TestStdioClientNegotiatesLineDelimitedMCP(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewStdioClient(StdioClientConfig{Command: executable, Args: []string{"-test.run=TestMCPStdioHelperProcess"}, Env: map[string]string{"GO_WANT_MCP_HELPER": "1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	listed, err := client.ListTools(context.Background(), "")
	if err != nil || len(listed.Tools) != 0 {
		t.Fatalf("list=%#v err=%v", listed, err)
	}
}

func TestMCPStdioHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_MCP_HELPER") != "1" {
		return
	}
	broker := New(concurrentLease{}, testPolicy{}, &testExecutor{output: []byte(`{}`)}, nil, &testRecorder{}, nil, time.Now)
	host, err := NewHost(broker)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewMCPServer(MCPServerConfig{Host: host, ServerInfo: mcp.Implementation{Name: "stdio-helper", Version: "1"}, RequireAuth: false})
	if err != nil {
		t.Fatal(err)
	}
	principal := authn.Principal{ID: "service-1", Type: authn.PrincipalService, Role: authn.RoleService}
	if err := server.ServeStdio(context.Background(), os.Stdin, os.Stdout, principal); err != nil {
		t.Fatal(err)
	}
}
