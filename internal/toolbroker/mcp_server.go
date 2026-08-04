package toolbroker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/pkg/mcp"
)

const (
	defaultSessionTTL = 60 * time.Minute
	maxToolsPage      = 100
	maxMCPSessions    = 10000
	maxSessionCalls   = 64
)

type MCPServerConfig struct {
	Host           *Host
	ServerInfo     mcp.Implementation
	Instructions   string
	AllowedOrigins []string
	RequireAuth    bool
	SessionTTL     time.Duration
	Clock          func() time.Time
}

type mcpSession struct {
	id           string
	principalKey string
	protocol     string
	initialized  bool
	expiresAt    time.Time
	activeMu     sync.Mutex
	active       map[string]context.CancelFunc
}

// MCPServer provides one endpoint for Streamable HTTP and a newline-delimited
// stdio loop. It deliberately has no unauthenticated production mode: callers
// must wrap Handler with authn.HTTPMiddleware when RequireAuth is true.
type MCPServer struct {
	host           *Host
	serverInfo     mcp.Implementation
	instructions   string
	allowedOrigins map[string]struct{}
	requireAuth    bool
	sessionTTL     time.Duration
	clock          func() time.Time
	mu             sync.Mutex
	sessions       map[string]*mcpSession
}

func NewMCPServer(config MCPServerConfig) (*MCPServer, error) {
	if config.Host == nil || !safeBrokerOpaque(config.ServerInfo.Name, 128) || !safeBrokerOpaque(config.ServerInfo.Version, 128) || config.ServerInfo.Description != "" && !safeBrokerOpaque(config.ServerInfo.Description, 4096) || config.Instructions != "" && !safeBrokerOpaque(config.Instructions, 16<<10) {
		return nil, ErrMCPConfig
	}
	if config.SessionTTL <= 0 || config.SessionTTL > 24*time.Hour {
		config.SessionTTL = defaultSessionTTL
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	origins := make(map[string]struct{}, len(config.AllowedOrigins))
	for _, origin := range config.AllowedOrigins {
		parsed, err := url.ParseRequestURI(origin)
		if err != nil || origin == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" || (parsed.Scheme != "http" && parsed.Scheme != "https") || strings.ContainsAny(origin, "\r\n\x00") {
			return nil, ErrMCPConfig
		}
		origins[origin] = struct{}{}
	}
	return &MCPServer{host: config.Host, serverInfo: config.ServerInfo, instructions: config.Instructions, allowedOrigins: origins, requireAuth: config.RequireAuth, sessionTTL: config.SessionTTL, clock: config.Clock, sessions: make(map[string]*mcpSession)}, nil
}

func (server *MCPServer) Handler() http.Handler {
	return http.HandlerFunc(server.serveHTTP)
}

func (server *MCPServer) serveHTTP(response http.ResponseWriter, request *http.Request) {
	if server == nil || request == nil {
		return
	}
	if len(request.Header.Values("Origin")) > 1 || len(request.Header.Values("MCP-Session-Id")) > 1 || len(request.Header.Values("MCP-Protocol-Version")) > 1 || len(request.Header.Values("Content-Type")) > 1 || !server.validOrigin(request.Header.Get("Origin")) {
		response.WriteHeader(http.StatusForbidden)
		return
	}
	if server.requireAuth {
		if _, ok := authn.PrincipalFromContext(request.Context()); !ok {
			response.Header().Set("WWW-Authenticate", `Bearer realm="aor-tool-broker"`)
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	switch request.Method {
	case http.MethodPost:
		server.handleHTTPPost(response, request)
	case http.MethodGet:
		server.handleHTTPGet(response, request)
	case http.MethodDelete:
		server.handleHTTPDelete(response, request)
	default:
		response.Header().Set("Allow", "POST, GET, DELETE")
		response.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (server *MCPServer) handleHTTPPost(response http.ResponseWriter, request *http.Request) {
	mediaType, _, contentTypeErr := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if contentTypeErr != nil || !strings.EqualFold(mediaType, "application/json") {
		response.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	accept := request.Header.Get("Accept")
	if !accepts(accept, "application/json") || !accepts(accept, "text/event-stream") {
		response.WriteHeader(http.StatusNotAcceptable)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, mcp.MaxMessageBytes+1))
	if err != nil || len(body) > mcp.MaxMessageBytes {
		writeHTTPErrorStatus(response, http.StatusBadRequest, nil, mcp.ParseError, "Parse error")
		return
	}
	message, err := mcp.Decode(bytes.TrimSpace(body))
	if err != nil {
		writeHTTPErrorStatus(response, http.StatusBadRequest, nil, mcp.ParseError, "Parse error")
		return
	}
	principal, _ := authn.PrincipalFromContext(request.Context())
	sessionID := request.Header.Get("MCP-Session-Id")
	if message.Method == "initialize" {
		if sessionID != "" {
			writeHTTPErrorStatus(response, http.StatusBadRequest, message.ID, mcp.InvalidRequest, "Invalid session")
			return
		}
		result, newSession, handleErr := server.initialize(request.Context(), message, principal)
		if handleErr != nil {
			writeHTTPError(response, message.ID, handleErr.code, handleErr.message)
			return
		}
		encoded, encodeErr := mcp.Response(message.ID, result)
		if encodeErr != nil {
			writeHTTPError(response, message.ID, mcp.InternalError, "Internal error")
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("MCP-Session-Id", newSession.id)
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(encoded)
		return
	}
	if sessionID == "" {
		writeHTTPErrorStatus(response, http.StatusBadRequest, message.ID, mcp.InvalidRequest, "Session required")
		return
	}
	session, sessionErr := server.getSession(sessionID, principal)
	if sessionErr != nil {
		writeHTTPErrorStatus(response, http.StatusNotFound, message.ID, sessionErr.code, sessionErr.message)
		return
	}
	if version := request.Header.Get("MCP-Protocol-Version"); version != session.protocol {
		writeHTTPErrorStatus(response, http.StatusBadRequest, message.ID, mcp.InvalidRequest, "Unsupported protocol version")
		return
	}
	if message.IsResponse() {
		response.WriteHeader(http.StatusAccepted)
		return
	}
	if message.IsNotification() {
		server.handleNotification(request.Context(), session, message)
		response.WriteHeader(http.StatusAccepted)
		return
	}
	if !session.isInitialized() && message.Method != "ping" {
		writeHTTPError(response, message.ID, mcp.InvalidRequest, "Initialization required")
		return
	}
	encoded, handleErr := server.handleRequest(request.Context(), session, principal, message)
	if handleErr != nil {
		if handleErr.code == suppressResponseCode {
			response.WriteHeader(http.StatusNoContent)
			return
		}
		writeHTTPError(response, message.ID, handleErr.code, handleErr.message)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func (server *MCPServer) handleHTTPGet(response http.ResponseWriter, request *http.Request) {
	if !accepts(request.Header.Get("Accept"), "text/event-stream") {
		response.WriteHeader(http.StatusNotAcceptable)
		return
	}
	sessionID := request.Header.Get("MCP-Session-Id")
	if sessionID == "" {
		response.Header().Set("Allow", "POST")
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	principal, _ := authn.PrincipalFromContext(request.Context())
	session, sessionErr := server.getSession(sessionID, principal)
	if sessionErr != nil {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	if version := request.Header.Get("MCP-Protocol-Version"); version != session.protocol {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	response.Header().Set("Content-Type", "text/event-stream")
	response.Header().Set("Cache-Control", "no-cache")
	response.WriteHeader(http.StatusOK)
	if flusher, ok := response.(http.Flusher); ok {
		_, _ = io.WriteString(response, ": aor-mcp\n\nretry: 1000\n\n")
		flusher.Flush()
	}
}

func (server *MCPServer) handleHTTPDelete(response http.ResponseWriter, request *http.Request) {
	sessionID := request.Header.Get("MCP-Session-Id")
	if sessionID == "" {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	principal, _ := authn.PrincipalFromContext(request.Context())
	session, sessionErr := server.getSession(sessionID, principal)
	if sessionErr != nil {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	if request.Header.Get("MCP-Protocol-Version") != mcp.BaselineProtocolVersion {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	server.mu.Lock()
	delete(server.sessions, sessionID)
	server.mu.Unlock()
	session.cancelAll()
	response.WriteHeader(http.StatusNoContent)
}

type protocolError struct {
	code    int
	message string
}

const suppressResponseCode = -32099

func (server *MCPServer) initialize(ctx context.Context, message mcp.Message, principal authn.Principal) (mcp.InitializeResponse, *mcpSession, *protocolError) {
	if !message.IsRequest() {
		return mcp.InitializeResponse{}, nil, &protocolError{mcp.InvalidRequest, "initialize requires an id"}
	}
	var params mcp.InitializeParams
	if err := mcp.ParseParams(message, &params); err != nil || mcp.ValidateInitialize(params) != nil {
		return mcp.InitializeResponse{}, nil, &protocolError{mcp.InvalidParams, "Invalid initialize parameters"}
	}
	negotiated, err := mcp.Negotiate(mcp.InitializeRequest{ProtocolVersion: params.ProtocolVersion}, mcp.ServerProfile{SupportedProtocolVersions: []string{mcp.BaselineProtocolVersion}})
	if err != nil {
		return mcp.InitializeResponse{}, nil, &protocolError{mcp.InvalidRequest, "Unsupported protocol version"}
	}
	if ctx == nil {
		return mcp.InitializeResponse{}, nil, &protocolError{mcp.InternalError, "Internal error"}
	}
	sessionID, err := newSessionID()
	if err != nil {
		return mcp.InitializeResponse{}, nil, &protocolError{mcp.InternalError, "Internal error"}
	}
	now := server.clock().UTC()
	session := &mcpSession{id: sessionID, principalKey: mcpPrincipalKey(principal), protocol: negotiated.ProtocolVersion, expiresAt: now.Add(server.sessionTTL), active: make(map[string]context.CancelFunc)}
	if !server.registerSession(session) {
		return mcp.InitializeResponse{}, nil, &protocolError{mcp.InternalError, "Session capacity reached"}
	}
	return mcp.InitializeResponse{ProtocolVersion: negotiated.ProtocolVersion, Capabilities: map[string]any{"tools": map[string]any{"listChanged": false}}, ServerInfo: server.serverInfo, Instructions: server.instructions}, session, nil
}

func (server *MCPServer) handleNotification(ctx context.Context, session *mcpSession, message mcp.Message) {
	switch message.Method {
	case "notifications/initialized":
		session.activeMu.Lock()
		session.initialized = true
		session.activeMu.Unlock()
	case "notifications/cancelled":
		var params struct {
			RequestID json.RawMessage `json:"requestId"`
			Reason    string          `json:"reason,omitempty"`
		}
		if mcp.ParseParams(message, &params) != nil || len(params.RequestID) == 0 {
			return
		}
		key := string(params.RequestID)
		session.activeMu.Lock()
		cancel := session.active[key]
		delete(session.active, key)
		session.activeMu.Unlock()
		if cancel != nil {
			cancel()
		}
	case "notifications/tools/list_changed":
		// The host currently has a static registry; accepting this notification
		// keeps an upstream client's optional notification harmless.
	default:
		_ = ctx
	}
}

func (server *MCPServer) handleRequest(ctx context.Context, session *mcpSession, principal authn.Principal, message mcp.Message) ([]byte, *protocolError) {
	switch message.Method {
	case "ping":
		encoded, err := mcp.Response(message.ID, map[string]any{})
		if err != nil {
			return nil, &protocolError{mcp.InternalError, "Internal error"}
		}
		return encoded, nil
	case "tools/list":
		return server.toolsList(message)
	case "tools/call":
		return server.toolsCall(ctx, session, principal, message)
	default:
		return nil, &protocolError{mcp.MethodNotFound, "Method not found"}
	}
}

func (server *MCPServer) toolsList(message mcp.Message) ([]byte, *protocolError) {
	var params mcp.ToolListParams
	if len(message.Params) > 0 && mcp.ParseParams(message, &params) != nil {
		return nil, &protocolError{mcp.InvalidParams, "Invalid tools/list parameters"}
	}
	tools := server.host.Tools()
	start := 0
	if params.Cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(params.Cursor)
		if err != nil || len(decoded) < 2 || string(decoded[:1]) != "i" || parseDecimal(decoded[1:]) < 0 {
			return nil, &protocolError{mcp.InvalidParams, "Invalid cursor"}
		}
		start = parseDecimal(decoded[1:])
	}
	if start > len(tools) {
		return nil, &protocolError{mcp.InvalidParams, "Invalid cursor"}
	}
	end := start + maxToolsPage
	if end > len(tools) {
		end = len(tools)
	}
	result := mcp.ToolListResult{Tools: tools[start:end]}
	if end < len(tools) {
		result.NextCursor = base64.RawURLEncoding.EncodeToString([]byte("i" + fmt.Sprint(end)))
	}
	encoded, err := mcp.Response(message.ID, result)
	if err != nil {
		return nil, &protocolError{mcp.InternalError, "Internal error"}
	}
	return encoded, nil
}

func (server *MCPServer) toolsCall(ctx context.Context, session *mcpSession, principal authn.Principal, message mcp.Message) ([]byte, *protocolError) {
	var raw map[string]json.RawMessage
	if len(message.Params) == 0 || json.Unmarshal(message.Params, &raw) != nil {
		return nil, &protocolError{mcp.InvalidParams, "Invalid tools/call parameters"}
	}
	var name string
	if json.Unmarshal(raw["name"], &name) != nil || !mcp.ValidateToolName(name) {
		return nil, &protocolError{mcp.InvalidParams, "Invalid tool name"}
	}
	arguments := map[string]any{}
	if value, exists := raw["arguments"]; exists {
		if json.Unmarshal(value, &arguments) != nil || arguments == nil {
			return nil, &protocolError{mcp.InvalidParams, "Invalid tool arguments"}
		}
	}
	metadata, err := callMetadata(raw["_meta"])
	if err != nil {
		return nil, &protocolError{mcp.InvalidParams, "Tool authorization metadata required"}
	}
	if principal.TenantID != "" && principal.TenantID != metadata.TenantID || principal.ProjectID != "" && principal.ProjectID != metadata.ProjectID {
		return nil, &protocolError{mcp.InvalidParams, "Tool scope rejected"}
	}
	version, ok := server.host.Version(name)
	if !ok {
		return nil, &protocolError{mcp.InvalidParams, "Unknown tool"}
	}
	toolRequest := ToolRequest{RequestID: metadata.IdempotencyKey, TenantID: metadata.TenantID, ProjectID: metadata.ProjectID, TaskID: metadata.TaskID, Principal: Principal{ID: principal.ID, Type: string(principal.Type), Role: principal.Role}, Lease: metadata.Lease, Approval: metadata.Approval, ToolID: name, Version: version, PolicyVersion: metadata.PolicyVersion, BudgetAccountID: metadata.BudgetAccountID}
	parameters, marshalErr := json.Marshal(arguments)
	if marshalErr != nil || len(parameters) > maxInputBytes {
		return nil, &protocolError{mcp.InvalidParams, "Tool arguments too large"}
	}
	toolRequest.Parameters = parameters
	callCtx, cancel := context.WithCancel(ctx)
	key := string(message.ID)
	session.activeMu.Lock()
	if len(session.active) >= maxSessionCalls {
		session.activeMu.Unlock()
		cancel()
		return nil, &protocolError{mcp.InternalError, "Too many active requests"}
	}
	if _, exists := session.active[key]; exists {
		session.activeMu.Unlock()
		cancel()
		return nil, &protocolError{mcp.InvalidRequest, "Duplicate request id"}
	}
	session.active[key] = cancel
	session.activeMu.Unlock()
	defer func() {
		session.activeMu.Lock()
		delete(session.active, key)
		session.activeMu.Unlock()
		cancel()
	}()
	result, invokeErr := server.host.Invoke(callCtx, toolRequest)
	if invokeErr != nil {
		if errors.Is(invokeErr, context.Canceled) {
			return nil, &protocolError{code: suppressResponseCode}
		}
		if errors.Is(invokeErr, ErrUnknownTool) || errors.Is(invokeErr, ErrInvalidRequest) || errors.Is(invokeErr, ErrIdempotencyConflict) {
			return nil, &protocolError{mcp.InvalidParams, "Tool invocation rejected"}
		}
		encoded, encodeErr := mcp.Response(message.ID, mcp.ToolCallResult{Content: []mcp.Content{{Type: "text", Text: "Tool invocation failed"}}, IsError: true})
		if encodeErr != nil {
			return nil, &protocolError{mcp.InternalError, "Internal error"}
		}
		return encoded, nil
	}
	response := toolResultResponse(result)
	encoded, encodeErr := mcp.Response(message.ID, response)
	if encodeErr != nil {
		return nil, &protocolError{mcp.InternalError, "Internal error"}
	}
	return encoded, nil
}

type callAuthMetadata struct {
	IdempotencyKey  string
	TenantID        string
	ProjectID       string
	TaskID          string
	PolicyVersion   string
	BudgetAccountID string
	Lease           Lease
	Approval        *Approval
}

func callMetadata(raw json.RawMessage) (callAuthMetadata, error) {
	if len(raw) == 0 {
		return callAuthMetadata{}, ErrInvalidRequest
	}
	var envelope struct {
		AOR map[string]json.RawMessage `json:"aor"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.AOR == nil {
		return callAuthMetadata{}, ErrInvalidRequest
	}
	readString := func(key string) (string, error) {
		var value string
		if json.Unmarshal(envelope.AOR[key], &value) != nil || value == "" || len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
			return "", ErrInvalidRequest
		}
		return value, nil
	}
	idempotencyKey, err := readString("idempotencyKey")
	if err != nil {
		return callAuthMetadata{}, err
	}
	tenant, err := readString("tenantId")
	if err != nil {
		return callAuthMetadata{}, err
	}
	project, err := readString("projectId")
	if err != nil {
		return callAuthMetadata{}, err
	}
	task, err := readString("taskId")
	if err != nil {
		return callAuthMetadata{}, err
	}
	policyVersion, err := readString("policyVersion")
	if err != nil {
		return callAuthMetadata{}, err
	}
	budget, err := readString("budgetAccountId")
	if err != nil {
		return callAuthMetadata{}, err
	}
	var lease Lease
	if json.Unmarshal(envelope.AOR["lease"], &lease) != nil || lease.ID == "" || lease.ExpiresAt == "" || lease.FencingToken < 1 {
		return callAuthMetadata{}, ErrInvalidRequest
	}
	var approval *Approval
	if value := envelope.AOR["approval"]; len(value) > 0 && string(value) != "null" {
		var parsed Approval
		if json.Unmarshal(value, &parsed) != nil {
			return callAuthMetadata{}, ErrInvalidRequest
		}
		approval = &parsed
	}
	return callAuthMetadata{IdempotencyKey: idempotencyKey, TenantID: tenant, ProjectID: project, TaskID: task, PolicyVersion: policyVersion, BudgetAccountID: budget, Lease: lease, Approval: approval}, nil
}

func toolResultResponse(result ToolResult) mcp.ToolCallResult {
	if result.Artifact != nil {
		return mcp.ToolCallResult{Content: []mcp.Content{{Type: "resource_link", URI: result.Artifact.URI, Name: "tool-output", MIMEType: result.Artifact.MediaType}}, IsError: false}
	}
	var response mcp.ToolCallResult
	if json.Unmarshal(result.Output, &response) != nil {
		response.Content = []mcp.Content{{Type: "text", Text: string(result.Output)}}
	}
	return response
}

func (server *MCPServer) getSession(id string, principal authn.Principal) (*mcpSession, *protocolError) {
	if !validSessionID(id) {
		return nil, &protocolError{mcp.InvalidRequest, "Invalid session"}
	}
	server.mu.Lock()
	session, ok := server.sessions[id]
	expired := false
	if ok && !server.clock().UTC().Before(session.expiresAt) {
		delete(server.sessions, id)
		ok = false
		expired = true
	}
	server.mu.Unlock()
	if expired {
		session.cancelAll()
	}
	if !ok || session.principalKey != mcpPrincipalKey(principal) {
		return nil, &protocolError{mcp.InvalidRequest, "Invalid session"}
	}
	return session, nil
}

func (server *MCPServer) validOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	_, ok := server.allowedOrigins[origin]
	return ok
}

func (server *MCPServer) ServeStdio(ctx context.Context, reader io.Reader, writer io.Writer, principal authn.Principal) error {
	if server == nil || ctx == nil || reader == nil || writer == nil {
		return ErrMCPConfig
	}
	contextWithPrincipal, err := authn.ContextWithPrincipal(ctx, principal)
	if err != nil && server.requireAuth {
		return err
	}
	if contextWithPrincipal == nil {
		contextWithPrincipal = ctx
	}
	runCtx, stop := context.WithCancel(contextWithPrincipal)
	var session *mcpSession
	writerMu := sync.Mutex{}
	writeMessage := func(data []byte) error {
		writerMu.Lock()
		defer writerMu.Unlock()
		_, err := writer.Write(append(data, '\n'))
		return err
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), mcp.MaxMessageBytes)
	var active sync.WaitGroup
	defer func() {
		stop()
		if session != nil {
			session.cancelAll()
		}
		active.Wait()
	}()
	for scanner.Scan() {
		message, decodeErr := mcp.Decode(bytes.TrimSpace(scanner.Bytes()))
		if decodeErr != nil {
			encoded, _ := mcp.ErrorResponse(nil, mcp.ParseError, "Parse error", nil)
			if err := writeMessage(encoded); err != nil {
				return err
			}
			continue
		}
		if message.Method == "initialize" {
			if session != nil {
				encoded, _ := mcp.ErrorResponse(message.ID, mcp.InvalidRequest, "Already initialized", nil)
				if err := writeMessage(encoded); err != nil {
					return err
				}
				continue
			}
			result, newSession, protocolErr := server.initialize(runCtx, message, principal)
			if protocolErr != nil {
				encoded, _ := mcp.ErrorResponse(message.ID, protocolErr.code, protocolErr.message, nil)
				if err := writeMessage(encoded); err != nil {
					return err
				}
				continue
			}
			session = newSession
			server.mu.Lock()
			delete(server.sessions, newSession.id)
			server.mu.Unlock()
			encoded, _ := mcp.Response(message.ID, result)
			if err := writeMessage(encoded); err != nil {
				return err
			}
			continue
		}
		if message.IsNotification() {
			if session != nil {
				server.handleNotification(runCtx, session, message)
			}
			continue
		}
		if session == nil || !session.isInitialized() && message.Method != "ping" {
			encoded, _ := mcp.ErrorResponse(message.ID, mcp.InvalidRequest, "Initialization required", nil)
			if err := writeMessage(encoded); err != nil {
				return err
			}
			continue
		}
		currentSession := session
		active.Add(1)
		go func(request mcp.Message, requestSession *mcpSession) {
			defer active.Done()
			encoded, protocolErr := server.handleRequest(runCtx, requestSession, principal, request)
			if protocolErr != nil {
				if protocolErr.code == suppressResponseCode {
					return
				}
				encoded, _ = mcp.ErrorResponse(request.ID, protocolErr.code, protocolErr.message, nil)
			}
			_ = writeMessage(encoded)
		}(message, currentSession)
	}
	return scanner.Err()
}

func accepts(value, expected string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]), expected) {
			return true
		}
	}
	return false
}

func writeHTTPError(response http.ResponseWriter, id json.RawMessage, code int, message string) {
	writeHTTPErrorStatus(response, http.StatusOK, id, code, message)
}

func writeHTTPErrorStatus(response http.ResponseWriter, status int, id json.RawMessage, code int, message string) {
	encoded, err := mcp.ErrorResponse(id, code, message, nil)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

func (session *mcpSession) isInitialized() bool {
	session.activeMu.Lock()
	defer session.activeMu.Unlock()
	return session.initialized
}

func (session *mcpSession) cancelAll() {
	session.activeMu.Lock()
	cancellations := make([]context.CancelFunc, 0, len(session.active))
	for key, cancel := range session.active {
		cancellations = append(cancellations, cancel)
		delete(session.active, key)
	}
	session.activeMu.Unlock()
	for _, cancel := range cancellations {
		cancel()
	}
}

func (server *MCPServer) registerSession(session *mcpSession) bool {
	server.mu.Lock()
	expired := make([]*mcpSession, 0)
	now := server.clock().UTC()
	for id, candidate := range server.sessions {
		if !now.Before(candidate.expiresAt) {
			delete(server.sessions, id)
			expired = append(expired, candidate)
		}
	}
	if len(server.sessions) >= maxMCPSessions {
		server.mu.Unlock()
		for _, candidate := range expired {
			candidate.cancelAll()
		}
		return false
	}
	server.sessions[session.id] = session
	server.mu.Unlock()
	for _, candidate := range expired {
		candidate.cancelAll()
	}
	return true
}

func newSessionID() (string, error) {
	buffer := make([]byte, 24)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func parseDecimal(value []byte) int {
	if len(value) == 0 || len(value) > 8 {
		return -1
	}
	result := 0
	for _, character := range value {
		if character < '0' || character > '9' {
			return -1
		}
		result = result*10 + int(character-'0')
		if result > 10000000 {
			return -1
		}
	}
	return result
}

func mcpPrincipalKey(principal authn.Principal) string {
	return principal.Issuer + "\x00" + string(principal.Type) + "\x00" + principal.ID + "\x00" + principal.Role + "\x00" + principal.TenantID + "\x00" + principal.ProjectID
}
