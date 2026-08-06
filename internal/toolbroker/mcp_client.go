package toolbroker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akimisaka/aor/internal/observability"
	"github.com/akimisaka/aor/pkg/mcp"
)

const (
	maxClientResponseBytes = 1 << 20
	maxStdioLineBytes      = 1 << 20
)

type StreamableHTTPClientConfig struct {
	Endpoint     string
	AllowHTTP    bool
	Origin       string
	Timeout      time.Duration
	BearerToken  []byte
	AllowPrivate bool
}

// StreamableHTTPClient implements the MCP 2025-11-25 POST/GET transport. It
// accepts either a JSON response or a bounded SSE response and never follows
// redirects across trust boundaries.
type StreamableHTTPClient struct {
	endpoint    *url.URL
	client      *http.Client
	origin      string
	bearerToken []byte
	mu          sync.Mutex
	version     string
	sessionID   string
	sequence    atomic.Uint64
}

func NewStreamableHTTPClient(config StreamableHTTPClientConfig) (*StreamableHTTPClient, error) {
	if strings.TrimSpace(config.Endpoint) != config.Endpoint || config.Endpoint == "" {
		return nil, ErrMCPConfig
	}
	endpoint, err := url.ParseRequestURI(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path == "" {
		return nil, ErrMCPConfig
	}
	if endpoint.Scheme != "https" && !(config.AllowHTTP && endpoint.Scheme == "http") {
		return nil, ErrMCPConfig
	}
	if config.Origin != "" {
		origin, originErr := url.ParseRequestURI(config.Origin)
		if originErr != nil || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Scheme != "http" && origin.Scheme != "https") {
			return nil, ErrMCPConfig
		}
	}
	if config.Timeout <= 0 || config.Timeout > 5*time.Minute {
		config.Timeout = 30 * time.Second
	}
	if len(config.BearerToken) > 64<<10 || bytes.ContainsAny(config.BearerToken, "\r\n\x00") {
		return nil, ErrMCPConfig
	}
	httpClient := &http.Client{Timeout: config.Timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	if !config.AllowPrivate {
		parameters, marshalErr := json.Marshal(map[string]string{"url": endpoint.String()})
		if marshalErr != nil {
			return nil, ErrMCPConfig
		}
		authorizeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		bounded, boundaryErr := NewNetworkBoundary(nil, nil).Client(authorizeCtx, parameters, []string{endpoint.Scheme + "://" + endpoint.Host})
		cancel()
		if boundaryErr != nil {
			return nil, ErrMCPConfig
		}
		bounded.Timeout = config.Timeout
		if transport, ok := bounded.Transport.(*http.Transport); ok {
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			transport.TLSHandshakeTimeout = 5 * time.Second
			transport.ResponseHeaderTimeout = config.Timeout
		}
		httpClient = bounded
	}
	return &StreamableHTTPClient{endpoint: endpoint, origin: config.Origin, bearerToken: append([]byte(nil), config.BearerToken...), client: httpClient}, nil
}

func (client *StreamableHTTPClient) Initialize(ctx context.Context) (mcp.InitializeResponse, error) {
	if client == nil {
		return mcp.InitializeResponse{}, ErrMCPTransport
	}
	params := mcp.InitializeParams{ProtocolVersion: mcp.BaselineProtocolVersion, Capabilities: map[string]any{}, ClientInfo: mcp.Implementation{Name: "aor-tool-broker", Version: "1.0.0"}}
	message, err := client.request(ctx, "initialize", params, true)
	if err != nil {
		return mcp.InitializeResponse{}, err
	}
	var result mcp.InitializeResponse
	if err := decodeResult(message, &result); err != nil || result.ProtocolVersion != mcp.BaselineProtocolVersion || !hasToolsCapability(result.Capabilities) {
		return mcp.InitializeResponse{}, ErrMCPTransport
	}
	client.mu.Lock()
	client.version = result.ProtocolVersion
	client.mu.Unlock()
	if _, err := client.notification(ctx, "notifications/initialized", nil); err != nil {
		return mcp.InitializeResponse{}, err
	}
	return result, nil
}

func (client *StreamableHTTPClient) ListTools(ctx context.Context, cursor string) (mcp.ToolListResult, error) {
	client.mu.Lock()
	initialized := client.version != ""
	client.mu.Unlock()
	if !initialized {
		return mcp.ToolListResult{}, ErrMCPTransport
	}
	message, err := client.request(ctx, "tools/list", mcp.ToolListParams{Cursor: cursor}, false)
	if err != nil {
		return mcp.ToolListResult{}, err
	}
	var result mcp.ToolListResult
	if err := decodeResult(message, &result); err != nil || len(result.Tools) > 10000 {
		return mcp.ToolListResult{}, ErrMCPTransport
	}
	for _, tool := range result.Tools {
		if !mcp.ValidateToolName(tool.Name) || len(tool.InputSchema) == 0 {
			return mcp.ToolListResult{}, ErrMCPConfig
		}
	}
	return result, nil
}

func (client *StreamableHTTPClient) CallTool(ctx context.Context, name string, arguments map[string]any) (mcp.ToolCallResult, error) {
	return client.CallToolWithRequestID(ctx, name, arguments, "")
}

func (client *StreamableHTTPClient) CallToolWithRequestID(ctx context.Context, name string, arguments map[string]any, requestID string) (mcp.ToolCallResult, error) {
	if !mcp.ValidateToolName(name) || arguments == nil {
		return mcp.ToolCallResult{}, ErrMCPConfig
	}
	params := mcp.ToolCallParams{Name: name, Arguments: arguments}
	if requestID != "" {
		params.Meta = map[string]any{"aor": map[string]any{"idempotencyKey": requestID}}
	}
	message, err := client.request(ctx, "tools/call", params, false)
	if err != nil {
		return mcp.ToolCallResult{}, err
	}
	var result mcp.ToolCallResult
	if err := decodeResult(message, &result); err != nil || len(result.Content) > 4096 {
		return mcp.ToolCallResult{}, ErrMCPTransport
	}
	return result, nil
}

func (client *StreamableHTTPClient) Close() error {
	if client == nil {
		return nil
	}
	client.mu.Lock()
	for index := range client.bearerToken {
		client.bearerToken[index] = 0
	}
	client.bearerToken = nil
	client.mu.Unlock()
	return nil
}

func (client *StreamableHTTPClient) request(ctx context.Context, method string, params any, initialize bool) (mcp.Message, error) {
	if ctx == nil {
		return mcp.Message{}, ErrMCPTransport
	}
	sequence := client.sequence.Add(1)
	id := json.RawMessage(strconv.FormatUint(sequence, 10))
	body, err := mcp.Request(id, method, params)
	if err != nil {
		return mcp.Message{}, ErrMCPTransport
	}
	client.mu.Lock()
	version, sessionID := client.version, client.sessionID
	client.mu.Unlock()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return mcp.Message{}, ErrMCPTransport
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	client.injectTrace(ctx, request)
	client.setAuthorization(request)
	if client.origin != "" {
		request.Header.Set("Origin", client.origin)
	}
	if version != "" && !initialize {
		request.Header.Set("MCP-Protocol-Version", version)
	}
	if sessionID != "" && !initialize {
		request.Header.Set("MCP-Session-Id", sessionID)
	}
	finished := make(chan struct{})
	var cancellation sync.Once
	sendCancellation := func() {
		cancellation.Do(func() {
			cancelCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _ = client.notification(cancelCtx, "notifications/cancelled", map[string]any{"requestId": json.RawMessage(id), "reason": "context cancelled"})
		})
	}
	if !initialize {
		go func() {
			select {
			case <-ctx.Done():
				sendCancellation()
			case <-finished:
			}
		}()
	}
	defer close(finished)
	response, err := client.client.Do(request)
	if err != nil {
		if ctx.Err() != nil && !initialize {
			sendCancellation()
		}
		return mcp.Message{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return mcp.Message{}, fmt.Errorf("%w: HTTP status %d", ErrMCPTransport, response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maxClientResponseBytes+1))
	if err != nil || len(content) > maxClientResponseBytes {
		return mcp.Message{}, ErrMCPTransport
	}
	if session := response.Header.Get("MCP-Session-Id"); session != "" {
		if !validSessionID(session) {
			return mcp.Message{}, ErrMCPTransport
		}
		client.mu.Lock()
		client.sessionID = session
		client.mu.Unlock()
	}
	message, err := decodeHTTPMessage(response.Header.Get("Content-Type"), content)
	if err != nil {
		return mcp.Message{}, err
	}
	if !bytes.Equal(message.ID, id) {
		return mcp.Message{}, ErrMCPTransport
	}
	return message, nil
}

func (client *StreamableHTTPClient) notification(ctx context.Context, method string, params any) (mcp.Message, error) {
	body, err := mcp.Notification(method, params)
	if err != nil {
		return mcp.Message{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return mcp.Message{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	client.injectTrace(ctx, request)
	client.setAuthorization(request)
	client.mu.Lock()
	if client.version != "" {
		request.Header.Set("MCP-Protocol-Version", client.version)
	}
	if client.sessionID != "" {
		request.Header.Set("MCP-Session-Id", client.sessionID)
	}
	client.mu.Unlock()
	response, err := client.client.Do(request)
	if err != nil {
		return mcp.Message{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted && (response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices) {
		return mcp.Message{}, ErrMCPTransport
	}
	return mcp.Message{}, nil
}

func (client *StreamableHTTPClient) setAuthorization(request *http.Request) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.bearerToken) > 0 {
		request.Header.Set("Authorization", "Bearer "+string(client.bearerToken))
	}
}

func (client *StreamableHTTPClient) injectTrace(ctx context.Context, request *http.Request) {
	if trace, found := observability.TraceFromContext(ctx); found {
		_ = observability.InjectTrace(request.Header, trace)
	}
}

func decodeHTTPMessage(contentType string, content []byte) (mcp.Message, error) {
	if strings.Contains(strings.ToLower(contentType), "text/event-stream") {
		return decodeSSEMessage(content)
	}
	if !strings.Contains(strings.ToLower(contentType), "application/json") {
		return mcp.Message{}, ErrMCPTransport
	}
	return mcp.Decode(content)
}

func decodeSSEMessage(content []byte) (mcp.Message, error) {
	var data []string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 4096), maxStdioLineBytes)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimPrefix(line, "data:"))
		}
		if line == "" && len(data) > 0 {
			message, err := mcp.Decode([]byte(strings.Join(data, "\n")))
			if err == nil {
				return message, nil
			}
			data = nil
		}
	}
	if len(data) > 0 {
		return mcp.Decode([]byte(strings.Join(data, "\n")))
	}
	if err := scanner.Err(); err != nil {
		return mcp.Message{}, err
	}
	return mcp.Message{}, ErrMCPTransport
}

func decodeResult(message mcp.Message, target any) error {
	if message.Error != nil {
		return fmt.Errorf("MCP error %d", message.Error.Code)
	}
	if len(message.Result) == 0 {
		return ErrMCPTransport
	}
	decoder := json.NewDecoder(bytes.NewReader(message.Result))
	if err := decoder.Decode(target); err != nil {
		return ErrMCPTransport
	}
	return nil
}

type StdioClientConfig struct {
	Command string
	Args    []string
	Env     map[string]string
}

// StdioClient launches a local MCP server with a minimal explicit environment
// and exchanges newline-delimited JSON-RPC messages. It never writes logs to
// stdout, preserving the stdio transport framing contract.
type StdioClient struct {
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdout     *bufio.Reader
	writeMu    sync.Mutex
	callMu     sync.Mutex
	waitCh     chan error
	responses  chan mcp.Message
	readErrors chan error
	ignored    sync.Map
	seq        atomic.Uint64
	closed     atomic.Bool
}

func NewStdioClient(config StdioClientConfig) (*StdioClient, error) {
	if !filepath.IsAbs(config.Command) || config.Command == "/" || len(config.Command) > 4096 || len(config.Args) > 128 {
		return nil, ErrMCPConfig
	}
	commandInfo, err := os.Lstat(config.Command)
	if err != nil || !commandInfo.Mode().IsRegular() || commandInfo.Mode()&os.ModeSymlink != 0 || commandInfo.Mode().Perm()&0o111 == 0 {
		return nil, ErrMCPConfig
	}
	for _, arg := range config.Args {
		if len(arg) > 4096 || strings.ContainsAny(arg, "\x00\r\n") {
			return nil, ErrMCPConfig
		}
	}
	env := make([]string, 0, len(config.Env)+1)
	for key, value := range config.Env {
		if !validEnvKey(key) || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") || sensitiveEnvKey(key) {
			return nil, ErrMCPConfig
		}
		env = append(env, key+"="+value)
	}
	sort.Strings(env)
	if path := os.Getenv("PATH"); path != "" && config.Env["PATH"] == "" {
		env = append(env, "PATH="+path)
	}
	cmd := exec.Command(config.Command, config.Args...)
	cmd.Env = env
	cmd.Stderr = io.Discard
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, ErrMCPTransport
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, ErrMCPTransport
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, ErrMCPTransport
	}
	client := &StdioClient{cmd: cmd, stdin: stdin, stdout: bufio.NewReaderSize(stdout, maxStdioLineBytes+1), waitCh: make(chan error, 1), responses: make(chan mcp.Message, 16), readErrors: make(chan error, 1)}
	go func() { client.waitCh <- cmd.Wait() }()
	go client.readLoop()
	return client, nil
}

func (client *StdioClient) Initialize(ctx context.Context) (mcp.InitializeResponse, error) {
	params := mcp.InitializeParams{ProtocolVersion: mcp.BaselineProtocolVersion, Capabilities: map[string]any{}, ClientInfo: mcp.Implementation{Name: "aor-tool-broker", Version: "1.0.0"}}
	message, err := client.roundTrip(ctx, "initialize", params)
	if err != nil {
		return mcp.InitializeResponse{}, err
	}
	var result mcp.InitializeResponse
	if err := decodeResult(message, &result); err != nil || result.ProtocolVersion != mcp.BaselineProtocolVersion || !hasToolsCapability(result.Capabilities) {
		return mcp.InitializeResponse{}, ErrMCPTransport
	}
	if _, err := client.writeNotification("notifications/initialized", nil); err != nil {
		return mcp.InitializeResponse{}, err
	}
	return result, nil
}

func (client *StdioClient) ListTools(ctx context.Context, cursor string) (mcp.ToolListResult, error) {
	message, err := client.roundTrip(ctx, "tools/list", mcp.ToolListParams{Cursor: cursor})
	if err != nil {
		return mcp.ToolListResult{}, err
	}
	var result mcp.ToolListResult
	if err := decodeResult(message, &result); err != nil || len(result.Tools) > 10000 {
		return mcp.ToolListResult{}, ErrMCPTransport
	}
	for _, tool := range result.Tools {
		if !mcp.ValidateToolName(tool.Name) || len(tool.InputSchema) == 0 {
			return mcp.ToolListResult{}, ErrMCPConfig
		}
	}
	return result, nil
}

func (client *StdioClient) CallTool(ctx context.Context, name string, arguments map[string]any) (mcp.ToolCallResult, error) {
	return client.CallToolWithRequestID(ctx, name, arguments, "")
}

func (client *StdioClient) CallToolWithRequestID(ctx context.Context, name string, arguments map[string]any, requestID string) (mcp.ToolCallResult, error) {
	if !mcp.ValidateToolName(name) || arguments == nil {
		return mcp.ToolCallResult{}, ErrMCPConfig
	}
	params := mcp.ToolCallParams{Name: name, Arguments: arguments}
	if requestID != "" {
		params.Meta = map[string]any{"aor": map[string]any{"idempotencyKey": requestID}}
	}
	message, err := client.roundTrip(ctx, "tools/call", params)
	if err != nil {
		return mcp.ToolCallResult{}, err
	}
	var result mcp.ToolCallResult
	if err := decodeResult(message, &result); err != nil || len(result.Content) > 4096 {
		return mcp.ToolCallResult{}, ErrMCPTransport
	}
	return result, nil
}

func (client *StdioClient) roundTrip(ctx context.Context, method string, params any) (mcp.Message, error) {
	if client == nil || client.closed.Load() || ctx == nil {
		return mcp.Message{}, ErrMCPTransport
	}
	client.callMu.Lock()
	defer client.callMu.Unlock()
	sequence := client.seq.Add(1)
	id := json.RawMessage(strconv.FormatUint(sequence, 10))
	body, err := mcp.Request(id, method, params)
	if err != nil {
		return mcp.Message{}, err
	}
	if err := client.write(body); err != nil {
		return mcp.Message{}, err
	}
	for {
		select {
		case message := <-client.responses:
			if message.IsNotification() {
				continue
			}
			if !bytes.Equal(message.ID, id) {
				return mcp.Message{}, ErrMCPTransport
			}
			return message, nil
		case <-client.readErrors:
			return mcp.Message{}, ErrMCPTransport
		case <-ctx.Done():
			client.ignored.Store(string(id), struct{}{})
			_, _ = client.writeNotification("notifications/cancelled", map[string]any{"requestId": json.RawMessage(id), "reason": "context cancelled"})
			return mcp.Message{}, ctx.Err()
		}
	}
}

func (client *StdioClient) readLoop() {
	for {
		line, err := client.stdout.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			select {
			case client.readErrors <- mcp.ErrMessageTooLarge:
			default:
			}
			return
		}
		if err != nil {
			select {
			case client.readErrors <- err:
			default:
			}
			return
		}
		if len(line) > maxStdioLineBytes {
			select {
			case client.readErrors <- mcp.ErrMessageTooLarge:
			default:
			}
			return
		}
		message, decodeErr := mcp.Decode(bytes.TrimSpace(line))
		if decodeErr != nil {
			select {
			case client.readErrors <- decodeErr:
			default:
			}
			return
		}
		if _, ignored := client.ignored.LoadAndDelete(string(message.ID)); ignored {
			continue
		}
		select {
		case client.responses <- message:
		default:
			select {
			case client.readErrors <- ErrMCPTransport:
			default:
			}
			return
		}
	}
}

func (client *StdioClient) write(data []byte) error {
	client.writeMu.Lock()
	defer client.writeMu.Unlock()
	if client.closed.Load() {
		return ErrMCPTransport
	}
	data = append(append([]byte(nil), data...), '\n')
	_, err := client.stdin.Write(data)
	return err
}

func (client *StdioClient) writeNotification(method string, params any) (mcp.Message, error) {
	body, err := mcp.Notification(method, params)
	if err != nil {
		return mcp.Message{}, err
	}
	return mcp.Message{}, client.write(body)
}

func (client *StdioClient) Close() error {
	if client == nil || client.closed.Swap(true) {
		return nil
	}
	_ = client.stdin.Close()
	select {
	case err := <-client.waitCh:
		return err
	case <-time.After(5 * time.Second):
		return ErrMCPTransport
	}
}

func validSessionID(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validEnvKey(value string) bool {
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "=\x00\r\n") {
		return false
	}
	for _, character := range value {
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_') {
			return false
		}
	}
	return true
}

func sensitiveEnvKey(value string) bool {
	normalized := strings.ToLower(value)
	for _, fragment := range []string{"key", "token", "secret", "password", "credential"} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func hasToolsCapability(capabilities map[string]any) bool {
	value, ok := capabilities["tools"]
	if !ok {
		return false
	}
	_, ok = value.(map[string]any)
	return ok
}
