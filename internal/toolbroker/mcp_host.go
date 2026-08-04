package toolbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/akimisaka/aor/pkg/mcp"
)

var (
	ErrMCPConfig    = errors.New("invalid MCP configuration")
	ErrMCPTransport = errors.New("MCP transport unavailable")
)

// MCPToolClient is the small transport-neutral client contract used by the
// broker host. Implementations are Streamable HTTP and stdio clients.
type MCPToolClient interface {
	Initialize(context.Context) (mcp.InitializeResponse, error)
	ListTools(context.Context, string) (mcp.ToolListResult, error)
	CallTool(context.Context, string, map[string]any) (mcp.ToolCallResult, error)
	Close() error
}

type mcpRequestIDToolClient interface {
	CallToolWithRequestID(context.Context, string, map[string]any, string) (mcp.ToolCallResult, error)
}

type remoteTool struct {
	serverID string
	version  string
	client   MCPToolClient
	tool     mcp.Tool
}

// MCPToolPolicy is operator-owned metadata. Upstream annotations are untrusted
// and therefore cannot lower risk, approval, rate, or output boundaries.
type MCPToolPolicy struct {
	Risk                  Risk
	SideEffect            SideEffect
	NetworkAccess         NetworkAccess
	AllowedNetworkTargets []string
	FilesystemAccess      FilesystemAccess
	RequiresApproval      ApprovalRequirement
	AllowedRoles          []string
	RateLimit             string
	TimeoutSeconds        int
	MaxOutputBytes        int
}

// Host joins one or more MCP servers to the policy-enforcing Broker. Upstream
// tools are never exposed until initialize and tools/list have completed.
type Host struct {
	mu       sync.RWMutex
	broker   *Broker
	clients  map[string]MCPToolClient
	tools    map[string]remoteTool
	versions map[string]string
}

func NewHost(broker *Broker) (*Host, error) {
	if broker == nil {
		return nil, ErrMCPConfig
	}
	host := &Host{broker: broker, clients: make(map[string]MCPToolClient), tools: make(map[string]remoteTool), versions: make(map[string]string)}
	broker.executor = hostExecutor{host: host}
	return host, nil
}

func (host *Host) Broker() *Broker { return host.broker }

// AddServer performs the mandatory MCP lifecycle before registering tools.
// A server that cannot negotiate the baseline protocol or expose a valid,
// bounded schema is rejected in full; partial registration is unsafe.
func (host *Host) AddServer(ctx context.Context, serverID, version string, client MCPToolClient) error {
	return host.AddServerWithPolicies(ctx, serverID, version, client, nil)
}

func (host *Host) AddServerWithPolicies(ctx context.Context, serverID, version string, client MCPToolClient, policies map[string]MCPToolPolicy) error {
	if host == nil || host.broker == nil || ctx == nil || !safeToken(serverID) || !safeVersion(version) || client == nil {
		return ErrMCPConfig
	}
	initialized, err := client.Initialize(ctx)
	if err != nil {
		return fmt.Errorf("%w: initialize %s", ErrMCPTransport, serverID)
	}
	if initialized.ProtocolVersion != mcp.BaselineProtocolVersion || !hasToolsCapability(initialized.Capabilities) {
		return fmt.Errorf("%w: unsupported negotiated protocol", ErrMCPTransport)
	}
	cursor := ""
	var discovered []mcp.Tool
	for {
		page, listErr := client.ListTools(ctx, cursor)
		if listErr != nil {
			return fmt.Errorf("%w: list tools %s", ErrMCPTransport, serverID)
		}
		discovered = append(discovered, page.Tools...)
		if len(discovered) > 10000 {
			return ErrMCPConfig
		}
		if page.NextCursor == "" {
			break
		}
		if page.NextCursor == cursor {
			return ErrMCPConfig
		}
		cursor = page.NextCursor
	}
	sort.Slice(discovered, func(left, right int) bool { return discovered[left].Name < discovered[right].Name })
	type registration struct {
		tool       mcp.Tool
		descriptor ToolDescriptor
	}
	registrations := make([]registration, 0, len(discovered))
	seenTools := make(map[string]struct{}, len(discovered))
	for _, tool := range discovered {
		if !mcp.ValidateToolName(tool.Name) || len(tool.InputSchema) == 0 || tool.InputSchema["type"] != "object" {
			return ErrMCPConfig
		}
		if _, duplicate := seenTools[tool.Name]; duplicate {
			return ErrMCPConfig
		}
		seenTools[tool.Name] = struct{}{}
		inputSchema, marshalErr := json.Marshal(tool.InputSchema)
		if marshalErr != nil || !json.Valid(inputSchema) || len(inputSchema) > MaxSchemaBytes {
			return ErrMCPConfig
		}
		brokerOutputSchema, marshalErr := json.Marshal(defaultMCPOutputSchema)
		if marshalErr != nil {
			return ErrMCPConfig
		}
		if len(tool.OutputSchema) > 0 {
			if tool.OutputSchema["type"] != "object" {
				return ErrMCPConfig
			}
			declaredOutputSchema, outputErr := json.Marshal(tool.OutputSchema)
			if outputErr != nil || !json.Valid(declaredOutputSchema) || len(declaredOutputSchema) > MaxSchemaBytes {
				return ErrMCPConfig
			}
		}
		policy, configured := policies[tool.Name]
		if !configured {
			policy = defaultMCPToolPolicy()
		}
		if policy.NetworkAccess == "" {
			policy.NetworkAccess = NetworkNone
		}
		descriptor := ToolDescriptor{ToolID: tool.Name, Version: version, MCPServerID: serverID, InputSchemaRef: "mcp://" + serverID + "/" + tool.Name + "/input", OutputSchemaRef: "mcp://" + serverID + "/" + tool.Name + "/result", InputSchema: inputSchema, OutputSchema: brokerOutputSchema, Risk: policy.Risk, SideEffect: policy.SideEffect, NetworkAccess: policy.NetworkAccess, AllowedNetworkTargets: append([]string(nil), policy.AllowedNetworkTargets...), FilesystemAccess: policy.FilesystemAccess, RequiresApproval: policy.RequiresApproval, AllowedRoles: append([]string(nil), policy.AllowedRoles...), RateLimit: policy.RateLimit, TimeoutSeconds: policy.TimeoutSeconds, MaxOutputBytes: policy.MaxOutputBytes}
		if err := descriptor.Validate(); err != nil {
			return err
		}
		registrations = append(registrations, registration{tool: tool, descriptor: descriptor})
	}
	for name := range policies {
		found := false
		for _, registration := range registrations {
			if registration.tool.Name == name {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: policy for unknown tool", ErrMCPConfig)
		}
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if _, exists := host.clients[serverID]; exists {
		return fmt.Errorf("%w: duplicate MCP server", ErrMCPConfig)
	}
	for _, registration := range registrations {
		if _, exists := host.tools[registration.tool.Name]; exists {
			return fmt.Errorf("%w: duplicate tool name", ErrMCPConfig)
		}
	}
	descriptors := make([]ToolDescriptor, len(registrations))
	for index, registration := range registrations {
		descriptors[index] = registration.descriptor
	}
	if len(descriptors) > 0 {
		if err := host.broker.registerBatch(descriptors); err != nil {
			return err
		}
	}
	for _, registration := range registrations {
		host.tools[registration.tool.Name] = remoteTool{serverID: serverID, version: version, client: client, tool: registration.tool}
		host.versions[registration.tool.Name] = version
	}
	host.clients[serverID] = client
	return nil
}

func (host *Host) Tools() []mcp.Tool {
	host.mu.RLock()
	defer host.mu.RUnlock()
	result := make([]mcp.Tool, 0, len(host.tools))
	for _, remote := range host.tools {
		result = append(result, cloneMCPTool(remote.tool))
	}
	mcp.SortTools(result)
	return result
}

func (host *Host) Version(toolName string) (string, bool) {
	host.mu.RLock()
	defer host.mu.RUnlock()
	version, ok := host.versions[toolName]
	return version, ok
}

func (host *Host) Invoke(ctx context.Context, request ToolRequest) (ToolResult, error) {
	host.mu.RLock()
	remote, ok := host.tools[request.ToolID]
	host.mu.RUnlock()
	if !ok || remote.version != request.Version {
		return ToolResult{}, ErrUnknownTool
	}
	return host.broker.Invoke(ctx, request)
}

type hostExecutor struct{ host *Host }

func (executor hostExecutor) Execute(ctx context.Context, descriptor ToolDescriptor, parameters []byte) ([]byte, error) {
	if executor.host == nil {
		return nil, ErrMCPTransport
	}
	executor.host.mu.RLock()
	remote, ok := executor.host.tools[descriptor.ToolID]
	executor.host.mu.RUnlock()
	if !ok || remote.version != descriptor.Version || remote.client == nil {
		return nil, ErrUnknownTool
	}
	var arguments map[string]any
	if err := json.Unmarshal(parameters, &arguments); err != nil {
		return nil, ErrInvalidRequest
	}
	requestID, _ := ctx.Value(invocationRequestIDContextKey{}).(string)
	var result mcp.ToolCallResult
	var err error
	if requestIDClient, ok := remote.client.(mcpRequestIDToolClient); ok {
		result, err = requestIDClient.CallToolWithRequestID(ctx, remote.tool.Name, arguments, requestID)
	} else {
		result, err = remote.client.CallTool(ctx, remote.tool.Name, arguments)
	}
	if err != nil {
		return nil, err
	}
	if len(remote.tool.OutputSchema) > 0 {
		structured, marshalErr := json.Marshal(result.StructuredContent)
		schema, schemaErr := json.Marshal(remote.tool.OutputSchema)
		if marshalErr != nil || schemaErr != nil || result.StructuredContent == nil || validateSchema("mcp://"+remote.serverID+"/"+remote.tool.Name+"/output", schema, structured) != nil {
			return nil, ErrInvalidRequest
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func (host *Host) Close() error {
	if host == nil {
		return nil
	}
	host.mu.Lock()
	clients := make([]MCPToolClient, 0, len(host.clients))
	for _, client := range host.clients {
		clients = append(clients, client)
	}
	host.clients = make(map[string]MCPToolClient)
	host.mu.Unlock()
	var first error
	for _, client := range clients {
		if err := client.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

const MaxSchemaBytes = 256 << 10

var defaultMCPOutputSchema = map[string]any{"type": "object", "required": []any{"content"}, "properties": map[string]any{"content": map[string]any{"type": "array"}, "isError": map[string]any{"type": "boolean"}}, "additionalProperties": true}

func defaultMCPToolPolicy() MCPToolPolicy {
	return MCPToolPolicy{Risk: RiskCritical, SideEffect: SideEffectIrreversible, NetworkAccess: NetworkNone, FilesystemAccess: FilesystemNone, RequiresApproval: ApprovalAlways, AllowedRoles: []string{"EXECUTOR", "SERVICE"}, RateLimit: "1/s", TimeoutSeconds: 30, MaxOutputBytes: maxOutputBytes}
}

func cloneMCPTool(tool mcp.Tool) mcp.Tool {
	return mcp.Tool{Name: tool.Name, Title: tool.Title, Description: tool.Description, InputSchema: cloneMap(tool.InputSchema), OutputSchema: cloneMap(tool.OutputSchema), Annotations: cloneMap(tool.Annotations), Execution: cloneMap(tool.Execution)}
}

func cloneMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var clone map[string]any
	if json.Unmarshal(encoded, &clone) != nil {
		return nil
	}
	return clone
}

func safeToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '-' || character == '.') {
			return false
		}
	}
	return true
}

func safeVersion(value string) bool {
	return safeToken(value) && len(value) <= 64
}
