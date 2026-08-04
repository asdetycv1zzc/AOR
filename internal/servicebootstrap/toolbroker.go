package servicebootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/credentials"
	"github.com/akimisaka/aor/internal/policy"
	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/runtimeclient"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	"github.com/akimisaka/aor/internal/toolbroker"
	"github.com/akimisaka/aor/pkg/mcp"
)

type mcpServerConfig struct {
	ID               string                         `json:"id"`
	Transport        string                         `json:"transport"`
	Endpoint         string                         `json:"endpoint,omitempty"`
	Command          string                         `json:"command,omitempty"`
	Args             []string                       `json:"args,omitempty"`
	Env              map[string]string              `json:"env,omitempty"`
	Version          string                         `json:"version"`
	AuthorizationRef string                         `json:"authorizationRef,omitempty"`
	Tools            map[string]mcpToolPolicyConfig `json:"tools,omitempty"`
}

type mcpToolPolicyConfig struct {
	Risk                  toolbroker.Risk                `json:"risk"`
	SideEffect            toolbroker.SideEffect          `json:"sideEffect"`
	NetworkAccess         toolbroker.NetworkAccess       `json:"networkAccess"`
	AllowedNetworkTargets []string                       `json:"allowedNetworkTargets,omitempty"`
	FilesystemAccess      toolbroker.FilesystemAccess    `json:"filesystemAccess"`
	RequiresApproval      toolbroker.ApprovalRequirement `json:"requiresApproval"`
	AllowedRoles          []string                       `json:"allowedRoles"`
	RateLimit             string                         `json:"rateLimit"`
	TimeoutSeconds        int                            `json:"timeoutSeconds"`
	MaxOutputBytes        int                            `json:"maxOutputBytes"`
}

type closedToolBrokerHandler struct {
	http.Handler
	host *toolbroker.Host
}

func (handler *closedToolBrokerHandler) Close() error {
	if handler == nil || handler.host == nil {
		return nil
	}
	return handler.host.Close()
}

func ToolBroker(config runtimeconfig.Config, clients *runtimeclient.Clients) (http.Handler, error) {
	if clients == nil || clients.Database() == nil || clients.JetStream() == nil || clients.S3() == nil {
		return nil, runtimeclient.ErrInvalidClientConfig
	}
	secretResolver := credentials.NewSecretResolver(os.Getenv("AOR_SECRET_ROOT"))
	leaseKeyReference := config.LeaseSigningKeyRef
	if !validToolSecretReference(leaseKeyReference) {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	resolveCtx, resolveCancel := context.WithTimeout(context.Background(), 5*time.Second)
	leaseKey, err := secretResolver.Resolve(resolveCtx, leaseKeyReference)
	resolveCancel()
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	repositoryKey := deriveRepositorySigningKey(leaseKey)
	leaseSigner, err := authz.NewHMACSigner(leaseKey)
	repositorySigner, repositorySignerErr := repository.NewHMACSigner(repositoryKey)
	for index := range leaseKey {
		leaseKey[index] = 0
	}
	for index := range repositoryKey {
		repositoryKey[index] = 0
	}
	if err != nil || repositorySignerErr != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	leaseStore, err := authz.NewPostgresLeaseStore(clients.Database())
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	leaseManager, err := authz.NewLeaseManager(authz.LeaseManagerConfig{Store: leaseStore, Signer: leaseSigner, Clock: time.Now, HeartbeatInterval: 30 * time.Second})
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	scopes, err := toolbroker.NewPostgresScopeResolver(toolbroker.PostgresScopeResolverConfig{Database: clients.Database(), DeploymentProfile: config.DeploymentProfile})
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	authenticator, err := oidcAuthenticator(config)
	if err != nil {
		return nil, err
	}
	policyClient, err := policy.NewOPAClient(config.OPA.URL)
	if err != nil {
		return nil, err
	}
	recorder, err := toolbroker.NewJetStreamInvocationRecorder(clients.JetStream(), config.NATS.Stream)
	if err != nil {
		return nil, err
	}
	durableRecorder, err := toolbroker.NewPostgresInvocationRecorder(clients.Database())
	if err != nil {
		return nil, err
	}
	invocationRecorder, err := toolbroker.NewCompositeInvocationRecorder(durableRecorder, recorder)
	if err != nil {
		return nil, err
	}
	policyEvaluator := toolbroker.OPAPolicyEvaluator{Policy: policyClient, Scopes: scopes, Clock: time.Now}
	leaseChecker := toolbroker.AuthzLeaseChecker{Manager: leaseManager, Scopes: scopes}
	artifactCatalog, err := artifact.NewPostgresS3Catalog(clients.Database(), clients.S3(), config.S3.Bucket, time.Now)
	if err != nil {
		return nil, err
	}
	artifactPublisher, err := toolbroker.NewArtifactPublisher(artifactCatalog)
	if err != nil {
		return nil, err
	}
	broker := toolbroker.New(leaseChecker, policyEvaluator, nil, artifactPublisher, invocationRecorder, policyEvaluator.Revalidate, time.Now)
	host, err := toolbroker.NewHost(broker)
	if err != nil {
		return nil, err
	}
	repositoryClient, err := newRepositoryMCPClient(config.RepositoryRoot, clients.Database(), leaseChecker, repositorySigner, time.Now)
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	repositoryLoadCtx, repositoryLoadCancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = host.AddServerWithPolicies(repositoryLoadCtx, repositoryMCPServerID, repositoryMCPVersion, repositoryClient, repositoryMCPPolicies())
	repositoryLoadCancel()
	if err != nil {
		_ = repositoryClient.Close()
		_ = host.Close()
		return nil, err
	}
	configured, err := loadMCPServerConfig(os.Getenv("AOR_MCP_SERVERS_JSON"))
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	for _, serverConfig := range configured {
		client, clientErr := configuredMCPClient(serverConfig, secretResolver)
		if clientErr != nil {
			_ = host.Close()
			return nil, clientErr
		}
		policies := make(map[string]toolbroker.MCPToolPolicy, len(serverConfig.Tools))
		for name, configuredPolicy := range serverConfig.Tools {
			policies[name] = toolbroker.MCPToolPolicy{Risk: configuredPolicy.Risk, SideEffect: configuredPolicy.SideEffect, NetworkAccess: configuredPolicy.NetworkAccess, AllowedNetworkTargets: append([]string(nil), configuredPolicy.AllowedNetworkTargets...), FilesystemAccess: configuredPolicy.FilesystemAccess, RequiresApproval: configuredPolicy.RequiresApproval, AllowedRoles: append([]string(nil), configuredPolicy.AllowedRoles...), RateLimit: configuredPolicy.RateLimit, TimeoutSeconds: configuredPolicy.TimeoutSeconds, MaxOutputBytes: configuredPolicy.MaxOutputBytes}
		}
		loadCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		loadErr := host.AddServerWithPolicies(loadCtx, serverConfig.ID, serverConfig.Version, client, policies)
		cancel()
		if loadErr != nil {
			_ = client.Close()
			_ = host.Close()
			return nil, loadErr
		}
	}
	server, err := toolbroker.NewMCPServer(toolbroker.MCPServerConfig{Host: host, ServerInfo: mcp.Implementation{Name: "aor-tool-broker", Version: "1.0.0", Description: "AOR policy-enforcing MCP host"}, AllowedOrigins: configuredOrigins(os.Getenv("AOR_MCP_ALLOWED_ORIGINS")), RequireAuth: true})
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", server.Handler())
	authenticated, err := authn.NewHTTPMiddleware(authenticator, mux)
	if err != nil {
		_ = host.Close()
		return nil, err
	}
	return &closedToolBrokerHandler{Handler: authenticated, host: host}, nil
}

func loadMCPServerConfig(raw string) ([]mcpServerConfig, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var servers []mcpServerConfig
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&servers); err != nil || len(servers) > 64 {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	seen := make(map[string]struct{}, len(servers))
	for _, server := range servers {
		if server.ID == "" || server.Version == "" || (server.Transport != "streamable-http" && server.Transport != "stdio") {
			return nil, runtimeconfig.ErrInvalidConfiguration
		}
		if _, duplicate := seen[server.ID]; duplicate {
			return nil, runtimeconfig.ErrInvalidConfiguration
		}
		seen[server.ID] = struct{}{}
		if server.Transport == "streamable-http" && (server.Endpoint == "" || !validToolSecretReference(server.AuthorizationRef) || server.Command != "" || len(server.Args) > 0 || len(server.Env) > 0) || server.Transport == "stdio" && (server.Command == "" || server.Endpoint != "" || server.AuthorizationRef != "") {
			return nil, runtimeconfig.ErrInvalidConfiguration
		}
	}
	return servers, nil
}

func configuredMCPClient(server mcpServerConfig, resolver *credentials.SecretResolver) (toolbroker.MCPToolClient, error) {
	switch server.Transport {
	case "streamable-http":
		resolveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		token, err := resolver.Resolve(resolveCtx, server.AuthorizationRef)
		cancel()
		if err != nil {
			return nil, runtimeconfig.ErrInvalidConfiguration
		}
		client, clientErr := toolbroker.NewStreamableHTTPClient(toolbroker.StreamableHTTPClientConfig{Endpoint: server.Endpoint, AllowHTTP: false, Timeout: 30 * time.Second, BearerToken: token})
		for index := range token {
			token[index] = 0
		}
		return client, clientErr
	case "stdio":
		return toolbroker.NewStdioClient(toolbroker.StdioClientConfig{Command: server.Command, Args: append([]string(nil), server.Args...), Env: cloneStringMap(server.Env)})
	default:
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
}

func configuredOrigins(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func cloneStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func validToolSecretReference(reference string) bool {
	if !strings.HasPrefix(reference, "secret://") || strings.ContainsAny(reference, "\\\x00") {
		return false
	}
	components := strings.Split(strings.TrimPrefix(reference, "secret://"), "/")
	if len(components) == 0 {
		return false
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

var _ authz.PolicyEvaluator = (*policy.OPAClient)(nil)
