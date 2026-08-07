package runtimeconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

var ErrInvalidConfiguration = errors.New("invalid runtime configuration")

const (
	EnvironmentDevelopment   = "development"
	EnvironmentTest          = "test"
	EnvironmentPreproduction = "preproduction"
	EnvironmentProduction    = "production"
)

type LookupEnv func(string) (string, bool)

type Config struct {
	Component           string
	Environment         string
	DeploymentProfile   string
	LeaseSigningKeyRef  string
	ListenAddress       string
	KnowledgeRoot       string
	KnowledgeCuratorURL string
	RepositoryRoot      string
	Database            DatabaseConfig
	Temporal            TemporalConfig
	NATS                NATSConfig
	S3                  S3Config
	OPA                 OPAConfig
	Identity            IdentityConfig
	ModelGateway        ModelGatewayConfig
	ModelGatewayClient  ModelGatewayClientConfig
	GoalPlan            GoalPlanConfig
	ModuleAuditRoute    GoalPlanRouteConfig
	GlobalAuditRoute    GoalPlanRouteConfig
	Execution           ExecutionConfig
	Integration         IntegrationConfig
	Services            ServiceEndpoints
	Sandbox             SandboxConfig
	Telemetry           TelemetryConfig
}

type DatabaseConfig struct {
	Host        string
	Port        int
	Name        string
	User        string
	PasswordRef string
	SSLMode     string
}

func (config DatabaseConfig) Address() string {
	return net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
}

type TemporalConfig struct {
	Address   string
	Namespace string
	TaskQueue string
}

type NATSConfig struct {
	URL    string
	Stream string
}

type S3Config struct {
	Endpoint     string
	Bucket       string
	Region       string
	AccessKeyRef string
	SecretKeyRef string
	UsePathStyle bool
}

type TelemetryConfig struct {
	OTLPEndpoint string
}

type OPAConfig struct {
	URL string
}

type IdentityConfig struct {
	Issuer          string
	JWKSURL         string
	Audience        string
	DefaultTenantID string
	DefaultRole     string
	ServiceSubjects []ServiceSubjectMapping
}

type ServiceSubjectMapping struct {
	Subject  string `json:"subject"`
	TenantID string `json:"tenantId"`
}

type ModelGatewayConfig struct {
	Providers      []ProviderConfig
	ReplayKeyRef   string
	ReplayKeyID    string
	ReplayTTLHours int
}

type ModelGatewayClientConfig struct {
	TokenEndpoint   string
	ClientID        string
	ClientSecretRef string
	Scopes          []string
	Audience        string
}

type GoalPlanConfig struct {
	Routes map[string]GoalPlanRouteConfig
}

type ExecutionConfig struct {
	Route                    GoalPlanRouteConfig
	MaxToolRounds            int
	ModuleTestCommand        []string
	ModuleTestTimeoutSeconds int
}

type IntegrationConfig struct {
	WorkRoot        string
	DependencyCache string
	Checks          []IntegrationCheckConfig
}

type IntegrationCheckConfig struct {
	Kind           string   `json:"kind"`
	Argv           []string `json:"argv"`
	TimeoutSeconds int      `json:"timeoutSeconds"`
}

type GoalPlanRouteConfig struct {
	Provider            string  `json:"provider"`
	Model               string  `json:"model"`
	MaxOutputTokens     int     `json:"maxOutputTokens"`
	Temperature         float64 `json:"temperature"`
	Seed                *int64  `json:"seed,omitempty"`
	ProviderPolicy      string  `json:"providerPolicy"`
	CachePolicy         string  `json:"cachePolicy"`
	WorstCaseCostMicros int64   `json:"worstCaseCostMicros"`
	MaxAttempts         int     `json:"maxAttempts"`
}

type ProviderConfig struct {
	ID                         string   `json:"id"`
	Provider                   string   `json:"provider"`
	BaseURL                    string   `json:"baseUrl"`
	APIKeyRef                  string   `json:"apiKeyRef"`
	Models                     []string `json:"models"`
	ReasoningEffort            string   `json:"reasoningEffort,omitempty"`
	InputMicrosPerToken        int64    `json:"inputMicrosPerToken"`
	OutputMicrosPerToken       int64    `json:"outputMicrosPerToken"`
	SupportsStreaming          bool     `json:"supportsStreaming"`
	SupportsToolCalls          bool     `json:"supportsToolCalls"`
	SupportsJSONSchema         bool     `json:"supportsJsonSchema"`
	SupportsSeed               bool     `json:"supportsSeed"`
	SupportsPromptCaching      bool     `json:"supportsPromptCaching"`
	MaxInputTokens             int      `json:"maxInputTokens"`
	MaxOutputTokens            int      `json:"maxOutputTokens"`
	AllowedDataClassifications []string `json:"allowedDataClassifications"`
	DataResidency              []string `json:"dataResidency"`
	RetentionPolicy            string   `json:"retentionPolicy"`
	Modalities                 []string `json:"modalities"`
	capabilitiesConfigured     bool
}

type ServiceEndpoints struct {
	API          string
	ModelGateway string
	ToolBroker   string
}

type SandboxConfig struct {
	LinuxLevel                   string
	WindowsLevel                 string
	AllowWindowsUntrusted        bool
	LinuxDefaultNetworkMode      string
	WindowsNetworkIsolationLevel string
	EngineEndpoint               string
	RuntimeName                  string
	ImageReference               string
	SeccompProfile               string
	MandatoryPolicy              string
	HoldCommand                  []string
	AllowedMountRoots            []string
}

func Load(component string, lookup LookupEnv) (Config, error) {
	if lookup == nil || !knownComponent(component) {
		return Config{}, ErrInvalidConfiguration
	}
	config := Config{
		Component:           component,
		Environment:         value(lookup, "AOR_ENVIRONMENT", EnvironmentDevelopment),
		DeploymentProfile:   value(lookup, "AOR_DEPLOYMENT_PROFILE", ""),
		LeaseSigningKeyRef:  value(lookup, "AOR_LEASE_SIGNING_KEY_REF", ""),
		ListenAddress:       value(lookup, "AOR_LISTEN_ADDR", ":8080"),
		KnowledgeRoot:       strictValue(lookup, "AOR_KNOWLEDGE_ROOT", "/var/lib/aor/knowledge"),
		KnowledgeCuratorURL: value(lookup, "AOR_KNOWLEDGE_CURATOR_URL", ""),
		RepositoryRoot:      strictValue(lookup, "AOR_REPOSITORY_ROOT", "/var/lib/aor/repositories"),
		Integration: IntegrationConfig{
			WorkRoot:        strictValue(lookup, "AOR_INTEGRATION_WORK_ROOT", ""),
			DependencyCache: strictValue(lookup, "AOR_INTEGRATION_DEPENDENCY_CACHE", ""),
		},
		Execution: ExecutionConfig{
			ModuleTestCommand: []string{"/usr/local/go/bin/go", "test", "-p=1", "./..."},
		},
		Database: DatabaseConfig{
			Host:        value(lookup, "AOR_DATABASE_HOST", "postgres"),
			Name:        value(lookup, "AOR_DATABASE_NAME", "aor"),
			User:        value(lookup, "AOR_DATABASE_USER", "aor"),
			PasswordRef: value(lookup, "AOR_DATABASE_PASSWORD_REF", ""),
			SSLMode:     value(lookup, "AOR_DATABASE_SSLMODE", "disable"),
		},
		Temporal: TemporalConfig{
			Address:   value(lookup, "AOR_TEMPORAL_ADDRESS", "temporal:7233"),
			Namespace: value(lookup, "AOR_TEMPORAL_NAMESPACE", "aor"),
			TaskQueue: value(lookup, "AOR_TEMPORAL_TASK_QUEUE", "aor-control-plane"),
		},
		NATS: NATSConfig{
			URL:    value(lookup, "AOR_NATS_URL", "nats://nats:4222"),
			Stream: value(lookup, "AOR_NATS_STREAM", "AOR_EVENTS"),
		},
		S3: S3Config{
			Endpoint:     value(lookup, "AOR_S3_ENDPOINT", "http://minio:9000"),
			Bucket:       value(lookup, "AOR_S3_BUCKET", "aor-artifacts"),
			Region:       value(lookup, "AOR_S3_REGION", "us-east-1"),
			AccessKeyRef: value(lookup, "AOR_S3_ACCESS_KEY_REF", ""),
			SecretKeyRef: value(lookup, "AOR_S3_SECRET_KEY_REF", ""),
		},
		OPA: OPAConfig{URL: value(lookup, "AOR_OPA_URL", "http://opa:8181")},
		Identity: IdentityConfig{
			Issuer:          value(lookup, "AOR_OIDC_ISSUER", "http://identity:5556/dex"),
			JWKSURL:         value(lookup, "AOR_OIDC_JWKS_URL", "http://identity:5556/dex/keys"),
			Audience:        value(lookup, "AOR_OIDC_AUDIENCE", "aor-control-plane"),
			DefaultTenantID: value(lookup, "AOR_OIDC_DEFAULT_TENANT_ID", ""),
			DefaultRole:     value(lookup, "AOR_OIDC_DEFAULT_ROLE", ""),
		},
		ModelGateway: ModelGatewayConfig{
			ReplayKeyRef: value(lookup, "AOR_MODEL_REPLAY_KEY_REF", "secret://model/replay-key"),
			ReplayKeyID:  value(lookup, "AOR_MODEL_REPLAY_KEY_ID", "model-replay-v1"),
		},
		ModelGatewayClient: ModelGatewayClientConfig{
			TokenEndpoint:   value(lookup, "AOR_MODEL_GATEWAY_OAUTH_TOKEN_ENDPOINT", ""),
			ClientID:        value(lookup, "AOR_MODEL_GATEWAY_OAUTH_CLIENT_ID", ""),
			ClientSecretRef: value(lookup, "AOR_MODEL_GATEWAY_OAUTH_CLIENT_SECRET_REF", ""),
			Audience:        value(lookup, "AOR_MODEL_GATEWAY_OAUTH_AUDIENCE", ""),
		},
		Services: ServiceEndpoints{
			API:          value(lookup, "AOR_API_URL", "http://aor-api:8090"),
			ModelGateway: value(lookup, "AOR_MODEL_GATEWAY_URL", "http://aor-model-gateway:8091"),
			ToolBroker:   value(lookup, "AOR_TOOL_BROKER_URL", "http://aor-tool-broker:8092"),
		},
		Sandbox: SandboxConfig{
			LinuxLevel:                   value(lookup, "AOR_SANDBOX_LINUX_LEVEL", "CONTAINER"),
			WindowsLevel:                 value(lookup, "AOR_SANDBOX_WINDOWS_LEVEL", "NONE"),
			LinuxDefaultNetworkMode:      value(lookup, "AOR_SANDBOX_LINUX_NETWORK_MODE", "DENY_ALL"),
			WindowsNetworkIsolationLevel: value(lookup, "AOR_SANDBOX_WINDOWS_NETWORK_ISOLATION", "NONE"),
			EngineEndpoint:               strictValue(lookup, "AOR_SANDBOX_ENGINE_ENDPOINT", ""),
			RuntimeName:                  strictValue(lookup, "AOR_SANDBOX_RUNTIME", "runc"),
			ImageReference:               strictValue(lookup, "AOR_SANDBOX_IMAGE_REFERENCE", ""),
			SeccompProfile:               strictValue(lookup, "AOR_SANDBOX_SECCOMP_PROFILE", "builtin"),
			MandatoryPolicy:              strictValue(lookup, "AOR_SANDBOX_MANDATORY_POLICY", "apparmor=aor-sandbox"),
		},
		Telemetry: TelemetryConfig{OTLPEndpoint: value(lookup, "AOR_OTEL_EXPORTER_OTLP_ENDPOINT", "")},
	}

	var err error
	config.Database.Port, err = integer(lookup, "AOR_DATABASE_PORT", 5432, 1, 65535)
	if err != nil {
		return Config{}, err
	}
	config.S3.UsePathStyle, err = boolean(lookup, "AOR_S3_USE_PATH_STYLE", true)
	if err != nil {
		return Config{}, err
	}
	config.Sandbox.AllowWindowsUntrusted, err = boolean(lookup, "AOR_ALLOW_WINDOWS_UNTRUSTED", false)
	if err != nil {
		return Config{}, err
	}
	config.ModelGateway.ReplayTTLHours, err = integer(lookup, "AOR_MODEL_REPLAY_TTL_HOURS", 24, 1, 30*24)
	if err != nil {
		return Config{}, err
	}
	config.Execution.MaxToolRounds, err = integer(lookup, "AOR_EXECUTOR_MAX_TOOL_ROUNDS", 8, 2, 8)
	if err != nil {
		return Config{}, err
	}
	config.Execution.ModuleTestTimeoutSeconds, err = integer(lookup, "AOR_MODULE_TEST_TIMEOUT_SECONDS", 300, 1, 900)
	if err != nil {
		return Config{}, err
	}
	config.ModelGatewayClient.Scopes, err = oauthScopes(lookup, "AOR_MODEL_GATEWAY_OAUTH_SCOPES")
	if err != nil {
		return Config{}, err
	}
	if raw := value(lookup, "AOR_SANDBOX_HOLD_COMMAND_JSON", `["/bin/sh","-c","while :; do sleep 3600; done"]`); raw != "" {
		decoder := json.NewDecoder(strings.NewReader(raw))
		if err := decoder.Decode(&config.Sandbox.HoldCommand); err != nil {
			return Config{}, configurationError("AOR_SANDBOX_HOLD_COMMAND_JSON")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return Config{}, configurationError("AOR_SANDBOX_HOLD_COMMAND_JSON")
		}
	}
	if raw, found := lookup("AOR_SANDBOX_ALLOWED_MOUNT_ROOTS_JSON"); found && strings.TrimSpace(raw) != "" {
		decoder := json.NewDecoder(strings.NewReader(raw))
		if err := decoder.Decode(&config.Sandbox.AllowedMountRoots); err != nil {
			return Config{}, configurationError("AOR_SANDBOX_ALLOWED_MOUNT_ROOTS_JSON")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return Config{}, configurationError("AOR_SANDBOX_ALLOWED_MOUNT_ROOTS_JSON")
		}
	}
	if raw, found := lookup("AOR_MODEL_PROVIDERS_JSON"); found && strings.TrimSpace(raw) != "" {
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config.ModelGateway.Providers); err != nil {
			return Config{}, configurationError("AOR_MODEL_PROVIDERS_JSON")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return Config{}, configurationError("AOR_MODEL_PROVIDERS_JSON")
		}
		if err := markProviderCapabilityConfiguration(raw, config.ModelGateway.Providers); err != nil {
			return Config{}, configurationError("AOR_MODEL_PROVIDERS_JSON")
		}
	}
	if raw, found := lookup("AOR_OIDC_SERVICE_SUBJECTS_JSON"); found && strings.TrimSpace(raw) != "" {
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config.Identity.ServiceSubjects); err != nil {
			return Config{}, configurationError("AOR_OIDC_SERVICE_SUBJECTS_JSON")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return Config{}, configurationError("AOR_OIDC_SERVICE_SUBJECTS_JSON")
		}
	}
	if raw, found := lookup("AOR_GOAL_PLAN_ROUTES_JSON"); found && strings.TrimSpace(raw) != "" {
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config.GoalPlan.Routes); err != nil {
			return Config{}, configurationError("AOR_GOAL_PLAN_ROUTES_JSON")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return Config{}, configurationError("AOR_GOAL_PLAN_ROUTES_JSON")
		}
	}
	if raw, found := lookup("AOR_EXECUTOR_ROUTE_JSON"); found && strings.TrimSpace(raw) != "" {
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config.Execution.Route); err != nil {
			return Config{}, configurationError("AOR_EXECUTOR_ROUTE_JSON")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return Config{}, configurationError("AOR_EXECUTOR_ROUTE_JSON")
		}
	}
	if raw, found := lookup("AOR_MODULE_TEST_COMMAND_JSON"); found && strings.TrimSpace(raw) != "" {
		decoder := json.NewDecoder(strings.NewReader(raw))
		if err := decoder.Decode(&config.Execution.ModuleTestCommand); err != nil {
			return Config{}, configurationError("AOR_MODULE_TEST_COMMAND_JSON")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return Config{}, configurationError("AOR_MODULE_TEST_COMMAND_JSON")
		}
	}
	if raw, found := lookup("AOR_GLOBAL_AUDITOR_ROUTE_JSON"); found && strings.TrimSpace(raw) != "" {
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config.GlobalAuditRoute); err != nil {
			return Config{}, configurationError("AOR_GLOBAL_AUDITOR_ROUTE_JSON")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return Config{}, configurationError("AOR_GLOBAL_AUDITOR_ROUTE_JSON")
		}
	}
	if raw, found := lookup("AOR_MODULE_AUDITOR_ROUTE_JSON"); found && strings.TrimSpace(raw) != "" {
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config.ModuleAuditRoute); err != nil {
			return Config{}, configurationError("AOR_MODULE_AUDITOR_ROUTE_JSON")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return Config{}, configurationError("AOR_MODULE_AUDITOR_ROUTE_JSON")
		}
	}
	if raw, found := lookup("AOR_INTEGRATION_CHECKS_JSON"); found && strings.TrimSpace(raw) != "" {
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config.Integration.Checks); err != nil {
			return Config{}, configurationError("AOR_INTEGRATION_CHECKS_JSON")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return Config{}, configurationError("AOR_INTEGRATION_CHECKS_JSON")
		}
	}
	applyProviderCapabilityDefaults(config.ModelGateway.Providers)
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config Config) Validate() error {
	if !knownComponent(config.Component) || !oneOf(config.Environment, EnvironmentDevelopment, EnvironmentTest, EnvironmentPreproduction, EnvironmentProduction) || !validListenAddress(config.ListenAddress) {
		return ErrInvalidConfiguration
	}
	if config.Telemetry.OTLPEndpoint != "" && !validOTLPEndpoint(config.Telemetry.OTLPEndpoint) ||
		(config.Environment == EnvironmentPreproduction || config.Environment == EnvironmentProduction) && config.Telemetry.OTLPEndpoint == "" ||
		config.Environment == EnvironmentProduction && !strings.HasPrefix(config.Telemetry.OTLPEndpoint, "https://") {
		return ErrInvalidConfiguration
	}
	if config.Component == "aor-tool-broker" && (!validSecretReference(config.LeaseSigningKeyRef) || !validDeploymentProfile(config.DeploymentProfile) || !validKnowledgeRoot(config.RepositoryRoot)) {
		return ErrInvalidConfiguration
	}
	if config.Component == "aor-server" && (!validKnowledgeRoot(config.KnowledgeRoot) || !validKnowledgeCuratorURL(config.KnowledgeCuratorURL, config.Environment) || !validSecretReference(config.LeaseSigningKeyRef) || !validDeploymentProfile(config.DeploymentProfile)) {
		return ErrInvalidConfiguration
	}
	if config.Component == "aor-server" {
		if err := validateGoalPlanRoutes(config.GoalPlan.Routes); err != nil {
			return err
		}
	}
	if needsDatabase(config.Component) {
		if config.Database.Host == "" || config.Database.Port < 1 || config.Database.Port > 65535 || config.Database.Name == "" || config.Database.User == "" || !validSecretReference(config.Database.PasswordRef) || !oneOf(config.Database.SSLMode, "disable", "require", "verify-ca", "verify-full") {
			return ErrInvalidConfiguration
		}
		if config.Environment == EnvironmentProduction && config.Database.SSLMode != "verify-full" {
			return ErrInvalidConfiguration
		}
	}
	if needsTemporal(config.Component) && (!validHostPort(config.Temporal.Address) || config.Temporal.Namespace == "" || config.Temporal.TaskQueue == "") {
		return ErrInvalidConfiguration
	}
	if needsNATS(config.Component) && (!validURL(config.NATS.URL, "nats", "tls") || config.NATS.Stream == "") {
		return ErrInvalidConfiguration
	}
	if needsS3(config.Component) && (!validURL(config.S3.Endpoint, "http", "https") || config.S3.Bucket == "" || config.S3.Region == "" || !validSecretReference(config.S3.AccessKeyRef) || !validSecretReference(config.S3.SecretKeyRef)) {
		return ErrInvalidConfiguration
	}
	if needsOPA(config.Component) && !validURL(config.OPA.URL, "http", "https") {
		return ErrInvalidConfiguration
	}
	if needsIdentity(config.Component) && (!validURL(config.Identity.Issuer, "http", "https") || !validURL(config.Identity.JWKSURL, "http", "https") || config.Identity.Audience == "" || len(config.Identity.Audience) > 512 || strings.ContainsAny(config.Identity.Audience, "\r\n\x00")) {
		return ErrInvalidConfiguration
	}
	if (config.Identity.DefaultTenantID == "") != (config.Identity.DefaultRole == "") || config.Identity.DefaultTenantID != "" && (!validUUID(config.Identity.DefaultTenantID) || len(config.Identity.DefaultRole) > 128 || strings.ContainsAny(config.Identity.DefaultRole, "\r\n\x00/\\")) {
		return ErrInvalidConfiguration
	}
	if config.Environment != EnvironmentDevelopment && config.Environment != EnvironmentTest && (config.Identity.DefaultTenantID != "" || config.Identity.DefaultRole != "") {
		return ErrInvalidConfiguration
	}
	if err := validateServiceSubjectMappings(config); err != nil {
		return err
	}
	if needsModelGatewayClient(config.Component) || modelGatewayClientConfigured(config.ModelGatewayClient) {
		client := config.ModelGatewayClient
		if !validURL(config.Services.ModelGateway, "http", "https") || !validURL(client.TokenEndpoint, "http", "https") || !validOAuthClientID(client.ClientID) || !validSecretReference(client.ClientSecretRef) || !validOAuthAudience(client.Audience) || !validOAuthScopes(client.Scopes) {
			return ErrInvalidConfiguration
		}
	}
	if config.Environment == EnvironmentProduction {
		if (needsS3(config.Component) && !strings.HasPrefix(config.S3.Endpoint, "https://")) || (needsOPA(config.Component) && !strings.HasPrefix(config.OPA.URL, "https://")) || (needsNATS(config.Component) && !strings.HasPrefix(config.NATS.URL, "tls://")) || (needsIdentity(config.Component) && (!strings.HasPrefix(config.Identity.Issuer, "https://") || !strings.HasPrefix(config.Identity.JWKSURL, "https://"))) || (needsModelGatewayClient(config.Component) && (!strings.HasPrefix(config.Services.ModelGateway, "https://") || !strings.HasPrefix(config.ModelGatewayClient.TokenEndpoint, "https://"))) {
			return ErrInvalidConfiguration
		}
	}
	if config.Component == "aor-model-gateway" {
		if !validSecretReference(config.ModelGateway.ReplayKeyRef) || config.ModelGateway.ReplayKeyID == "" || len(config.ModelGateway.ReplayKeyID) > 128 || strings.ContainsAny(config.ModelGateway.ReplayKeyID, "\r\n\x00") || config.ModelGateway.ReplayTTLHours < 1 || config.ModelGateway.ReplayTTLHours > 30*24 {
			return ErrInvalidConfiguration
		}
		if err := validateProviders(config.ModelGateway.Providers); err != nil {
			return err
		}
	}
	if config.Component == "aor-worker" {
		if !validSecretReference(config.LeaseSigningKeyRef) || !validDeploymentProfile(config.DeploymentProfile) || !validKnowledgeRoot(config.KnowledgeRoot) || !validKnowledgeRoot(config.RepositoryRoot) || !validURL(config.Services.API, "http", "https") || !validURL(config.Services.ModelGateway, "http", "https") || !validURL(config.Services.ToolBroker, "http", "https") || !validGoalPlanRoute(config.Execution.Route) || config.Execution.MaxToolRounds < 2 || config.Execution.MaxToolRounds > 8 {
			return ErrInvalidConfiguration
		}
		if !validModuleTestCommand(config.Execution.ModuleTestCommand) || config.Execution.ModuleTestTimeoutSeconds < 1 || config.Execution.ModuleTestTimeoutSeconds > 900 {
			return ErrInvalidConfiguration
		}
		if globalAuditRouteConfigured(config.GlobalAuditRoute) && !validGoalPlanRoute(config.GlobalAuditRoute) {
			return ErrInvalidConfiguration
		}
		if globalAuditRouteConfigured(config.ModuleAuditRoute) && !validGoalPlanRoute(config.ModuleAuditRoute) {
			return ErrInvalidConfiguration
		}
		engineConfigured := config.Sandbox.EngineEndpoint != "" || config.Sandbox.ImageReference != ""
		if !validIntegrationConfig(config.Integration, config.Sandbox.AllowedMountRoots, engineConfigured) {
			return ErrInvalidConfiguration
		}
		if config.Sandbox.LinuxLevel != "CONTAINER" || config.Sandbox.WindowsLevel != "NONE" || config.Sandbox.AllowWindowsUntrusted || config.Sandbox.LinuxDefaultNetworkMode != "DENY_ALL" || config.Sandbox.WindowsNetworkIsolationLevel != "NONE" {
			return ErrInvalidConfiguration
		}
		if engineConfigured && (!validSandboxEngineEndpoint(config.Sandbox.EngineEndpoint) || !validSandboxRuntimeName(config.Sandbox.RuntimeName) || !validImmutableImageReference(config.Sandbox.ImageReference) || !validSandboxSeccompProfile(config.Sandbox.SeccompProfile) || !validSandboxMandatoryPolicy(config.Sandbox.MandatoryPolicy) || !validSandboxHoldCommand(config.Sandbox.HoldCommand) || !validSandboxMountRoots(config.Sandbox.AllowedMountRoots)) {
			return ErrInvalidConfiguration
		}
	}
	return nil
}

func globalAuditRouteConfigured(route GoalPlanRouteConfig) bool {
	return route.Provider != "" || route.Model != "" || route.MaxOutputTokens != 0 || route.Temperature != 0 || route.Seed != nil || route.ProviderPolicy != "" || route.CachePolicy != "" || route.WorstCaseCostMicros != 0 || route.MaxAttempts != 0
}

func validateProviders(providers []ProviderConfig) error {
	if len(providers) < 2 {
		return ErrInvalidConfiguration
	}
	ids := make(map[string]struct{}, len(providers))
	families := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		if provider.ID == "" || provider.Provider == "" || !validURL(provider.BaseURL, "http", "https") || !validSecretReference(provider.APIKeyRef) || len(provider.Models) == 0 || !oneOf(provider.ReasoningEffort, "", "none", "minimal", "low", "medium", "high", "xhigh") || provider.InputMicrosPerToken < 0 || provider.OutputMicrosPerToken < 0 || provider.MaxInputTokens <= 0 || provider.MaxOutputTokens <= 0 || len(provider.AllowedDataClassifications) == 0 || strings.TrimSpace(provider.RetentionPolicy) == "" || len(provider.DataResidency) == 0 || len(provider.Modalities) == 0 {
			return ErrInvalidConfiguration
		}
		if _, duplicate := ids[provider.ID]; duplicate {
			return ErrInvalidConfiguration
		}
		ids[provider.ID] = struct{}{}
		families[strings.ToLower(provider.Provider)] = struct{}{}
		models := make(map[string]struct{}, len(provider.Models))
		for _, model := range provider.Models {
			if strings.TrimSpace(model) == "" {
				return ErrInvalidConfiguration
			}
			if _, duplicate := models[model]; duplicate {
				return ErrInvalidConfiguration
			}
			models[model] = struct{}{}
		}
		for _, residency := range provider.DataResidency {
			if strings.TrimSpace(residency) == "" || len(residency) > 128 || strings.ContainsAny(residency, "\r\n\x00") {
				return ErrInvalidConfiguration
			}
		}
		for _, classification := range provider.AllowedDataClassifications {
			if !oneOf(classification, "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED") {
				return ErrInvalidConfiguration
			}
		}
		if (provider.RetentionPolicy == "provider-defined" || len(provider.DataResidency) == 1 && provider.DataResidency[0] == "provider-defined") && allowsNonPublic(provider.AllowedDataClassifications) {
			return ErrInvalidConfiguration
		}
		for _, modality := range provider.Modalities {
			if strings.TrimSpace(modality) == "" || len(modality) > 64 || strings.ContainsAny(modality, "\r\n\x00") {
				return ErrInvalidConfiguration
			}
		}
		if len(provider.RetentionPolicy) > 256 || strings.ContainsAny(provider.RetentionPolicy, "\r\n\x00") {
			return ErrInvalidConfiguration
		}
	}
	if len(families) < 2 {
		return ErrInvalidConfiguration
	}
	return nil
}

func validateGoalPlanRoutes(routes map[string]GoalPlanRouteConfig) error {
	required := []string{"GOAL_PROPOSER", "GOAL_CHALLENGER", "PLAN_SUPERVISOR", "MODULE_PLANNER", "KNOWLEDGE_CURATOR"}
	if len(routes) != len(required) {
		return ErrInvalidConfiguration
	}
	for _, role := range required {
		route, found := routes[role]
		if !found || !validGoalPlanRoute(route) {
			return ErrInvalidConfiguration
		}
	}
	return nil
}

func validGoalPlanRoute(route GoalPlanRouteConfig) bool {
	return validIdentityPart(route.Provider, 128) && validIdentityPart(route.Model, 256) &&
		route.MaxOutputTokens >= 1 && route.MaxOutputTokens <= 1_000_000 && route.Temperature >= 0 && route.Temperature <= 2 &&
		validIdentityPart(route.ProviderPolicy, 256) && validIdentityPart(route.CachePolicy, 128) &&
		route.WorstCaseCostMicros >= 0 && route.MaxAttempts >= 1 && route.MaxAttempts <= 5
}

func allowsNonPublic(classifications []string) bool {
	for _, classification := range classifications {
		if classification != "PUBLIC" {
			return true
		}
	}
	return false
}

// Capability defaults are deliberately conservative for providers that do not
// publish a complete static model catalogue. Deployments can override every
// value in AOR_MODEL_PROVIDERS_JSON; unsupported optional features stay off.
func applyProviderCapabilityDefaults(providers []ProviderConfig) {
	for index := range providers {
		provider := &providers[index]
		if len(provider.AllowedDataClassifications) == 0 {
			provider.AllowedDataClassifications = []string{"PUBLIC"}
		}
		if provider.capabilitiesConfigured {
			continue
		}
		if provider.MaxInputTokens == 0 {
			provider.MaxInputTokens = 32768
		}
		if provider.MaxOutputTokens == 0 {
			provider.MaxOutputTokens = 4096
		}
		if len(provider.DataResidency) == 0 {
			provider.DataResidency = []string{"provider-defined"}
		}
		if len(provider.Modalities) == 0 {
			provider.Modalities = []string{"text"}
		}
		if provider.RetentionPolicy == "" {
			provider.RetentionPolicy = "provider-defined"
		}
		if !provider.SupportsStreaming {
			// OpenAI-compatible providers in the supported deployment profile
			// expose Chat Completions streaming. Explicit false remains useful
			// only when a provider entry supplies a complete capability profile.
			provider.SupportsStreaming = true
		}
	}
}

func markProviderCapabilityConfiguration(raw string, providers []ProviderConfig) error {
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &entries); err != nil || len(entries) != len(providers) {
		return ErrInvalidConfiguration
	}
	keys := []string{"supportsStreaming", "supportsToolCalls", "supportsJsonSchema", "supportsSeed", "supportsPromptCaching", "maxInputTokens", "maxOutputTokens", "dataResidency", "retentionPolicy", "modalities"}
	for index, entry := range entries {
		for _, key := range keys {
			if _, found := entry[key]; found {
				providers[index].capabilitiesConfigured = true
				break
			}
		}
	}
	return nil
}

func value(lookup LookupEnv, key, fallback string) string {
	if current, found := lookup(key); found {
		return strings.TrimSpace(current)
	}
	return fallback
}

func strictValue(lookup LookupEnv, key, fallback string) string {
	if current, found := lookup(key); found {
		return current
	}
	return fallback
}

func integer(lookup LookupEnv, key string, fallback, minimum, maximum int) (int, error) {
	raw, found := lookup(key)
	if !found {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, configurationError(key)
	}
	return parsed, nil
}

func boolean(lookup LookupEnv, key string, fallback bool) (bool, error) {
	raw, found := lookup(key)
	if !found {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return false, configurationError(key)
	}
	return parsed, nil
}

func oauthScopes(lookup LookupEnv, key string) ([]string, error) {
	raw, found := lookup(key)
	if !found || strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	if strings.ContainsAny(raw, "\t\r\n\x00") {
		return nil, configurationError(key)
	}
	return strings.Fields(raw), nil
}

func validateServiceSubjectMappings(config Config) error {
	mappings := config.Identity.ServiceSubjects
	if len(mappings) == 0 {
		return nil
	}
	if !needsIdentity(config.Component) || config.Environment != EnvironmentDevelopment && config.Environment != EnvironmentTest || len(mappings) > 32 {
		return ErrInvalidConfiguration
	}
	seen := make(map[string]struct{}, len(mappings))
	for _, mapping := range mappings {
		if !validIdentityPart(mapping.Subject, 512) || !validUUID(mapping.TenantID) {
			return ErrInvalidConfiguration
		}
		if _, duplicate := seen[mapping.Subject]; duplicate {
			return ErrInvalidConfiguration
		}
		seen[mapping.Subject] = struct{}{}
	}
	return nil
}

func modelGatewayClientConfigured(config ModelGatewayClientConfig) bool {
	return config.TokenEndpoint != "" || config.ClientID != "" || config.ClientSecretRef != "" || len(config.Scopes) != 0 || config.Audience != ""
}

func validOAuthClientID(value string) bool {
	return validIdentityPart(value, 256) && !strings.ContainsAny(value, ":")
}

func validOAuthAudience(value string) bool {
	return validIdentityPart(value, 2048)
}

func validOAuthScopes(scopes []string) bool {
	if len(scopes) > 32 {
		return false
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if !validIdentityPart(scope, 256) {
			return false
		}
		if _, duplicate := seen[scope]; duplicate {
			return false
		}
		seen[scope] = struct{}{}
	}
	return true
}

func validIdentityPart(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validSecretReference(reference string) bool {
	parsed, err := url.Parse(reference)
	if err != nil || parsed.Scheme != "secret" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || strings.ContainsAny(reference, "\\\x00") {
		return false
	}
	for _, component := range strings.Split(parsed.Host+parsed.Path, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func validURL(raw string, schemes ...string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Host != "" && oneOf(parsed.Scheme, schemes...) && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validOTLPEndpoint(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Host != "" && oneOf(parsed.Scheme, "http", "https") && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && (parsed.Path == "" || parsed.Path == "/")
}

func validHostPort(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return false
	}
	parsed, err := strconv.Atoi(port)
	return err == nil && parsed > 0 && parsed <= 65535
}

func validListenAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return false
	}
	parsed, err := strconv.Atoi(port)
	return err == nil && parsed > 0 && parsed <= 65535 && !strings.ContainsAny(host, "\r\n")
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || value[14] < '1' || value[14] > '8' || !strings.ContainsRune("89abAB", rune(value[19])) {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !strings.ContainsRune("0123456789abcdefABCDEF", character) {
			return false
		}
	}
	return true
}

func oneOf(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}

func knownComponent(component string) bool {
	return oneOf(component, "aor-server", "aor-model-gateway", "aor-tool-broker", "aor-worker")
}

func validDeploymentProfile(value string) bool {
	return oneOf(value, "LOCAL", "TEST", "PREPRODUCTION", "PRODUCTION")
}

func validKnowledgeRoot(value string) bool {
	return value != "" && len(value) <= 4096 && filepath.IsAbs(value) && filepath.Clean(value) == value && value != string(filepath.Separator) && !strings.ContainsAny(value, "\r\n\x00")
}

func validKnowledgeCuratorURL(value, environment string) bool {
	if value == "" {
		return true
	}
	if len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00\\") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || !oneOf(strings.ToLower(parsed.Scheme), "http", "https") {
		return false
	}
	if strings.Contains(parsed.Path, "..") {
		return false
	}
	return environment != EnvironmentProduction || parsed.Scheme == "https"
}

func validSandboxMountRoots(values []string) bool {
	if len(values) == 0 || len(values) > 16 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validKnowledgeRoot(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validIntegrationConfig(config IntegrationConfig, allowedMountRoots []string, requireDependencyCache bool) bool {
	requiredKinds := map[string]bool{
		"COMPILE": false, "CONTRACT": false, "INTEGRATION": false, "E2E": false, "MIGRATION": false,
	}
	if !validKnowledgeRoot(config.WorkRoot) || len(config.Checks) != len(requiredKinds) || requireDependencyCache && !pathWithinAllowedRoot(config.WorkRoot, allowedMountRoots) {
		return false
	}
	if requireDependencyCache && config.DependencyCache == "" {
		return false
	}
	if config.DependencyCache != "" && (!validKnowledgeRoot(config.DependencyCache) || config.DependencyCache == config.WorkRoot || requireDependencyCache && !pathWithinAllowedRoot(config.DependencyCache, allowedMountRoots)) {
		return false
	}
	totalTimeout := 0
	for _, check := range config.Checks {
		seen, found := requiredKinds[check.Kind]
		if !found || seen || len(check.Argv) == 0 || len(check.Argv) > 64 || check.TimeoutSeconds < 1 || check.TimeoutSeconds > 300 || !validIntegrationExecutable(check.Argv[0]) {
			return false
		}
		for _, argument := range check.Argv[1:] {
			if argument == "" || len(argument) > 4096 || strings.ContainsAny(argument, "\r\n\x00") {
				return false
			}
		}
		requiredKinds[check.Kind] = true
		totalTimeout += check.TimeoutSeconds
	}
	if totalTimeout > 25*60 {
		return false
	}
	for _, found := range requiredKinds {
		if !found {
			return false
		}
	}
	return true
}

func pathWithinAllowedRoot(candidate string, allowedMountRoots []string) bool {
	for _, root := range allowedMountRoots {
		if !validKnowledgeRoot(root) {
			continue
		}
		relative, err := filepath.Rel(root, candidate)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func validIntegrationExecutable(value string) bool {
	return len(value) <= 4096 && filepath.IsAbs(value) && filepath.Clean(value) == value && value != string(filepath.Separator) && !strings.ContainsAny(value, "\r\n\x00")
}

func validSandboxEngineEndpoint(value string) bool {
	if !strings.HasPrefix(value, "unix:///") || strings.ContainsAny(value, "\r\n\x00%") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "unix" || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasPrefix(parsed.Path, "/") || parsed.Path == "/" || strings.Contains(parsed.Path, "//") {
		return false
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return parsed.Path != "/var/run/docker.sock" && parsed.Path != "/run/docker.sock"
}

func validSandboxRuntimeName(value string) bool {
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\r\n\x00/\\") {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validImmutableImageReference(value string) bool {
	separator := strings.LastIndex(value, "@")
	if separator <= 0 || separator == len(value)-1 || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	digest := value[separator+1:]
	if len(digest) != len("sha256:")+64 || !strings.HasPrefix(digest, "sha256:") {
		return false
	}
	for _, character := range strings.TrimPrefix(digest, "sha256:") {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func validSandboxSeccompProfile(value string) bool {
	return value != "" && !strings.EqualFold(value, "unconfined") && !strings.ContainsAny(value, "\r\n\x00")
}

func validSandboxMandatoryPolicy(value string) bool {
	if value == "" || strings.ContainsAny(value, "\r\n\x00") || strings.Contains(strings.ToLower(value), "unconfined") {
		return false
	}
	return (strings.HasPrefix(value, "apparmor=") && len(strings.TrimPrefix(value, "apparmor=")) > 0) || (strings.HasPrefix(value, "label=type:") && len(strings.TrimPrefix(value, "label=type:")) > 0)
}

func validSandboxHoldCommand(command []string) bool {
	if len(command) == 0 || len(command) > 16 || !strings.HasPrefix(command[0], "/") {
		return false
	}
	for _, argument := range command {
		if argument == "" || len(argument) > 4096 || strings.ContainsAny(argument, "\r\n\x00") {
			return false
		}
	}
	return true
}

func validModuleTestCommand(command []string) bool {
	if len(command) == 0 || len(command) > 64 || !validIntegrationExecutable(command[0]) {
		return false
	}
	if oneOf(strings.ToLower(filepath.Base(command[0])), "sh", "bash", "dash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe") {
		return false
	}
	for _, argument := range command[1:] {
		if argument == "" || len(argument) > 4096 || strings.ContainsAny(argument, "\r\n\x00") {
			return false
		}
	}
	return true
}

func needsDatabase(component string) bool {
	return oneOf(component, "aor-server", "aor-model-gateway", "aor-tool-broker", "aor-worker")
}

func needsTemporal(component string) bool {
	return oneOf(component, "aor-server", "aor-worker")
}

func needsNATS(component string) bool {
	return knownComponent(component)
}

func needsS3(component string) bool {
	return component == "aor-server" || component == "aor-tool-broker" || component == "aor-worker"
}

func needsOPA(component string) bool {
	return oneOf(component, "aor-server", "aor-model-gateway", "aor-tool-broker", "aor-worker")
}

func needsIdentity(component string) bool {
	return oneOf(component, "aor-server", "aor-model-gateway", "aor-tool-broker")
}

func needsModelGatewayClient(component string) bool {
	return component == "aor-server" || component == "aor-worker"
}

func configurationError(key string) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfiguration, key)
}
