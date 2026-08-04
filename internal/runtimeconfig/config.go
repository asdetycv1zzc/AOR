package runtimeconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
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
	Component     string
	Environment   string
	ListenAddress string
	Database      DatabaseConfig
	Temporal      TemporalConfig
	NATS          NATSConfig
	S3            S3Config
	OPA           OPAConfig
	ModelGateway  ModelGatewayConfig
	Services      ServiceEndpoints
	Sandbox       SandboxConfig
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

type OPAConfig struct {
	URL string
}

type ModelGatewayConfig struct {
	Providers []ProviderConfig
}

type ProviderConfig struct {
	ID                   string   `json:"id"`
	Provider             string   `json:"provider"`
	BaseURL              string   `json:"baseUrl"`
	APIKeyRef            string   `json:"apiKeyRef"`
	Models               []string `json:"models"`
	InputMicrosPerToken  int64    `json:"inputMicrosPerToken"`
	OutputMicrosPerToken int64    `json:"outputMicrosPerToken"`
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
}

func Load(component string, lookup LookupEnv) (Config, error) {
	if lookup == nil || !knownComponent(component) {
		return Config{}, ErrInvalidConfiguration
	}
	config := Config{
		Component:     component,
		Environment:   value(lookup, "AOR_ENVIRONMENT", EnvironmentDevelopment),
		ListenAddress: value(lookup, "AOR_LISTEN_ADDR", ":8080"),
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
		Services: ServiceEndpoints{
			API:          value(lookup, "AOR_API_URL", "http://aor-api:8080"),
			ModelGateway: value(lookup, "AOR_MODEL_GATEWAY_URL", "http://aor-model-gateway:8080"),
			ToolBroker:   value(lookup, "AOR_TOOL_BROKER_URL", "http://aor-tool-broker:8080"),
		},
		Sandbox: SandboxConfig{
			LinuxLevel:                   value(lookup, "AOR_SANDBOX_LINUX_LEVEL", "CONTAINER"),
			WindowsLevel:                 value(lookup, "AOR_SANDBOX_WINDOWS_LEVEL", "NONE"),
			LinuxDefaultNetworkMode:      value(lookup, "AOR_SANDBOX_LINUX_NETWORK_MODE", "DENY_ALL"),
			WindowsNetworkIsolationLevel: value(lookup, "AOR_SANDBOX_WINDOWS_NETWORK_ISOLATION", "NONE"),
		},
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
	if raw, found := lookup("AOR_MODEL_PROVIDERS_JSON"); found && strings.TrimSpace(raw) != "" {
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config.ModelGateway.Providers); err != nil {
			return Config{}, configurationError("AOR_MODEL_PROVIDERS_JSON")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return Config{}, configurationError("AOR_MODEL_PROVIDERS_JSON")
		}
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config Config) Validate() error {
	if !knownComponent(config.Component) || !oneOf(config.Environment, EnvironmentDevelopment, EnvironmentTest, EnvironmentPreproduction, EnvironmentProduction) || !validListenAddress(config.ListenAddress) {
		return ErrInvalidConfiguration
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
	if config.Environment == EnvironmentProduction {
		if (needsS3(config.Component) && !strings.HasPrefix(config.S3.Endpoint, "https://")) || (needsOPA(config.Component) && !strings.HasPrefix(config.OPA.URL, "https://")) || (needsNATS(config.Component) && !strings.HasPrefix(config.NATS.URL, "tls://")) {
			return ErrInvalidConfiguration
		}
	}
	if config.Component == "aor-model-gateway" {
		if err := validateProviders(config.ModelGateway.Providers); err != nil {
			return err
		}
	}
	if config.Component == "aor-worker" {
		if !validURL(config.Services.API, "http", "https") || !validURL(config.Services.ModelGateway, "http", "https") || !validURL(config.Services.ToolBroker, "http", "https") {
			return ErrInvalidConfiguration
		}
		if config.Sandbox.LinuxLevel != "CONTAINER" || config.Sandbox.WindowsLevel != "NONE" || config.Sandbox.AllowWindowsUntrusted || config.Sandbox.LinuxDefaultNetworkMode != "DENY_ALL" || config.Sandbox.WindowsNetworkIsolationLevel != "NONE" {
			return ErrInvalidConfiguration
		}
	}
	return nil
}

func validateProviders(providers []ProviderConfig) error {
	if len(providers) < 2 {
		return ErrInvalidConfiguration
	}
	ids := make(map[string]struct{}, len(providers))
	families := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		if provider.ID == "" || provider.Provider == "" || !validURL(provider.BaseURL, "http", "https") || !validSecretReference(provider.APIKeyRef) || len(provider.Models) == 0 || provider.InputMicrosPerToken < 0 || provider.OutputMicrosPerToken < 0 {
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
	}
	if len(families) < 2 {
		return ErrInvalidConfiguration
	}
	return nil
}

func value(lookup LookupEnv, key, fallback string) string {
	if current, found := lookup(key); found {
		return strings.TrimSpace(current)
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

func needsDatabase(component string) bool {
	return oneOf(component, "aor-server", "aor-model-gateway", "aor-worker")
}

func needsTemporal(component string) bool {
	return oneOf(component, "aor-server", "aor-worker")
}

func needsNATS(component string) bool {
	return knownComponent(component)
}

func needsS3(component string) bool {
	return component == "aor-server" || component == "aor-worker"
}

func needsOPA(component string) bool {
	return oneOf(component, "aor-server", "aor-tool-broker", "aor-worker")
}

func configurationError(key string) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfiguration, key)
}
