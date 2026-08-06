package deployment

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"gopkg.in/yaml.v3"
)

var ErrInvalidDeployment = errors.New("invalid deployment profile")

type Profile struct {
	Environment        string
	LinuxIsolation     string
	WindowsIsolation   string
	AuditRetentionDays int
	Replicas           int
	BackupEnabled      bool
}

type ConfigurationEntry struct {
	Path            string          `json:"path"`
	Default         json.RawMessage `json:"default"`
	Constraints     string          `json:"constraints"`
	Sensitive       *bool           `json:"sensitive"`
	ReloadMode      string          `json:"reloadMode"`
	RestartRequired *bool           `json:"restartRequired"`
}

func ValidateConfigurationCatalog(schemaInput, catalogInput []byte) error {
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schemaInput, &schema); err != nil || len(schema.Properties) == 0 {
		return ErrInvalidDeployment
	}
	var catalog struct {
		CatalogVersion int                  `json:"catalogVersion"`
		Entries        []ConfigurationEntry `json:"entries"`
	}
	if err := json.Unmarshal(catalogInput, &catalog); err != nil || catalog.CatalogVersion != 1 || len(catalog.Entries) == 0 {
		return ErrInvalidDeployment
	}
	leaves := make(map[string]struct{})
	for name, property := range schema.Properties {
		if err := collectConfigurationLeaves(name, property, leaves); err != nil {
			return err
		}
	}
	seen := make(map[string]struct{}, len(catalog.Entries))
	for _, entry := range catalog.Entries {
		if _, expected := leaves[entry.Path]; !expected || entry.Path == "" || len(entry.Default) == 0 || !json.Valid(entry.Default) || entry.Constraints == "" || entry.Sensitive == nil || entry.RestartRequired == nil {
			return ErrInvalidDeployment
		}
		if _, duplicate := seen[entry.Path]; duplicate {
			return ErrInvalidDeployment
		}
		switch entry.ReloadMode {
		case "HOT_RELOAD_AUDITED":
			if *entry.RestartRequired {
				return ErrInvalidDeployment
			}
		case "STATIC_RESTART":
			if !*entry.RestartRequired {
				return ErrInvalidDeployment
			}
		case "IMMUTABLE":
			if *entry.RestartRequired {
				return ErrInvalidDeployment
			}
		default:
			return ErrInvalidDeployment
		}
		seen[entry.Path] = struct{}{}
	}
	if len(seen) != len(leaves) {
		return ErrInvalidDeployment
	}
	return nil
}

func collectConfigurationLeaves(prefix string, input json.RawMessage, leaves map[string]struct{}) error {
	var property struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(input, &property); err != nil {
		return ErrInvalidDeployment
	}
	if len(property.Properties) == 0 {
		leaves[prefix] = struct{}{}
		return nil
	}
	for name, child := range property.Properties {
		if err := collectConfigurationLeaves(prefix+"."+name, child, leaves); err != nil {
			return err
		}
	}
	return nil
}

func ValidateCompose(input []byte) error {
	var document struct {
		Services map[string]struct {
			Image       string            `yaml:"image"`
			NetworkMode string            `yaml:"network_mode"`
			Privileged  bool              `yaml:"privileged"`
			ReadOnly    bool              `yaml:"read_only"`
			User        string            `yaml:"user"`
			Volumes     []string          `yaml:"volumes"`
			CapDrop     []string          `yaml:"cap_drop"`
			SecurityOpt []string          `yaml:"security_opt"`
			Environment map[string]string `yaml:"environment"`
			Secrets     []string          `yaml:"secrets"`
			DependsOn   map[string]struct {
				Condition string `yaml:"condition"`
			} `yaml:"depends_on"`
			Healthcheck struct {
				Test []string `yaml:"test"`
			} `yaml:"healthcheck"`
			Build struct {
				Target string `yaml:"target"`
			} `yaml:"build"`
		} `yaml:"services"`
		Secrets map[string]struct{} `yaml:"secrets"`
	}
	var root yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(input))
	if err := decoder.Decode(&root); err != nil {
		return ErrInvalidDeployment
	}
	clearComposeExtensionTags(&root)
	if err := root.Decode(&document); err != nil || len(document.Services) == 0 {
		return ErrInvalidDeployment
	}
	for _, service := range document.Services {
		if service.Privileged || service.NetworkMode == "host" {
			return ErrInvalidDeployment
		}
		for _, volume := range service.Volumes {
			if strings.Contains(volume, "/var/run/docker.sock") || strings.Contains(volume, "containerd.sock") || strings.Contains(volume, "podman.sock") {
				return ErrInvalidDeployment
			}
		}
		for key, value := range service.Environment {
			if strings.Contains(strings.ToLower(key+"="+value), "password=") || strings.Contains(strings.ToLower(key+"="+value), "api_key=") {
				return ErrInvalidDeployment
			}
		}
	}
	worker, workerFound := document.Services["aor-worker"]
	api, apiFound := document.Services["aor-api"]
	curator, curatorFound := document.Services["aor-curator"]
	modelGateway, modelGatewayFound := document.Services["aor-model-gateway"]
	toolBroker, toolBrokerFound := document.Services["aor-tool-broker"]
	identity, identityFound := document.Services["identity"]
	collector, collectorFound := document.Services["otel-collector"]
	if !apiFound || !curatorFound || !modelGatewayFound || !identityFound || !toolBrokerFound || api.Environment["AOR_SERVER_MODE"] != "CONTROL" || curator.Environment["AOR_SERVER_MODE"] != "KNOWLEDGE_CURATOR" || api.Environment["AOR_KNOWLEDGE_ROOT"] != "/var/lib/aor/knowledge" || api.Environment["AOR_KNOWLEDGE_CURATOR_URL"] != "http://aor-curator:8080" || !hasReadOnlyVolume(api.Volumes, "AOR_KNOWLEDGE_HOST_PATH", "/var/lib/aor/knowledge") || curator.Environment["AOR_KNOWLEDGE_CURATOR_URL"] != "" || !hasReadWriteVolume(curator.Volumes, "AOR_KNOWLEDGE_HOST_PATH", "/var/lib/aor/knowledge") || !hasS3Environment(api.Environment) || api.Environment["AOR_DEPLOYMENT_PROFILE"] != "TEST" || api.Environment["AOR_LEASE_SIGNING_KEY_REF"] != "secret://lease_signing_key" || !containsString(api.Secrets, "lease_signing_key") || !hasS3Environment(toolBroker.Environment) || toolBroker.Build.Target != "tool-broker-runtime" || toolBroker.Environment["AOR_REPOSITORY_ROOT"] != "/var/lib/aor/repositories" || !hasVolume(toolBroker.Volumes, "repository-data", "/var/lib/aor/repositories") || !containsString(toolBroker.CapDrop, "ALL") {
		return ErrInvalidDeployment
	}
	apiTelemetry, apiTelemetryFound := api.DependsOn["otel-collector"]
	modelTelemetry, modelTelemetryFound := modelGateway.DependsOn["otel-collector"]
	toolTelemetry, toolTelemetryFound := toolBroker.DependsOn["otel-collector"]
	if !collectorFound || !collector.ReadOnly || collector.User == "" || collector.User == "0" || collector.User == "root" || !isImmutableSHA256Reference(collector.Image) || !hasReadOnlyVolume(collector.Volumes, "otel-collector.compose.yaml", "/etc/otelcol-contrib/config.yaml") || !containsString(collector.CapDrop, "ALL") || !containsString(collector.SecurityOpt, "no-new-privileges:true") || !containsString(collector.Healthcheck.Test, "/otelcol-contrib") || !containsString(collector.Healthcheck.Test, "validate") || !containsString(collector.Healthcheck.Test, "--config=/etc/otelcol-contrib/config.yaml") || !apiTelemetryFound || apiTelemetry.Condition != "service_healthy" || !modelTelemetryFound || modelTelemetry.Condition != "service_healthy" || !toolTelemetryFound || toolTelemetry.Condition != "service_healthy" {
		return ErrInvalidDeployment
	}
	if api.Environment["AOR_MODEL_GATEWAY_URL"] != "http://aor-model-gateway:8080" || api.Environment["AOR_MODEL_GATEWAY_OAUTH_TOKEN_ENDPOINT"] != "http://identity:5556/dex/token" || api.Environment["AOR_MODEL_GATEWAY_OAUTH_CLIENT_ID"] != "aor-server" || api.Environment["AOR_MODEL_GATEWAY_OAUTH_CLIENT_SECRET_REF"] != "secret://aor_server_oauth_client_secret" || api.Environment["AOR_MODEL_GATEWAY_OAUTH_SCOPES"] != "audience:server:client_id:aor-control-plane" || api.Environment["AOR_MODEL_GATEWAY_OAUTH_AUDIENCE"] != "aor-control-plane" || !containsString(api.Secrets, "aor_server_oauth_client_secret") || !containsString(identity.Secrets, "aor_server_oauth_client_secret") || !isImmutableSHA256Reference(identity.Image) {
		return ErrInvalidDeployment
	}
	if modelGateway.Environment["AOR_OIDC_SERVICE_SUBJECTS_JSON"] != `[{"subject":"Cgphb3Itc2VydmVy","tenantId":"11111111-1111-4111-8111-111111111111"}]` || modelGateway.Environment["AOR_OIDC_DEFAULT_TENANT_ID"] != "" || modelGateway.Environment["AOR_OIDC_DEFAULT_ROLE"] != "" {
		return ErrInvalidDeployment
	}
	if !workerFound || !worker.ReadOnly || worker.Build.Target != "worker-runtime" || !containsString(worker.CapDrop, "ALL") || !containsString(worker.SecurityOpt, "no-new-privileges:true") {
		return ErrInvalidDeployment
	}
	if worker.Environment["AOR_LEASE_SIGNING_KEY_REF"] != "secret://lease_signing_key" || !containsString(worker.Secrets, "lease_signing_key") {
		return ErrInvalidDeployment
	}
	if !hasReadOnlyVolume(worker.Volumes, "AOR_KNOWLEDGE_HOST_PATH", "/var/lib/aor/knowledge") || !hasVolume(worker.Volumes, "repository-data", "/var/lib/aor/repositories") {
		return ErrInvalidDeployment
	}
	for name := range document.Secrets {
		if name == "" {
			return ErrInvalidDeployment
		}
	}
	return nil
}

// Compose uses extension tags such as !override to alter merge behavior. They
// do not change the service fields this validator inspects, so preserve the
// parsed value while removing only the tag before decoding into our view.
func clearComposeExtensionTags(node *yaml.Node) {
	if node == nil {
		return
	}
	if strings.HasPrefix(node.Tag, "!") && !strings.HasPrefix(node.Tag, "!!") {
		node.Tag = ""
	}
	for index := range node.Content {
		clearComposeExtensionTags(node.Content[index])
	}
}

func isImmutableSHA256Reference(value string) bool {
	const marker = "@sha256:"
	digestStart := strings.LastIndex(value, marker)
	if digestStart <= 0 || digestStart+len(marker)+64 != len(value) {
		return false
	}
	for _, character := range value[digestStart+len(marker):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func hasVolume(volumes []string, sourceFragment, target string) bool {
	for _, volume := range volumes {
		if strings.Contains(volume, sourceFragment) && strings.Contains(volume, ":"+target) {
			return true
		}
	}
	return false
}

func hasReadOnlyVolume(volumes []string, sourceFragment, target string) bool {
	for _, volume := range volumes {
		if strings.Contains(volume, sourceFragment) && strings.Contains(volume, ":"+target+":ro") {
			return true
		}
	}
	return false
}

func hasReadWriteVolume(volumes []string, sourceFragment, target string) bool {
	for _, volume := range volumes {
		if strings.Contains(volume, sourceFragment) && strings.Contains(volume, ":"+target+":rw") {
			return true
		}
	}
	return false
}

func hasS3Environment(environment map[string]string) bool {
	return environment["AOR_S3_ENDPOINT"] != "" && environment["AOR_S3_BUCKET"] != "" && environment["AOR_S3_REGION"] != "" && strings.HasPrefix(environment["AOR_S3_ACCESS_KEY_REF"], "secret://") && strings.HasPrefix(environment["AOR_S3_SECRET_KEY_REF"], "secret://")
}

func ValidateHelmValues(input []byte) error {
	var document struct {
		ReplicaCount    int `yaml:"replicaCount"`
		SecurityContext struct {
			RunAsNonRoot           bool `yaml:"runAsNonRoot"`
			ReadOnlyRootFilesystem bool `yaml:"readOnlyRootFilesystem"`
		} `yaml:"securityContext"`
		Sandbox struct {
			LinuxLevel                     string `yaml:"linuxLevel"`
			WindowsLevel                   string `yaml:"windowsLevel"`
			AllowWindowsUntrustedExecution bool   `yaml:"allowWindowsUntrustedExecution"`
		} `yaml:"sandbox"`
		Audit struct {
			RetentionDays int `yaml:"retentionDays"`
		} `yaml:"audit"`
	}
	if err := yaml.Unmarshal(input, &document); err != nil || document.ReplicaCount < 1 || !document.SecurityContext.RunAsNonRoot || !document.SecurityContext.ReadOnlyRootFilesystem || document.Sandbox.LinuxLevel != "CONTAINER" || document.Sandbox.WindowsLevel != "NONE" || document.Sandbox.AllowWindowsUntrustedExecution || document.Audit.RetentionDays < 400 {
		return ErrInvalidDeployment
	}
	return nil
}

func ValidateWindowsProfile(input []byte) error {
	var document map[string]any
	decoder := yaml.NewDecoder(bytes.NewReader(input))
	if err := decoder.Decode(&document); err != nil {
		return ErrInvalidDeployment
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return ErrInvalidDeployment
	}
	text := strings.ToLower(string(encoded))
	if !strings.Contains(text, `"isolationlevel":"none"`) || strings.Contains(text, "container") || strings.Contains(text, "vm") || strings.Contains(text, "docker") || strings.Contains(text, "password") {
		return ErrInvalidDeployment
	}
	return nil
}
