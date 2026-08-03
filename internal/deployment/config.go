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
			NetworkMode string            `yaml:"network_mode"`
			Privileged  bool              `yaml:"privileged"`
			Volumes     []string          `yaml:"volumes"`
			Environment map[string]string `yaml:"environment"`
		} `yaml:"services"`
		Secrets map[string]struct{} `yaml:"secrets"`
	}
	if err := yaml.Unmarshal(input, &document); err != nil || len(document.Services) == 0 {
		return ErrInvalidDeployment
	}
	for name, service := range document.Services {
		if service.Privileged || service.NetworkMode == "host" {
			return ErrInvalidDeployment
		}
		for _, volume := range service.Volumes {
			if strings.Contains(volume, "/var/run/docker.sock") || strings.Contains(volume, "docker.sock") {
				return ErrInvalidDeployment
			}
		}
		for key, value := range service.Environment {
			if strings.Contains(strings.ToLower(key+"="+value), "password=") || strings.Contains(strings.ToLower(key+"="+value), "api_key=") {
				return ErrInvalidDeployment
			}
		}
		if name == "aor-worker" && service.NetworkMode == "host" {
			return ErrInvalidDeployment
		}
	}
	for name := range document.Secrets {
		if name == "" {
			return ErrInvalidDeployment
		}
	}
	return nil
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
