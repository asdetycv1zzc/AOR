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
