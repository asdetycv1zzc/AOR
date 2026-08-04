package deployment

import (
	"os"
	"strings"
	"testing"
)

func TestDeploymentProfilesFailClosed(t *testing.T) {
	compose, err := os.ReadFile("../../deploy/compose/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCompose(compose); err != nil {
		t.Fatal(err)
	}
	composeText := string(compose)
	for _, value := range []string{
		"AOR_DATABASE_USER: aor_app", "AOR_DATABASE_PASSWORD_REF: secret://postgres_app_password",
		"postgres_app_password", "000003_runtime_app_role.up.sql", "model_provider_deepseek_key",
		"provider\":\"deepseek",
	} {
		if !strings.Contains(composeText, value) {
			t.Errorf("compose missing %q", value)
		}
	}
	for _, value := range []string{"AOR_DATABASE_USER: aor\n", "model_provider_anthropic_key", "provider\":\"anthropic"} {
		if strings.Contains(composeText, value) {
			t.Errorf("compose contains forbidden runtime setting %q", value)
		}
	}
	values, err := os.ReadFile("../../deploy/helm/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateHelmValues(values); err != nil {
		t.Fatal(err)
	}
	windows, err := os.ReadFile("../../deploy/windows/worker.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateWindowsProfile(windows); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationCatalogCoversEverySchemaField(t *testing.T) {
	schema, err := os.ReadFile("../../api/json-schema/aor-configuration.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := os.ReadFile("../../deploy/configuration-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfigurationCatalog(schema, catalog); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationCatalogRejectsMissingAndContradictoryMetadata(t *testing.T) {
	schema := []byte(`{"properties":{"value":{"type":"integer"}}}`)
	missing := []byte(`{"catalogVersion":1,"entries":[]}`)
	if ValidateConfigurationCatalog(schema, missing) == nil {
		t.Fatal("empty configuration catalog accepted")
	}
	contradictory := []byte(`{"catalogVersion":1,"entries":[{"path":"value","default":1,"constraints":"positive","sensitive":false,"reloadMode":"HOT_RELOAD_AUDITED","restartRequired":true}]}`)
	if ValidateConfigurationCatalog(schema, contradictory) == nil {
		t.Fatal("contradictory reload metadata accepted")
	}
}

func TestDeploymentRejectsPrivilegedAndWrongWindowsProfiles(t *testing.T) {
	if ValidateCompose([]byte("services:\n  worker:\n    privileged: true\n")) == nil {
		t.Fatal("privileged compose accepted")
	}
	if ValidateHelmValues([]byte("replicaCount: 1\nsecurityContext:\n  runAsNonRoot: true\n  readOnlyRootFilesystem: true\nsandbox:\n  linuxLevel: NONE\n  windowsLevel: CONTAINER\n  allowWindowsUntrustedExecution: true\naudit:\n  retentionDays: 1\n")) == nil {
		t.Fatal("unsafe helm values accepted")
	}
}
