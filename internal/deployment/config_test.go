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
		"postgres_app_password", "000003_runtime_app_role.up.sql", "000004_model_authorizer_reads.up.sql", "model_provider_deepseek_key",
		"provider\":\"deepseek", "ghcr.io/dexidp/dex:v2.45.1@sha256:",
		"AOR_OIDC_JWKS_URL: http://identity:5556/dex/keys", "AOR_OIDC_DEFAULT_ROLE: USER",
		"AOR_OPA_URL: http://opa:8181",
		"aor-sandbox-runtime:", "aor-sandbox-preflight:", "target: worker-runtime",
		"AOR_SANDBOX_ENGINE_ENDPOINT: unix:///run/aor-sandbox/engine.sock", "apparmor=aor-sandbox",
		"sandbox-preflight.sh", "AOR_SANDBOX_ENGINE_SOCKET", "network_mode: none",
		"000010_outbox_tenant_discovery.up.sql",
	} {
		if !strings.Contains(composeText, value) {
			t.Errorf("compose missing %q", value)
		}
	}
	dex, err := os.ReadFile("../../deploy/compose/dex.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"issuer: http://127.0.0.1:5556/dex", "id: aor-control-plane", "type: mockCallback"} {
		if !strings.Contains(string(dex), value) {
			t.Errorf("Dex config missing %q", value)
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

func TestComposeSandboxRuntimeCannotDowngradeIsolation(t *testing.T) {
	compose, err := os.ReadFile("../../deploy/compose/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []struct {
		old string
		new string
	}{
		{old: "target: worker-runtime", new: "target: runtime"},
		{old: "user: \"65532:65532\"", new: "user: root"},
		{old: "golang:1.26.0-alpine3.23@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5", new: "golang:1.26.0-alpine3.23"},
		{old: "docker:29.6.1-cli@sha256:862099ada15c669000bef53aa4cb9d821262829f45b0dda2159ccb276443043b", new: "docker:29.6.1-cli"},
		{old: "AOR_SANDBOX_SECCOMP_PROFILE: builtin", new: "AOR_SANDBOX_SECCOMP_PROFILE: unconfined"},
		{old: "AOR_SANDBOX_MANDATORY_POLICY: apparmor=aor-sandbox", new: "AOR_SANDBOX_MANDATORY_POLICY: apparmor=unconfined"},
		{old: "${AOR_SANDBOX_ENGINE_SOCKET:?Set AOR_SANDBOX_ENGINE_SOCKET to the rootless engine socket}:/run/aor-sandbox/engine.sock", new: "/var/run/docker.sock:/run/aor-sandbox/engine.sock"},
	} {
		candidate := strings.Replace(string(compose), replacement.old, replacement.new, 1)
		if candidate == string(compose) {
			t.Fatalf("fixture does not contain %q", replacement.old)
		}
		if ValidateCompose([]byte(candidate)) == nil {
			t.Fatalf("compose downgrade %q accepted", replacement.new)
		}
	}
}
