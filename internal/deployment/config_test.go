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
		"postgres_app_password", "000003_runtime_app_role.up.sql", "000004_model_authorizer_reads.up.sql", "000013_workflow_activity_results.up.sql", "000014_project_initialization_selection.up.sql", "000015_model_call_replays.up.sql", "model_provider_deepseek_key",
		"AOR_MODEL_REPLAY_KEY_REF: secret://model_replay_key", "model_replay_key",
		"provider\":\"deepseek", "ghcr.io/dexidp/dex:v2.45.1@sha256:",
		"AOR_OIDC_JWKS_URL: http://identity:5556/dex/keys", "AOR_OIDC_DEFAULT_ROLE: USER",
		"AOR_OPA_URL: http://opa:8181",
		"aor-sandbox-runtime:", "aor-sandbox-preflight:", "target: worker-runtime",
		"AOR_SANDBOX_ENGINE_ENDPOINT: unix:///run/aor-sandbox/engine.sock", "apparmor=aor-sandbox",
		"sandbox-preflight.sh", "AOR_SANDBOX_ENGINE_SOCKET", "network_mode: none",
		"AOR_SANDBOX_ALLOWED_MOUNT_ROOTS_JSON", "AOR_SANDBOX_SHARED_ROOT",
		"AOR_LEASE_SIGNING_KEY_REF: secret://lease_signing_key",
		"000010_outbox_tenant_discovery.up.sql", "000012_artifact_project_uri_scope.up.sql",
		"000017_relational_projection_sync.up.sql", "000018_repository_submissions.up.sql", "000019_model_usage_reconciliation.up.sql", "000020_repository_registry.up.sql",
		"target: tool-broker-runtime", "AOR_REPOSITORY_ROOT: /var/lib/aor/repositories", "repository-data:/var/lib/aor/repositories",
	} {
		if !strings.Contains(composeText, value) {
			t.Errorf("compose missing %q", value)
		}
	}
	dockerfile, err := os.ReadFile("../../deploy/compose/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"FROM ${GO_IMAGE} AS tool-broker-runtime", "git=2.52.0-r0", "USER 65532:65532"} {
		if !strings.Contains(string(dockerfile), value) {
			t.Errorf("Dockerfile missing %q", value)
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
		{old: "golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc", new: "golang:1.26.5-alpine3.23"},
		{old: "docker:29.6.1-cli@sha256:862099ada15c669000bef53aa4cb9d821262829f45b0dda2159ccb276443043b", new: "docker:29.6.1-cli"},
		{old: "AOR_SANDBOX_SECCOMP_PROFILE: builtin", new: "AOR_SANDBOX_SECCOMP_PROFILE: unconfined"},
		{old: "AOR_SANDBOX_MANDATORY_POLICY: apparmor=aor-sandbox", new: "AOR_SANDBOX_MANDATORY_POLICY: apparmor=unconfined"},
		{old: "${AOR_SANDBOX_ENGINE_SOCKET:?Set AOR_SANDBOX_ENGINE_SOCKET to the rootless engine socket}:/run/aor-sandbox/engine.sock", new: "/var/run/docker.sock:/run/aor-sandbox/engine.sock"},
		{old: "AOR_SANDBOX_ALLOWED_MOUNT_ROOTS_JSON: '[\"${AOR_SANDBOX_SHARED_ROOT:?Set AOR_SANDBOX_SHARED_ROOT to an absolute host path shared with the rootless engine}\"]'", new: "AOR_SANDBOX_ALLOWED_MOUNT_ROOTS_JSON: '[\"/\"]'"},
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

func TestComposeArtifactAndKnowledgeDependenciesCannotBeDropped(t *testing.T) {
	compose, err := os.ReadFile("../../deploy/compose/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	composeText := string(compose)
	for _, replacement := range []struct {
		old string
		new string
	}{
		{old: "AOR_KNOWLEDGE_ROOT: /var/lib/aor/knowledge", new: "AOR_KNOWLEDGE_ROOT: /tmp/knowledge"},
		{old: ":/var/lib/aor/knowledge:ro", new: ":/var/lib/aor/knowledge:rw"},
	} {
		candidate := strings.Replace(composeText, replacement.old, replacement.new, 1)
		if candidate == composeText || ValidateCompose([]byte(candidate)) == nil {
			t.Fatalf("compose dependency downgrade %q accepted", replacement.new)
		}
	}

	brokerStart := strings.Index(composeText, "\n  aor-tool-broker:")
	workerStart := strings.Index(composeText, "\n  aor-worker:")
	if brokerStart < 0 || workerStart <= brokerStart {
		t.Fatal("compose tool broker section not found")
	}
	brokerSection := composeText[brokerStart:workerStart]
	withoutS3 := strings.Replace(brokerSection, "AOR_S3_ACCESS_KEY_REF: secret://minio_root_user", "AOR_S3_ACCESS_KEY_REF: missing", 1)
	if withoutS3 == brokerSection {
		t.Fatal("tool broker S3 fixture not found")
	}
	candidate := composeText[:brokerStart] + withoutS3 + composeText[workerStart:]
	if ValidateCompose([]byte(candidate)) == nil {
		t.Fatal("compose tool broker without S3 credentials accepted")
	}
}

func TestComposeControlAPICannotDropLeaseAuthorityConfiguration(t *testing.T) {
	compose, err := os.ReadFile("../../deploy/compose/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	composeText := string(compose)
	for _, replacement := range []struct {
		old string
		new string
	}{
		{old: "AOR_DEPLOYMENT_PROFILE: TEST", new: "AOR_DEPLOYMENT_PROFILE: missing"},
		{old: "AOR_LEASE_SIGNING_KEY_REF: secret://lease_signing_key", new: "AOR_LEASE_SIGNING_KEY_REF: missing"},
		{old: "secrets: [postgres_app_password, lease_signing_key, minio_root_user, minio_root_password]", new: "secrets: [postgres_app_password, minio_root_user, minio_root_password]"},
	} {
		candidate := strings.Replace(composeText, replacement.old, replacement.new, 1)
		if candidate == composeText || ValidateCompose([]byte(candidate)) == nil {
			t.Fatalf("compose lease authority downgrade %q accepted", replacement.new)
		}
	}
}
