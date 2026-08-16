package deployment

import (
	"encoding/json"
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
		"provider\":\"deepseek", "ghcr.io/dexidp/dex:master-alpine@sha256:",
		"AOR_OIDC_JWKS_URL: http://127.0.0.1:5556/dex/keys", "AOR_OIDC_DEFAULT_ROLE: USER",
		"AOR_MODEL_GATEWAY_OAUTH_CLIENT_SECRET_REF: secret://aor_server_oauth_client_secret", "AOR_OIDC_SERVICE_SUBJECTS_JSON",
		"AOR_GOAL_PLAN_ROUTES_JSON", "supportsJsonSchema\":true",
		"AOR_OPA_URL: http://127.0.0.1:8181", "target: worker-runtime", "cap_drop: [ALL]",
		"security_opt: [no-new-privileges:true]", "AOR_EXECUTOR_ROUTE_JSON", "AOR_MODULE_AUDITOR_ROUTE_JSON",
		"AOR_LEASE_SIGNING_KEY_REF: secret://lease_signing_key",
		"aor-curator:", "network_mode: host", "AOR_SERVER_MODE: CONTROL", "AOR_SERVER_MODE: KNOWLEDGE_CURATOR", "AOR_KNOWLEDGE_CURATOR_URL: http://127.0.0.1:8094",
		"otel-collector:", "otel/opentelemetry-collector-contrib:0.157.0@sha256:", "otel-collector.compose.yaml:/etc/otelcol-contrib/config.yaml:ro",
		"000010_outbox_tenant_discovery.up.sql", "000012_artifact_project_uri_scope.up.sql",
		"000017_relational_projection_sync.up.sql", "000018_repository_submissions.up.sql", "000019_model_usage_reconciliation.up.sql", "000020_repository_registry.up.sql", "000021_event_replay_state.up.sql", "000022_project_agent_leases.up.sql", "000023_staged_module_planning.up.sql",
		"target: tool-broker-runtime", "AOR_REPOSITORY_ROOT: /var/lib/aor/repositories", "AOR_PROJECTS_HOST_PATH",
	} {
		if !strings.Contains(composeText, value) {
			t.Errorf("compose missing %q", value)
		}
	}
	dockerfile, err := os.ReadFile("../../deploy/compose/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"FROM ${ALPINE_IMAGE} AS tool-broker-runtime", "git=2.52.0-r0", "USER 65532:65532"} {
		if !strings.Contains(string(dockerfile), value) {
			t.Errorf("Dockerfile missing %q", value)
		}
	}
	dex, err := os.ReadFile("../../deploy/compose/dex.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"issuer: http://127.0.0.1:5556/dex", "id: aor-control-plane", "id: aor-server", "client_credentials", "type: mockCallback"} {
		if !strings.Contains(string(dex), value) {
			t.Errorf("Dex config missing %q", value)
		}
	}
	for _, value := range []string{"AOR_DATABASE_USER: aor\n", "model_provider_anthropic_key", "provider\":\"anthropic"} {
		if strings.Contains(composeText, value) {
			t.Errorf("compose contains forbidden runtime setting %q", value)
		}
	}
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"COMPOSE_DEPENDENCIES = postgres temporal temporal-ui nats minio opa identity otel-collector", "compose-aor-up: compose-deps-up"} {
		if !strings.Contains(string(makefile), value) {
			t.Errorf("Makefile missing ordered Compose startup setting %q", value)
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

func TestComposeStartupIncludesToolchainServices(t *testing.T) {
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"COMPOSE_AOR = aor-api aor-curator aor-model-gateway aor-tool-broker aor-worker aor-toolchain-prober aor-toolchain-provisioner",
		"--profile aor build aor-toolchain-prober",
		"--profile aor build aor-toolchain-provisioner",
	} {
		if !strings.Contains(string(makefile), value) {
			t.Errorf("Makefile missing toolchain service startup setting %q", value)
		}
	}
}

func TestComposeTelemetryDependencyCannotBeDropped(t *testing.T) {
	compose, err := os.ReadFile("../../deploy/compose/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	composeText := string(compose)
	for _, replacement := range []struct {
		old string
		new string
	}{
		{old: "otel/opentelemetry-collector-contrib:0.157.0@sha256:f2f01157055a9b2aab9df7118e1f1c9abf345e99b23bc7a2bc791db374a7d0f6", new: "otel/opentelemetry-collector-contrib:0.157.0"},
		{old: "otel-collector.compose.yaml:/etc/otelcol-contrib/config.yaml:ro", new: "otel-collector.compose.yaml:/tmp/config.yaml:ro"},
		{old: "otel-collector:\n        condition: service_healthy", new: "otel-collector:\n        condition: service_started"},
	} {
		candidate := strings.Replace(composeText, replacement.old, replacement.new, 1)
		if candidate == composeText || ValidateCompose([]byte(candidate)) == nil {
			t.Fatalf("compose telemetry downgrade %q accepted", replacement.new)
		}
	}
}

func TestComposeAppliesEveryManifestMigration(t *testing.T) {
	manifestJSON, err := os.ReadFile("../../migrations/postgres/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Migrations []struct {
			File string `json:"file"`
		} `json:"migrations"`
	}
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		t.Fatal(err)
	}
	compose, err := os.ReadFile("../../deploy/compose/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	composeText := string(compose)
	lastExecution := -1
	lastMount := -1
	for _, migration := range manifest.Migrations {
		execution := "--file /migrations/" + migration.File
		executionIndex := strings.Index(composeText, execution)
		if executionIndex < 0 {
			t.Errorf("compose does not execute manifest migration %q", migration.File)
		} else if executionIndex <= lastExecution {
			t.Errorf("compose executes manifest migration %q out of order", migration.File)
		}
		lastExecution = executionIndex

		mount := "../../migrations/postgres/" + migration.File + ":/migrations/" + migration.File + ":ro"
		mountIndex := strings.Index(composeText, mount)
		if mountIndex < 0 {
			t.Errorf("compose does not mount manifest migration %q read-only", migration.File)
		} else if mountIndex <= lastMount {
			t.Errorf("compose mounts manifest migration %q out of order", migration.File)
		}
		lastMount = mountIndex
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

func TestComposeWorkerCannotDowngradeIsolation(t *testing.T) {
	compose, err := os.ReadFile("../../deploy/compose/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []struct {
		old string
		new string
	}{
		{old: "target: worker-runtime", new: "target: runtime"},
		{old: "cap_drop: [ALL]", new: "cap_drop: []"},
		{old: "security_opt: [no-new-privileges:true]", new: "security_opt: []"},
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
		{old: "AOR_KNOWLEDGE_CURATOR_URL: http://127.0.0.1:8094", new: "AOR_KNOWLEDGE_CURATOR_URL: \"\""},
		{old: "AOR_SERVER_MODE: KNOWLEDGE_CURATOR", new: "AOR_SERVER_MODE: CONTROL"},
		{old: ":/var/lib/aor/knowledge:rw", new: ":/var/lib/aor/knowledge:ro"},
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
		{old: "secrets: [postgres_app_password, lease_signing_key, minio_root_user, minio_root_password, aor_server_oauth_client_secret]", new: "secrets: [postgres_app_password, minio_root_user, minio_root_password, aor_server_oauth_client_secret]"},
	} {
		candidate := strings.Replace(composeText, replacement.old, replacement.new, 1)
		if candidate == composeText || ValidateCompose([]byte(candidate)) == nil {
			t.Fatalf("compose lease authority downgrade %q accepted", replacement.new)
		}
	}
}

func TestComposeModelGatewayWorkloadIdentityCannotBeDropped(t *testing.T) {
	compose, err := os.ReadFile("../../deploy/compose/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	composeText := string(compose)
	for _, replacement := range []struct {
		old string
		new string
	}{
		{old: "AOR_MODEL_GATEWAY_OAUTH_CLIENT_ID: aor-server", new: "AOR_MODEL_GATEWAY_OAUTH_CLIENT_ID: missing"},
		{old: "AOR_MODEL_GATEWAY_OAUTH_CLIENT_SECRET_REF: secret://aor_server_oauth_client_secret", new: "AOR_MODEL_GATEWAY_OAUTH_CLIENT_SECRET_REF: missing"},
		{old: "AOR_MODEL_GATEWAY_OAUTH_SCOPES: audience:server:client_id:aor-control-plane", new: "AOR_MODEL_GATEWAY_OAUTH_SCOPES: openid"},
		{old: "AOR_OIDC_SERVICE_SUBJECTS_JSON: '[{\"subject\":\"Cgphb3Itc2VydmVy\",\"tenantId\":\"11111111-1111-4111-8111-111111111111\"}]'", new: "AOR_OIDC_SERVICE_SUBJECTS_JSON: '[]'"},
	} {
		candidate := strings.Replace(composeText, replacement.old, replacement.new, 1)
		if candidate == composeText || ValidateCompose([]byte(candidate)) == nil {
			t.Fatalf("compose workload identity downgrade %q accepted", replacement.new)
		}
	}
}
