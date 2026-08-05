package runtimeconfig

import (
	"errors"
	"testing"
)

func TestLoadServerConfiguration(t *testing.T) {
	config, err := Load("aor-server", environment(validServerEnvironment()))
	if err != nil {
		t.Fatalf("load server config: %v", err)
	}
	if config.Database.Address() != "postgres:5432" || config.Temporal.Namespace != "aor" || config.NATS.Stream != "AOR_EVENTS" || !config.S3.UsePathStyle || config.KnowledgeRoot != "/var/lib/aor/knowledge" || config.ModelGatewayClient.ClientID != "aor-server" || len(config.GoalPlan.Routes) != 4 {
		t.Fatalf("unexpected defaults: %+v", config)
	}
}

func TestServerRequiresExactGoalPlanRoutes(t *testing.T) {
	valid := validServerEnvironment()
	config, err := Load("aor-server", environment(valid))
	if err != nil {
		t.Fatal(err)
	}
	if route := config.GoalPlan.Routes["MODULE_PLANNER"]; route.Provider != "primary" || route.Model != "model-a" || route.MaxAttempts != 3 {
		t.Fatalf("module planner route = %#v", route)
	}

	for _, value := range []string{
		`{}`,
		`{"GOAL_PROPOSER":{"provider":"primary","model":"model-a","maxOutputTokens":4096,"temperature":0,"providerPolicy":"default","cachePolicy":"NO_STORE","worstCaseCostMicros":0,"maxAttempts":3}}`,
		`{"GOAL_PROPOSER":{"provider":"primary","model":"model-a","maxOutputTokens":4096,"temperature":0,"providerPolicy":"default","cachePolicy":"NO_STORE","worstCaseCostMicros":0,"maxAttempts":3,"unknown":true}}`,
		validGoalPlanRoutesJSON() + ` {}`,
	} {
		values := validServerEnvironment()
		values["AOR_GOAL_PLAN_ROUTES_JSON"] = value
		if _, err := Load("aor-server", environment(values)); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("routes %q error = %v", value, err)
		}
	}

	values := validServerEnvironment()
	delete(values, "AOR_GOAL_PLAN_ROUTES_JSON")
	if _, err := Load("aor-server", environment(values)); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("missing routes error = %v", err)
	}
}

func TestLoadModelGatewayOAuthClientConfiguration(t *testing.T) {
	values := validServerEnvironment()
	values["AOR_MODEL_GATEWAY_OAUTH_SCOPES"] = "profile audience:server:client_id:aor-control-plane"
	config, err := Load("aor-server", environment(values))
	if err != nil {
		t.Fatal(err)
	}
	if config.ModelGatewayClient.TokenEndpoint != "http://identity:5556/dex/token" || config.ModelGatewayClient.ClientSecretRef != "secret://aor_server_oauth_client_secret" || len(config.ModelGatewayClient.Scopes) != 2 || config.ModelGatewayClient.Audience != "aor-control-plane" {
		t.Fatalf("model gateway client config = %#v", config.ModelGatewayClient)
	}
}

func TestServerRequiresCompleteModelGatewayOAuthClientConfiguration(t *testing.T) {
	for _, key := range []string{
		"AOR_MODEL_GATEWAY_OAUTH_TOKEN_ENDPOINT",
		"AOR_MODEL_GATEWAY_OAUTH_CLIENT_ID",
		"AOR_MODEL_GATEWAY_OAUTH_CLIENT_SECRET_REF",
		"AOR_MODEL_GATEWAY_OAUTH_AUDIENCE",
	} {
		values := validServerEnvironment()
		delete(values, key)
		if _, err := Load("aor-server", environment(values)); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("missing %s error = %v", key, err)
		}
	}

	for _, scopes := range []string{"scope\nother", "scope scope", "scope\tother"} {
		values := validServerEnvironment()
		values["AOR_MODEL_GATEWAY_OAUTH_SCOPES"] = scopes
		if _, err := Load("aor-server", environment(values)); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("scopes %q error = %v", scopes, err)
		}
	}
}

func TestServiceSubjectMappingsAreExactAndTestOnly(t *testing.T) {
	const mappings = `[{"subject":"Cgphb3Itc2VydmVy","tenantId":"11111111-1111-4111-8111-111111111111"}]`
	values := map[string]string{
		"AOR_DATABASE_PASSWORD_REF":      "secret://postgres/password",
		"AOR_MODEL_PROVIDERS_JSON":       validModelProvidersJSON(),
		"AOR_OIDC_SERVICE_SUBJECTS_JSON": mappings,
	}
	config, err := Load("aor-model-gateway", environment(values))
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Identity.ServiceSubjects) != 1 || config.Identity.ServiceSubjects[0].Subject != "Cgphb3Itc2VydmVy" {
		t.Fatalf("service mappings = %#v", config.Identity.ServiceSubjects)
	}

	values["AOR_ENVIRONMENT"] = EnvironmentPreproduction
	if _, err := Load("aor-model-gateway", environment(values)); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("preproduction service mapping error = %v", err)
	}

	values["AOR_ENVIRONMENT"] = EnvironmentTest
	values["AOR_OIDC_SERVICE_SUBJECTS_JSON"] = `[{"subject":"same","tenantId":"11111111-1111-4111-8111-111111111111"},{"subject":"same","tenantId":"22222222-2222-4222-8222-222222222222"}]`
	if _, err := Load("aor-model-gateway", environment(values)); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("duplicate service mapping error = %v", err)
	}

	values["AOR_OIDC_SERVICE_SUBJECTS_JSON"] = `[{"subject":"service","tenantId":"11111111-1111-4111-8111-111111111111","role":"USER"}]`
	if _, err := Load("aor-model-gateway", environment(values)); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("configurable service role error = %v", err)
	}
}

func TestToolBrokerRequiresDatabaseConfiguration(t *testing.T) {
	if _, err := Load("aor-tool-broker", environment(nil)); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("missing tool broker database error = %v", err)
	}
	config, err := Load("aor-tool-broker", environment(map[string]string{"AOR_DATABASE_PASSWORD_REF": "secret://postgres/password", "AOR_LEASE_SIGNING_KEY_REF": "secret://authz/lease-signing-key", "AOR_DEPLOYMENT_PROFILE": "TEST", "AOR_S3_ACCESS_KEY_REF": "secret://minio/access-key", "AOR_S3_SECRET_KEY_REF": "secret://minio/secret-key"}))
	if err != nil || config.Database.PasswordRef == "" || config.S3.AccessKeyRef == "" || config.S3.SecretKeyRef == "" || config.RepositoryRoot != "/var/lib/aor/repositories" {
		t.Fatalf("tool broker config database=%#v s3=%#v err=%v", config.Database, config.S3, err)
	}
}

func TestToolBrokerRejectsUnsafeRepositoryRoot(t *testing.T) {
	for _, root := range []string{"relative/repositories", "/", "/var/lib/aor/../repositories", "/var/lib/aor/repositories\n"} {
		_, err := Load("aor-tool-broker", environment(map[string]string{
			"AOR_DATABASE_PASSWORD_REF": "secret://postgres/password",
			"AOR_LEASE_SIGNING_KEY_REF": "secret://authz/lease-signing-key",
			"AOR_DEPLOYMENT_PROFILE":    "TEST",
			"AOR_S3_ACCESS_KEY_REF":     "secret://minio/access-key",
			"AOR_S3_SECRET_KEY_REF":     "secret://minio/secret-key",
			"AOR_REPOSITORY_ROOT":       root,
		}))
		if !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("repository root %q error = %v", root, err)
		}
	}
}

func TestServerRejectsUnsafeKnowledgeRoot(t *testing.T) {
	for _, root := range []string{"relative/knowledge", "/", "/var/lib/aor/../knowledge", "/var/lib/aor/knowledge\n"} {
		_, err := Load("aor-server", environment(map[string]string{
			"AOR_DATABASE_PASSWORD_REF": "secret://postgres/password",
			"AOR_DEPLOYMENT_PROFILE":    "TEST",
			"AOR_LEASE_SIGNING_KEY_REF": "secret://authz/lease-signing-key",
			"AOR_S3_ACCESS_KEY_REF":     "secret://minio/access-key",
			"AOR_S3_SECRET_KEY_REF":     "secret://minio/secret-key",
			"AOR_KNOWLEDGE_ROOT":        root,
		}))
		if !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("knowledge root %q error = %v", root, err)
		}
	}
}

func TestModelGatewayRequiresTwoProviderFamilies(t *testing.T) {
	base := map[string]string{
		"AOR_DATABASE_PASSWORD_REF": "secret://postgres/password",
		"AOR_MODEL_PROVIDERS_JSON": `[
			{"id":"primary","provider":"openai","baseUrl":"https://api.openai.example/v1","apiKeyRef":"secret://model/openai","models":["model-a"],"inputMicrosPerToken":1,"outputMicrosPerToken":2},
			{"id":"audit","provider":"anthropic","baseUrl":"https://api.anthropic.example/v1","apiKeyRef":"secret://model/anthropic","models":["model-b"],"inputMicrosPerToken":1,"outputMicrosPerToken":2}
		]`,
	}
	config, err := Load("aor-model-gateway", environment(base))
	if err != nil {
		t.Fatalf("load gateway config: %v", err)
	}
	if len(config.ModelGateway.Providers) != 2 {
		t.Fatalf("provider count = %d", len(config.ModelGateway.Providers))
	}
	for _, provider := range config.ModelGateway.Providers {
		if len(provider.AllowedDataClassifications) != 1 || provider.AllowedDataClassifications[0] != "PUBLIC" {
			t.Fatalf("default provider classification = %#v", provider.AllowedDataClassifications)
		}
	}

	base["AOR_MODEL_PROVIDERS_JSON"] = `[
		{"id":"one","provider":"openai","baseUrl":"https://one.example/v1","apiKeyRef":"secret://model/one","models":["model-a"]},
		{"id":"two","provider":"openai","baseUrl":"https://two.example/v1","apiKeyRef":"secret://model/two","models":["model-b"]}
	]`
	if _, err := Load("aor-model-gateway", environment(base)); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("same provider family error = %v", err)
	}
}

func TestModelGatewayValidatesReplayEncryptionConfiguration(t *testing.T) {
	base := map[string]string{
		"AOR_DATABASE_PASSWORD_REF": "secret://postgres/password",
		"AOR_MODEL_PROVIDERS_JSON": `[
			{"id":"primary","provider":"openai","baseUrl":"https://api.openai.example/v1","apiKeyRef":"secret://model/openai","models":["model-a"]},
			{"id":"audit","provider":"anthropic","baseUrl":"https://api.anthropic.example/v1","apiKeyRef":"secret://model/anthropic","models":["model-b"]}
		]`,
	}
	config, err := Load("aor-model-gateway", environment(base))
	if err != nil {
		t.Fatal(err)
	}
	if config.ModelGateway.ReplayKeyRef != "secret://model/replay-key" || config.ModelGateway.ReplayKeyID != "model-replay-v1" || config.ModelGateway.ReplayTTLHours != 24 {
		t.Fatalf("replay defaults = %#v", config.ModelGateway)
	}

	for _, invalid := range []struct {
		key   string
		value string
	}{
		{key: "AOR_MODEL_REPLAY_KEY_REF", value: "plaintext-key"},
		{key: "AOR_MODEL_REPLAY_KEY_REF", value: "secret://model/../key"},
		{key: "AOR_MODEL_REPLAY_KEY_ID", value: "key\nversion"},
		{key: "AOR_MODEL_REPLAY_TTL_HOURS", value: "0"},
		{key: "AOR_MODEL_REPLAY_TTL_HOURS", value: "721"},
	} {
		values := make(map[string]string, len(base)+1)
		for key, value := range base {
			values[key] = value
		}
		values[invalid.key] = invalid.value
		if _, err := Load("aor-model-gateway", environment(values)); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("%s=%q error = %v", invalid.key, invalid.value, err)
		}
	}
}

func TestLoadRejectsSecretValuesAndUnsafeReferences(t *testing.T) {
	for _, reference := range []string{"plain-password", "secret:///absolute", "secret://postgres/../password", "secret://postgres/password?version=1"} {
		_, err := Load("aor-server", environment(map[string]string{
			"AOR_DATABASE_PASSWORD_REF": reference,
			"AOR_DEPLOYMENT_PROFILE":    "TEST",
			"AOR_LEASE_SIGNING_KEY_REF": "secret://authz/lease-signing-key",
			"AOR_S3_ACCESS_KEY_REF":     "secret://minio/access-key",
			"AOR_S3_SECRET_KEY_REF":     "secret://minio/secret-key",
		}))
		if !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("reference %q error = %v", reference, err)
		}
	}
}

func TestProductionRequiresAuthenticatedEncryptedDependencies(t *testing.T) {
	_, err := Load("aor-server", environment(map[string]string{
		"AOR_ENVIRONMENT":           EnvironmentProduction,
		"AOR_DATABASE_PASSWORD_REF": "secret://postgres/password",
		"AOR_DEPLOYMENT_PROFILE":    "PRODUCTION",
		"AOR_LEASE_SIGNING_KEY_REF": "secret://authz/lease-signing-key",
		"AOR_S3_ACCESS_KEY_REF":     "secret://minio/access-key",
		"AOR_S3_SECRET_KEY_REF":     "secret://minio/secret-key",
	}))
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("production plaintext error = %v", err)
	}
}

func TestServerRequiresLeaseAuthorityConfiguration(t *testing.T) {
	base := map[string]string{
		"AOR_DATABASE_PASSWORD_REF": "secret://postgres/password",
		"AOR_DEPLOYMENT_PROFILE":    "TEST",
		"AOR_LEASE_SIGNING_KEY_REF": "secret://authz/lease-signing-key",
		"AOR_S3_ACCESS_KEY_REF":     "secret://minio/access-key",
		"AOR_S3_SECRET_KEY_REF":     "secret://minio/secret-key",
	}
	for _, key := range []string{"AOR_DEPLOYMENT_PROFILE", "AOR_LEASE_SIGNING_KEY_REF"} {
		values := make(map[string]string, len(base))
		for name, value := range base {
			values[name] = value
		}
		delete(values, key)
		if _, err := Load("aor-server", environment(values)); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("missing %s error = %v", key, err)
		}
	}
}

func TestWorkerRejectsUnsafeSandboxClaims(t *testing.T) {
	values := validWorkerEnvironment()
	values["AOR_ALLOW_WINDOWS_UNTRUSTED"] = "true"
	_, err := Load("aor-worker", environment(values))
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("unsafe worker error = %v", err)
	}
}

func TestWorkerRequiresImmutableSandboxRuntimeAndDedicatedRootlessEndpoint(t *testing.T) {
	values := validWorkerEnvironment()
	config, err := Load("aor-worker", environment(values))
	if err != nil {
		t.Fatal(err)
	}
	if config.Sandbox.EngineEndpoint != "unix:///run/aor-sandbox/engine.sock" || len(config.Sandbox.HoldCommand) != 3 || len(config.Sandbox.AllowedMountRoots) != 1 || config.Sandbox.AllowedMountRoots[0] != "/var/lib/aor/sandbox-data" {
		t.Fatalf("sandbox config = %#v", config.Sandbox)
	}
	for _, invalid := range []struct {
		key   string
		value string
	}{
		{key: "AOR_SANDBOX_ENGINE_ENDPOINT", value: "unix:///var/run/docker.sock"},
		{key: "AOR_SANDBOX_ENGINE_ENDPOINT", value: ""},
		{key: "AOR_SANDBOX_ENGINE_ENDPOINT", value: "unix:////var/run/docker.sock"},
		{key: "AOR_SANDBOX_ENGINE_ENDPOINT", value: "unix:///run/aor-sandbox/engine.sock\n"},
		{key: "AOR_SANDBOX_IMAGE_REFERENCE", value: "golang:latest"},
		{key: "AOR_SANDBOX_IMAGE_REFERENCE", value: ""},
		{key: "AOR_SANDBOX_SECCOMP_PROFILE", value: "unconfined"},
		{key: "AOR_SANDBOX_SECCOMP_PROFILE", value: "Unconfined"},
		{key: "AOR_SANDBOX_MANDATORY_POLICY", value: "apparmor=unconfined"},
		{key: "AOR_SANDBOX_HOLD_COMMAND_JSON", value: `[]`},
		{key: "AOR_SANDBOX_ALLOWED_MOUNT_ROOTS_JSON", value: `[]`},
		{key: "AOR_SANDBOX_ALLOWED_MOUNT_ROOTS_JSON", value: `["/"]`},
		{key: "AOR_SANDBOX_ALLOWED_MOUNT_ROOTS_JSON", value: `["relative"]`},
		{key: "AOR_SANDBOX_ALLOWED_MOUNT_ROOTS_JSON", value: `["/var/lib/aor/data","/var/lib/aor/data"]`},
		{key: "AOR_SANDBOX_ALLOWED_MOUNT_ROOTS_JSON", value: `["/var/lib/aor/data"] {}`},
	} {
		candidate := validWorkerEnvironment()
		candidate[invalid.key] = invalid.value
		if _, err := Load("aor-worker", environment(candidate)); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("%s=%q error = %v", invalid.key, invalid.value, err)
		}
	}
}

func TestWorkerConfigurationAllowsWindowsNativeBackendWithoutLinuxEngine(t *testing.T) {
	config, err := Load("aor-worker", environment(map[string]string{
		"AOR_DEPLOYMENT_PROFILE":                    "TEST",
		"AOR_DATABASE_PASSWORD_REF":                 "secret://postgres/password",
		"AOR_LEASE_SIGNING_KEY_REF":                 "secret://authz/lease-signing-key",
		"AOR_S3_ACCESS_KEY_REF":                     "secret://minio/access-key",
		"AOR_S3_SECRET_KEY_REF":                     "secret://minio/secret-key",
		"AOR_MODEL_GATEWAY_OAUTH_TOKEN_ENDPOINT":    "http://identity:5556/dex/token",
		"AOR_MODEL_GATEWAY_OAUTH_CLIENT_ID":         "aor-server",
		"AOR_MODEL_GATEWAY_OAUTH_CLIENT_SECRET_REF": "secret://aor_server_oauth_client_secret",
		"AOR_MODEL_GATEWAY_OAUTH_AUDIENCE":          "aor-control-plane",
		"AOR_EXECUTOR_ROUTE_JSON":                   validExecutorRouteJSON(),
		"AOR_SANDBOX_ALLOWED_MOUNT_ROOTS_JSON":      `["/var/lib/aor/sandbox-data"]`,
		"AOR_INTEGRATION_WORK_ROOT":                 "/var/lib/aor/sandbox-data/integration",
		"AOR_INTEGRATION_CHECKS_JSON":               validIntegrationChecksJSON(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.Sandbox.EngineEndpoint != "" || config.Sandbox.ImageReference != "" {
		t.Fatalf("unexpected Linux engine config: %#v", config.Sandbox)
	}
}

func TestLoadRejectsUnknownProviderFieldsAndTrailingJSON(t *testing.T) {
	for _, value := range []string{
		`[{"id":"one","provider":"openai","baseUrl":"https://one.example","apiKeyRef":"secret://model/one","models":["m"],"unknown":true}]`,
		`[] {}`,
		`[] true`,
	} {
		_, err := Load("aor-model-gateway", environment(map[string]string{
			"AOR_DATABASE_PASSWORD_REF": "secret://postgres/password",
			"AOR_MODEL_PROVIDERS_JSON":  value,
		}))
		if !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("provider JSON %q error = %v", value, err)
		}
	}
}

func TestProviderCapabilityProfilePreservesExplicitFalse(t *testing.T) {
	config, err := Load("aor-model-gateway", environment(map[string]string{
		"AOR_DATABASE_PASSWORD_REF": "secret://postgres/password",
		"AOR_MODEL_PROVIDERS_JSON": `[
			{"id":"one","provider":"openai","baseUrl":"https://one.example","apiKeyRef":"secret://model/one","models":["m"],"supportsStreaming":false,"supportsToolCalls":false,"supportsJsonSchema":false,"supportsSeed":false,"supportsPromptCaching":false,"maxInputTokens":1024,"maxOutputTokens":256,"dataResidency":["US"],"retentionPolicy":"none","modalities":["text"]},
			{"id":"two","provider":"deepseek","baseUrl":"https://two.example","apiKeyRef":"secret://model/two","models":["m"],"supportsStreaming":true,"supportsToolCalls":false,"supportsJsonSchema":false,"supportsSeed":false,"supportsPromptCaching":false,"maxInputTokens":1024,"maxOutputTokens":256,"dataResidency":["CN"],"retentionPolicy":"none","modalities":["text"]}
		]`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.ModelGateway.Providers[0].SupportsStreaming || config.ModelGateway.Providers[0].SupportsToolCalls {
		t.Fatalf("explicit capability false was overwritten: %#v", config.ModelGateway.Providers[0])
	}
}

func TestProviderClassificationRequiresTrustedMetadata(t *testing.T) {
	base := map[string]string{
		"AOR_DATABASE_PASSWORD_REF": "secret://postgres/password",
		"AOR_MODEL_PROVIDERS_JSON": `[
			{"id":"one","provider":"openai","baseUrl":"https://one.example","apiKeyRef":"secret://model/one","models":["m"],"allowedDataClassifications":["CONFIDENTIAL"]},
			{"id":"two","provider":"deepseek","baseUrl":"https://two.example","apiKeyRef":"secret://model/two","models":["m"]}
		]`,
	}
	if _, err := Load("aor-model-gateway", environment(base)); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("provider-defined confidential metadata error = %v", err)
	}
	base["AOR_MODEL_PROVIDERS_JSON"] = `[
		{"id":"one","provider":"openai","baseUrl":"https://one.example","apiKeyRef":"secret://model/one","models":["m"],"allowedDataClassifications":["UNKNOWN"],"dataResidency":["US"],"retentionPolicy":"none","modalities":["text"],"maxInputTokens":1024,"maxOutputTokens":256},
		{"id":"two","provider":"deepseek","baseUrl":"https://two.example","apiKeyRef":"secret://model/two","models":["m"]}
	]`
	if _, err := Load("aor-model-gateway", environment(base)); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("invalid provider classification error = %v", err)
	}
}

func environment(values map[string]string) LookupEnv {
	return func(key string) (string, bool) {
		value, found := values[key]
		return value, found
	}
}

func validServerEnvironment() map[string]string {
	return map[string]string{
		"AOR_DATABASE_PASSWORD_REF":                 "secret://postgres/password",
		"AOR_DEPLOYMENT_PROFILE":                    "TEST",
		"AOR_LEASE_SIGNING_KEY_REF":                 "secret://authz/lease-signing-key",
		"AOR_S3_ACCESS_KEY_REF":                     "secret://minio/access-key",
		"AOR_S3_SECRET_KEY_REF":                     "secret://minio/secret-key",
		"AOR_MODEL_GATEWAY_OAUTH_TOKEN_ENDPOINT":    "http://identity:5556/dex/token",
		"AOR_MODEL_GATEWAY_OAUTH_CLIENT_ID":         "aor-server",
		"AOR_MODEL_GATEWAY_OAUTH_CLIENT_SECRET_REF": "secret://aor_server_oauth_client_secret",
		"AOR_MODEL_GATEWAY_OAUTH_AUDIENCE":          "aor-control-plane",
		"AOR_GOAL_PLAN_ROUTES_JSON":                 validGoalPlanRoutesJSON(),
	}
}

func validGoalPlanRoutesJSON() string {
	return `{
		"GOAL_PROPOSER":{"provider":"primary","model":"model-a","maxOutputTokens":4096,"temperature":0,"providerPolicy":"default","cachePolicy":"NO_STORE","worstCaseCostMicros":0,"maxAttempts":3},
		"GOAL_CHALLENGER":{"provider":"primary","model":"model-a","maxOutputTokens":4096,"temperature":0,"providerPolicy":"default","cachePolicy":"NO_STORE","worstCaseCostMicros":0,"maxAttempts":3},
		"PLAN_SUPERVISOR":{"provider":"primary","model":"model-a","maxOutputTokens":4096,"temperature":0,"providerPolicy":"default","cachePolicy":"NO_STORE","worstCaseCostMicros":0,"maxAttempts":3},
		"MODULE_PLANNER":{"provider":"primary","model":"model-a","maxOutputTokens":4096,"temperature":0,"providerPolicy":"default","cachePolicy":"NO_STORE","worstCaseCostMicros":0,"maxAttempts":3}
	}`
}

func validModelProvidersJSON() string {
	return `[
		{"id":"primary","provider":"openai","baseUrl":"https://api.openai.example/v1","apiKeyRef":"secret://model/openai","models":["model-a"]},
		{"id":"audit","provider":"anthropic","baseUrl":"https://api.anthropic.example/v1","apiKeyRef":"secret://model/anthropic","models":["model-b"]}
	]`
}

func validWorkerEnvironment() map[string]string {
	return map[string]string{
		"AOR_DATABASE_PASSWORD_REF":                 "secret://postgres/password",
		"AOR_DEPLOYMENT_PROFILE":                    "TEST",
		"AOR_LEASE_SIGNING_KEY_REF":                 "secret://authz/lease-signing-key",
		"AOR_S3_ACCESS_KEY_REF":                     "secret://minio/access-key",
		"AOR_S3_SECRET_KEY_REF":                     "secret://minio/secret-key",
		"AOR_SANDBOX_ENGINE_ENDPOINT":               "unix:///run/aor-sandbox/engine.sock",
		"AOR_SANDBOX_IMAGE_REFERENCE":               "golang:1.26@sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"AOR_SANDBOX_SECCOMP_PROFILE":               "builtin",
		"AOR_SANDBOX_MANDATORY_POLICY":              "apparmor=aor-sandbox",
		"AOR_SANDBOX_HOLD_COMMAND_JSON":             `["/bin/sh","-c","while :; do sleep 3600; done"]`,
		"AOR_SANDBOX_ALLOWED_MOUNT_ROOTS_JSON":      `["/var/lib/aor/sandbox-data"]`,
		"AOR_MODEL_GATEWAY_OAUTH_TOKEN_ENDPOINT":    "http://identity:5556/dex/token",
		"AOR_MODEL_GATEWAY_OAUTH_CLIENT_ID":         "aor-server",
		"AOR_MODEL_GATEWAY_OAUTH_CLIENT_SECRET_REF": "secret://aor_server_oauth_client_secret",
		"AOR_MODEL_GATEWAY_OAUTH_AUDIENCE":          "aor-control-plane",
		"AOR_EXECUTOR_ROUTE_JSON":                   validExecutorRouteJSON(),
		"AOR_INTEGRATION_WORK_ROOT":                 "/var/lib/aor/sandbox-data/integration",
		"AOR_INTEGRATION_CHECKS_JSON":               validIntegrationChecksJSON(),
	}
}

func validExecutorRouteJSON() string {
	return `{"provider":"primary","model":"model-a","maxOutputTokens":4096,"temperature":0,"providerPolicy":"default","cachePolicy":"NO_STORE","worstCaseCostMicros":0,"maxAttempts":3}`
}

func validIntegrationChecksJSON() string {
	return `[
		{"kind":"COMPILE","argv":["/usr/local/go/bin/go","build","./..."],"timeoutSeconds":300},
		{"kind":"CONTRACT","argv":["/usr/local/go/bin/go","run","./cmd/aor-conformance","contracts"],"timeoutSeconds":300},
		{"kind":"INTEGRATION","argv":["/usr/local/go/bin/go","test","./internal/integration"],"timeoutSeconds":300},
		{"kind":"E2E","argv":["/usr/local/go/bin/go","test","./tests/integration"],"timeoutSeconds":300},
		{"kind":"MIGRATION","argv":["/usr/local/go/bin/go","run","./cmd/aor-conformance","schemas"],"timeoutSeconds":300}
	]`
}
