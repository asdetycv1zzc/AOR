package runtimeconfig

import (
	"errors"
	"testing"
)

func TestLoadServerConfiguration(t *testing.T) {
	config, err := Load("aor-server", environment(map[string]string{
		"AOR_DATABASE_PASSWORD_REF": "secret://postgres/password",
		"AOR_S3_ACCESS_KEY_REF":     "secret://minio/access-key",
		"AOR_S3_SECRET_KEY_REF":     "secret://minio/secret-key",
	}))
	if err != nil {
		t.Fatalf("load server config: %v", err)
	}
	if config.Database.Address() != "postgres:5432" || config.Temporal.Namespace != "aor" || config.NATS.Stream != "AOR_EVENTS" || !config.S3.UsePathStyle || config.KnowledgeRoot != "/var/lib/aor/knowledge" {
		t.Fatalf("unexpected defaults: %+v", config)
	}
}

func TestToolBrokerRequiresDatabaseConfiguration(t *testing.T) {
	if _, err := Load("aor-tool-broker", environment(nil)); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("missing tool broker database error = %v", err)
	}
	config, err := Load("aor-tool-broker", environment(map[string]string{"AOR_DATABASE_PASSWORD_REF": "secret://postgres/password", "AOR_LEASE_SIGNING_KEY_REF": "secret://authz/lease-signing-key", "AOR_DEPLOYMENT_PROFILE": "TEST", "AOR_S3_ACCESS_KEY_REF": "secret://minio/access-key", "AOR_S3_SECRET_KEY_REF": "secret://minio/secret-key"}))
	if err != nil || config.Database.PasswordRef == "" || config.S3.AccessKeyRef == "" || config.S3.SecretKeyRef == "" {
		t.Fatalf("tool broker config database=%#v s3=%#v err=%v", config.Database, config.S3, err)
	}
}

func TestServerRejectsUnsafeKnowledgeRoot(t *testing.T) {
	for _, root := range []string{"relative/knowledge", "/", "/var/lib/aor/../knowledge", "/var/lib/aor/knowledge\n"} {
		_, err := Load("aor-server", environment(map[string]string{
			"AOR_DATABASE_PASSWORD_REF": "secret://postgres/password",
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
		"AOR_S3_ACCESS_KEY_REF":     "secret://minio/access-key",
		"AOR_S3_SECRET_KEY_REF":     "secret://minio/secret-key",
	}))
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("production plaintext error = %v", err)
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
	if config.Sandbox.EngineEndpoint != "unix:///run/aor-sandbox/engine.sock" || len(config.Sandbox.HoldCommand) != 3 {
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
		"AOR_DATABASE_PASSWORD_REF": "secret://postgres/password",
		"AOR_S3_ACCESS_KEY_REF":     "secret://minio/access-key",
		"AOR_S3_SECRET_KEY_REF":     "secret://minio/secret-key",
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

func validWorkerEnvironment() map[string]string {
	return map[string]string{
		"AOR_DATABASE_PASSWORD_REF":     "secret://postgres/password",
		"AOR_S3_ACCESS_KEY_REF":         "secret://minio/access-key",
		"AOR_S3_SECRET_KEY_REF":         "secret://minio/secret-key",
		"AOR_SANDBOX_ENGINE_ENDPOINT":   "unix:///run/aor-sandbox/engine.sock",
		"AOR_SANDBOX_IMAGE_REFERENCE":   "golang:1.26@sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"AOR_SANDBOX_SECCOMP_PROFILE":   "builtin",
		"AOR_SANDBOX_MANDATORY_POLICY":  "apparmor=aor-sandbox",
		"AOR_SANDBOX_HOLD_COMMAND_JSON": `["/bin/sh","-c","while :; do sleep 3600; done"]`,
	}
}
