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
	if config.Database.Address() != "postgres:5432" || config.Temporal.Namespace != "aor" || config.NATS.Stream != "AOR_EVENTS" || !config.S3.UsePathStyle {
		t.Fatalf("unexpected defaults: %+v", config)
	}
}

func TestToolBrokerRequiresDatabaseConfiguration(t *testing.T) {
	if _, err := Load("aor-tool-broker", environment(nil)); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("missing tool broker database error = %v", err)
	}
	config, err := Load("aor-tool-broker", environment(map[string]string{"AOR_DATABASE_PASSWORD_REF": "secret://postgres/password", "AOR_LEASE_SIGNING_KEY_REF": "secret://authz/lease-signing-key", "AOR_DEPLOYMENT_PROFILE": "TEST"}))
	if err != nil || config.Database.PasswordRef == "" {
		t.Fatalf("tool broker config = %#v err=%v", config.Database, err)
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

	base["AOR_MODEL_PROVIDERS_JSON"] = `[
		{"id":"one","provider":"openai","baseUrl":"https://one.example/v1","apiKeyRef":"secret://model/one","models":["model-a"]},
		{"id":"two","provider":"openai","baseUrl":"https://two.example/v1","apiKeyRef":"secret://model/two","models":["model-b"]}
	]`
	if _, err := Load("aor-model-gateway", environment(base)); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("same provider family error = %v", err)
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
	_, err := Load("aor-worker", environment(map[string]string{
		"AOR_DATABASE_PASSWORD_REF":      "secret://postgres/password",
		"AOR_ALLOW_WINDOWS_UNTRUSTED":    "true",
		"AOR_SANDBOX_LINUX_NETWORK_MODE": "DENY_ALL",
	}))
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("unsafe worker error = %v", err)
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

func environment(values map[string]string) LookupEnv {
	return func(key string) (string, bool) {
		value, found := values[key]
		return value, found
	}
}
