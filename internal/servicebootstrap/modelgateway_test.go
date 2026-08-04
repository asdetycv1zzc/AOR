package servicebootstrap

import (
	"context"
	"errors"
	"testing"

	"github.com/akimisaka/aor/internal/runtimeclient"
	"github.com/akimisaka/aor/internal/runtimeconfig"
)

func TestChatCompletionsEndpointNormalizesProviderBaseURL(t *testing.T) {
	for _, test := range []struct {
		base string
		want string
	}{
		{base: "https://api.openai.com/v1", want: "https://api.openai.com/v1/chat/completions"},
		{base: "https://api.deepseek.com/v1/", want: "https://api.deepseek.com/v1/chat/completions"},
		{base: "http://127.0.0.1:8081/v1/chat/completions", want: "http://127.0.0.1:8081/v1/chat/completions"},
	} {
		got, err := chatCompletionsEndpoint(test.base)
		if err != nil || got != test.want {
			t.Fatalf("chatCompletionsEndpoint(%q) = %q, %v; want %q", test.base, got, err, test.want)
		}
	}
	for _, base := range []string{"", "ftp://provider.example/v1", "https://provider.example/v1?key=bad", "http://provider.example/v1"} {
		if _, err := chatCompletionsEndpoint(base); err == nil {
			t.Fatalf("chatCompletionsEndpoint(%q) accepted unsafe endpoint", base)
		}
	}
}

func TestNewConfiguredAdapterCarriesProviderCapabilities(t *testing.T) {
	provider := runtimeconfig.ProviderConfig{
		ID: "openai-primary", Provider: "openai", BaseURL: "https://api.openai.com/v1", APIKeyRef: "secret://model/openai",
		Models: []string{"gpt-test"}, SupportsStreaming: true, SupportsToolCalls: true, SupportsJSONSchema: true,
		MaxInputTokens: 8192, MaxOutputTokens: 1024, DataResidency: []string{"US"}, RetentionPolicy: "provider-defined", Modalities: []string{"text"},
	}
	adapter, err := newConfiguredAdapter(provider, []byte("credential-value"))
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := adapter.Capabilities(context.Background(), "gpt-test")
	if err != nil || !capabilities.SupportsStreaming || !capabilities.SupportsToolCalls || !capabilities.SupportsJSONSchema || capabilities.MaxInputTokens != 8192 || capabilities.MaxOutputTokens != 1024 || capabilities.ActualModelVersion != "NON_REPRODUCIBLE_PROVIDER" {
		t.Fatalf("capabilities = %#v, %v", capabilities, err)
	}
}

func TestModelGatewayFactoryFailsClosedWithoutRuntimeClients(t *testing.T) {
	_, err := ModelGateway(runtimeconfig.Config{ModelGateway: runtimeconfig.ModelGatewayConfig{Providers: []runtimeconfig.ProviderConfig{{ID: "one"}, {ID: "two"}}}}, nil)
	if !errors.Is(err, runtimeclient.ErrInvalidClientConfig) {
		t.Fatalf("ModelGateway(nil clients) error = %v", err)
	}
}

func TestDeploymentProfileFollowsRuntimeEnvironment(t *testing.T) {
	tests := map[string]string{
		runtimeconfig.EnvironmentDevelopment:   "LOCAL",
		runtimeconfig.EnvironmentTest:          "TEST",
		runtimeconfig.EnvironmentPreproduction: "PREPRODUCTION",
		runtimeconfig.EnvironmentProduction:    "PRODUCTION",
	}
	for environment, expected := range tests {
		if actual := deploymentProfileForEnvironment(environment); actual != expected {
			t.Fatalf("deploymentProfileForEnvironment(%q) = %q, want %q", environment, actual, expected)
		}
	}
}
