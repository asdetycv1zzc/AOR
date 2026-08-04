package servicebootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/credentials"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/runtimeconfig"
)

type fixedClaimsVerifier struct {
	claims authn.OIDCClaims
	err    error
}

func (verifier fixedClaimsVerifier) Verify(context.Context, string) (authn.OIDCClaims, error) {
	return verifier.claims, verifier.err
}

func TestConfiguredModelGatewayClientUsesOAuthWorkloadToken(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "model-gateway-client-secret"), []byte("client-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenRequests := 0
	tokenServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		tokenRequests++
		clientID, clientSecret, ok := request.BasicAuth()
		if !ok || clientID != "aor-server" || clientSecret != "client-secret" {
			t.Fatalf("basic auth client=%q secret=%q ok=%t", clientID, clientSecret, ok)
		}
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if request.Form.Get("grant_type") != "client_credentials" || request.Form.Get("scope") != "audience:server:client_id:aor-control-plane" || request.Form.Get("audience") != "aor-control-plane" {
			t.Fatalf("token form = %v", request.Form)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"access_token":"short-lived-token","token_type":"Bearer","expires_in":300,"scope":"audience:server:client_id:aor-control-plane"}`))
	}))
	defer tokenServer.Close()

	gatewayRequests := 0
	gatewayServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		gatewayRequests++
		if request.Header.Get("Authorization") != "Bearer short-lived-token" {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = response.Write([]byte(`{"error":{"code":"AOR_UNAUTHENTICATED","message":"","retryable":false}}`))
	}))
	defer gatewayServer.Close()

	config := runtimeconfig.Config{
		Environment: runtimeconfig.EnvironmentTest,
		ModelGatewayClient: runtimeconfig.ModelGatewayClientConfig{
			TokenEndpoint: tokenServer.URL, ClientID: "aor-server",
			ClientSecretRef: "secret://model-gateway-client-secret",
			Scopes:          []string{"audience:server:client_id:aor-control-plane"},
			Audience:        "aor-control-plane",
		},
		Services: runtimeconfig.ServiceEndpoints{ModelGateway: gatewayServer.URL},
	}
	client, err := configuredModelGatewayClient(t.Context(), config, credentials.NewSecretResolver(root))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Generate(t.Context(), modelgateway.NormalizedRequest{
		RequestID: "request", TenantID: "tenant", ProjectID: "project", TaskID: "task", AgentInstanceID: "agent",
		Role: "EXECUTOR", Model: "model", PromptBundleVersion: "v1", Messages: []modelgateway.Message{{Role: "user", Content: "hello"}},
		MaxOutputTokens: 64, ProviderPolicy: "default", DataClassification: "INTERNAL", CachePolicy: "NO_STORE",
		PromptDigest: "prompt-digest", ToolSchemaDigest: "tool-digest", PolicyDigest: "policy-digest", WorstCaseCostMicros: 100,
	}, modelgateway.GenerateOptions{Provider: "provider", AccountID: "account", ReservationID: "reservation"})
	if !errors.Is(err, modelgateway.ErrAuthorizationDenied) || tokenRequests != 1 || gatewayRequests != 1 {
		t.Fatalf("generate error=%v tokenRequests=%d gatewayRequests=%d", err, tokenRequests, gatewayRequests)
	}
}

func TestConfiguredModelGatewayClientFailsClosed(t *testing.T) {
	config := runtimeconfig.Config{
		Environment: runtimeconfig.EnvironmentProduction,
		ModelGatewayClient: runtimeconfig.ModelGatewayClientConfig{
			TokenEndpoint: "http://identity.example/token", ClientID: "aor-server",
			ClientSecretRef: "secret://missing", Audience: "aor-control-plane",
		},
		Services: runtimeconfig.ServiceEndpoints{ModelGateway: "https://model.example"},
	}
	if _, err := configuredModelGatewayClient(t.Context(), config, credentials.NewSecretResolver(t.TempDir())); !errors.Is(err, runtimeconfig.ErrInvalidConfiguration) {
		t.Fatalf("missing secret error = %v", err)
	}
	if _, err := configuredModelGatewayClient(nil, config, credentials.NewSecretResolver(t.TempDir())); !errors.Is(err, runtimeconfig.ErrInvalidConfiguration) {
		t.Fatalf("nil context error = %v", err)
	}
}

func TestServiceSubjectClaimsVerifierMapsOnlyExactUnclaimedSubject(t *testing.T) {
	now := time.Now().UTC()
	base := authn.OIDCClaims{
		Issuer: "https://identity.example", Subject: "service-subject", Audience: []string{"aor-control-plane"},
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	verifier := &serviceSubjectClaimsVerifier{
		inner:           fixedClaimsVerifier{claims: base},
		tenantBySubject: map[string]string{"service-subject": "11111111-1111-4111-8111-111111111111"},
	}
	authenticator := authn.NewOIDCAuthenticator(verifier, []string{"https://identity.example"}, "aor-control-plane")
	authenticator.Clock = func() time.Time { return now }
	principal, err := authenticator.Authenticate(t.Context(), authn.BearerCredential("verified-token"))
	if err != nil {
		t.Fatal(err)
	}
	if principal.Type != authn.PrincipalService || principal.Role != authn.RoleService || principal.TenantID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("mapped principal = %#v", principal)
	}

	base.Subject = "human-subject"
	verifier.inner = fixedClaimsVerifier{claims: base}
	localAuthenticator, err := authn.NewDefaultClaimsAuthenticator(authenticator, "22222222-2222-4222-8222-222222222222", authn.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	principal, err = localAuthenticator.Authenticate(t.Context(), authn.BearerCredential("verified-token"))
	if err != nil {
		t.Fatal(err)
	}
	if principal.Type != authn.PrincipalUser || principal.Role != authn.RoleUser {
		t.Fatalf("unmapped principal = %#v", principal)
	}
}

func TestServiceSubjectClaimsVerifierRejectsConflictingClaims(t *testing.T) {
	verifier := &serviceSubjectClaimsVerifier{
		inner: fixedClaimsVerifier{claims: authn.OIDCClaims{
			Subject: "service-subject", PrincipalType: authn.PrincipalUser, Role: authn.RoleUser,
		}},
		tenantBySubject: map[string]string{"service-subject": "11111111-1111-4111-8111-111111111111"},
	}
	if _, err := verifier.Verify(t.Context(), "verified-token"); !errors.Is(err, authn.ErrOIDCProofInvalid) {
		t.Fatalf("conflicting claims error = %v", err)
	}
	verifier.inner = fixedClaimsVerifier{err: errors.New("verification failed")}
	if _, err := verifier.Verify(t.Context(), "bad-token"); err == nil {
		t.Fatal("expected verifier failure")
	}
}

var _ authn.OIDCVerifier = fixedClaimsVerifier{}
