package authn

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

var authnTestNow = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

type oidcVerifierFunc func(context.Context, string) (OIDCClaims, error)

func (f oidcVerifierFunc) Verify(ctx context.Context, token string) (OIDCClaims, error) {
	return f(ctx, token)
}

type svidVerifierFunc func(context.Context, SVID) (SVID, error)

func (f svidVerifierFunc) Verify(ctx context.Context, svid SVID) (SVID, error) {
	return f(ctx, svid)
}

type revocationFunc func(context.Context, string, string) (bool, error)

func (f revocationFunc) IsRevoked(ctx context.Context, kind, value string) (bool, error) {
	return f(ctx, kind, value)
}

func validOIDCClaims() OIDCClaims {
	return OIDCClaims{
		Issuer: "https://identity.example", Subject: "user@example.com", Audience: []string{"aor-control-plane"},
		IssuedAt: authnTestNow.Add(-time.Minute), NotBefore: authnTestNow.Add(-time.Minute), ExpiresAt: authnTestNow.Add(time.Minute),
		PrincipalType: PrincipalUser, Role: RoleUser, TenantID: "tenant_1",
	}
}

func TestValidateOIDCClaimsExactSecurityBindings(t *testing.T) {
	validation := OIDCValidation{TrustedIssuers: map[string]struct{}{"https://identity.example": {}}, Audience: "aor-control-plane", Clock: func() time.Time { return authnTestNow }}
	principal, err := ValidateOIDCClaims(validOIDCClaims(), validation)
	if err != nil {
		t.Fatalf("valid claims rejected: %v", err)
	}
	if principal.ID != "user@example.com" || principal.Type != PrincipalUser || principal.TenantID != "tenant_1" {
		t.Fatalf("unexpected principal: %#v", principal)
	}

	tests := []struct {
		name   string
		mutate func(*OIDCClaims)
	}{
		{name: "issuer", mutate: func(c *OIDCClaims) { c.Issuer = "https://evil.example" }},
		{name: "audience", mutate: func(c *OIDCClaims) { c.Audience = []string{"another-service"} }},
		{name: "subject", mutate: func(c *OIDCClaims) { c.Subject = "" }},
		{name: "expired", mutate: func(c *OIDCClaims) { c.ExpiresAt = authnTestNow }},
		{name: "not yet valid", mutate: func(c *OIDCClaims) { c.NotBefore = authnTestNow.Add(time.Second) }},
		{name: "future issuance", mutate: func(c *OIDCClaims) { c.IssuedAt = authnTestNow.Add(time.Second) }},
		{name: "unknown type", mutate: func(c *OIDCClaims) { c.PrincipalType = PrincipalType("ROOT") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := validOIDCClaims()
			test.mutate(&claims)
			if _, err := ValidateOIDCClaims(claims, validation); err == nil {
				t.Fatal("invalid claims were accepted")
			}
		})
	}

	claimsWithoutNBF := validOIDCClaims()
	claimsWithoutNBF.NotBefore = time.Time{}
	if _, err := ValidateOIDCClaims(claimsWithoutNBF, validation); err != nil {
		t.Fatalf("optional nbf claim was rejected: %v", err)
	}
}

func TestOIDCAuthenticatorFailsClosedAndRedactsToken(t *testing.T) {
	secret := "bearer-secret-value"
	authenticator := NewOIDCAuthenticator(oidcVerifierFunc(func(context.Context, string) (OIDCClaims, error) {
		return validOIDCClaims(), nil
	}), []string{"https://identity.example"}, "aor-control-plane")
	authenticator.Clock = func() time.Time { return authnTestNow }
	authenticator.Revocations = revocationFunc(func(context.Context, string, string) (bool, error) {
		return false, errors.New("revocation backend contained " + secret)
	})
	_, err := authenticator.Authenticate(context.Background(), BearerCredential(secret))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("expected redacted fail-closed error, got %v", err)
	}
	assertAORErrorCode(t, err, aorerrors.CodeDependencyUnavailable)

	authenticator.Revocations = revocationFunc(func(context.Context, string, string) (bool, error) { return true, nil })
	_, err = authenticator.Authenticate(context.Background(), BearerCredential(secret))
	assertAORErrorCode(t, err, aorerrors.CodeUnauthorized)
}

func TestPrincipalRejectsCredentialAttributes(t *testing.T) {
	principal := Principal{ID: "service_1", Type: PrincipalService, Role: RoleService, Attributes: map[string]string{"api_token": "must-not-be-a-principal-attribute"}}
	if err := principal.Validate(); err == nil {
		t.Fatal("credential-shaped principal attribute accepted")
	}
}

func TestParseAndValidateSPIFFEIdentity(t *testing.T) {
	identity, err := ParseSPIFFEID("spiffe://prod.example/aor/production/orchestrator/instance-7")
	if err != nil {
		t.Fatalf("parse valid SPIFFE ID: %v", err)
	}
	if identity.TrustDomain != "prod.example" || identity.Environment != "production" || identity.Service != "orchestrator" || identity.Instance != "instance-7" || identity.String() != "spiffe://prod.example/aor/production/orchestrator/instance-7" {
		t.Fatalf("unexpected identity: %#v", identity)
	}

	invalid := []string{
		"https://prod.example/aor/production/svc/one",
		"spiffe://prod.example/aor/production/svc",
		"spiffe://prod.example/aor/production/svc/one/extra",
		"spiffe://prod.example/aor/production/svc/%2e%2e",
		"spiffe://prod.example/aor/production/svc/one?tenant=x",
	}
	for _, raw := range invalid {
		if _, err := ParseSPIFFEID(raw); err == nil {
			t.Fatalf("invalid SPIFFE ID accepted: %s", raw)
		}
	}

	svid := SVID{ID: identity.String(), IssuedAt: authnTestNow.Add(-time.Minute), NotBefore: authnTestNow.Add(-time.Minute), ExpiresAt: authnTestNow.Add(time.Minute), PrincipalType: PrincipalService, Role: RoleService, TenantID: "tenant_1"}
	principal, err := ValidateSVID(svid, SVIDValidation{TrustDomain: "prod.example", Environment: "production", Clock: func() time.Time { return authnTestNow }})
	if err != nil || principal.ID != identity.String() {
		t.Fatalf("valid SVID rejected: principal=%#v err=%v", principal, err)
	}
	if _, err := ValidateSVID(svid, SVIDValidation{TrustDomain: "test.example", Environment: "production", Clock: func() time.Time { return authnTestNow }}); err == nil {
		t.Fatal("cross-trust-domain SVID accepted")
	}
	if _, err := ValidateSVID(svid, SVIDValidation{TrustDomain: "prod.example", Environment: "development", Clock: func() time.Time { return authnTestNow }}); err == nil {
		t.Fatal("cross-environment SVID accepted")
	}
}

func TestSPIFFEAuthenticatorAndRotationWindow(t *testing.T) {
	svid := SVID{ID: "spiffe://prod.example/aor/production/worker/worker-1", IssuedAt: authnTestNow.Add(-time.Minute), NotBefore: authnTestNow.Add(-time.Minute), ExpiresAt: authnTestNow.Add(time.Minute), PrincipalType: PrincipalAgentRuntime, Role: RoleService, TenantID: "tenant_1"}
	authenticator := NewSPIFFEAuthenticator(svidVerifierFunc(func(_ context.Context, candidate SVID) (SVID, error) { return candidate, nil }), "prod.example", "production")
	authenticator.Clock = func() time.Time { return authnTestNow }
	principal, err := authenticator.Authenticate(context.Background(), SVIDCredential(svid))
	if err != nil || principal.Type != PrincipalAgentRuntime {
		t.Fatalf("authenticate SVID: principal=%#v err=%v", principal, err)
	}
	if !svid.ValidAt(authnTestNow) || svid.RotationDue(authnTestNow, 30*time.Second) || !svid.RotationDue(authnTestNow, time.Minute) {
		t.Fatal("unexpected rotation window result")
	}
}

func assertAORErrorCode(t *testing.T, err error, expected aorerrors.Code) {
	t.Helper()
	var typed *aorerrors.Error
	if !errors.As(err, &typed) || typed.Code != expected {
		t.Fatalf("expected %s, got %v", expected, err)
	}
}
