package servicebootstrap

import (
	"context"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/credentials"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/runtimeconfig"
)

func configuredModelGatewayClient(ctx context.Context, config runtimeconfig.Config, resolver *credentials.SecretResolver) (*modelgateway.HTTPClient, error) {
	if ctx == nil || resolver == nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	secret, err := resolver.Resolve(ctx, config.ModelGatewayClient.ClientSecretRef)
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	defer clearBytes(secret)

	allowHTTP := config.Environment == runtimeconfig.EnvironmentDevelopment || config.Environment == runtimeconfig.EnvironmentTest
	tokenSource, err := modelgateway.NewOAuthClientCredentialsTokenSource(modelgateway.OAuthClientCredentialsConfig{
		TokenEndpoint: config.ModelGatewayClient.TokenEndpoint,
		ClientID:      config.ModelGatewayClient.ClientID,
		ClientSecret:  secret,
		Scopes:        append([]string(nil), config.ModelGatewayClient.Scopes...),
		Audience:      config.ModelGatewayClient.Audience,
		AllowHTTP:     allowHTTP,
	})
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	client, err := modelgateway.NewHTTPClient(modelgateway.HTTPClientConfig{
		Endpoint:    config.Services.ModelGateway,
		TokenSource: tokenSource,
	})
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	return client, nil
}

type serviceSubjectClaimsVerifier struct {
	inner           authn.OIDCVerifier
	tenantBySubject map[string]string
}

func (verifier *serviceSubjectClaimsVerifier) Verify(ctx context.Context, bearerToken string) (authn.OIDCClaims, error) {
	if verifier == nil || verifier.inner == nil {
		return authn.OIDCClaims{}, authn.ErrOIDCProofInvalid
	}
	claims, err := verifier.inner.Verify(ctx, bearerToken)
	if err != nil {
		return authn.OIDCClaims{}, err
	}
	tenantID, mapped := verifier.tenantBySubject[claims.Subject]
	if !mapped {
		return claims, nil
	}
	if claims.PrincipalType == "" && claims.Role == "" && claims.TenantID == "" && claims.ProjectID == "" && len(claims.Attributes) == 0 {
		claims.PrincipalType = authn.PrincipalService
		claims.Role = authn.RoleService
		claims.TenantID = tenantID
		return claims, nil
	}
	if claims.PrincipalType != authn.PrincipalService || claims.Role != authn.RoleService || claims.TenantID != tenantID || claims.ProjectID != "" || len(claims.Attributes) != 0 {
		return authn.OIDCClaims{}, authn.ErrOIDCProofInvalid
	}
	return claims, nil
}

var _ authn.OIDCVerifier = (*serviceSubjectClaimsVerifier)(nil)
