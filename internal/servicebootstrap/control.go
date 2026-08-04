package servicebootstrap

import (
	"net/http"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/controlapi"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/policy"
	"github.com/akimisaka/aor/internal/runtimeclient"
	"github.com/akimisaka/aor/internal/runtimeconfig"
)

func ControlAPI(config runtimeconfig.Config, clients *runtimeclient.Clients) (http.Handler, error) {
	if clients == nil || clients.Database() == nil {
		return nil, runtimeclient.ErrInvalidClientConfig
	}
	authenticator, err := oidcAuthenticator(config)
	if err != nil {
		return nil, err
	}
	authorizer, err := policy.NewOPAClient(config.OPA.URL)
	if err != nil {
		return nil, err
	}
	store := eventing.NewPostgresStore(clients.Database())
	return controlapi.New(controlapi.Config{
		Store: store, Authenticator: authenticator, Authorizer: authorizer,
		Database: clients.Database(), Clock: time.Now,
	})
}

func oidcAuthenticator(config runtimeconfig.Config) (authn.Authenticator, error) {
	allowHTTP := config.Environment == runtimeconfig.EnvironmentDevelopment || config.Environment == runtimeconfig.EnvironmentTest
	verifier, err := authn.NewRemoteJWKSVerifier(authn.RemoteJWKSConfig{
		Issuer: config.Identity.Issuer, JWKSURL: config.Identity.JWKSURL, AllowHTTP: allowHTTP,
	})
	if err != nil {
		return nil, err
	}
	authenticator := authn.NewOIDCAuthenticator(verifier, []string{config.Identity.Issuer}, config.Identity.Audience)
	authenticator.ClockSkew = 30 * time.Second
	if config.Identity.DefaultTenantID != "" {
		return authn.NewDefaultClaimsAuthenticator(authenticator, config.Identity.DefaultTenantID, config.Identity.DefaultRole)
	}
	return authenticator, nil
}
