package authn

import (
	"context"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

// DefaultClaimsAuthenticator supplies deployment-scoped claim defaults only
// when the verified issuer omitted them. It is intended for local/test IdPs;
// production configuration rejects these defaults.
type DefaultClaimsAuthenticator struct {
	inner    Authenticator
	tenantID string
	role     string
}

func NewDefaultClaimsAuthenticator(inner Authenticator, tenantID, role string) (*DefaultClaimsAuthenticator, error) {
	if nilInterface(inner) || tenantID == "" || role == "" {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "identity claim defaults"})
	}
	return &DefaultClaimsAuthenticator{inner: inner, tenantID: tenantID, role: role}, nil
}

func (authenticator *DefaultClaimsAuthenticator) Authenticate(ctx context.Context, credential Credential) (Principal, error) {
	if authenticator == nil || authenticator.inner == nil {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	principal, err := authenticator.inner.Authenticate(ctx, credential)
	if err != nil {
		return Principal{}, err
	}
	if principal.TenantID == "" {
		principal.TenantID = authenticator.tenantID
	}
	if principal.Role == "" {
		principal.Role = authenticator.role
	}
	if err := principal.Validate(); err != nil {
		return Principal{}, err
	}
	return principal, nil
}

var _ Authenticator = (*DefaultClaimsAuthenticator)(nil)
