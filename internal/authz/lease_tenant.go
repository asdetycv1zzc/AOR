package authz

import (
	"context"

	"github.com/akimisaka/aor/internal/authn"
)

type leaseTenantContextKey struct{}

func withLeaseTenant(ctx context.Context, tenantID string) context.Context {
	if ctx == nil || tenantID == "" {
		return ctx
	}
	return context.WithValue(ctx, leaseTenantContextKey{}, tenantID)
}

func leaseTenantID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if tenantID, ok := ctx.Value(leaseTenantContextKey{}).(string); ok && tenantID != "" {
		return tenantID
	}
	if principal, ok := authn.PrincipalFromContext(ctx); ok {
		return principal.TenantID
	}
	return ""
}
