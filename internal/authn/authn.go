// Package authn contains the authentication boundary for AOR principals.
//
// The package deliberately delegates proof verification (JWT signatures and
// SVID attestation) to injected verifiers. It owns claim validation and never
// stores bearer tokens or private key material in a Principal.
package authn

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

// PrincipalType is the kind of subject authenticated by AOR.
type PrincipalType string

const (
	PrincipalUser             PrincipalType = "USER"
	PrincipalService          PrincipalType = "SERVICE"
	PrincipalAgentRuntime     PrincipalType = "AGENT_RUNTIME"
	PrincipalAgentInstance    PrincipalType = "AGENT_INSTANCE"
	PrincipalSandbox          PrincipalType = "SANDBOX"
	PrincipalMCPServer        PrincipalType = "MCP_SERVER"
	PrincipalCIRunner         PrincipalType = "CI_RUNNER"
	PrincipalKnowledgeCurator PrincipalType = "KNOWLEDGE_CURATOR"
	PrincipalBreakGlassAdmin  PrincipalType = "BREAK_GLASS_ADMIN"
)

// Well-known role values used by the policy engine. Roles remain strings on
// the wire so deployments can add a role through a versioned policy bundle.
const (
	RoleGoalProposer     = "GOAL_PROPOSER"
	RoleGoalChallenger   = "GOAL_CHALLENGER"
	RolePlanSupervisor   = "PLAN_SUPERVISOR"
	RoleModulePlanner    = "MODULE_PLANNER"
	RoleExecutor         = "EXECUTOR"
	RoleAuditor          = "AUDITOR"
	RoleGlobalAuditor    = "GLOBAL_AUDITOR"
	RoleKnowledgeCurator = "KNOWLEDGE_CURATOR"
	RoleService          = "SERVICE"
	RoleUser             = "USER"
	RoleBreakGlassAdmin  = "BREAK_GLASS_ADMIN"
)

var (
	identityPartPattern = regexp.MustCompile(`^[A-Za-z0-9._:@/+~-]{1,256}$`)
	spiffePartPattern   = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)
)

// Principal is the normalized identity used by authorization. It contains
// metadata safe to persist in an audit event; credentials are intentionally
// absent.
type Principal struct {
	ID         string            `json:"id"`
	Type       PrincipalType     `json:"type"`
	Role       string            `json:"role,omitempty"`
	TenantID   string            `json:"tenantId,omitempty"`
	ProjectID  string            `json:"projectId,omitempty"`
	Issuer     string            `json:"issuer,omitempty"`
	Subject    string            `json:"subject,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type principalContextKey struct{}

// ContextWithPrincipal carries only an already verified, normalized identity.
// Raw credentials must never be placed in context values.
func ContextWithPrincipal(ctx context.Context, principal Principal) (context.Context, error) {
	if ctx == nil || principal.Validate() != nil {
		return nil, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	return context.WithValue(ctx, principalContextKey{}, principal), nil
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	if ctx == nil {
		return Principal{}, false
	}
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	if !ok || principal.Validate() != nil {
		return Principal{}, false
	}
	return principal, true
}

// Validate checks only the shape and safe identity fields. Scope checks that
// require a project or task belong to authz and are repeated there.
func (p Principal) Validate() *aorerrors.Error {
	if !safeOpaque(p.ID, 512) {
		return aorerrors.New(aorerrors.CodeUnauthorized, "", map[string]any{"subjectType": string(p.Type)})
	}
	if !knownPrincipalType(p.Type) {
		return aorerrors.New(aorerrors.CodeUnauthorized, "", map[string]any{"subjectType": string(p.Type)})
	}
	if p.Role != "" && !identityPartPattern.MatchString(p.Role) {
		return aorerrors.New(aorerrors.CodeUnauthorized, "", map[string]any{"subjectType": string(p.Type)})
	}
	if p.TenantID != "" && !identityPartPattern.MatchString(p.TenantID) {
		return aorerrors.New(aorerrors.CodeUnauthorized, "", map[string]any{"subjectType": string(p.Type)})
	}
	if p.ProjectID != "" && !identityPartPattern.MatchString(p.ProjectID) {
		return aorerrors.New(aorerrors.CodeUnauthorized, "", map[string]any{"subjectType": string(p.Type)})
	}
	if len(p.Attributes) > 64 {
		return aorerrors.New(aorerrors.CodeUnauthorized, "", map[string]any{"subjectType": string(p.Type)})
	}
	for key, value := range p.Attributes {
		if !identityPartPattern.MatchString(key) || sensitiveName(key) || len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
			return aorerrors.New(aorerrors.CodeUnauthorized, "", map[string]any{"subjectType": string(p.Type)})
		}
	}
	return nil
}

func sensitiveName(value string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(value, "_", ""), "-", ""))
	for _, fragment := range []string{"secret", "password", "passwd", "token", "credential", "privatekey", "apikey", "refreshtoken"} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func safeOpaque(value string, max int) bool {
	if value == "" || len(value) > max || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, runeValue := range value {
		if runeValue < 0x20 || runeValue == 0x7f {
			return false
		}
	}
	return true
}

func knownPrincipalType(value PrincipalType) bool {
	switch value {
	case PrincipalUser, PrincipalService, PrincipalAgentRuntime, PrincipalAgentInstance,
		PrincipalSandbox, PrincipalMCPServer, PrincipalCIRunner, PrincipalKnowledgeCurator,
		PrincipalBreakGlassAdmin:
		return true
	default:
		return false
	}
}

// Credential is a discriminated input to an authenticator. Raw bearer tokens
// are consumed by a verifier and are never returned to callers.
type Credential struct {
	BearerToken string
	SVID        *SVID
}

type Authenticator interface {
	Authenticate(context.Context, Credential) (Principal, error)
}

func BearerCredential(token string) Credential { return Credential{BearerToken: token} }
func SVIDCredential(svid SVID) Credential      { return Credential{SVID: &svid} }

// RevocationChecker is consulted after proof and time validation. Returning an
// error is fail closed; a network outage must not become an allow.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, kind, value string) (bool, error)
}

// OIDCClaims is the verifier output. A verifier is responsible for checking a
// JWT signature and extracting claims; this package validates their meaning.
type OIDCClaims struct {
	Issuer        string            `json:"iss"`
	Subject       string            `json:"sub"`
	Audience      []string          `json:"aud"`
	IssuedAt      time.Time         `json:"iat"`
	NotBefore     time.Time         `json:"nbf"`
	ExpiresAt     time.Time         `json:"exp"`
	PrincipalType PrincipalType     `json:"principalType,omitempty"`
	Role          string            `json:"role,omitempty"`
	TenantID      string            `json:"tenantId,omitempty"`
	ProjectID     string            `json:"projectId,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

// OIDCValidation controls semantic claim validation. TrustedIssuers and
// Audience are exact matches; an empty set is invalid and never means "any".
type OIDCValidation struct {
	TrustedIssuers map[string]struct{}
	Audience       string
	Clock          func() time.Time
	ClockSkew      time.Duration
}

func (v OIDCValidation) now() time.Time {
	if v.Clock != nil {
		return v.Clock().UTC()
	}
	return time.Now().UTC()
}

// ValidateOIDCClaims validates claims and returns safe principal metadata.
func ValidateOIDCClaims(claims OIDCClaims, validation OIDCValidation) (Principal, error) {
	if len(validation.TrustedIssuers) == 0 || validation.Audience == "" || claims.Issuer == "" || claims.Subject == "" {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	if _, ok := validation.TrustedIssuers[claims.Issuer]; !ok {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	if !containsExact(claims.Audience, validation.Audience) {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	if len(claims.Audience) == 0 || len(claims.Audience) > 32 {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	for _, audience := range claims.Audience {
		if !safeOpaque(audience, 512) {
			return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
		}
	}
	if claims.ExpiresAt.IsZero() {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	skew := validation.ClockSkew
	if skew < 0 || skew > 5*time.Minute {
		return Principal{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", nil)
	}
	now := validation.now()
	if !now.Before(claims.ExpiresAt.Add(skew)) || (!claims.NotBefore.IsZero() && now.Add(skew).Before(claims.NotBefore)) {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	if !claims.IssuedAt.IsZero() && now.Add(skew).Before(claims.IssuedAt) {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	principalType := claims.PrincipalType
	if principalType == "" {
		principalType = PrincipalUser
	}
	principal := Principal{
		ID: claims.Subject, Type: principalType, Role: claims.Role, TenantID: claims.TenantID,
		ProjectID: claims.ProjectID, Issuer: claims.Issuer, Subject: claims.Subject,
		Attributes: cloneAttributes(claims.Attributes),
	}
	if err := principal.Validate(); err != nil {
		return Principal{}, err
	}
	return principal, nil
}

func containsExact(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

// OIDCVerifier verifies a bearer token's cryptographic proof and decodes its
// claims. Implementations normally use a pinned issuer/JWKS cache.
type OIDCVerifier interface {
	Verify(ctx context.Context, bearerToken string) (OIDCClaims, error)
}

// OIDCAuthenticator validates an OIDC credential using an injected verifier.
type OIDCAuthenticator struct {
	Verifier       OIDCVerifier
	TrustedIssuers map[string]struct{}
	Audience       string
	Clock          func() time.Time
	ClockSkew      time.Duration
	Revocations    RevocationChecker
}

func NewOIDCAuthenticator(verifier OIDCVerifier, issuers []string, audience string) *OIDCAuthenticator {
	trusted := make(map[string]struct{}, len(issuers))
	for _, issuer := range issuers {
		if issuer != "" {
			trusted[issuer] = struct{}{}
		}
	}
	return &OIDCAuthenticator{Verifier: verifier, TrustedIssuers: trusted, Audience: audience, ClockSkew: 30 * time.Second}
}

func (a *OIDCAuthenticator) Authenticate(ctx context.Context, credential Credential) (Principal, error) {
	if a == nil || a.Verifier == nil || credential.BearerToken == "" || len(credential.BearerToken) > 64<<10 || strings.ContainsAny(credential.BearerToken, "\r\n\x00") {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return Principal{}, aorerrors.Wrap(aorerrors.CodeUnauthorized, "", err, nil)
	}
	claims, err := a.Verifier.Verify(ctx, credential.BearerToken)
	if err != nil {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	principal, err := ValidateOIDCClaims(claims, OIDCValidation{TrustedIssuers: a.TrustedIssuers, Audience: a.Audience, Clock: a.Clock, ClockSkew: a.ClockSkew})
	if err != nil {
		return Principal{}, err
	}
	if a.Revocations != nil {
		revoked, checkErr := a.Revocations.IsRevoked(ctx, "oidc", claims.Subject)
		if checkErr != nil {
			return Principal{}, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
		}
		if revoked {
			return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
		}
	}
	return principal, nil
}

// SPIFFEID is the parsed canonical workload identity URI.
type SPIFFEID struct {
	TrustDomain string `json:"trustDomain"`
	Environment string `json:"environment"`
	Service     string `json:"service"`
	Instance    string `json:"instance"`
}

func (id SPIFFEID) String() string {
	return "spiffe://" + id.TrustDomain + "/aor/" + id.Environment + "/" + id.Service + "/" + id.Instance
}

// ParseSPIFFEID parses only the AOR workload identity profile. Query strings,
// fragments, percent escapes, extra path segments, and empty components are
// rejected to prevent alternate spellings of an identity.
func ParseSPIFFEID(raw string) (SPIFFEID, error) {
	if len(raw) == 0 || len(raw) > 2048 || strings.ContainsAny(raw, "\r\n\x00") {
		return SPIFFEID{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "spiffe" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return SPIFFEID{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	if parsed.Path != "/aor/"+strings.TrimPrefix(parsed.Path, "/aor/") || strings.Contains(parsed.EscapedPath(), "%") {
		return SPIFFEID{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/aor/"), "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" || !spiffePartPattern.MatchString(parsed.Host) {
		return SPIFFEID{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	for _, part := range parts {
		if !spiffePartPattern.MatchString(part) {
			return SPIFFEID{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
		}
	}
	return SPIFFEID{TrustDomain: parsed.Host, Environment: parts[0], Service: parts[1], Instance: parts[2]}, nil
}

// SVID is the verified output from a SPIFFE/SPIRE proof verifier.
type SVID struct {
	ID            string            `json:"id"`
	Audience      []string          `json:"audience"`
	IssuedAt      time.Time         `json:"issuedAt"`
	NotBefore     time.Time         `json:"notBefore"`
	ExpiresAt     time.Time         `json:"expiresAt"`
	PrincipalType PrincipalType     `json:"principalType,omitempty"`
	Role          string            `json:"role,omitempty"`
	TenantID      string            `json:"tenantId,omitempty"`
	ProjectID     string            `json:"projectId,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

func (svid SVID) ValidAt(now time.Time) bool {
	return !svid.ExpiresAt.IsZero() && now.Before(svid.ExpiresAt) && (svid.NotBefore.IsZero() || !now.Before(svid.NotBefore))
}

// RotationDue reports whether a short-lived credential should be renewed
// before the supplied safety window. It does not extend the credential.
func (svid SVID) RotationDue(now time.Time, safetyWindow time.Duration) bool {
	return safetyWindow < 0 || !svid.ValidAt(now) || !now.Add(safetyWindow).Before(svid.ExpiresAt)
}

type SVIDValidation struct {
	TrustDomain string
	Environment string
	Audience    string
	Clock       func() time.Time
	ClockSkew   time.Duration
}

func (v SVIDValidation) now() time.Time {
	if v.Clock != nil {
		return v.Clock().UTC()
	}
	return time.Now().UTC()
}

func ValidateSVID(svid SVID, validation SVIDValidation) (Principal, error) {
	identity, err := ParseSPIFFEID(svid.ID)
	if err != nil || validation.TrustDomain == "" || identity.TrustDomain != validation.TrustDomain || validation.Environment == "" || identity.Environment != validation.Environment {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	if validation.Audience != "" && !containsExact(svid.Audience, validation.Audience) {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	if len(svid.Audience) > 32 {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	for _, audience := range svid.Audience {
		if !safeOpaque(audience, 512) {
			return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
		}
	}
	if svid.ExpiresAt.IsZero() || svid.NotBefore.IsZero() {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	if validation.ClockSkew < 0 || validation.ClockSkew > 5*time.Minute {
		return Principal{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", nil)
	}
	now := validation.now()
	if !now.Before(svid.ExpiresAt.Add(validation.ClockSkew)) || now.Add(validation.ClockSkew).Before(svid.NotBefore) {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	if !svid.IssuedAt.IsZero() && now.Add(validation.ClockSkew).Before(svid.IssuedAt) {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	principalType := svid.PrincipalType
	if principalType == "" {
		principalType = PrincipalService
	}
	principal := Principal{ID: svid.ID, Type: principalType, Role: svid.Role, TenantID: svid.TenantID, ProjectID: svid.ProjectID, Subject: svid.ID, Attributes: cloneAttributes(svid.Attributes)}
	if err := principal.Validate(); err != nil {
		return Principal{}, err
	}
	return principal, nil
}

type SVIDVerifier interface {
	Verify(ctx context.Context, svid SVID) (SVID, error)
}

// SPIFFEAuthenticator validates a verified SVID. The credential must contain a
// complete SVID value; a nil/zero SVID is never treated as an ambient identity.
type SPIFFEAuthenticator struct {
	Verifier    SVIDVerifier
	TrustDomain string
	Environment string
	Audience    string
	Clock       func() time.Time
	ClockSkew   time.Duration
	Revocations RevocationChecker
}

func NewSPIFFEAuthenticator(verifier SVIDVerifier, trustDomain, environment string) *SPIFFEAuthenticator {
	return &SPIFFEAuthenticator{Verifier: verifier, TrustDomain: trustDomain, Environment: environment, ClockSkew: 30 * time.Second}
}

func (a *SPIFFEAuthenticator) Authenticate(ctx context.Context, credential Credential) (Principal, error) {
	if a == nil || a.Verifier == nil || credential.SVID == nil {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return Principal{}, aorerrors.Wrap(aorerrors.CodeUnauthorized, "", err, nil)
	}
	svid, err := a.Verifier.Verify(ctx, *credential.SVID)
	if err != nil {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	principal, err := ValidateSVID(svid, SVIDValidation{TrustDomain: a.TrustDomain, Environment: a.Environment, Audience: a.Audience, Clock: a.Clock, ClockSkew: a.ClockSkew})
	if err != nil {
		return Principal{}, err
	}
	if a.Revocations != nil {
		revoked, checkErr := a.Revocations.IsRevoked(ctx, "spiffe", svid.ID)
		if checkErr != nil {
			return Principal{}, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
		}
		if revoked {
			return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
		}
	}
	return principal, nil
}

func cloneAttributes(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func (p Principal) String() string {
	if p.ID == "" {
		return "<invalid-principal>"
	}
	if p.Role == "" {
		return fmt.Sprintf("%s:%s", p.Type, p.ID)
	}
	return fmt.Sprintf("%s:%s:%s", p.Type, p.Role, p.ID)
}
