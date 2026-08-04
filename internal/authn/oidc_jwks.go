package authn

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrOIDCProofInvalid = errors.New("oidc proof invalid")

const (
	maximumOIDCTokenBytes = 64 << 10
	maximumJWKSBytes      = 1 << 20
	maximumJWKCount       = 128
	defaultJWKSCacheTTL   = 5 * time.Minute
)

type RemoteJWKSConfig struct {
	Issuer      string
	JWKSURL     string
	HTTPClient  *http.Client
	CacheTTL    time.Duration
	AllowHTTP   bool
	Clock       func() time.Time
	MinimumBits int
}

// RemoteJWKSVerifier verifies RS256 JWTs against an issuer-bound remote JWKS.
// It refreshes on cache expiry and once on an unknown key ID to support rotation.
type RemoteJWKSVerifier struct {
	issuer      string
	jwksURL     string
	client      *http.Client
	cacheTTL    time.Duration
	clock       func() time.Time
	minimumBits int

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
}

type jwtHeader struct {
	Algorithm string          `json:"alg"`
	KeyID     string          `json:"kid"`
	Type      string          `json:"typ,omitempty"`
	Critical  json.RawMessage `json:"crit,omitempty"`
}

type remoteJWKSet struct {
	Keys []remoteJWK `json:"keys"`
}

type remoteJWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use,omitempty"`
	Algorithm string `json:"alg,omitempty"`
	KeyID     string `json:"kid"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

func NewRemoteJWKSVerifier(config RemoteJWKSConfig) (*RemoteJWKSVerifier, error) {
	issuer, err := validateOIDCEndpoint(config.Issuer, config.AllowHTTP)
	if err != nil {
		return nil, ErrOIDCProofInvalid
	}
	jwksURL, err := validateOIDCEndpoint(config.JWKSURL, config.AllowHTTP)
	if err != nil || issuer.Scheme != jwksURL.Scheme {
		return nil, ErrOIDCProofInvalid
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = defaultJWKSCacheTTL
	}
	if config.CacheTTL < time.Second || config.CacheTTL > 24*time.Hour {
		return nil, ErrOIDCProofInvalid
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.MinimumBits == 0 {
		config.MinimumBits = 2048
	}
	if config.MinimumBits < 2048 || config.MinimumBits > 8192 {
		return nil, ErrOIDCProofInvalid
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	copyClient := *client
	if copyClient.Timeout <= 0 || copyClient.Timeout > 30*time.Second {
		copyClient.Timeout = 5 * time.Second
	}
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &RemoteJWKSVerifier{
		issuer: strings.TrimRight(issuer.String(), "/"), jwksURL: jwksURL.String(), client: &copyClient,
		cacheTTL: config.CacheTTL, clock: config.Clock, minimumBits: config.MinimumBits,
		keys: make(map[string]*rsa.PublicKey),
	}, nil
}

func (verifier *RemoteJWKSVerifier) Verify(ctx context.Context, bearerToken string) (OIDCClaims, error) {
	if verifier == nil || ctx == nil || bearerToken == "" || len(bearerToken) > maximumOIDCTokenBytes || strings.ContainsAny(bearerToken, "\r\n\x00") {
		return OIDCClaims{}, ErrOIDCProofInvalid
	}
	if err := ctx.Err(); err != nil {
		return OIDCClaims{}, ErrOIDCProofInvalid
	}
	segments := strings.Split(bearerToken, ".")
	if len(segments) != 3 || segments[0] == "" || segments[1] == "" || segments[2] == "" {
		return OIDCClaims{}, ErrOIDCProofInvalid
	}
	headerBytes, err := decodeBase64URL(segments[0], 16<<10)
	if err != nil {
		return OIDCClaims{}, ErrOIDCProofInvalid
	}
	var header jwtHeader
	if err := decodeSingleJSON(headerBytes, &header); err != nil || header.Algorithm != "RS256" || header.KeyID == "" || len(header.KeyID) > 256 || len(header.Critical) != 0 || header.Type != "" && !strings.EqualFold(header.Type, "JWT") || strings.ContainsAny(header.KeyID, "\r\n\x00") {
		return OIDCClaims{}, ErrOIDCProofInvalid
	}
	signature, err := decodeBase64URL(segments[2], 16<<10)
	if err != nil {
		return OIDCClaims{}, ErrOIDCProofInvalid
	}
	key, err := verifier.key(ctx, header.KeyID, false)
	if err != nil {
		key, err = verifier.key(ctx, header.KeyID, true)
	}
	if err != nil || key == nil {
		return OIDCClaims{}, ErrOIDCProofInvalid
	}
	digest := sha256.Sum256([]byte(segments[0] + "." + segments[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return OIDCClaims{}, ErrOIDCProofInvalid
	}
	claimsBytes, err := decodeBase64URL(segments[1], maximumOIDCTokenBytes)
	if err != nil {
		return OIDCClaims{}, ErrOIDCProofInvalid
	}
	claims, err := decodeOIDCClaims(claimsBytes)
	if err != nil || subtle.ConstantTimeCompare([]byte(strings.TrimRight(claims.Issuer, "/")), []byte(verifier.issuer)) != 1 {
		return OIDCClaims{}, ErrOIDCProofInvalid
	}
	return claims, nil
}

func (verifier *RemoteJWKSVerifier) key(ctx context.Context, keyID string, force bool) (*rsa.PublicKey, error) {
	now := verifier.clock().UTC()
	verifier.mu.RLock()
	key := verifier.keys[keyID]
	valid := now.Before(verifier.expiresAt)
	verifier.mu.RUnlock()
	if !force && valid {
		if key == nil {
			return nil, ErrOIDCProofInvalid
		}
		return key, nil
	}
	if err := verifier.refresh(ctx, now); err != nil {
		return nil, err
	}
	verifier.mu.RLock()
	defer verifier.mu.RUnlock()
	key = verifier.keys[keyID]
	if key == nil {
		return nil, ErrOIDCProofInvalid
	}
	return key, nil
}

func (verifier *RemoteJWKSVerifier) refresh(ctx context.Context, now time.Time) error {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, verifier.jwksURL, nil)
	if err != nil {
		return ErrOIDCProofInvalid
	}
	request.Header.Set("Accept", "application/json")
	response, err := verifier.client.Do(request)
	if err != nil {
		return ErrOIDCProofInvalid
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ErrOIDCProofInvalid
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumJWKSBytes+1))
	if err != nil || len(body) == 0 || len(body) > maximumJWKSBytes {
		return ErrOIDCProofInvalid
	}
	var set remoteJWKSet
	if err := decodeSingleJSON(body, &set); err != nil || len(set.Keys) == 0 || len(set.Keys) > maximumJWKCount {
		return ErrOIDCProofInvalid
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, candidate := range set.Keys {
		if candidate.KeyType != "RSA" || candidate.KeyID == "" || len(candidate.KeyID) > 256 || candidate.Use != "" && candidate.Use != "sig" || candidate.Algorithm != "" && candidate.Algorithm != "RS256" {
			continue
		}
		if _, duplicate := keys[candidate.KeyID]; duplicate {
			return ErrOIDCProofInvalid
		}
		key, err := rsaKey(candidate, verifier.minimumBits)
		if err != nil {
			continue
		}
		keys[candidate.KeyID] = key
	}
	if len(keys) == 0 {
		return ErrOIDCProofInvalid
	}
	verifier.keys = keys
	verifier.expiresAt = now.Add(verifier.cacheTTL)
	return nil
}

func rsaKey(jwk remoteJWK, minimumBits int) (*rsa.PublicKey, error) {
	modulusBytes, err := decodeBase64URL(jwk.Modulus, maximumJWKSBytes)
	if err != nil || len(modulusBytes) == 0 {
		return nil, ErrOIDCProofInvalid
	}
	exponentBytes, err := decodeBase64URL(jwk.Exponent, 8)
	if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
		return nil, ErrOIDCProofInvalid
	}
	exponent := 0
	for _, value := range exponentBytes {
		exponent = exponent<<8 | int(value)
	}
	modulus := new(big.Int).SetBytes(modulusBytes)
	if exponent < 3 || exponent%2 == 0 || modulus.BitLen() < minimumBits || modulus.BitLen() > 8192 {
		return nil, ErrOIDCProofInvalid
	}
	return &rsa.PublicKey{N: modulus, E: exponent}, nil
}

func decodeOIDCClaims(content []byte) (OIDCClaims, error) {
	if err := rejectDuplicateJSONMembers(content); err != nil {
		return OIDCClaims{}, err
	}
	var raw struct {
		Issuer        string            `json:"iss"`
		Subject       string            `json:"sub"`
		Audience      json.RawMessage   `json:"aud"`
		IssuedAt      json.Number       `json:"iat"`
		NotBefore     json.Number       `json:"nbf"`
		ExpiresAt     json.Number       `json:"exp"`
		PrincipalType PrincipalType     `json:"principalType"`
		Role          string            `json:"role"`
		TenantID      string            `json:"tenantId"`
		ProjectID     string            `json:"projectId"`
		Attributes    map[string]string `json:"attributes"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.UseNumber()
	if err := decoder.Decode(&raw); err != nil {
		return OIDCClaims{}, ErrOIDCProofInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return OIDCClaims{}, ErrOIDCProofInvalid
	}
	audience, err := decodeAudience(raw.Audience)
	if err != nil {
		return OIDCClaims{}, err
	}
	issuedAt, err := numericDate(raw.IssuedAt, false)
	if err != nil {
		return OIDCClaims{}, err
	}
	notBefore, err := numericDate(raw.NotBefore, false)
	if err != nil {
		return OIDCClaims{}, err
	}
	expiresAt, err := numericDate(raw.ExpiresAt, true)
	if err != nil {
		return OIDCClaims{}, err
	}
	return OIDCClaims{
		Issuer: raw.Issuer, Subject: raw.Subject, Audience: audience, IssuedAt: issuedAt,
		NotBefore: notBefore, ExpiresAt: expiresAt, PrincipalType: raw.PrincipalType,
		Role: raw.Role, TenantID: raw.TenantID, ProjectID: raw.ProjectID, Attributes: cloneAttributes(raw.Attributes),
	}, nil
}

func decodeAudience(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, ErrOIDCProofInvalid
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}, nil
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil || len(many) == 0 || len(many) > 32 {
		return nil, ErrOIDCProofInvalid
	}
	return many, nil
}

func numericDate(value json.Number, required bool) (time.Time, error) {
	if value == "" {
		if required {
			return time.Time{}, ErrOIDCProofInvalid
		}
		return time.Time{}, nil
	}
	seconds, err := strconv.ParseInt(value.String(), 10, 64)
	if err != nil || seconds < 0 {
		return time.Time{}, ErrOIDCProofInvalid
	}
	return time.Unix(seconds, 0).UTC(), nil
}

func decodeBase64URL(value string, maximum int) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") || len(value) > maximum*2 {
		return nil, ErrOIDCProofInvalid
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) > maximum {
		return nil, ErrOIDCProofInvalid
	}
	return decoded, nil
}

func decodeSingleJSON(content []byte, target any) error {
	if err := rejectDuplicateJSONMembers(content); err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrOIDCProofInvalid
	}
	return nil
}

// rejectDuplicateJSONMembers prevents ambiguous security claims such as two
// tenantId or alg members from being interpreted differently by different
// JSON implementations. It also bounds nesting so malformed input cannot
// consume unbounded stack space.
func rejectDuplicateJSONMembers(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := walkJSONValue(decoder, 0); err != nil {
		return ErrOIDCProofInvalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrOIDCProofInvalid
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return ErrOIDCProofInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		members := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrOIDCProofInvalid
			}
			if _, duplicate := members[key]; duplicate {
				return ErrOIDCProofInvalid
			}
			members[key] = struct{}{}
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrOIDCProofInvalid
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return ErrOIDCProofInvalid
		}
	default:
		return ErrOIDCProofInvalid
	}
	return nil
}

func validateOIDCEndpoint(raw string, allowHTTP bool) (*url.URL, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || len(raw) > 2048 {
		return nil, ErrOIDCProofInvalid
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrOIDCProofInvalid
	}
	if parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http") {
		return nil, ErrOIDCProofInvalid
	}
	return parsed, nil
}

var _ OIDCVerifier = (*RemoteJWKSVerifier)(nil)
