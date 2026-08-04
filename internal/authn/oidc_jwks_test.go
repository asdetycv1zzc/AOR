package authn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var jwksTestTime = time.Date(2026, 8, 4, 5, 0, 0, 0, time.UTC)

type rotatingJWKS struct {
	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
}

func (set *rotatingJWKS) ServeHTTP(response http.ResponseWriter, _ *http.Request) {
	set.mu.RLock()
	defer set.mu.RUnlock()
	type key struct {
		KeyType   string `json:"kty"`
		Use       string `json:"use"`
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Modulus   string `json:"n"`
		Exponent  string `json:"e"`
	}
	keys := make([]key, 0, len(set.keys))
	for keyID, publicKey := range set.keys {
		keys = append(keys, key{
			KeyType: "RSA", Use: "sig", Algorithm: "RS256", KeyID: keyID,
			Modulus:  base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
			Exponent: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
		})
	}
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(map[string]any{"keys": keys})
}

func (set *rotatingJWKS) replace(keyID string, key *rsa.PublicKey) {
	set.mu.Lock()
	defer set.mu.Unlock()
	set.keys = map[string]*rsa.PublicKey{keyID: key}
}

func TestRemoteJWKSVerifierAuthenticatesAndRefreshesRotation(t *testing.T) {
	firstKey := generateRSAKey(t)
	secondKey := generateRSAKey(t)
	set := &rotatingJWKS{keys: map[string]*rsa.PublicKey{"key-1": &firstKey.PublicKey}}
	server := httptest.NewServer(set)
	defer server.Close()

	verifier, err := NewRemoteJWKSVerifier(RemoteJWKSConfig{
		Issuer: server.URL, JWKSURL: server.URL, AllowHTTP: true, CacheTTL: time.Hour,
		Clock: func() time.Time { return jwksTestTime }, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	authenticator := NewOIDCAuthenticator(verifier, []string{server.URL}, "aor-control-plane")
	authenticator.Clock = func() time.Time { return jwksTestTime }
	claims := validRemoteClaims(server.URL)
	principal, err := authenticator.Authenticate(context.Background(), BearerCredential(signJWT(t, firstKey, "key-1", claims)))
	if err != nil {
		t.Fatal(err)
	}
	if principal.ID != "user-1" || principal.TenantID != "11111111-1111-4111-8111-111111111111" || principal.Role != RoleUser {
		t.Fatalf("principal = %#v", principal)
	}

	set.replace("key-2", &secondKey.PublicKey)
	principal, err = authenticator.Authenticate(context.Background(), BearerCredential(signJWT(t, secondKey, "key-2", claims)))
	if err != nil || principal.ID != "user-1" {
		t.Fatalf("rotated principal=%#v err=%v", principal, err)
	}
}

func TestRemoteJWKSVerifierRejectsForgeryAlgorithmsAndIssuer(t *testing.T) {
	key := generateRSAKey(t)
	attacker := generateRSAKey(t)
	set := &rotatingJWKS{keys: map[string]*rsa.PublicKey{"key-1": &key.PublicKey}}
	server := httptest.NewServer(set)
	defer server.Close()
	verifier, err := NewRemoteJWKSVerifier(RemoteJWKSConfig{Issuer: server.URL, JWKSURL: server.URL, AllowHTTP: true, CacheTTL: time.Minute, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	claims := validRemoteClaims(server.URL)

	for name, token := range map[string]string{
		"forged":       signJWT(t, attacker, "key-1", claims),
		"wrong issuer": signJWT(t, key, "key-1", withIssuer(claims, "http://untrusted.example")),
		"none":         unsignedJWT(t, claims),
		"malformed":    "not.a.jwt.with.extra.segment",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Verify(context.Background(), token); err == nil {
				t.Fatal("invalid proof was accepted")
			}
		})
	}
}

func TestRemoteJWKSVerifierFailsClosedOnRedirectAndOversize(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path == "/redirect" {
			http.Redirect(response, request, "/keys", http.StatusFound)
			return
		}
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(make([]byte, maximumJWKSBytes+1))
	}))
	defer server.Close()
	key := generateRSAKey(t)
	claims := validRemoteClaims(server.URL)

	for _, path := range []string{"/redirect", "/keys"} {
		verifier, err := NewRemoteJWKSVerifier(RemoteJWKSConfig{Issuer: server.URL, JWKSURL: server.URL + path, AllowHTTP: true, HTTPClient: server.Client()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifier.Verify(context.Background(), signJWT(t, key, "key", claims)); err == nil {
			t.Fatalf("path %s did not fail closed", path)
		}
	}
	if requests.Load() != 4 {
		// Each first lookup retries once for an unknown key; redirects are not followed.
		t.Fatalf("requests = %d", requests.Load())
	}
}

func TestSecurityJSONDecodersRejectDuplicateMembers(t *testing.T) {
	if err := decodeSingleJSON([]byte(`{"alg":"RS256","alg":"none","kid":"key"}`), &struct {
		Algorithm string `json:"alg"`
	}{}); err == nil {
		t.Fatal("duplicate JWT header member accepted")
	}
	if _, err := decodeOIDCClaims([]byte(`{"iss":"issuer","sub":"user","aud":"aor","iat":1,"exp":2,"principalType":"USER","role":"USER","tenantId":"tenant","tenantId":"other"}`)); err == nil {
		t.Fatal("duplicate claims member accepted")
	}
}

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func validRemoteClaims(issuer string) map[string]any {
	return map[string]any{
		"iss": issuer, "sub": "user-1", "aud": []string{"aor-control-plane"},
		"iat": jwksTestTime.Add(-time.Minute).Unix(), "nbf": jwksTestTime.Add(-time.Minute).Unix(), "exp": jwksTestTime.Add(time.Hour).Unix(),
		"principalType": PrincipalUser, "role": RoleUser, "tenantId": "11111111-1111-4111-8111-111111111111",
	}
}

func withIssuer(claims map[string]any, issuer string) map[string]any {
	copyClaims := make(map[string]any, len(claims))
	for key, value := range claims {
		copyClaims[key] = value
	}
	copyClaims["iss"] = issuer
	return copyClaims
}

func signJWT(t *testing.T, key *rsa.PrivateKey, keyID string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "RS256", "kid": keyID, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func unsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "none", "kid": "key-1", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".invalid"
}
