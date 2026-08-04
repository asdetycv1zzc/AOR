package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type httpAuthenticatorFunc func(context.Context, Credential) (Principal, error)

func (function httpAuthenticatorFunc) Authenticate(ctx context.Context, credential Credential) (Principal, error) {
	return function(ctx, credential)
}

func TestHTTPMiddlewareBindsPrincipalAndRemovesCredential(t *testing.T) {
	authenticator := httpAuthenticatorFunc(func(_ context.Context, credential Credential) (Principal, error) {
		if credential.BearerToken != "valid-token" {
			t.Fatal("unexpected credential")
		}
		return Principal{ID: "user-1", Type: PrincipalUser, Role: RoleUser, TenantID: "tenant-1"}, nil
	})
	called := false
	next := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		called = true
		principal, ok := PrincipalFromContext(request.Context())
		if !ok || principal.ID != "user-1" {
			t.Fatalf("principal = %#v ok=%v", principal, ok)
		}
		if request.Header.Get("Authorization") != "" {
			t.Fatal("credential reached downstream handler")
		}
		response.WriteHeader(http.StatusNoContent)
	})
	middleware, err := NewHTTPMiddleware(authenticator, next)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()
	middleware.ServeHTTP(response, request)
	if !called || response.Code != http.StatusNoContent {
		t.Fatalf("called=%v status=%d", called, response.Code)
	}
}

func TestHTTPMiddlewareFailsClosedWithoutLeakingToken(t *testing.T) {
	secret := "token-that-must-not-leak"
	authenticator := httpAuthenticatorFunc(func(context.Context, Credential) (Principal, error) {
		return Principal{}, ErrOIDCProofInvalid
	})
	middleware, err := NewHTTPMiddleware(authenticator, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("downstream handler was called")
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	request.Header.Set("Authorization", "Bearer "+secret)
	response := httptest.NewRecorder()
	middleware.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), secret) || response.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

var _ Authenticator = httpAuthenticatorFunc(nil)
