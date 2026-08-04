package modelgateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOAuthClientCredentialsTokenSourceCachesShortLivedToken(t *testing.T) {
	now := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		clientID, secret, ok := request.BasicAuth()
		if !ok || clientID != "aor-server" || secret != "service-secret" {
			t.Error("missing client authentication")
		}
		if err := request.ParseForm(); err != nil || request.Form.Get("grant_type") != "client_credentials" || request.Form.Get("scope") != "model.generate openid" || request.Form.Get("audience") != "aor" {
			t.Errorf("token form = %#v err=%v", request.Form, err)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"access_token":"short-lived-token","token_type":"Bearer","expires_in":120}`))
	}))
	defer server.Close()
	source, err := NewOAuthClientCredentialsTokenSource(OAuthClientCredentialsConfig{
		TokenEndpoint: server.URL, ClientID: "aor-server", ClientSecret: []byte("service-secret"),
		Scopes: []string{"openid", "model.generate"}, Audience: "aor", AllowHTTP: true, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.Value != "short-lived-token" || !first.ExpiresAt.Equal(now.Add(120*time.Second)) || calls.Load() != 1 {
		t.Fatalf("tokens first=%#v second=%#v calls=%d", first, second, calls.Load())
	}
}

func TestOAuthClientCredentialsTokenSourceRefreshesNearExpiry(t *testing.T) {
	now := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"access_token":"token-` + string(rune('0'+call)) + `","token_type":"Bearer","expires_in":40}`))
	}))
	defer server.Close()
	source, err := NewOAuthClientCredentialsTokenSource(OAuthClientCredentialsConfig{
		TokenEndpoint: server.URL, ClientID: "client", ClientSecret: []byte("secret"), AllowHTTP: true, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(15 * time.Second)
	second, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Value == second.Value || calls.Load() != 2 {
		t.Fatalf("tokens first=%#v second=%#v calls=%d", first, second, calls.Load())
	}
}

func TestOAuthClientCredentialsTokenSourceRejectsUnsafeResponses(t *testing.T) {
	for _, test := range []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "content type", contentType: "text/plain", body: `{"access_token":"token","token_type":"Bearer","expires_in":60}`},
		{name: "token", contentType: "application/json", body: `{"access_token":"unsafe token","token_type":"Bearer","expires_in":60}`},
		{name: "unknown field", contentType: "application/json", body: `{"access_token":"token","token_type":"Bearer","expires_in":60,"secret":"leak"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", test.contentType)
				_, _ = response.Write([]byte(test.body))
			}))
			defer server.Close()
			source, err := NewOAuthClientCredentialsTokenSource(OAuthClientCredentialsConfig{
				TokenEndpoint: server.URL, ClientID: "client", ClientSecret: []byte("not-in-errors"), AllowHTTP: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = source.Token(context.Background())
			if err == nil || strings.Contains(err.Error(), "not-in-errors") || strings.Contains(err.Error(), test.body) {
				t.Fatalf("unsafe response error = %v", err)
			}
		})
	}
}

func TestOAuthClientCredentialsTokenSourceRequiresTLSByDefault(t *testing.T) {
	if _, err := NewOAuthClientCredentialsTokenSource(OAuthClientCredentialsConfig{
		TokenEndpoint: "http://identity.example/token", ClientID: "client", ClientSecret: []byte("secret"),
	}); err == nil {
		t.Fatal("plaintext token endpoint accepted")
	}
}
