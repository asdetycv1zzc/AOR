package controlapi

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/eventing"
)

type curatorRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip curatorRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestKnowledgeCuratorProxyRouteAllowlist(t *testing.T) {
	const projectID = "22222222-2222-4222-8222-222222222222"
	const updateID = "33333333-3333-4333-8333-333333333333"
	for _, test := range []struct {
		method, path string
		allowed      bool
	}{
		{method: http.MethodPost, path: "/v1/projects/" + projectID + "/knowledge:propose-update", allowed: true},
		{method: http.MethodGet, path: "/v1/projects/" + projectID + "/knowledge/updates/" + updateID, allowed: true},
		{method: http.MethodPost, path: "/v1/projects/" + projectID + "/knowledge/updates/" + updateID + ":approve", allowed: true},
		{method: http.MethodGet, path: "/v1/projects/" + projectID + "/knowledge:search"},
		{method: http.MethodPost, path: "/v1/projects/" + projectID + "/knowledge/updates/" + updateID},
		{method: http.MethodPost, path: "/v1/projects/" + projectID + "/knowledge/updates/" + updateID + ":reject"},
		{method: http.MethodPost, path: "/v1/projects/not-a-uuid/knowledge:propose-update"},
	} {
		request, err := http.NewRequest(test.method, "http://aor-api"+test.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := isKnowledgeCuratorRequest(request); got != test.allowed {
			t.Errorf("isKnowledgeCuratorRequest(%s %s) = %t, want %t", test.method, test.path, got, test.allowed)
		}
	}
}

func TestKnowledgeCuratorProxyForwardsOnlyWriterRoutesWithCallerCredential(t *testing.T) {
	const projectID = "22222222-2222-4222-8222-222222222222"
	type receivedRequest struct {
		method, path, authorization, idempotencyKey, forwardedBy, body string
	}
	received := make(chan receivedRequest, 1)
	transport := curatorRoundTripper(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		received <- receivedRequest{
			method: request.Method, path: request.URL.RequestURI(), authorization: request.Header.Get("Authorization"),
			idempotencyKey: request.Header.Get("Idempotency-Key"), forwardedBy: request.Header.Get(curatorForwardedHeader), body: string(body),
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
				"Location":     []string{"/v1/projects/" + projectID + "/knowledge/updates/update-1"},
			},
			Body: io.NopCloser(strings.NewReader(`{"proxied":true}`)),
		}, nil
	})

	handler, err := New(Config{
		Store: eventing.NewMemoryStore(),
		Authenticator: fixedAuthenticator{principal: authn.Principal{
			ID: "user-1", Type: authn.PrincipalUser, Role: authn.RoleUser, TenantID: testTenantID,
		}},
		Authorizer: &recordingAuthorizer{}, KnowledgeCuratorURL: "http://aor-curator:8080",
	})
	if err != nil {
		t.Fatal(err)
	}
	handler.knowledgeCuratorHTTP = &http.Client{Transport: transport}
	body := `{"expectedVersion":1,"instruction":"update","proposal":{}}`
	response := performRequest(handler, http.MethodPost, "/v1/projects/"+projectID+"/knowledge:propose-update", []byte(body), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "curator-proxy-1",
	})
	if response.Code != http.StatusCreated || response.Header().Get("Location") == "" || !strings.Contains(response.Body.String(), `"proxied":true`) {
		t.Fatalf("proxy response status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	request := <-received
	if request.method != http.MethodPost || request.path != "/v1/projects/"+projectID+"/knowledge:propose-update" ||
		request.authorization != "Bearer "+testBearer || request.idempotencyKey != "curator-proxy-1" || request.forwardedBy != "aor-api" || request.body != body {
		t.Fatalf("forwarded request = %#v", request)
	}
}

func TestKnowledgeCuratorProxyFailsClosedOnLoop(t *testing.T) {
	const projectID = "22222222-2222-4222-8222-222222222222"
	handler, err := New(Config{
		Store: eventing.NewMemoryStore(),
		Authenticator: fixedAuthenticator{principal: authn.Principal{
			ID: "user-1", Type: authn.PrincipalUser, Role: authn.RoleUser, TenantID: testTenantID,
		}},
		Authorizer: &recordingAuthorizer{}, KnowledgeCuratorURL: "http://127.0.0.1:65535",
	})
	if err != nil {
		t.Fatal(err)
	}
	response := performRequest(handler, http.MethodPost, "/v1/projects/"+projectID+"/knowledge:propose-update", []byte(`{}`), map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", curatorForwardedHeader: "aor-api",
	})
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "AOR_DEPENDENCY_UNAVAILABLE") {
		t.Fatalf("loop response status=%d body=%s", response.Code, response.Body.String())
	}
}
