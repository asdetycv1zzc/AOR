package aor

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestGetProjectBuildsAuthenticatedRequest(t *testing.T) {
	var received *http.Request
	client, err := NewClient("https://api.example.test/edge", &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			received = request
			return &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{}`)),
				Request:    request,
			}, nil
		}),
	}, func(context.Context) (string, error) { return "token-1", nil })
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.GetProject(context.Background(), RequestOptions{
		PathParameters: map[string]string{"projectId": "project-1"},
		Query:          url.Values{"cursor": {"next"}},
		Headers:        http.Header{"X-Request-Id": {"request-1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if received == nil {
		t.Fatal("transport did not receive a request")
	}
	if received.Method != http.MethodGet || received.URL.String() != "https://api.example.test/edge/v1/projects/project-1?cursor=next" {
		t.Fatalf("unexpected request: %s %s", received.Method, received.URL)
	}
	if received.Header.Get("Authorization") != "Bearer token-1" || received.Header.Get("X-Request-ID") != "request-1" {
		t.Fatalf("request headers were not preserved: %v", received.Header)
	}
}

func TestClientRejectsUnsafeBaseURLAndMissingPath(t *testing.T) {
	if _, err := NewClient("http://api.example.test", nil, nil); err == nil {
		t.Fatal("HTTP base URL was accepted")
	}
	client, err := NewClient("https://api.example.test", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetProject(context.Background(), RequestOptions{})
	if err == nil || !strings.Contains(err.Error(), "missing OpenAPI path parameter") {
		t.Fatalf("missing path parameter error = %v", err)
	}
	_, err = client.GetProject(context.Background(), RequestOptions{PathParameters: map[string]string{"projectId": ""}})
	if err == nil || !strings.Contains(err.Error(), "missing OpenAPI path parameter") {
		t.Fatalf("empty path parameter error = %v", err)
	}
	client, err = NewClient("https://api.example.test", &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{}`)),
				Request:    request,
			}, nil
		}),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetProject(context.Background(), RequestOptions{PathParameters: map[string]string{"projectId": "project-1"}}); err != nil {
		t.Fatalf("nil headers caused a request failure: %v", err)
	}
}
