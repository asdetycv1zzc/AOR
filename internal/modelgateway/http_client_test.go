package modelgateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/observability"
)

func TestHTTPClientGenerateUsesPrivateEnvelopeTokenAndTrace(t *testing.T) {
	type observedRequest struct {
		Method        string
		Path          string
		Authorization string
		Accept        string
		ContentType   string
		Traceparent   string
		Tracestate    string
		Input         transportGenerateRequest
	}
	observed := make(chan observedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var input transportGenerateRequest
		decodeErr := json.NewDecoder(request.Body).Decode(&input)
		if decodeErr != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		observed <- observedRequest{
			Method: request.Method, Path: request.URL.Path, Authorization: request.Header.Get("Authorization"),
			Accept: request.Header.Get("Accept"), ContentType: request.Header.Get("Content-Type"),
			Traceparent: request.Header.Get(observability.TraceParentHeader), Tracestate: request.Header.Get(observability.TraceStateHeader), Input: input,
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(transportGenerateResponse{Response: NormalizedResponse{
			RequestID: input.Request.RequestID, ProviderRequestID: "provider-request", ModelVersion: "model-v1",
			Content: json.RawMessage(`{"ok":true}`), FinishReason: "stop",
		}})
	}))
	defer server.Close()

	tokens := &httpClientTokenSource{token: validHTTPClientToken()}
	client, err := NewHTTPClient(HTTPClientConfig{Endpoint: server.URL, TokenSource: tokens})
	if err != nil {
		t.Fatal(err)
	}
	traceparent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	trace, err := observability.ParseTraceParent(traceparent, "vendor=value")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := observability.ContextWithTrace(context.Background(), trace)
	if err != nil {
		t.Fatal(err)
	}
	semanticCalls := 0
	input := httpClientNormalizedRequest()
	input.ResponseSchema = json.RawMessage(`{"type":"object","required":["ok"],"properties":{"ok":{"type":"boolean"}},"additionalProperties":false}`)
	input.ResponseSemanticValidator = func(content json.RawMessage) error {
		semanticCalls++
		if string(content) != `{"ok":true}` {
			return errors.New("unexpected content")
		}
		return nil
	}
	response, err := client.Generate(ctx, input, GenerateOptions{Provider: "provider", AccountID: "account", ReservationID: "reservation"})
	if err != nil {
		t.Fatal(err)
	}
	if response.RequestID != input.RequestID || string(response.Content) != `{"ok":true}` || semanticCalls != 1 || tokens.Calls() != 1 {
		t.Fatalf("response=%#v semanticCalls=%d tokenCalls=%d", response, semanticCalls, tokens.Calls())
	}
	captured := <-observed
	if captured.Method != http.MethodPost || captured.Path != "/v1/model/generate" || captured.Authorization != "Bearer "+httpClientTestToken() {
		t.Fatalf("request method=%s path=%s authorization=%q", captured.Method, captured.Path, captured.Authorization)
	}
	if captured.Accept != "application/json" || captured.ContentType != "application/json" || captured.Traceparent != traceparent || captured.Tracestate != "vendor=value" {
		t.Fatalf("headers=%#v", captured)
	}
	if captured.Input.Request.RequestID != input.RequestID || captured.Input.Options.Provider != "provider" || captured.Input.Options.MaxAttempts != 5 {
		t.Fatalf("transport input=%#v", captured.Input)
	}
}

func TestHTTPClientSkipsFinalValidationForToolCallResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var input transportGenerateRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(transportGenerateResponse{Response: NormalizedResponse{
			RequestID: input.Request.RequestID, ProviderRequestID: "provider-tool", ModelVersion: "model-v1",
			ToolCalls: []ToolCall{{ID: "call-1", Name: "repo.read", Arguments: json.RawMessage(`{"path":"README.md"}`)}}, FinishReason: "tool_calls",
		}})
	}))
	defer server.Close()

	client, err := NewHTTPClient(HTTPClientConfig{Endpoint: server.URL, TokenSource: &httpClientTokenSource{token: validHTTPClientToken()}})
	if err != nil {
		t.Fatal(err)
	}
	input := httpClientNormalizedRequest()
	input.Tools = []ToolDefinition{{Name: "repo.read", Schema: json.RawMessage(`{"type":"object"}`)}}
	input.ResponseSchema = json.RawMessage(`{"type":"object","required":["ok"]}`)
	semanticCalls := 0
	input.ResponseSemanticValidator = func(json.RawMessage) error {
		semanticCalls++
		return errors.New("final-content validation must be skipped")
	}
	response, err := client.Generate(context.Background(), input, GenerateOptions{Provider: "provider", AccountID: "account", ReservationID: "reservation", MaxAttempts: 1})
	if err != nil || len(response.Content) != 0 || len(response.ToolCalls) != 1 || semanticCalls != 0 {
		t.Fatalf("response=%#v error=%v semanticCalls=%d", response, err, semanticCalls)
	}
}

func TestHTTPClientMapsStableErrorEnvelope(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		code      string
		retryable bool
		target    error
		unknown   bool
	}{
		{name: "forbidden", status: http.StatusForbidden, code: "AOR_FORBIDDEN", target: ErrAuthorizationDenied},
		{name: "invalid", status: http.StatusBadRequest, code: "AOR_INVALID_ARGUMENT", target: ErrInvalidRequest},
		{name: "budget", status: http.StatusConflict, code: "AOR_BUDGET_EXCEEDED", target: ErrBudgetExceeded},
		{name: "idempotency", status: http.StatusConflict, code: "AOR_IDEMPOTENCY_CONFLICT", target: ErrRequestConflict},
		{name: "reservation", status: http.StatusConflict, code: "AOR_BUDGET_RESERVATION_FAILED", target: ErrReservationConflict},
		{name: "model", status: http.StatusForbidden, code: "AOR_MODEL_NOT_ALLOWED", target: ErrProviderNotAllowed},
		{name: "schema", status: http.StatusUnprocessableEntity, code: "AOR_MODEL_OUTPUT_SCHEMA_INVALID", target: ErrOutputSchema},
		{name: "timeout", status: http.StatusGatewayTimeout, code: "AOR_TIMEOUT", retryable: true, target: context.DeadlineExceeded},
		{name: "dependency", status: http.StatusServiceUnavailable, code: "AOR_DEPENDENCY_UNAVAILABLE", retryable: true, target: ErrProviderUnavailable},
		{name: "unknown outcome", status: http.StatusBadGateway, code: "AOR_PROVIDER_RESULT_UNKNOWN", retryable: true, target: ErrProviderUnavailable, unknown: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(test.status)
				_ = json.NewEncoder(writer).Encode(map[string]any{"error": map[string]any{
					"code": test.code, "message": "must not escape the client", "retryable": test.retryable,
				}})
			}))
			defer server.Close()
			client, err := NewHTTPClient(HTTPClientConfig{Endpoint: server.URL, TokenSource: &httpClientTokenSource{token: validHTTPClientToken()}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Generate(context.Background(), httpClientNormalizedRequest(), GenerateOptions{Provider: "provider", AccountID: "account", ReservationID: "reservation", MaxAttempts: 1})
			if !errors.Is(err, test.target) || strings.Contains(err.Error(), "must not escape") {
				t.Fatalf("error=%v target=%v", err, test.target)
			}
			var responseErr *HTTPResponseError
			if !errors.As(err, &responseErr) || responseErr.StatusCode != test.status || responseErr.Code != test.code || responseErr.Retryable != test.retryable {
				t.Fatalf("HTTP error=%#v", responseErr)
			}
			var providerFailure *ProviderFailure
			if errors.As(err, &providerFailure) != test.unknown {
				t.Fatalf("provider failure=%#v unknown=%t", providerFailure, test.unknown)
			}
			if test.unknown && (providerFailure.OutcomeKnown || !providerFailure.Retryable) {
				t.Fatalf("provider failure=%#v", providerFailure)
			}
		})
	}
}

func TestHTTPClientRejectsUnsafeTokensWithoutLeakingSourceError(t *testing.T) {
	var serverCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		serverCalls.Add(1)
	}))
	defer server.Close()
	tests := []struct {
		name   string
		token  BearerToken
		source error
	}{
		{name: "source", token: validHTTPClientToken(), source: errors.New("secret from token source")},
		{name: "expired", token: BearerToken{Value: httpClientTestToken(), ExpiresAt: time.Now().Add(-time.Minute)}},
		{name: "header injection", token: BearerToken{Value: httpClientTestToken() + "\r\nforged: value", ExpiresAt: time.Now().Add(time.Minute)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewHTTPClient(HTTPClientConfig{Endpoint: server.URL, TokenSource: &httpClientTokenSource{token: test.token, err: test.source}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Generate(context.Background(), httpClientNormalizedRequest(), GenerateOptions{Provider: "provider", AccountID: "account", ReservationID: "reservation", MaxAttempts: 1})
			if !errors.Is(err, ErrAuthorizationDenied) || strings.Contains(err.Error(), "secret from token source") {
				t.Fatalf("error=%v", err)
			}
		})
	}
	if serverCalls.Load() != 0 {
		t.Fatalf("server calls=%d", serverCalls.Load())
	}
}

func TestHTTPClientEnforcesTimeoutAndNeverFollowsRedirects(t *testing.T) {
	releaseTimeoutHandler := make(chan struct{})
	timeoutServer := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-releaseTimeoutHandler:
		}
	}))
	client, err := NewHTTPClient(HTTPClientConfig{Endpoint: timeoutServer.URL, TokenSource: &httpClientTokenSource{token: validHTTPClientToken()}, Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Generate(context.Background(), httpClientNormalizedRequest(), GenerateOptions{Provider: "provider", AccountID: "account", ReservationID: "reservation", MaxAttempts: 1})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error=%v", err)
	}
	close(releaseTimeoutHandler)
	timeoutServer.Close()

	var redirectedCalls atomic.Int32
	redirected := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectedCalls.Add(1)
	}))
	defer redirected.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, redirected.URL+"/capture", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	client, err = NewHTTPClient(HTTPClientConfig{Endpoint: redirector.URL, TokenSource: &httpClientTokenSource{token: validHTTPClientToken()}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Generate(context.Background(), httpClientNormalizedRequest(), GenerateOptions{Provider: "provider", AccountID: "account", ReservationID: "reservation", MaxAttempts: 1})
	var responseErr *HTTPResponseError
	if !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusTemporaryRedirect || redirectedCalls.Load() != 0 {
		t.Fatalf("redirect error=%v calls=%d", err, redirectedCalls.Load())
	}
}

type httpClientTokenSource struct {
	mu    sync.Mutex
	token BearerToken
	err   error
	calls int
}

func (source *httpClientTokenSource) Token(context.Context) (BearerToken, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.calls++
	return source.token, source.err
}

func (source *httpClientTokenSource) Calls() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.calls
}

func validHTTPClientToken() BearerToken {
	return BearerToken{Value: httpClientTestToken(), ExpiresAt: time.Now().Add(time.Minute)}
}

func httpClientTestToken() string { return "workload-" + "token" }

func httpClientNormalizedRequest() NormalizedRequest {
	return NormalizedRequest{
		RequestID: "request", TenantID: "tenant", ProjectID: "project", TaskID: "task", AgentInstanceID: "agent",
		Role: "EXECUTOR", Model: "model", PromptBundleVersion: "v1", Messages: []Message{{Role: "user", Content: "hello"}},
		MaxOutputTokens: 64, Temperature: 0, ProviderPolicy: "default", DataClassification: "INTERNAL", CachePolicy: "NO_STORE",
		PromptDigest: "prompt-digest", ToolSchemaDigest: "tool-digest", PolicyDigest: "policy-digest", WorstCaseCostMicros: 100,
	}
}
