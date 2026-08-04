package modelgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/observability"
)

func TestHTTPServiceRequiresAuthorizer(t *testing.T) {
	if _, err := NewHTTPService(NewGateway(nil, time.Now), nil, HTTPConfig{}); err != ErrInvalidRequest {
		t.Fatalf("nil authorizer error = %v", err)
	}
	var typedNil *nilServiceAuthorizer
	if _, err := NewHTTPService(NewGateway(nil, time.Now), typedNil, HTTPConfig{}); err != ErrInvalidRequest {
		t.Fatalf("typed nil authorizer error = %v", err)
	}
}

func TestHTTPServiceGeneratesWithAuthorizedIdentityAndTrace(t *testing.T) {
	service, adapter, _ := newHTTPService(t)
	body := marshalTransport(t, transportGenerateRequest{Request: transportRequest("request-1"), Options: GenerateOptions{Provider: "provider", AccountID: "account", ReservationID: "reservation-1", MaxAttempts: 1}})
	request := httptest.NewRequest(http.MethodPost, "/v1/model/generate", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Tenant-ID", "forged")
	request.Header.Set(observability.TraceParentHeader, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	writer := httptest.NewRecorder()
	service.ServeHTTP(writer, request)
	if writer.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", writer.Code, writer.Body.String())
	}
	if writer.Header().Get(observability.TraceParentHeader) != request.Header.Get(observability.TraceParentHeader) {
		t.Fatalf("trace = %q", writer.Header().Get(observability.TraceParentHeader))
	}
	var response transportGenerateResponse
	if err := json.Unmarshal(writer.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Response.RequestID != "request-1" || string(response.Response.Content) != `{"ok":true}` || adapter.GenerateCalls() != 1 {
		t.Fatalf("response = %#v calls=%d", response, adapter.GenerateCalls())
	}
}

func TestHTTPServiceRejectsUntrustedFieldsAndTrailingJSON(t *testing.T) {
	service, adapter, _ := newHTTPService(t)
	valid := marshalTransport(t, transportGenerateRequest{Request: transportRequest("request-1"), Options: GenerateOptions{Provider: "provider", AccountID: "account", ReservationID: "reservation-1", MaxAttempts: 1}})
	cases := []struct {
		name        string
		contentType string
		body        []byte
	}{
		{name: "unknown", contentType: "application/json", body: append([]byte(`{"unexpected":true}`), valid...)},
		{name: "trailing", contentType: "application/json", body: append(valid, []byte(` {}`)...)},
		{name: "content type", contentType: "text/plain", body: valid},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/model/generate", bytes.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			writer := httptest.NewRecorder()
			service.ServeHTTP(writer, request)
			if writer.Code != http.StatusBadRequest || errorCode(t, writer) != "AOR_INVALID_ARGUMENT" || adapter.GenerateCalls() != 0 {
				t.Fatalf("status=%d code=%s calls=%d", writer.Code, errorCode(t, writer), adapter.GenerateCalls())
			}
		})
	}
}

func TestHTTPServiceBindsAuthorizationBeforeGateway(t *testing.T) {
	service, adapter, _ := newHTTPService(t)
	input := transportGenerateRequest{Request: transportRequest("request-1"), Options: GenerateOptions{Provider: "provider", AccountID: "account", ReservationID: "reservation-1", MaxAttempts: 1}}
	input.Request.TenantID = "other-tenant"
	request := httptest.NewRequest(http.MethodPost, "/v1/model/generate", bytes.NewReader(marshalTransport(t, input)))
	request.Header.Set("Content-Type", "application/json")
	writer := httptest.NewRecorder()
	service.ServeHTTP(writer, request)
	if writer.Code != http.StatusForbidden || errorCode(t, writer) != "AOR_FORBIDDEN" || adapter.GenerateCalls() != 0 {
		t.Fatalf("status=%d code=%s calls=%d", writer.Code, errorCode(t, writer), adapter.GenerateCalls())
	}
}

func TestHTTPServiceCapabilitiesCancelAndStreaming(t *testing.T) {
	service, adapter, ledger := newHTTPService(t)
	capabilities := httptest.NewRequest(http.MethodGet, "/v1/model/capabilities?provider=provider&model=model", nil)
	capabilitiesWriter := httptest.NewRecorder()
	service.ServeHTTP(capabilitiesWriter, capabilities)
	if capabilitiesWriter.Code != http.StatusOK {
		t.Fatalf("capabilities status=%d body=%s", capabilitiesWriter.Code, capabilitiesWriter.Body.String())
	}

	if _, err := ledger.Reserve(context.Background(), "tenant", "account", "cancel-reservation", "cancel-request", 1); err != nil {
		t.Fatal(err)
	}
	cancelBody := marshalTransport(t, transportCancelRequest{Provider: "provider", Model: "model", ProviderRequestID: "provider-request-1", AccountID: "account", ReservationID: "cancel-reservation"})
	cancelRequest := httptest.NewRequest(http.MethodPost, "/v1/model/cancel", bytes.NewReader(cancelBody))
	cancelRequest.Header.Set("Content-Type", "application/json")
	cancelWriter := httptest.NewRecorder()
	service.ServeHTTP(cancelWriter, cancelRequest)
	if cancelWriter.Code != http.StatusOK || adapter.CancelCalls() != 1 {
		t.Fatalf("cancel status=%d calls=%d", cancelWriter.Code, adapter.CancelCalls())
	}
	cancelReservation, found := ledger.Reservation("tenant", "cancel-reservation")
	if !found || cancelReservation.State != ReservationReconcile {
		t.Fatalf("cancel reservation = %#v found=%v", cancelReservation, found)
	}

	streamBody := marshalTransport(t, transportGenerateRequest{Request: transportRequest("stream-1"), Options: GenerateOptions{Provider: "provider", AccountID: "account", ReservationID: "stream-reservation", MaxAttempts: 1}})
	streamRequest := httptest.NewRequest(http.MethodPost, "/v1/model/stream", bytes.NewReader(streamBody))
	streamRequest.Header.Set("Content-Type", "application/json")
	streamWriter := httptest.NewRecorder()
	service.ServeHTTP(streamWriter, streamRequest)
	if streamWriter.Code != http.StatusOK || streamWriter.Header().Get("Content-Type") != "text/event-stream" || !strings.Contains(streamWriter.Body.String(), "data: {\"delta\":\"ok\"}") || !strings.Contains(streamWriter.Body.String(), "data: [DONE]") {
		t.Fatalf("stream status=%d headers=%v body=%q", streamWriter.Code, streamWriter.Header(), streamWriter.Body.String())
	}
	reservation, found := ledger.Reservation("tenant", "stream-reservation")
	if !found || reservation.State != ReservationReconcile {
		t.Fatalf("stream reservation = %#v found=%v", reservation, found)
	}
}

func TestHTTPServiceConcurrentGenerateIsRaceSafe(t *testing.T) {
	service, adapter, _ := newHTTPService(t)
	server := httptest.NewServer(service.Handler())
	defer server.Close()
	const requests = 24
	var wait sync.WaitGroup
	failures := make(chan error, requests)
	for index := 0; index < requests; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			id := strconv.Itoa(index)
			body := marshalTransport(t, transportGenerateRequest{Request: transportRequest("request-" + id), Options: GenerateOptions{Provider: "provider", AccountID: "account", ReservationID: "reservation-" + id, MaxAttempts: 1}})
			request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/v1/model/generate", bytes.NewReader(body))
			if err != nil {
				failures <- err
				return
			}
			request.Header.Set("Content-Type", "application/json")
			response, err := server.Client().Do(request)
			if err == nil {
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if response.StatusCode != http.StatusOK {
					err = errors.New("unexpected model gateway status")
				}
			}
			if err != nil {
				failures <- err
			}
		}(index)
	}
	wait.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	if adapter.GenerateCalls() != requests {
		t.Fatalf("generate calls=%d", adapter.GenerateCalls())
	}
}

func TestHTTPServiceMapsStableErrorsAndBoundsBodies(t *testing.T) {
	service, _, _ := newHTTPService(t)
	for _, test := range []struct {
		err  error
		code string
	}{
		{err: ErrBudgetExceeded, code: "AOR_BUDGET_EXCEEDED"},
		{err: ErrProviderNotAllowed, code: "AOR_MODEL_NOT_ALLOWED"},
		{err: &ProviderFailure{OutcomeKnown: false, Retryable: true}, code: "AOR_PROVIDER_RESULT_UNKNOWN"},
	} {
		writer := httptest.NewRecorder()
		writeHTTPError(writer, "", test.err)
		if errorCode(t, writer) != test.code {
			t.Fatalf("error %v mapped to %s", test.err, errorCode(t, writer))
		}
	}
	bounded, err := NewHTTPService(service.gateway, serviceAuthorizer{}, HTTPConfig{MaxRequestBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/model/generate", strings.NewReader(strings.Repeat("x", 33)))
	request.Header.Set("Content-Type", "application/json")
	writer := httptest.NewRecorder()
	bounded.ServeHTTP(writer, request)
	if writer.Code != http.StatusBadRequest || errorCode(t, writer) != "AOR_INVALID_ARGUMENT" {
		t.Fatalf("bounded status=%d code=%s", writer.Code, errorCode(t, writer))
	}
}

type serviceAuthorizer struct{}

type nilServiceAuthorizer struct{}

func (*nilServiceAuthorizer) AuthorizeModel(context.Context, ModelAuthorizationRequest) (ModelAuthorization, error) {
	return ModelAuthorization{}, nil
}

func (serviceAuthorizer) AuthorizeModel(_ context.Context, request ModelAuthorizationRequest) (ModelAuthorization, error) {
	if request.Provider != "provider" {
		return ModelAuthorization{}, errors.New("denied")
	}
	return ModelAuthorization{TenantID: "tenant", ProjectID: "project", TaskID: "task", AgentInstanceID: "agent", Role: "EXECUTOR", Provider: "provider", AccountID: "account"}, nil
}

type serviceAdapter struct {
	mu            sync.Mutex
	generateCalls int
	cancelCalls   int
}

func (a *serviceAdapter) Capabilities(context.Context, string) (ModelCapabilities, error) {
	return ModelCapabilities{SupportsStreaming: true, SupportsJSONSchema: true, MaxInputTokens: 1024, MaxOutputTokens: 64, ActualModelVersion: "model-v1"}, nil
}

func (a *serviceAdapter) CountTokens(context.Context, NormalizedRequest) (TokenEstimate, error) {
	return TokenEstimate{InputTokens: 2}, nil
}

func (a *serviceAdapter) Generate(_ context.Context, request NormalizedRequest) (NormalizedResponse, error) {
	a.mu.Lock()
	a.generateCalls++
	a.mu.Unlock()
	return NormalizedResponse{RequestID: request.RequestID, ProviderRequestID: "provider-request-1", ModelVersion: "model-v1", Content: json.RawMessage(`{"ok":true}`), Usage: Usage{CostMicros: 1}}, nil
}

func (a *serviceAdapter) Stream(context.Context, NormalizedRequest) (ResponseStream, error) {
	return &serviceStream{events: []json.RawMessage{json.RawMessage(`{"delta":"ok"}`)}}, nil
}

func (a *serviceAdapter) Cancel(context.Context, string) error {
	a.mu.Lock()
	a.cancelCalls++
	a.mu.Unlock()
	return nil
}

func (a *serviceAdapter) NormalizeUsage(raw any) (Usage, error) {
	value, ok := raw.(Usage)
	if !ok {
		return Usage{}, ErrInvalidRequest
	}
	return value, nil
}

func (a *serviceAdapter) GenerateCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.generateCalls
}

func (a *serviceAdapter) CancelCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cancelCalls
}

type serviceStream struct {
	mu     sync.Mutex
	events []json.RawMessage
	closed bool
}

func (s *serviceStream) Recv(context.Context) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) == 0 || s.closed {
		return nil, io.EOF
	}
	event := s.events[0]
	s.events = s.events[1:]
	return append(json.RawMessage(nil), event...), nil
}

func (s *serviceStream) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func newHTTPService(t *testing.T) (*HTTPService, *serviceAdapter, *BudgetLedger) {
	t.Helper()
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 100_000}); err != nil {
		t.Fatal(err)
	}
	gateway := NewGateway(ledger, time.Now)
	adapter := &serviceAdapter{}
	if err := gateway.Register("provider", "model", adapter, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	service, err := NewHTTPService(gateway, serviceAuthorizer{}, HTTPConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return service, adapter, ledger
}

func transportRequest(requestID string) NormalizedRequest {
	return NormalizedRequest{
		RequestID: requestID, TenantID: "tenant", ProjectID: "project", TaskID: "task", AgentInstanceID: "agent", Role: "EXECUTOR",
		Model: "model", PromptBundleVersion: "v1", Messages: []Message{{Role: "user", Content: "hello"}}, MaxOutputTokens: 4, DataClassification: "INTERNAL",
	}
}

func marshalTransport(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func errorCode(t *testing.T, writer *httptest.ResponseRecorder) string {
	t.Helper()
	var value struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(writer.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	return value.Error.Code
}
