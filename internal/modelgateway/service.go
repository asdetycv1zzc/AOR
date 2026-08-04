package modelgateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/observability"
)

const (
	defaultHTTPMaxRequestBytes  int64 = 1 << 20
	defaultHTTPMaxResponseBytes int64 = MaximumResponseBytes + 512<<10
	maximumHTTPBodyBytes        int64 = 8 << 20
)

var (
	ErrAuthorizationDenied = errors.New("model gateway authorization denied")
	errHTTPBodyTooLarge    = errors.New("model gateway request body too large")
)

// HTTPAuthorizer binds an untrusted transport request to the authenticated
// caller's tenant, workload, budget account, and allowed provider.
type HTTPAuthorizer interface {
	AuthorizeModel(ctx context.Context, request ModelAuthorizationRequest) (ModelAuthorization, error)
}

type ModelAuthorizationRequest struct {
	Operation          string
	Provider           string
	Model              string
	DataClassification string
	RequestID          string
	AccountID          string
	ReservationID      string
	ProviderRequestID  string
	ProjectID          string
	TaskID             string
	AgentInstanceID    string
	Role               string
}

type ModelAuthorization struct {
	TenantID           string
	ProjectID          string
	TaskID             string
	AgentInstanceID    string
	Role               string
	Provider           string
	AccountID          string
	DataClassification string
}

type HTTPConfig struct {
	MaxRequestBytes   int64
	MaxResponseBytes  int64
	StreamIdleTimeout time.Duration
}

type HTTPService struct {
	gateway           *Gateway
	authorizer        HTTPAuthorizer
	maxRequestBytes   int64
	maxResponseBytes  int64
	streamIdleTimeout time.Duration
}

func NewHTTPService(gateway *Gateway, authorizer HTTPAuthorizer, config HTTPConfig) (*HTTPService, error) {
	if gateway == nil || nilAuthorizer(authorizer) {
		return nil, ErrInvalidRequest
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultHTTPMaxRequestBytes
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultHTTPMaxResponseBytes
	}
	if config.StreamIdleTimeout == 0 {
		config.StreamIdleTimeout = 60 * time.Second
	}
	if config.MaxRequestBytes <= 0 || config.MaxResponseBytes <= 0 || config.MaxRequestBytes > maximumHTTPBodyBytes || config.MaxResponseBytes > maximumHTTPBodyBytes || config.StreamIdleTimeout <= 0 || config.StreamIdleTimeout > 10*time.Minute {
		return nil, ErrInvalidRequest
	}
	return &HTTPService{gateway: gateway, authorizer: authorizer, maxRequestBytes: config.MaxRequestBytes, maxResponseBytes: config.MaxResponseBytes, streamIdleTimeout: config.StreamIdleTimeout}, nil
}

func nilAuthorizer(authorizer HTTPAuthorizer) bool {
	if authorizer == nil {
		return true
	}
	value := reflect.ValueOf(authorizer)
	return (value.Kind() == reflect.Chan || value.Kind() == reflect.Func || value.Kind() == reflect.Interface || value.Kind() == reflect.Map || value.Kind() == reflect.Pointer || value.Kind() == reflect.Slice) && value.IsNil()
}

func (s *HTTPService) Handler() http.Handler {
	return http.HandlerFunc(s.ServeHTTP)
}

func (s *HTTPService) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	ctx, traceParent, err := transportContext(request)
	if err != nil {
		writeHTTPError(writer, "", err)
		return
	}
	writer.Header().Set(observability.TraceParentHeader, traceParent)
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/v1/model/generate":
		s.serveGenerate(writer, request.WithContext(ctx), traceParent)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/model/stream":
		s.serveStream(writer, request.WithContext(ctx), traceParent)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/model/cancel":
		s.serveCancel(writer, request.WithContext(ctx), traceParent)
	case request.Method == http.MethodGet && request.URL.Path == "/v1/model/capabilities":
		s.serveCapabilities(writer, request.WithContext(ctx), traceParent)
	default:
		writeHTTPError(writer, traceParent, ErrInvalidRequest)
	}
}

func (s *HTTPService) serveGenerate(writer http.ResponseWriter, request *http.Request, traceParent string) {
	var input transportGenerateRequest
	if err := s.decodeJSON(writer, request, &input); err != nil {
		writeHTTPError(writer, traceParent, err)
		return
	}
	requestValue, options, err := s.authorizeGenerate(request.Context(), "generate", input.Request, input.Options)
	if err != nil {
		writeHTTPError(writer, traceParent, err)
		return
	}
	response, err := s.gateway.Generate(request.Context(), requestValue, options)
	if err != nil {
		writeHTTPError(writer, traceParent, err)
		return
	}
	s.writeJSON(writer, traceParent, http.StatusOK, transportGenerateResponse{Response: response})
}

func (s *HTTPService) serveStream(writer http.ResponseWriter, request *http.Request, traceParent string) {
	var input transportGenerateRequest
	if err := s.decodeJSON(writer, request, &input); err != nil {
		writeHTTPError(writer, traceParent, err)
		return
	}
	requestValue, options, err := s.authorizeGenerate(request.Context(), "stream", input.Request, input.Options)
	if err != nil {
		writeHTTPError(writer, traceParent, err)
		return
	}
	stream, err := s.gateway.Stream(request.Context(), requestValue, options)
	if err != nil {
		writeHTTPError(writer, traceParent, err)
		return
	}
	defer func() { _ = stream.Close() }()
	flusher, supported := writer.(http.Flusher)
	if !supported {
		writeHTTPError(writer, traceParent, ErrInvalidRequest)
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	for {
		recvContext, cancel := context.WithTimeout(request.Context(), s.streamIdleTimeout)
		value, recvErr := stream.Recv(recvContext)
		cancel()
		if errors.Is(recvErr, io.EOF) {
			_, _ = writer.Write([]byte("data: [DONE]\n\n"))
			flusher.Flush()
			return
		}
		if recvErr != nil || int64(len(value)) > s.maxResponseBytes || !json.Valid(value) {
			writeSSEError(writer, stableError(recvErr))
			flusher.Flush()
			return
		}
		_, _ = writer.Write([]byte("data: "))
		_, _ = writer.Write(value)
		_, _ = writer.Write([]byte("\n\n"))
		flusher.Flush()
	}
}

func (s *HTTPService) serveCancel(writer http.ResponseWriter, request *http.Request, traceParent string) {
	var input transportCancelRequest
	if err := s.decodeJSON(writer, request, &input); err != nil {
		writeHTTPError(writer, traceParent, err)
		return
	}
	authorization, err := s.authorize(request.Context(), ModelAuthorizationRequest{
		Operation: "cancel", Provider: input.Provider, Model: input.Model, RequestID: input.RequestID,
		AccountID: input.AccountID, ReservationID: input.ReservationID, ProviderRequestID: input.ProviderRequestID,
		ProjectID: input.ProjectID, TaskID: input.TaskID, AgentInstanceID: input.AgentInstanceID, Role: input.Role,
	})
	if err != nil {
		writeHTTPError(writer, traceParent, err)
		return
	}
	if input.Provider != authorization.Provider || input.AccountID != authorization.AccountID || input.ProjectID != "" && input.ProjectID != authorization.ProjectID || input.TaskID != "" && input.TaskID != authorization.TaskID || input.AgentInstanceID != "" && input.AgentInstanceID != authorization.AgentInstanceID || input.Role != "" && input.Role != authorization.Role || input.Provider == "" || input.Model == "" || input.ProviderRequestID == "" || input.ReservationID == "" || input.AccountID == "" {
		writeHTTPError(writer, traceParent, ErrAuthorizationDenied)
		return
	}
	if err := s.gateway.CancelStream(request.Context(), authorization.TenantID, input.ReservationID, input.Provider, input.Model, input.ProviderRequestID); err != nil {
		writeHTTPError(writer, traceParent, err)
		return
	}
	s.writeJSON(writer, traceParent, http.StatusOK, map[string]bool{"cancelled": true})
}

func (s *HTTPService) serveCapabilities(writer http.ResponseWriter, request *http.Request, traceParent string) {
	query := request.URL.Query()
	if len(query) != 3 || len(query["provider"]) != 1 || len(query["model"]) != 1 || len(query["projectId"]) != 1 {
		writeHTTPError(writer, traceParent, ErrInvalidRequest)
		return
	}
	provider, model, projectID := query.Get("provider"), query.Get("model"), query.Get("projectId")
	authorization, err := s.authorize(request.Context(), ModelAuthorizationRequest{Operation: "capabilities", Provider: provider, Model: model, ProjectID: projectID})
	if err != nil {
		writeHTTPError(writer, traceParent, err)
		return
	}
	if provider == "" || model == "" || provider != authorization.Provider {
		writeHTTPError(writer, traceParent, ErrAuthorizationDenied)
		return
	}
	capabilities, err := s.gateway.Capabilities(request.Context(), provider, model)
	if err != nil {
		writeHTTPError(writer, traceParent, err)
		return
	}
	s.writeJSON(writer, traceParent, http.StatusOK, capabilities)
}

func (s *HTTPService) authorizeGenerate(ctx context.Context, operation string, request NormalizedRequest, options GenerateOptions) (NormalizedRequest, GenerateOptions, error) {
	authorization, err := s.authorize(ctx, ModelAuthorizationRequest{
		Operation: operation, Provider: options.Provider, Model: request.Model, RequestID: request.RequestID,
		DataClassification: request.DataClassification,
		AccountID:          options.AccountID, ReservationID: options.ReservationID,
		ProjectID: request.ProjectID, TaskID: request.TaskID, AgentInstanceID: request.AgentInstanceID, Role: request.Role,
	})
	if err != nil {
		return NormalizedRequest{}, GenerateOptions{}, err
	}
	if request.TenantID != authorization.TenantID || request.ProjectID != authorization.ProjectID || request.TaskID != authorization.TaskID || request.AgentInstanceID != authorization.AgentInstanceID || request.Role != authorization.Role || request.DataClassification != authorization.DataClassification || options.Provider != authorization.Provider || options.AccountID != authorization.AccountID ||
		request.TenantID == "" || request.ProjectID == "" || request.AgentInstanceID == "" || request.Role == "" || options.AccountID == "" {
		return NormalizedRequest{}, GenerateOptions{}, ErrAuthorizationDenied
	}
	if authorization.DataClassification == "" {
		return NormalizedRequest{}, GenerateOptions{}, ErrAuthorizationDenied
	}
	request.DataClassification = authorization.DataClassification
	return request, options, nil
}

func (s *HTTPService) authorize(ctx context.Context, request ModelAuthorizationRequest) (ModelAuthorization, error) {
	authorization, err := s.authorizer.AuthorizeModel(ctx, request)
	if err != nil {
		return ModelAuthorization{}, ErrAuthorizationDenied
	}
	if authorization.TenantID == "" || authorization.Provider == "" {
		return ModelAuthorization{}, ErrAuthorizationDenied
	}
	return authorization, nil
}

func (s *HTTPService) decodeJSON(writer http.ResponseWriter, request *http.Request, target any) error {
	if !strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), "application/json") {
		return ErrInvalidRequest
	}
	body := http.MaxBytesReader(writer, request.Body, s.maxRequestBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return errHTTPBodyTooLarge
		}
		return ErrInvalidRequest
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalidRequest
	}
	return nil
}

func (s *HTTPService) writeJSON(writer http.ResponseWriter, traceParent string, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil || int64(len(payload)) > s.maxResponseBytes {
		writeHTTPError(writer, traceParent, ErrOutputTooLarge)
		return
	}
	writer.Header().Set(observability.TraceParentHeader, traceParent)
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(payload)
}

func transportContext(request *http.Request) (context.Context, string, error) {
	carrier := observability.MapCarrier{
		observability.TraceParentHeader: request.Header.Get(observability.TraceParentHeader),
		observability.TraceStateHeader:  request.Header.Get(observability.TraceStateHeader),
	}
	var trace observability.TraceContext
	var err error
	if carrier.Get(observability.TraceParentHeader) == "" {
		if carrier.Get(observability.TraceStateHeader) != "" {
			return nil, "", ErrInvalidRequest
		}
		trace, err = observability.NewRootTraceContext(true)
	} else {
		trace, err = observability.ExtractTrace(carrier)
	}
	if err != nil {
		return nil, "", ErrInvalidRequest
	}
	ctx, err := observability.ContextWithTrace(request.Context(), trace)
	if err != nil {
		return nil, "", ErrInvalidRequest
	}
	traceParent, err := trace.TraceParent()
	if err != nil {
		return nil, "", ErrInvalidRequest
	}
	return ctx, traceParent, nil
}

func writeHTTPError(writer http.ResponseWriter, traceParent string, err error) {
	stable := stableError(err)
	if traceParent != "" {
		writer.Header().Set(observability.TraceParentHeader, traceParent)
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(stable.Status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"error": map[string]any{"code": stable.Code, "message": stable.Message, "retryable": stable.Retryable}})
}

func writeSSEError(writer http.ResponseWriter, stable httpError) {
	payload, _ := json.Marshal(map[string]any{"error": map[string]any{"code": stable.Code, "message": stable.Message, "retryable": stable.Retryable}})
	_, _ = writer.Write([]byte("event: error\ndata: "))
	_, _ = writer.Write(payload)
	_, _ = writer.Write([]byte("\n\n"))
}

type transportGenerateRequest struct {
	Request NormalizedRequest `json:"request"`
	Options GenerateOptions   `json:"options"`
}

type transportGenerateResponse struct {
	Response NormalizedResponse `json:"response"`
}

type transportCancelRequest struct {
	Provider          string `json:"provider"`
	Model             string `json:"model"`
	ProviderRequestID string `json:"providerRequestId"`
	AccountID         string `json:"accountId"`
	ReservationID     string `json:"reservationId"`
	RequestID         string `json:"requestId"`
	ProjectID         string `json:"projectId"`
	TaskID            string `json:"taskId"`
	AgentInstanceID   string `json:"agentInstanceId"`
	Role              string `json:"role"`
}

type httpError struct {
	Status    int
	Code      string
	Message   string
	Retryable bool
}

func stableError(err error) httpError {
	switch {
	case errors.Is(err, ErrAuthorizationDenied):
		return httpError{Status: http.StatusForbidden, Code: "AOR_FORBIDDEN", Message: "model operation denied"}
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, errHTTPBodyTooLarge):
		return httpError{Status: http.StatusBadRequest, Code: "AOR_INVALID_ARGUMENT", Message: "invalid model request"}
	case errors.Is(err, ErrBudgetExceeded):
		return httpError{Status: http.StatusConflict, Code: "AOR_BUDGET_EXCEEDED", Message: "model budget exceeded"}
	case errors.Is(err, ErrRequestConflict), errors.Is(err, ErrReplayUnavailable):
		return httpError{Status: http.StatusConflict, Code: "AOR_IDEMPOTENCY_CONFLICT", Message: "model request id conflicts with a previous request"}
	case errors.Is(err, ErrReservationConflict), errors.Is(err, ErrReservationNotFound), errors.Is(err, ErrReconciliationRequired):
		return httpError{Status: http.StatusConflict, Code: "AOR_BUDGET_RESERVATION_FAILED", Message: "model budget reservation failed"}
	case errors.Is(err, ErrProviderNotAllowed):
		return httpError{Status: http.StatusForbidden, Code: "AOR_MODEL_NOT_ALLOWED", Message: "model is not allowed"}
	case errors.Is(err, ErrOutputSchema), errors.Is(err, ErrOutputTooLarge), errors.Is(err, ErrCredentialDetected):
		return httpError{Status: http.StatusUnprocessableEntity, Code: "AOR_MODEL_OUTPUT_SCHEMA_INVALID", Message: "model output rejected"}
	case errors.Is(err, context.DeadlineExceeded):
		return httpError{Status: http.StatusGatewayTimeout, Code: "AOR_TIMEOUT", Message: "model request timed out", Retryable: true}
	case errors.Is(err, ErrProviderUnavailable):
		return httpError{Status: http.StatusServiceUnavailable, Code: "AOR_DEPENDENCY_UNAVAILABLE", Message: "model provider unavailable", Retryable: true}
	}
	var providerFailure *ProviderFailure
	if errors.As(err, &providerFailure) {
		if !providerFailure.OutcomeKnown {
			return httpError{Status: http.StatusBadGateway, Code: "AOR_PROVIDER_RESULT_UNKNOWN", Message: "model provider result is unknown", Retryable: providerFailure.Retryable}
		}
		return httpError{Status: http.StatusServiceUnavailable, Code: "AOR_DEPENDENCY_UNAVAILABLE", Message: "model provider unavailable", Retryable: providerFailure.Retryable}
	}
	return httpError{Status: http.StatusInternalServerError, Code: "AOR_INTERNAL_ERROR", Message: "model gateway failed"}
}
