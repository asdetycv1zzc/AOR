package modelgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/observability"
)

const (
	defaultHTTPClientTimeout       = 2 * time.Minute
	maximumHTTPClientTimeout       = 10 * time.Minute
	maximumHTTPBearerTokenBytes    = 64 << 10
	minimumHTTPBearerTokenValidity = 5 * time.Second
)

// BearerToken is a renewable workload token returned by a BearerTokenSource.
// The client requests a token for every model call and never caches it.
type BearerToken struct {
	Value     string
	ExpiresAt time.Time
}

type BearerTokenSource interface {
	Token(context.Context) (BearerToken, error)
}

type HTTPClientConfig struct {
	Endpoint         string
	TokenSource      BearerTokenSource
	Transport        http.RoundTripper
	Timeout          time.Duration
	MaxRequestBytes  int64
	MaxResponseBytes int64
}

// HTTPResponseError preserves the stable, non-sensitive error metadata returned
// by Model Gateway. The remote message is deliberately not retained.
type HTTPResponseError struct {
	StatusCode int
	Code       string
	Retryable  bool
	cause      error
}

func (err *HTTPResponseError) Error() string {
	if err == nil {
		return "model gateway request failed"
	}
	return "model gateway returned HTTP " + strconv.Itoa(err.StatusCode) + " (" + err.Code + ")"
}

func (err *HTTPResponseError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

// NonRetryable lets workflow boundaries honor the gateway's retry decision.
// An unknown provider outcome is terminal for this request identity: retrying
// it would reuse a reservation whose final disposition is already reconcile.
func (err *HTTPResponseError) NonRetryable() bool {
	if err == nil {
		return false
	}
	return !err.Retryable || err.Code == "AOR_PROVIDER_RESULT_UNKNOWN"
}

type HTTPClient struct {
	endpoint         string
	tokenSource      BearerTokenSource
	client           *http.Client
	timeout          time.Duration
	maxRequestBytes  int64
	maxResponseBytes int64
}

func NewHTTPClient(config HTTPClientConfig) (*HTTPClient, error) {
	if nilHTTPClientDependency(config.TokenSource) || nilHTTPClientTransport(config.Transport) {
		return nil, ErrInvalidRequest
	}
	endpoint, err := modelGenerateEndpoint(config.Endpoint)
	if err != nil {
		return nil, err
	}
	if config.Timeout == 0 {
		config.Timeout = defaultHTTPClientTimeout
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultHTTPMaxRequestBytes
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultHTTPMaxResponseBytes
	}
	if config.Timeout <= 0 || config.Timeout > maximumHTTPClientTimeout ||
		config.MaxRequestBytes <= 0 || config.MaxRequestBytes > maximumHTTPBodyBytes ||
		config.MaxResponseBytes <= 0 || config.MaxResponseBytes > maximumHTTPBodyBytes {
		return nil, ErrInvalidRequest
	}
	transport := config.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &HTTPClient{
		endpoint: endpoint, tokenSource: config.TokenSource, timeout: config.Timeout,
		maxRequestBytes: config.MaxRequestBytes, maxResponseBytes: config.MaxResponseBytes,
		client: &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (client *HTTPClient) Generate(ctx context.Context, request NormalizedRequest, options GenerateOptions) (NormalizedResponse, error) {
	if client == nil || client.client == nil || client.tokenSource == nil || ctx == nil {
		return NormalizedResponse{}, ErrInvalidRequest
	}
	if err := validateRequest(request); err != nil {
		return NormalizedResponse{}, err
	}
	normalizedOptions, err := normalizeGenerateOptions(options)
	if err != nil {
		return NormalizedResponse{}, err
	}
	payload, err := json.Marshal(transportGenerateRequest{Request: request, Options: normalizedOptions})
	if err != nil || int64(len(payload)) > client.maxRequestBytes {
		return NormalizedResponse{}, ErrInvalidRequest
	}

	requestContext, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	token, err := client.tokenSource.Token(requestContext)
	if err != nil {
		if contextErr := httpClientContextError(requestContext, err); contextErr != nil {
			return NormalizedResponse{}, contextErr
		}
		return NormalizedResponse{}, ErrAuthorizationDenied
	}
	if !validHTTPBearerToken(token, time.Now().UTC()) {
		return NormalizedResponse{}, ErrAuthorizationDenied
	}

	httpRequest, err := http.NewRequestWithContext(requestContext, http.MethodPost, client.endpoint, bytes.NewReader(payload))
	if err != nil {
		return NormalizedResponse{}, ErrInvalidRequest
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+token.Value)
	if traceContext, found := observability.TraceFromContext(requestContext); found {
		if err := observability.InjectTrace(httpRequest.Header, traceContext); err != nil {
			return NormalizedResponse{}, ErrInvalidRequest
		}
	}

	httpResponse, err := client.client.Do(httpRequest)
	if err != nil {
		if contextErr := httpClientContextError(requestContext, err); contextErr != nil {
			return NormalizedResponse{}, contextErr
		}
		return NormalizedResponse{}, ErrProviderUnavailable
	}
	defer httpResponse.Body.Close()
	body, err := io.ReadAll(io.LimitReader(httpResponse.Body, client.maxResponseBytes+1))
	if err != nil {
		if contextErr := httpClientContextError(requestContext, err); contextErr != nil {
			return NormalizedResponse{}, contextErr
		}
		return NormalizedResponse{}, ErrProviderUnavailable
	}
	if int64(len(body)) > client.maxResponseBytes {
		return NormalizedResponse{}, ErrProviderUnavailable
	}
	if httpResponse.StatusCode != http.StatusOK {
		return NormalizedResponse{}, decodeHTTPResponseError(httpResponse.StatusCode, body)
	}
	if !isJSONContentType(httpResponse.Header.Get("Content-Type")) {
		return NormalizedResponse{}, ErrProviderUnavailable
	}
	var output transportGenerateResponse
	if err := decodeHTTPClientJSON(body, &output); err != nil || output.Response.RequestID != request.RequestID {
		return NormalizedResponse{}, ErrProviderUnavailable
	}
	if err := validateGeneratedResponse(request, output.Response); err != nil {
		return NormalizedResponse{}, err
	}
	return output.Response, nil
}

type transportErrorResponse struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
	} `json:"error"`
}

func decodeHTTPResponseError(status int, body []byte) error {
	code := "HTTP_" + strconv.Itoa(status)
	retryable := false
	var response transportErrorResponse
	if decodeHTTPClientJSON(body, &response) == nil && validHTTPErrorCode(response.Error.Code) {
		code = response.Error.Code
		retryable = response.Error.Retryable
	}
	return &HTTPResponseError{StatusCode: status, Code: code, Retryable: retryable, cause: httpResponseCause(status, code, retryable)}
}

func httpResponseCause(status int, code string, retryable bool) error {
	switch code {
	case "AOR_FORBIDDEN", "AOR_UNAUTHENTICATED":
		return ErrAuthorizationDenied
	case "AOR_INVALID_ARGUMENT":
		return ErrInvalidRequest
	case "AOR_BUDGET_EXCEEDED":
		return ErrBudgetExceeded
	case "AOR_IDEMPOTENCY_CONFLICT":
		return ErrRequestConflict
	case "AOR_BUDGET_RESERVATION_FAILED":
		return ErrReservationConflict
	case "AOR_MODEL_NOT_ALLOWED":
		return ErrProviderNotAllowed
	case "AOR_MODEL_OUTPUT_SCHEMA_INVALID":
		return ErrOutputSchema
	case "AOR_TIMEOUT":
		return context.DeadlineExceeded
	case "AOR_DEPENDENCY_UNAVAILABLE", "AOR_INTERNAL_ERROR":
		return ErrProviderUnavailable
	case "AOR_PROVIDER_RESULT_UNKNOWN":
		return &ProviderFailure{Cause: ErrProviderUnavailable, Retryable: retryable, OutcomeKnown: false}
	}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return ErrAuthorizationDenied
	case status == http.StatusRequestTimeout || status == http.StatusGatewayTimeout:
		return context.DeadlineExceeded
	case status >= http.StatusBadRequest && status < http.StatusInternalServerError:
		return ErrInvalidRequest
	default:
		return ErrProviderUnavailable
	}
}

func decodeHTTPClientJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func modelGenerateEndpoint(raw string) (string, error) {
	if raw == "" || strings.ContainsAny(raw, "\r\n\x00") {
		return "", ErrInvalidRequest
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", ErrInvalidRequest
	}
	parsed.Path = "/v1/model/generate"
	parsed.RawPath = ""
	return parsed.String(), nil
}

func validHTTPBearerToken(token BearerToken, now time.Time) bool {
	return token.Value != "" && len(token.Value) <= maximumHTTPBearerTokenBytes &&
		!strings.ContainsAny(token.Value, " \t\r\n\x00") && !token.ExpiresAt.IsZero() &&
		token.ExpiresAt.After(now.Add(minimumHTTPBearerTokenValidity))
}

func validHTTPErrorCode(code string) bool {
	if code == "" || len(code) > 128 {
		return false
	}
	for _, character := range code {
		if character != '_' && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func httpClientContextError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}

func isJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func nilHTTPClientDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func nilHTTPClientTransport(transport http.RoundTripper) bool {
	return transport != nil && nilHTTPClientDependency(transport)
}
