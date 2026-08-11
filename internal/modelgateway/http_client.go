package modelgateway

import (
	"bufio"
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
	maximumHTTPClientTimeout       = 10*time.Minute + 30*time.Second
	maximumHTTPClientRetryWait     = 5 * time.Minute
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
	endpoint, err := modelStreamEndpoint(config.Endpoint)
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

	requestContext, cancel := context.WithTimeout(ctx, httpClientOperationTimeout(client.timeout, normalizedOptions.MaxAttempts))
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
	httpRequest.Header.Set("Accept", "text/event-stream")
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
	if httpResponse.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(httpResponse.Body, client.maxResponseBytes+1))
		if readErr != nil {
			if contextErr := httpClientContextError(requestContext, readErr); contextErr != nil {
				return NormalizedResponse{}, contextErr
			}
			return NormalizedResponse{}, ErrProviderUnavailable
		}
		if int64(len(body)) > client.maxResponseBytes {
			return NormalizedResponse{}, ErrProviderUnavailable
		}
		return NormalizedResponse{}, decodeHTTPResponseError(httpResponse.StatusCode, body)
	}
	if !isHTTPContentType(httpResponse.Header.Get("Content-Type"), "text/event-stream") {
		return NormalizedResponse{}, ErrProviderUnavailable
	}
	return client.readGenerateStream(requestContext, httpResponse.Body, request)
}

func (client *HTTPClient) readGenerateStream(ctx context.Context, body io.Reader, request NormalizedRequest) (NormalizedResponse, error) {
	reader := bufio.NewReaderSize(body, 4096)
	eventName := ""
	data := make([]byte, 0, 256)
	deltaBytes := 0
	var response NormalizedResponse
	responseReady := false
	processEvent := func() (bool, error) {
		defer func() {
			eventName = ""
			data = data[:0]
		}()
		if len(data) == 0 {
			return false, nil
		}
		if string(data) == "[DONE]" {
			if !responseReady {
				return false, ErrProviderUnavailable
			}
			return true, nil
		}
		switch eventName {
		case "":
			var delta struct {
				Delta string `json:"delta"`
			}
			if decodeHTTPClientJSON(data, &delta) != nil || delta.Delta == "" || len(delta.Delta) > MaximumResponseBytes-deltaBytes {
				return false, ErrProviderUnavailable
			}
			deltaBytes += len(delta.Delta)
			return false, nil
		case "response":
			if responseReady {
				return false, ErrProviderUnavailable
			}
			var output transportGenerateResponse
			if decodeHTTPClientJSON(data, &output) != nil || output.Response.RequestID != request.RequestID {
				return false, ErrProviderUnavailable
			}
			response = output.Response
			responseReady = true
			return false, nil
		case "error":
			return false, decodeHTTPResponseError(http.StatusBadGateway, data)
		default:
			return false, ErrProviderUnavailable
		}
	}
	for {
		line, readErr := readHTTPStreamLine(reader, client.maxResponseBytes)
		if len(line) == 0 {
			done, eventErr := processEvent()
			if eventErr != nil {
				return NormalizedResponse{}, eventErr
			}
			if done {
				if err := validateGeneratedResponse(request, response); err != nil {
					return NormalizedResponse{}, err
				}
				return response, nil
			}
		} else if line[0] != ':' {
			field, value, found := strings.Cut(string(line), ":")
			if !found {
				field = string(line)
				value = ""
			}
			value = strings.TrimPrefix(value, " ")
			switch field {
			case "event":
				eventName = value
			case "data":
				separator := 0
				if len(data) != 0 {
					separator = 1
				}
				if len(value) > int(client.maxResponseBytes)-len(data)-separator {
					return NormalizedResponse{}, ErrProviderUnavailable
				}
				if separator != 0 {
					data = append(data, '\n')
				}
				data = append(data, value...)
			}
		}
		if readErr != nil {
			if contextErr := httpClientContextError(ctx, readErr); contextErr != nil {
				return NormalizedResponse{}, contextErr
			}
			return NormalizedResponse{}, ErrProviderUnavailable
		}
	}
}

func readHTTPStreamLine(reader *bufio.Reader, maximum int64) ([]byte, error) {
	line := make([]byte, 0, 256)
	for {
		fragment, err := reader.ReadSlice('\n')
		if int64(len(fragment)) > maximum-int64(len(line)) {
			return nil, ErrOutputTooLarge
		}
		line = append(line, fragment...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if len(line) != 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}
		if len(line) != 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		return line, err
	}
}

func httpClientOperationTimeout(perAttempt time.Duration, maxAttempts int) time.Duration {
	attempts := time.Duration(maxAttempts)
	retries := time.Duration(maxAttempts - 1)
	return perAttempt*attempts + maximumHTTPClientRetryWait*retries
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

func modelStreamEndpoint(raw string) (string, error) {
	if raw == "" || strings.ContainsAny(raw, "\r\n\x00") {
		return "", ErrInvalidRequest
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", ErrInvalidRequest
	}
	parsed.Path = "/v1/model/stream"
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
	return isHTTPContentType(value, "application/json")
}

func isHTTPContentType(value, expected string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == expected
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
