// Package openaicompatible implements the OpenAI Chat Completions wire format.
package openaicompatible

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/akimisaka/aor/internal/modelgateway"
)

const (
	DefaultRequestTimeout      = 60 * time.Second
	MaximumRequestTimeout      = 10 * time.Minute
	DefaultMaxRequestBytes     = 8 << 20
	DefaultMaxResponseBytes    = 8 << 20
	DefaultMaxStreamEventBytes = 4 << 20
	maximumBodyBytes           = 16 << 20
)

// Config binds one adapter instance to a single Chat Completions endpoint and
// an explicitly configured set of model capabilities.
type Config struct {
	Endpoint            string
	Credential          string
	Models              map[string]modelgateway.ModelCapabilities
	HTTPClient          *http.Client
	RequestTimeout      time.Duration
	MaxRequestBytes     int64
	MaxResponseBytes    int64
	MaxStreamEventBytes int64
}

// Adapter never copies its credential into requests, responses, or errors.
type Adapter struct {
	endpoint            string
	credential          string
	models              map[string]modelgateway.ModelCapabilities
	client              *http.Client
	timeout             time.Duration
	maxRequestBytes     int64
	maxResponseBytes    int64
	maxStreamEventBytes int64

	mu     sync.Mutex
	active map[string]*responseStream
}

func New(config Config) (*Adapter, error) {
	endpoint, err := validateEndpoint(config.Endpoint)
	if err != nil || config.Credential == "" || len(config.Models) == 0 {
		return nil, modelgateway.ErrInvalidRequest
	}
	models := make(map[string]modelgateway.ModelCapabilities, len(config.Models))
	for model, capabilities := range config.Models {
		if model == "" || capabilities.MaxInputTokens <= 0 || capabilities.MaxOutputTokens <= 0 {
			return nil, modelgateway.ErrInvalidRequest
		}
		capabilities.DataResidency = append([]string(nil), capabilities.DataResidency...)
		models[model] = capabilities
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = DefaultRequestTimeout
	}
	if config.RequestTimeout < 0 || config.RequestTimeout > MaximumRequestTimeout {
		return nil, modelgateway.ErrInvalidRequest
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if config.MaxStreamEventBytes == 0 {
		config.MaxStreamEventBytes = DefaultMaxStreamEventBytes
	}
	if config.MaxRequestBytes <= 0 || config.MaxResponseBytes <= 0 || config.MaxStreamEventBytes <= 0 ||
		config.MaxRequestBytes > maximumBodyBytes || config.MaxResponseBytes > maximumBodyBytes || config.MaxStreamEventBytes > maximumBodyBytes {
		return nil, modelgateway.ErrInvalidRequest
	}
	client := http.DefaultClient
	if config.HTTPClient != nil {
		client = config.HTTPClient
	}
	copyClient := *client
	client = &copyClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Adapter{
		endpoint: endpoint, credential: config.Credential, models: models, client: client,
		timeout: config.RequestTimeout, maxRequestBytes: config.MaxRequestBytes,
		maxResponseBytes: config.MaxResponseBytes, maxStreamEventBytes: config.MaxStreamEventBytes,
		active: make(map[string]*responseStream),
	}, nil
}

func (a *Adapter) Capabilities(ctx context.Context, model string) (modelgateway.ModelCapabilities, error) {
	if err := contextError(ctx); err != nil {
		return modelgateway.ModelCapabilities{}, err
	}
	capabilities, found := a.models[model]
	if !found {
		return modelgateway.ModelCapabilities{}, modelgateway.ErrProviderNotAllowed
	}
	capabilities.DataResidency = append([]string(nil), capabilities.DataResidency...)
	return capabilities, nil
}

func (a *Adapter) CountTokens(ctx context.Context, request modelgateway.NormalizedRequest) (modelgateway.TokenEstimate, error) {
	if err := contextError(ctx); err != nil {
		return modelgateway.TokenEstimate{}, err
	}
	if _, err := a.validateRequest(request, false); err != nil {
		return modelgateway.TokenEstimate{}, err
	}
	bytesCount := int64(0)
	for _, message := range request.Messages {
		bytesCount += int64(len(message.Role) + len(message.Content) + 4)
	}
	for _, tool := range request.Tools {
		bytesCount += int64(len(tool.Name) + len(tool.Description) + len(tool.Schema) + 12)
	}
	bytesCount += int64(len(request.ResponseSchema))
	return modelgateway.TokenEstimate{InputTokens: (bytesCount + 3) / 4}, nil
}

func (a *Adapter) Generate(ctx context.Context, request modelgateway.NormalizedRequest) (modelgateway.NormalizedResponse, error) {
	capabilities, err := a.validateRequest(request, true)
	if err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	if err := a.requireInputLimit(ctx, request, capabilities); err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	body, err := a.encodeRequest(request, false)
	if err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	response, cancel, err := a.do(ctx, body)
	if err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	defer cancel()
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return modelgateway.NormalizedResponse{}, httpFailure(response.StatusCode)
	}
	payload, err := readBounded(response.Body, a.maxResponseBytes)
	if err != nil {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputTooLarge)
	}
	return a.decodeResponse(request, capabilities, payload)
}

func (a *Adapter) Stream(ctx context.Context, request modelgateway.NormalizedRequest) (modelgateway.ResponseStream, error) {
	capabilities, err := a.validateRequest(request, true)
	if err != nil {
		return nil, err
	}
	if !capabilities.SupportsStreaming {
		return nil, modelgateway.ErrProviderNotAllowed
	}
	if err := a.requireInputLimit(ctx, request, capabilities); err != nil {
		return nil, err
	}
	body, err := a.encodeRequest(request, true)
	if err != nil {
		return nil, err
	}
	response, cancel, err := a.do(ctx, body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		cancel()
		_ = response.Body.Close()
		return nil, httpFailure(response.StatusCode)
	}
	stream := &responseStream{
		adapter: a, body: response.Body, cancel: cancel, maxEventBytes: a.maxStreamEventBytes,
		events: make(chan json.RawMessage, 1), failures: make(chan error, 1), done: make(chan struct{}),
	}
	go stream.read()
	return stream, nil
}

// Cancel stops a locally active stream once its provider request ID has been
// observed. Chat Completions has no portable remote cancellation endpoint.
func (a *Adapter) Cancel(ctx context.Context, providerRequestID string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if providerRequestID == "" {
		return modelgateway.ErrInvalidRequest
	}
	a.mu.Lock()
	stream := a.active[providerRequestID]
	a.mu.Unlock()
	if stream != nil {
		return stream.Close()
	}
	return nil
}

func (a *Adapter) NormalizeUsage(raw any) (modelgateway.Usage, error) {
	var usage modelgateway.Usage
	switch value := raw.(type) {
	case modelgateway.Usage:
		usage = value
	case chatUsage:
		usage = modelgateway.Usage{InputTokens: value.PromptTokens, OutputTokens: value.CompletionTokens}
	case []byte:
		var err error
		usage, err = normalizeUsageJSON(value)
		if err != nil {
			return modelgateway.Usage{}, err
		}
	case json.RawMessage:
		var err error
		usage, err = normalizeUsageJSON(value)
		if err != nil {
			return modelgateway.Usage{}, err
		}
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return modelgateway.Usage{}, modelgateway.ErrInvalidRequest
		}
		usage, err = normalizeUsageJSON(encoded)
		if err != nil {
			return modelgateway.Usage{}, err
		}
	}
	if usage.InputTokens < 0 || usage.OutputTokens < 0 || usage.CostMicros < 0 || a.containsCredential(usage.ProviderRequestID) || a.containsCredential(usage.ModelVersion) {
		return modelgateway.Usage{}, modelgateway.ErrInvalidRequest
	}
	return usage, nil
}

func (a *Adapter) validateRequest(request modelgateway.NormalizedRequest, requireGeneration bool) (modelgateway.ModelCapabilities, error) {
	capabilities, err := a.Capabilities(context.Background(), request.Model)
	if err != nil {
		return modelgateway.ModelCapabilities{}, err
	}
	if request.Model == "" || len(request.Messages) == 0 || request.MaxOutputTokens <= 0 || request.MaxOutputTokens > capabilities.MaxOutputTokens ||
		request.Temperature < 0 || request.Temperature > 2 || !utf8.ValidString(request.Model) {
		return modelgateway.ModelCapabilities{}, modelgateway.ErrInvalidRequest
	}
	if request.Seed != nil && !capabilities.SupportsSeed {
		return modelgateway.ModelCapabilities{}, modelgateway.ErrProviderNotAllowed
	}
	if len(request.Tools) != 0 && !capabilities.SupportsToolCalls {
		return modelgateway.ModelCapabilities{}, modelgateway.ErrProviderNotAllowed
	}
	if len(request.ResponseSchema) != 0 && (!capabilities.SupportsJSONSchema || !json.Valid(request.ResponseSchema)) {
		return modelgateway.ModelCapabilities{}, modelgateway.ErrProviderNotAllowed
	}
	for _, message := range request.Messages {
		if strings.TrimSpace(message.Role) == "" || !utf8.ValidString(message.Role) || !utf8.ValidString(message.Content) || a.containsCredential(message.Content) {
			return modelgateway.ModelCapabilities{}, modelgateway.ErrInvalidRequest
		}
	}
	for _, tool := range request.Tools {
		if tool.Name == "" || !utf8.ValidString(tool.Name) || !utf8.ValidString(tool.Description) || len(tool.Schema) != 0 && !json.Valid(tool.Schema) || a.containsCredential(string(tool.Schema)) {
			return modelgateway.ModelCapabilities{}, modelgateway.ErrInvalidRequest
		}
	}
	if a.containsCredential(string(request.ResponseSchema)) {
		return modelgateway.ModelCapabilities{}, modelgateway.ErrInvalidRequest
	}
	if requireGeneration && request.RequestID == "" {
		return modelgateway.ModelCapabilities{}, modelgateway.ErrInvalidRequest
	}
	return capabilities, nil
}

func (a *Adapter) requireInputLimit(ctx context.Context, request modelgateway.NormalizedRequest, capabilities modelgateway.ModelCapabilities) error {
	estimate, err := a.CountTokens(ctx, request)
	if err != nil {
		return err
	}
	if estimate.InputTokens > int64(capabilities.MaxInputTokens) {
		return modelgateway.ErrInvalidRequest
	}
	return nil
}

func (a *Adapter) encodeRequest(request modelgateway.NormalizedRequest, stream bool) ([]byte, error) {
	value := chatRequest{Model: request.Model, MaxTokens: request.MaxOutputTokens, Temperature: request.Temperature, Stream: stream}
	for _, message := range request.Messages {
		value.Messages = append(value.Messages, chatMessage{Role: message.Role, Content: message.Content})
	}
	for _, tool := range request.Tools {
		parameters := tool.Schema
		if len(parameters) == 0 {
			parameters = json.RawMessage(`{}`)
		}
		value.Tools = append(value.Tools, chatTool{Type: "function", Function: chatFunction{Name: tool.Name, Description: tool.Description, Parameters: parameters}})
	}
	if request.Seed != nil {
		value.Seed = request.Seed
	}
	if len(request.ResponseSchema) != 0 {
		value.ResponseFormat = &chatResponseFormat{Type: "json_schema", JSONSchema: chatJSONSchema{Name: "aor_response", Schema: request.ResponseSchema, Strict: true}}
	}
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)) > a.maxRequestBytes {
		return nil, modelgateway.ErrInvalidRequest
	}
	return encoded, nil
}

func (a *Adapter) do(ctx context.Context, payload []byte) (*http.Response, context.CancelFunc, error) {
	if err := contextError(ctx); err != nil {
		return nil, nil, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, a.timeout)
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, a.endpoint, bytes.NewReader(payload))
	if err != nil {
		cancel()
		return nil, nil, modelgateway.ErrInvalidRequest
	}
	request.Header.Set("Authorization", "Bearer "+a.credential)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err := a.client.Do(request)
	if err != nil {
		cancel()
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, nil, requestCtx.Err()
		}
		return nil, nil, unknownFailure(errors.New("openai-compatible network request failed"))
	}
	return response, cancel, nil
}

func (a *Adapter) decodeResponse(request modelgateway.NormalizedRequest, capabilities modelgateway.ModelCapabilities, payload []byte) (modelgateway.NormalizedResponse, error) {
	var response chatResponse
	if err := json.Unmarshal(payload, &response); err != nil || len(response.Choices) == 0 {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
	}
	choice := response.Choices[0]
	if !utf8.ValidString(choice.Message.Content) || a.containsCredential(response.ID) || a.containsCredential(response.Model) || a.containsCredential(choice.Message.Content) {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrCredentialDetected)
	}
	usage, err := a.NormalizeUsage(response.Usage)
	if err != nil {
		return modelgateway.NormalizedResponse{}, unknownFailure(err)
	}
	usage.ProviderRequestID = response.ID
	if usage.ModelVersion == "" {
		usage.ModelVersion = response.Model
	}
	modelVersion := response.Model
	if modelVersion == "" {
		modelVersion = capabilities.ActualModelVersion
	}
	if a.containsCredential(modelVersion) {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrCredentialDetected)
	}
	return modelgateway.NormalizedResponse{
		RequestID: request.RequestID, ProviderRequestID: response.ID, ModelVersion: modelVersion,
		Content: json.RawMessage(choice.Message.Content), FinishReason: choice.FinishReason, Usage: usage,
	}, nil
}

func (a *Adapter) containsCredential(value string) bool {
	return a.credential != "" && strings.Contains(value, a.credential)
}

func validateEndpoint(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return "", modelgateway.ErrInvalidRequest
	}
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return "", modelgateway.ErrInvalidRequest
	}
	return parsed.String(), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func normalizeUsageJSON(encoded []byte) (modelgateway.Usage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil {
		return modelgateway.Usage{}, modelgateway.ErrInvalidRequest
	}
	if _, standard := fields["prompt_tokens"]; standard {
		var value chatUsage
		if json.Unmarshal(encoded, &value) != nil {
			return modelgateway.Usage{}, modelgateway.ErrInvalidRequest
		}
		return modelgateway.Usage{InputTokens: value.PromptTokens, OutputTokens: value.CompletionTokens}, nil
	}
	var usage modelgateway.Usage
	if json.Unmarshal(encoded, &usage) != nil {
		return modelgateway.Usage{}, modelgateway.ErrInvalidRequest
	}
	return usage, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return modelgateway.ErrInvalidRequest
	}
	return ctx.Err()
}

func readBounded(body io.Reader, maximum int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, modelgateway.ErrOutputTooLarge
	}
	return data, nil
}

func httpFailure(status int) error {
	return &modelgateway.ProviderFailure{
		Cause:        fmt.Errorf("openai-compatible provider returned HTTP %d", status),
		Retryable:    status == http.StatusTooManyRequests || status >= http.StatusInternalServerError,
		OutcomeKnown: true,
	}
}

func unknownFailure(cause error) error {
	return &modelgateway.ProviderFailure{Cause: cause, Retryable: true, OutcomeKnown: false}
}

type chatRequest struct {
	Model          string              `json:"model"`
	Messages       []chatMessage       `json:"messages"`
	Tools          []chatTool          `json:"tools,omitempty"`
	ResponseFormat *chatResponseFormat `json:"response_format,omitempty"`
	MaxTokens      int                 `json:"max_tokens"`
	Temperature    float64             `json:"temperature"`
	Seed           *int64              `json:"seed,omitempty"`
	Stream         bool                `json:"stream,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatTool struct {
	Type     string       `json:"type"`
	Function chatFunction `json:"function"`
}

type chatFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters"`
}

type chatResponseFormat struct {
	Type       string         `json:"type"`
	JSONSchema chatJSONSchema `json:"json_schema"`
}

type chatJSONSchema struct {
	Name   string          `json:"name"`
	Schema json.RawMessage `json:"schema"`
	Strict bool            `json:"strict"`
}

type chatResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage chatUsage `json:"usage"`
}

type chatUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}
