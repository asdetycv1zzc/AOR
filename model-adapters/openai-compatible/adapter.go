// Package openaicompatible implements the OpenAI Chat Completions and Responses
// wire formats behind the provider-independent model gateway contract.
package openaicompatible

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	MaximumRequestTimeout      = 10*time.Minute + 30*time.Second
	DefaultMaxRequestBytes     = 8 << 20
	DefaultMaxResponseBytes    = 8 << 20
	DefaultMaxStreamEventBytes = 4 << 20
	maximumBodyBytes           = 16 << 20
)

var errAdapterRequestTimeout = errors.New("openai-compatible adapter request timed out")

type WireFormat string

const (
	WireFormatChatCompletions WireFormat = "chat-completions"
	WireFormatResponses       WireFormat = "responses"
)

// Config binds one adapter instance to a single OpenAI-compatible endpoint and
// an explicitly configured set of model capabilities.
type Config struct {
	Endpoint                string
	Credential              string
	Models                  map[string]modelgateway.ModelCapabilities
	WireFormat              WireFormat
	SupportsReasoningEffort bool
	HTTPClient              *http.Client
	RequestTimeout          time.Duration
	MaxRequestBytes         int64
	MaxResponseBytes        int64
	MaxStreamEventBytes     int64
}

// Adapter never copies its credential into requests, responses, or errors.
type Adapter struct {
	endpoint                string
	credential              string
	models                  map[string]modelgateway.ModelCapabilities
	wireFormat              WireFormat
	supportsReasoningEffort bool
	client                  *http.Client
	timeout                 time.Duration
	maxRequestBytes         int64
	maxResponseBytes        int64
	maxStreamEventBytes     int64

	mu                         sync.Mutex
	active                     map[string]*responseStream
	responsesContinuations     map[string]responsesContinuation
	responsesContinuationOrder []string
	responsesContinuationBytes int
}

func New(config Config) (*Adapter, error) {
	endpoint, err := validateEndpoint(config.Endpoint)
	if config.WireFormat == "" {
		config.WireFormat = WireFormatChatCompletions
	}
	if err != nil || config.Credential == "" || len(config.Models) == 0 || config.WireFormat != WireFormatChatCompletions && config.WireFormat != WireFormatResponses {
		return nil, modelgateway.ErrInvalidRequest
	}
	models := make(map[string]modelgateway.ModelCapabilities, len(config.Models))
	for model, capabilities := range config.Models {
		if model == "" || capabilities.MaxInputTokens <= 0 || capabilities.MaxOutputTokens <= 0 {
			return nil, modelgateway.ErrInvalidRequest
		}
		capabilities.DataResidency = append([]string(nil), capabilities.DataResidency...)
		capabilities.Modalities = append([]string(nil), capabilities.Modalities...)
		if config.WireFormat == WireFormatResponses {
			capabilities.SupportsSeed = false
		}
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
		wireFormat:              config.WireFormat,
		supportsReasoningEffort: config.SupportsReasoningEffort,
		timeout:                 config.RequestTimeout, maxRequestBytes: config.MaxRequestBytes,
		maxResponseBytes: config.MaxResponseBytes, maxStreamEventBytes: config.MaxStreamEventBytes,
		active:                 make(map[string]*responseStream),
		responsesContinuations: make(map[string]responsesContinuation),
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
	capabilities.Modalities = append([]string(nil), capabilities.Modalities...)
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
		bytesCount += int64(len(message.Role) + len(message.Content) + len(message.ToolCallID) + 4)
		for _, call := range message.ToolCalls {
			bytesCount += int64(len(call.ID) + len(call.Name) + len(call.Arguments) + 12)
		}
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
	if capabilities.SupportsStreaming && !requestUsesNativeTools(request) {
		return a.generateStream(ctx, request, capabilities)
	}
	body, err := a.encodeRequest(request, false)
	if err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	response, cancel, err := a.do(ctx, request.RequestID, body)
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
		if contextErr := adapterRequestContextError(ctx, responseRequestContext(ctx, response)); contextErr != nil {
			return modelgateway.NormalizedResponse{}, contextErr
		}
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputTooLarge)
	}
	return a.decodeResponse(request, capabilities, payload)
}

func (a *Adapter) Stream(ctx context.Context, request modelgateway.NormalizedRequest) (modelgateway.ResponseStream, error) {
	capabilities, err := a.validateRequest(request, true)
	if err != nil {
		return nil, err
	}
	if requestUsesNativeTools(request) {
		return nil, modelgateway.ErrProviderNotAllowed
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
	response, cancel, err := a.doWithAccept(ctx, request.RequestID, body, "text/event-stream")
	if err != nil {
		return nil, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		cancel()
		_ = response.Body.Close()
		return nil, httpFailure(response.StatusCode)
	}
	if a.wireFormat == WireFormatResponses {
		return a.newResponsesResponseStream(ctx, request, capabilities, response, cancel), nil
	}
	jsonMode := !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream")
	maxEventBytes := a.maxStreamEventBytes
	if jsonMode {
		maxEventBytes = a.maxResponseBytes
	}
	requestContext := ctx
	if response.Request != nil {
		requestContext = response.Request.Context()
	}
	stream := &responseStream{
		adapter: a, body: response.Body, cancel: cancel, maxEventBytes: maxEventBytes,
		events: make(chan json.RawMessage, 1), failures: make(chan error, 1), done: make(chan struct{}), closed: make(chan struct{}), activityContext: ctx,
		callerContext: ctx, requestContext: requestContext, jsonMode: jsonMode,
	}
	go stream.read()
	return stream, nil
}

func (a *Adapter) generateStream(ctx context.Context, request modelgateway.NormalizedRequest, capabilities modelgateway.ModelCapabilities) (modelgateway.NormalizedResponse, error) {
	stream, err := a.Stream(ctx, request)
	if err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	defer stream.Close()
	for {
		_, receiveErr := stream.Recv(ctx)
		if errors.Is(receiveErr, io.EOF) {
			break
		}
		if receiveErr != nil {
			return modelgateway.NormalizedResponse{}, receiveErr
		}
	}
	contentStream, contentOK := stream.(modelgateway.FinalContentAwareStream)
	usageStream, usageOK := stream.(modelgateway.UsageAwareStream)
	finishStream, finishOK := stream.(interface{ FinalFinishReason() (string, bool) })
	if !contentOK || !usageOK || !finishOK {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
	}
	contentBytes, contentFound := contentStream.FinalContent()
	usage, usageFound := usageStream.FinalUsage()
	finishReason, finishFound := finishStream.FinalFinishReason()
	if !contentFound || !usageFound || !finishFound || len(contentBytes) == 0 {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
	}
	var content json.RawMessage
	if json.Valid(contentBytes) {
		content = append(json.RawMessage(nil), contentBytes...)
	} else {
		encoded, encodeErr := json.Marshal(string(contentBytes))
		if encodeErr != nil || len(encoded) > modelgateway.MaximumResponseBytes {
			return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputTooLarge)
		}
		content = encoded
	}
	modelVersion := usage.ModelVersion
	if modelVersion == "" {
		modelVersion = capabilities.ActualModelVersion
	}
	return modelgateway.NormalizedResponse{
		RequestID: request.RequestID, ProviderRequestID: usage.ProviderRequestID,
		ModelVersion: modelVersion, Content: content, FinishReason: finishReason, Usage: usage,
	}, nil
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
		usage = normalizedChatUsage(value)
	case responsesUsage:
		usage = normalizedResponsesUsage(value)
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
	if usage.InputTokens < 0 || usage.OutputTokens < 0 || usage.CostMicros < 0 ||
		usage.CacheReadTokens != nil && *usage.CacheReadTokens < 0 || usage.CacheWriteTokens != nil && *usage.CacheWriteTokens < 0 ||
		a.containsCredential(usage.ProviderRequestID) || a.containsCredential(usage.ModelVersion) {
		return modelgateway.Usage{}, modelgateway.ErrInvalidRequest
	}
	return usage, nil
}

func (a *Adapter) validateRequest(request modelgateway.NormalizedRequest, requireGeneration bool) (modelgateway.ModelCapabilities, error) {
	capabilities, err := a.Capabilities(context.Background(), request.Model)
	if err != nil {
		return modelgateway.ModelCapabilities{}, err
	}
	if request.Model == "" || len(request.Messages) == 0 || len(request.Messages) > modelgateway.MaximumMessages || len(request.Tools) > modelgateway.MaximumTools || request.MaxOutputTokens <= 0 || request.MaxOutputTokens > capabilities.MaxOutputTokens || request.ThinkingBudget < 0 || request.ThinkingBudget >= request.MaxOutputTokens ||
		request.Temperature < 0 || request.Temperature > 2 || request.TopP < 0 || request.TopP > 1 || request.TopK < 0 || request.TopK > modelgateway.MaximumTopK || !validReasoningEffort(request.ReasoningEffort) || !utf8.ValidString(request.Model) {
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
		if message.Validate() != nil || a.containsCredential(message.Role) || a.containsCredential(message.Content) || a.containsCredential(message.ToolCallID) {
			return modelgateway.ModelCapabilities{}, modelgateway.ErrInvalidRequest
		}
		for _, call := range message.ToolCalls {
			if a.containsCredential(call.ID) || a.containsCredential(call.Name) || a.containsCredential(string(call.Arguments)) {
				return modelgateway.ModelCapabilities{}, modelgateway.ErrInvalidRequest
			}
		}
	}
	seenTools := make(map[string]struct{}, len(request.Tools))
	for _, tool := range request.Tools {
		if tool.Validate() != nil || a.containsCredential(tool.Name) || a.containsCredential(tool.Description) || a.containsCredential(string(tool.Schema)) {
			return modelgateway.ModelCapabilities{}, modelgateway.ErrInvalidRequest
		}
		if _, found := seenTools[tool.Name]; found {
			return modelgateway.ModelCapabilities{}, modelgateway.ErrInvalidRequest
		}
		seenTools[tool.Name] = struct{}{}
	}
	if a.containsCredential(string(request.ResponseSchema)) {
		return modelgateway.ModelCapabilities{}, modelgateway.ErrInvalidRequest
	}
	if requireGeneration && !validRequestHeaderValue(request.RequestID) {
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
	if a.wireFormat == WireFormatResponses {
		return a.encodeResponsesRequest(request, stream)
	}
	return a.encodeChatRequest(request, stream)
}

func (a *Adapter) encodeChatRequest(request modelgateway.NormalizedRequest, stream bool) ([]byte, error) {
	if stream && requestUsesNativeTools(request) {
		return nil, modelgateway.ErrProviderNotAllowed
	}
	reasoningEffort := ""
	if a.supportsReasoningEffort {
		reasoningEffort = request.ReasoningEffort
	}
	value := chatRequest{
		Model: request.Model, MaxTokens: request.MaxOutputTokens, Temperature: request.Temperature,
		TopP: request.TopP, TopK: request.TopK, ReasoningEffort: reasoningEffort, ThinkingBudget: request.ThinkingBudget, Stream: stream,
	}
	value.PromptCacheKey = a.promptCacheKey(request)
	cacheBreakpoint := value.PromptCacheKey != "" && supportsExplicitPromptCaching(request.Model)
	if cacheBreakpoint {
		value.PromptCacheOptions = &promptCacheOptions{Mode: "explicit"}
	}
	if stream {
		value.StreamOptions = &chatStreamOptions{IncludeUsage: true}
	}
	breakpointIndex := promptCacheBreakpointIndex(request.Messages)
	for index, message := range request.Messages {
		wireMessage := chatRequestMessage{Role: message.Role, ToolCallID: message.ToolCallID}
		if message.Content != "" {
			content, err := encodeChatContent(message.Content, cacheBreakpoint && index == breakpointIndex)
			if err != nil {
				return nil, modelgateway.ErrInvalidRequest
			}
			wireMessage.Content = content
		}
		for _, call := range message.ToolCalls {
			wireMessage.ToolCalls = append(wireMessage.ToolCalls, chatToolCall{ID: call.ID, Type: "function", Function: chatToolCallFunction{Name: call.Name, Arguments: string(call.Arguments)}})
		}
		value.Messages = append(value.Messages, wireMessage)
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
	if len(request.ResponseSchema) != 0 && !stream {
		providerSchema, err := compatibleResponseSchema(request.ResponseSchema)
		if err != nil {
			return nil, err
		}
		value.ResponseFormat = &chatResponseFormat{Type: "json_schema", JSONSchema: chatJSONSchema{Name: "aor_response", Schema: providerSchema, Strict: true}}
	}
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)) > a.maxRequestBytes {
		return nil, modelgateway.ErrInvalidRequest
	}
	return encoded, nil
}

// Compatible endpoints commonly implement the strict structured-output shape
// but reject validation-only JSON Schema keywords. The gateway still validates
// the response against the original schema and semantic validator.
func compatibleResponseSchema(schema json.RawMessage) (json.RawMessage, error) {
	var value map[string]any
	if json.Unmarshal(schema, &value) != nil {
		return nil, modelgateway.ErrInvalidRequest
	}
	stripUnsupportedSchemaKeywords(value)
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > modelgateway.MaximumResponseSchemaBytes {
		return nil, modelgateway.ErrInvalidRequest
	}
	return encoded, nil
}

func stripUnsupportedSchemaKeywords(value any) {
	switch current := value.(type) {
	case map[string]any:
		for key := range current {
			if unsupportedSchemaKeyword(key) {
				delete(current, key)
				continue
			}
			stripUnsupportedSchemaKeywords(current[key])
		}
	case []any:
		for _, item := range current {
			stripUnsupportedSchemaKeywords(item)
		}
	}
}

func unsupportedSchemaKeyword(key string) bool {
	switch key {
	case "$schema", "$id", "minLength", "maxLength", "pattern", "format",
		"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
		"minItems", "maxItems", "uniqueItems", "contains", "minContains", "maxContains",
		"minProperties", "maxProperties", "patternProperties", "propertyNames", "unevaluatedProperties",
		"not", "if", "then", "else", "dependentRequired", "dependentSchemas":
		return true
	default:
		return false
	}
}

func (a *Adapter) do(ctx context.Context, requestID string, payload []byte) (*http.Response, context.CancelFunc, error) {
	return a.doWithAccept(ctx, requestID, payload, "application/json")
}

func (a *Adapter) doWithAccept(ctx context.Context, requestID string, payload []byte, accept string) (*http.Response, context.CancelFunc, error) {
	if err := contextError(ctx); err != nil {
		return nil, nil, err
	}
	requestCtx, cancel := context.WithTimeoutCause(ctx, a.timeout, errAdapterRequestTimeout)
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, a.endpoint, bytes.NewReader(payload))
	if err != nil {
		cancel()
		return nil, nil, modelgateway.ErrInvalidRequest
	}
	request.Header.Set("Authorization", "Bearer "+a.credential)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", accept)
	request.Header.Set("Idempotency-Key", requestID)
	request.Header.Set("X-Request-ID", requestID)
	response, err := a.client.Do(request)
	if err != nil {
		contextErr := adapterRequestContextError(ctx, requestCtx)
		cancel()
		if contextErr != nil {
			return nil, nil, contextErr
		}
		return nil, nil, unknownFailure(errors.New("openai-compatible network request failed"))
	}
	return response, cancel, nil
}

func (a *Adapter) decodeResponse(request modelgateway.NormalizedRequest, capabilities modelgateway.ModelCapabilities, payload []byte) (modelgateway.NormalizedResponse, error) {
	if a.wireFormat == WireFormatResponses {
		return a.decodeResponsesResponse(request, capabilities, payload)
	}
	return a.decodeChatResponse(request, capabilities, payload)
}

func (a *Adapter) decodeChatResponse(request modelgateway.NormalizedRequest, capabilities modelgateway.ModelCapabilities, payload []byte) (modelgateway.NormalizedResponse, error) {
	if !utf8.Valid(payload) {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
	}
	if a.containsCredential(string(payload)) {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrCredentialDetected)
	}
	var response chatResponse
	if json.Unmarshal(payload, &response) != nil || len(response.Choices) != 1 || response.Usage == nil || !usageFieldsPresent(payload, "prompt_tokens", "completion_tokens") {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
	}
	choice := response.Choices[0]
	if strings.TrimSpace(response.ID) == "" || len(response.ID) > modelgateway.MaximumToolCallIDBytes || strings.ContainsAny(response.ID, "\r\n\x00") || strings.TrimSpace(choice.FinishReason) == "" || len(choice.FinishReason) > 128 || len(response.Model) > modelgateway.MaximumToolCallIDBytes || !utf8.ValidString(response.ID) || !utf8.ValidString(response.Model) || !utf8.ValidString(choice.FinishReason) {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
	}
	if a.containsCredential(response.ID) || a.containsCredential(response.Model) || a.containsCredential(choice.FinishReason) {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrCredentialDetected)
	}
	hasContent := choice.Message.Content != nil && *choice.Message.Content != ""
	hasToolCalls := len(choice.Message.ToolCalls) != 0
	if !hasContent && !hasToolCalls || len(choice.Message.ToolCalls) > modelgateway.MaximumToolCalls {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
	}
	if choice.Message.ToolCallID != "" || choice.Message.Role != "" && choice.Message.Role != "assistant" {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
	}
	if hasContent {
		if len(*choice.Message.Content) > modelgateway.MaximumResponseBytes {
			return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputTooLarge)
		}
		if !utf8.ValidString(*choice.Message.Content) {
			return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
		}
		if a.containsCredential(*choice.Message.Content) {
			return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrCredentialDetected)
		}
		// Some compatible providers add prose beside native tool calls. The
		// provider-independent protocol carries the actionable calls only.
		if hasToolCalls && !json.Valid([]byte(*choice.Message.Content)) {
			hasContent = false
		}
	}
	if hasContent && hasToolCalls {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
	}
	outputBytes := 0
	for _, wireCall := range choice.Message.ToolCalls {
		callBytes := len(wireCall.ID) + len(wireCall.Function.Name) + len(wireCall.Function.Arguments)
		if callBytes > modelgateway.MaximumResponseBytes-outputBytes {
			return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputTooLarge)
		}
		outputBytes += callBytes
	}
	var content json.RawMessage
	if hasContent {
		if json.Valid([]byte(*choice.Message.Content)) {
			content = append(json.RawMessage(nil), (*choice.Message.Content)...)
		} else {
			encoded, err := json.Marshal(*choice.Message.Content)
			if err != nil || len(encoded) > modelgateway.MaximumResponseBytes {
				return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputTooLarge)
			}
			content = encoded
		}
	}
	toolCalls := make([]modelgateway.ToolCall, 0, len(choice.Message.ToolCalls))
	allowed := make(map[string]struct{}, len(request.Tools))
	for _, tool := range request.Tools {
		allowed[tool.Name] = struct{}{}
	}
	seenCallIDs := make(map[string]struct{}, len(choice.Message.ToolCalls))
	for _, wireCall := range choice.Message.ToolCalls {
		call := modelgateway.ToolCall{ID: wireCall.ID, Name: wireCall.Function.Name, Arguments: json.RawMessage(wireCall.Function.Arguments)}
		if wireCall.Type != "function" || call.Validate() != nil {
			return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
		}
		if a.containsCredential(call.ID) || a.containsCredential(call.Name) || a.containsCredential(string(call.Arguments)) {
			return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrCredentialDetected)
		}
		if _, found := allowed[call.Name]; !found {
			return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
		}
		if _, found := seenCallIDs[call.ID]; found {
			return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
		}
		seenCallIDs[call.ID] = struct{}{}
		toolCalls = append(toolCalls, call)
	}
	usage, err := a.NormalizeUsage(*response.Usage)
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
		Content: content, ToolCalls: toolCalls, FinishReason: choice.FinishReason, Usage: usage,
	}, nil
}

func requestUsesNativeTools(request modelgateway.NormalizedRequest) bool {
	if len(request.Tools) != 0 {
		return true
	}
	for _, message := range request.Messages {
		if len(message.ToolCalls) != 0 || message.ToolCallID != "" {
			return true
		}
	}
	return false
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
		return normalizedChatUsage(value), nil
	}
	if _, responses := fields["input_tokens"]; responses {
		var value responsesUsage
		if json.Unmarshal(encoded, &value) != nil {
			return modelgateway.Usage{}, modelgateway.ErrInvalidRequest
		}
		return normalizedResponsesUsage(value), nil
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

func adapterRequestContextError(callerCtx, requestCtx context.Context) error {
	if requestCtx != nil && errors.Is(context.Cause(requestCtx), errAdapterRequestTimeout) {
		return &modelgateway.ProviderFailure{
			Cause: context.DeadlineExceeded, Retryable: true, OutcomeKnown: true,
		}
	}
	if callerCtx != nil {
		if err := callerCtx.Err(); err != nil {
			return err
		}
	}
	if requestCtx == nil {
		return nil
	}
	return requestCtx.Err()
}

func responseRequestContext(fallback context.Context, response *http.Response) context.Context {
	if response != nil && response.Request != nil {
		return response.Request.Context()
	}
	return fallback
}

func validRequestHeaderValue(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= modelgateway.MaximumToolCallIDBytes && utf8.ValidString(value) && !strings.ContainsAny(value, "\r\n\x00")
}

func (a *Adapter) promptCacheKey(request modelgateway.NormalizedRequest) string {
	capabilities, found := a.models[request.Model]
	if !found || !capabilities.SupportsPromptCaching {
		return ""
	}
	breakpointIndex := promptCacheBreakpointIndex(request.Messages)
	if breakpointIndex < 0 {
		return ""
	}
	actualModelVersion := capabilities.ActualModelVersion
	if actualModelVersion == "" {
		actualModelVersion = request.Model
	}
	prefix, _ := json.Marshal(request.Messages[:breakpointIndex+1])
	prefixDigest := sha256.Sum256(prefix)
	tools, _ := json.Marshal(request.Tools)
	toolsDigest := sha256.Sum256(tools)
	responseSchemaDigest := sha256.Sum256(request.ResponseSchema)
	canonical, _ := json.Marshal(struct {
		TenantID             string `json:"tenantId"`
		WireFormat           string `json:"wireFormat"`
		Role                 string `json:"role"`
		Model                string `json:"model"`
		ActualModelVersion   string `json:"actualModelVersion"`
		PromptBundleVersion  string `json:"promptBundleVersion"`
		PrefixDigest         string `json:"prefixDigest"`
		ToolsDigest          string `json:"toolsDigest"`
		ResponseSchemaDigest string `json:"responseSchemaDigest"`
	}{
		TenantID: request.TenantID, WireFormat: string(a.wireFormat), Role: request.Role,
		Model: request.Model, ActualModelVersion: actualModelVersion,
		PromptBundleVersion: request.PromptBundleVersion,
		PrefixDigest:        hex.EncodeToString(prefixDigest[:]), ToolsDigest: hex.EncodeToString(toolsDigest[:]),
		ResponseSchemaDigest: hex.EncodeToString(responseSchemaDigest[:]),
	})
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:])
}

func promptCacheBreakpointIndex(messages []modelgateway.Message) int {
	index := -1
	for current, message := range messages {
		if message.Role != "system" {
			break
		}
		if message.Content != "" && len(message.ToolCalls) == 0 && message.ToolCallID == "" {
			index = current
		}
	}
	return index
}

func supportsExplicitPromptCaching(model string) bool {
	return strings.HasPrefix(model, "gpt-5.6")
}

func encodeChatContent(content string, breakpoint bool) (json.RawMessage, error) {
	if !breakpoint {
		return json.Marshal(content)
	}
	return json.Marshal([]chatContentBlock{{
		Type: "text", Text: content, PromptCacheBreakpoint: &promptCacheBreakpoint{Mode: "explicit"},
	}})
}

func normalizedChatUsage(value chatUsage) modelgateway.Usage {
	usage := modelgateway.Usage{InputTokens: value.PromptTokens, OutputTokens: value.CompletionTokens}
	usage.CacheReadTokens, usage.CacheWriteTokens = normalizedCacheTokens(value.PromptTokensDetails)
	return usage
}

func normalizedResponsesUsage(value responsesUsage) modelgateway.Usage {
	usage := modelgateway.Usage{InputTokens: value.InputTokens, OutputTokens: value.OutputTokens}
	usage.CacheReadTokens, usage.CacheWriteTokens = normalizedCacheTokens(value.InputTokensDetails)
	return usage
}

func normalizedCacheTokens(details *cacheTokenDetails) (*int64, *int64) {
	if details == nil {
		return nil, nil
	}
	return cloneOptionalInt64(details.CachedTokens), cloneOptionalInt64(details.CacheWriteTokens)
}

func cloneOptionalInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
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
	Model              string               `json:"model"`
	Messages           []chatRequestMessage `json:"messages"`
	Tools              []chatTool           `json:"tools,omitempty"`
	ResponseFormat     *chatResponseFormat  `json:"response_format,omitempty"`
	MaxTokens          int                  `json:"max_tokens"`
	Temperature        float64              `json:"temperature"`
	TopP               float64              `json:"top_p"`
	TopK               int                  `json:"top_k,omitempty"`
	ReasoningEffort    string               `json:"reasoning_effort,omitempty"`
	ThinkingBudget     int                  `json:"thinking_budget,omitempty"`
	PromptCacheKey     string               `json:"prompt_cache_key,omitempty"`
	PromptCacheOptions *promptCacheOptions  `json:"prompt_cache_options,omitempty"`
	Seed               *int64               `json:"seed,omitempty"`
	Stream             bool                 `json:"stream,omitempty"`
	StreamOptions      *chatStreamOptions   `json:"stream_options,omitempty"`
}

func validReasoningEffort(value string) bool {
	switch value {
	case "", "none", "low", "medium", "high", "xhigh", "max":
		return true
	default:
		return false
	}
}

type chatStreamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

type promptCacheOptions struct {
	Mode string `json:"mode"`
}

type promptCacheBreakpoint struct {
	Mode string `json:"mode"`
}

type chatRequestMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	ToolCalls  []chatToolCall  `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
}

type chatContentBlock struct {
	Type                  string                 `json:"type"`
	Text                  string                 `json:"text"`
	PromptCacheBreakpoint *promptCacheBreakpoint `json:"prompt_cache_breakpoint,omitempty"`
}

type chatMessage struct {
	Role       string         `json:"role"`
	Content    *string        `json:"content"`
	ToolCalls  []chatToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}

type chatToolCall struct {
	ID       string               `json:"id"`
	Type     string               `json:"type"`
	Function chatToolCallFunction `json:"function"`
}

type chatToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
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
		Message      chatMessage `json:"message"`
		FinishReason string      `json:"finish_reason"`
	} `json:"choices"`
	Usage *chatUsage `json:"usage"`
}

type chatUsage struct {
	PromptTokens        int64              `json:"prompt_tokens"`
	CompletionTokens    int64              `json:"completion_tokens"`
	TotalTokens         int64              `json:"total_tokens"`
	PromptTokensDetails *cacheTokenDetails `json:"prompt_tokens_details,omitempty"`
}

type cacheTokenDetails struct {
	CachedTokens     *int64 `json:"cached_tokens,omitempty"`
	CacheWriteTokens *int64 `json:"cache_write_tokens,omitempty"`
}
