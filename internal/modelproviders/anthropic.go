package modelproviders

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/akimisaka/aor/internal/modelgateway"
)

const (
	anthropicVersion               = "2023-06-01"
	maximumAnthropicRequestTimeout = 10*time.Minute + 30*time.Second
)

type anthropicConfig struct {
	BaseURL        string
	APIKey         string
	Models         map[string]modelgateway.ModelCapabilities
	HTTPClient     *http.Client
	RequestTimeout time.Duration
}

type anthropicAdapter struct {
	endpoint string
	apiKey   string
	models   map[string]modelgateway.ModelCapabilities
	client   *http.Client
	timeout  time.Duration
}

type anthropicRequest struct {
	Model        string                 `json:"model"`
	MaxTokens    int                    `json:"max_tokens"`
	Temperature  *float64               `json:"temperature,omitempty"`
	TopP         *float64               `json:"top_p,omitempty"`
	TopK         *int                   `json:"top_k,omitempty"`
	Thinking     *anthropicThinking     `json:"thinking,omitempty"`
	OutputConfig *anthropicOutputConfig `json:"output_config,omitempty"`
	System       string                 `json:"system,omitempty"`
	Messages     []anthropicMessage     `json:"messages"`
	Tools        []anthropicTool        `json:"tools,omitempty"`
	ToolChoice   *anthropicToolChoice   `json:"tool_choice,omitempty"`
	Stream       bool                   `json:"stream,omitempty"`
}

type anthropicOutputConfig struct {
	Effort string `json:"effort"`
}

type anthropicThinking struct {
	Type         string `json:"type"`
	BudgetTokens int    `json:"budget_tokens"`
}

type anthropicMessage struct {
	Role    string                  `json:"role"`
	Content []anthropicContentBlock `json:"content"`
}

type anthropicContentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   string          `json:"content,omitempty"`
}

type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type anthropicToolChoice struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}

type anthropicResponse struct {
	ID         string                  `json:"id"`
	Model      string                  `json:"model"`
	Role       string                  `json:"role"`
	Content    []anthropicContentBlock `json:"content"`
	StopReason string                  `json:"stop_reason"`
	Usage      *anthropicUsage         `json:"usage"`
}

type anthropicUsage struct {
	InputTokens              int64  `json:"input_tokens"`
	OutputTokens             int64  `json:"output_tokens"`
	CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     *int64 `json:"cache_read_input_tokens,omitempty"`
}

func newAnthropicAdapter(config anthropicConfig) (*anthropicAdapter, error) {
	if !validAPIKey(config.APIKey) || len(config.Models) == 0 || config.RequestTimeout <= 0 || config.RequestTimeout > maximumAnthropicRequestTimeout {
		return nil, ErrInvalidSettings
	}
	parsed, err := parseProviderURL(config.BaseURL)
	if err != nil {
		return nil, err
	}
	path := strings.TrimRight(parsed.Path, "/")
	if !strings.HasSuffix(path, "/messages") {
		if !strings.HasSuffix(path, "/v1") {
			path += "/v1"
		}
		path += "/messages"
	}
	parsed.Path, parsed.RawPath = path, ""
	client := http.DefaultClient
	if config.HTTPClient != nil {
		client = config.HTTPClient
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	models := make(map[string]modelgateway.ModelCapabilities, len(config.Models))
	for model, capabilities := range config.Models {
		if model == "" || capabilities.MaxInputTokens <= 0 || capabilities.MaxOutputTokens <= 0 {
			return nil, ErrInvalidSettings
		}
		models[model] = capabilities
	}
	return &anthropicAdapter{endpoint: parsed.String(), apiKey: config.APIKey, models: models, client: &copyClient, timeout: config.RequestTimeout}, nil
}

func (adapter *anthropicAdapter) Capabilities(ctx context.Context, model string) (modelgateway.ModelCapabilities, error) {
	if ctx == nil {
		return modelgateway.ModelCapabilities{}, modelgateway.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return modelgateway.ModelCapabilities{}, err
	}
	capabilities, found := adapter.models[model]
	if !found {
		return modelgateway.ModelCapabilities{}, modelgateway.ErrProviderNotAllowed
	}
	capabilities.DataResidency = append([]string(nil), capabilities.DataResidency...)
	capabilities.Modalities = append([]string(nil), capabilities.Modalities...)
	return capabilities, nil
}

func (adapter *anthropicAdapter) CountTokens(ctx context.Context, request modelgateway.NormalizedRequest) (modelgateway.TokenEstimate, error) {
	if _, err := adapter.validateRequest(ctx, request, false); err != nil {
		return modelgateway.TokenEstimate{}, err
	}
	bytesCount := len(request.ResponseSchema)
	for _, message := range request.Messages {
		bytesCount += len(message.Role) + len(message.Content) + len(message.ToolCallID)
		for _, call := range message.ToolCalls {
			bytesCount += len(call.ID) + len(call.Name) + len(call.Arguments)
		}
	}
	for _, tool := range request.Tools {
		bytesCount += len(tool.Name) + len(tool.Description) + len(tool.Schema)
	}
	return modelgateway.TokenEstimate{InputTokens: int64(bytesCount+3) / 4}, nil
}

func (adapter *anthropicAdapter) Generate(ctx context.Context, request modelgateway.NormalizedRequest) (modelgateway.NormalizedResponse, error) {
	capabilities, err := adapter.validateRequest(ctx, request, true)
	if err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	estimate, err := adapter.CountTokens(ctx, request)
	if err != nil || estimate.InputTokens > int64(capabilities.MaxInputTokens) {
		return modelgateway.NormalizedResponse{}, modelgateway.ErrInvalidRequest
	}
	if capabilities.SupportsStreaming && !anthropicRequestUsesNativeTools(request) {
		return adapter.generateStream(ctx, request, capabilities)
	}
	payload, err := adapter.encodeRequest(request)
	if err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, adapter.timeout)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(requestCtx, http.MethodPost, adapter.endpoint, bytes.NewReader(payload))
	if err != nil {
		return modelgateway.NormalizedResponse{}, modelgateway.ErrInvalidRequest
	}
	httpRequest.Header.Set("x-api-key", adapter.apiKey)
	httpRequest.Header.Set("anthropic-version", anthropicVersion)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Idempotency-Key", request.RequestID)
	httpRequest.Header.Set("X-Request-ID", request.RequestID)
	response, err := adapter.client.Do(httpRequest)
	if err != nil {
		if requestCtx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return modelgateway.NormalizedResponse{}, anthropicContextFailure(ctx, requestCtx, err)
		}
		return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(errors.New("anthropic network request failed"))
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return modelgateway.NormalizedResponse{}, anthropicHTTPFailure(response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, modelgateway.MaximumResponseBytes+1))
	if err != nil {
		if requestCtx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return modelgateway.NormalizedResponse{}, anthropicContextFailure(ctx, requestCtx, err)
		}
		return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(errors.New("anthropic response read failed"))
	}
	if len(body) > modelgateway.MaximumResponseBytes {
		return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputTooLarge)
	}
	return adapter.decodeResponse(request, capabilities, body)
}

func (adapter *anthropicAdapter) Stream(ctx context.Context, request modelgateway.NormalizedRequest) (modelgateway.ResponseStream, error) {
	capabilities, err := adapter.validateRequest(ctx, request, true)
	if err != nil {
		return nil, err
	}
	if !capabilities.SupportsStreaming || anthropicRequestUsesNativeTools(request) {
		return nil, modelgateway.ErrProviderNotAllowed
	}
	estimate, err := adapter.CountTokens(ctx, request)
	if err != nil {
		return nil, err
	}
	if estimate.InputTokens > int64(capabilities.MaxInputTokens) {
		return nil, modelgateway.ErrInvalidRequest
	}
	payload, err := adapter.encodeRequestWithStream(request)
	if err != nil {
		return nil, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, adapter.timeout)
	httpRequest, err := http.NewRequestWithContext(requestCtx, http.MethodPost, adapter.endpoint, bytes.NewReader(payload))
	if err != nil {
		cancel()
		return nil, modelgateway.ErrInvalidRequest
	}
	httpRequest.Header.Set("x-api-key", adapter.apiKey)
	httpRequest.Header.Set("anthropic-version", anthropicVersion)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "text/event-stream")
	httpRequest.Header.Set("Idempotency-Key", request.RequestID)
	httpRequest.Header.Set("X-Request-ID", request.RequestID)
	response, err := adapter.client.Do(httpRequest)
	if err != nil {
		var failure error
		if requestCtx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			failure = anthropicContextFailure(ctx, requestCtx, err)
		} else {
			failure = anthropicUnknownFailure(errors.New("anthropic network request failed"))
		}
		cancel()
		return nil, failure
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		cancel()
		_ = response.Body.Close()
		return nil, anthropicHTTPFailure(response.StatusCode)
	}
	stream := &anthropicResponseStream{
		adapter: adapter, request: request, capabilities: capabilities,
		body: response.Body, cancel: cancel, requestContext: requestCtx, activityContext: ctx,
		jsonMode: !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream"),
		events:   make(chan json.RawMessage, 1), failures: make(chan error, 1),
		done: make(chan struct{}), closed: make(chan struct{}), blocks: make(map[int]*anthropicStreamBlock),
	}
	go stream.read()
	return stream, nil
}

func anthropicRequestUsesNativeTools(request modelgateway.NormalizedRequest) bool {
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

type anthropicStreamBlock struct {
	typeName     string
	toolName     string
	initialInput json.RawMessage
	hasDelta     bool
	stopped      bool
}

type anthropicResponseStream struct {
	adapter         *anthropicAdapter
	request         modelgateway.NormalizedRequest
	capabilities    modelgateway.ModelCapabilities
	body            io.ReadCloser
	cancel          context.CancelFunc
	requestContext  context.Context
	activityContext context.Context
	jsonMode        bool
	events          chan json.RawMessage
	failures        chan error
	done            chan struct{}
	closed          chan struct{}
	closeOnce       sync.Once

	stateMu          sync.RWMutex
	providerID       string
	modelVersion     string
	stopReason       string
	content          []byte
	finalContent     json.RawMessage
	usage            modelgateway.Usage
	inputTokens      int64
	outputTokens     int64
	cacheReadTokens  *int64
	cacheWriteTokens *int64
	inputUsageFound  bool
	outputUsageFound bool
	messageStarted   bool
	complete         bool
	failed           bool
	blocks           map[int]*anthropicStreamBlock
}

var _ modelgateway.UsageAwareStream = (*anthropicResponseStream)(nil)
var _ modelgateway.FinalContentAwareStream = (*anthropicResponseStream)(nil)

func (stream *anthropicResponseStream) Recv(ctx context.Context) (json.RawMessage, error) {
	if ctx == nil {
		return nil, modelgateway.ErrInvalidRequest
	}
	for {
		select {
		case event := <-stream.events:
			if event != nil {
				return append(json.RawMessage(nil), event...), nil
			}
		default:
		}
		select {
		case event := <-stream.events:
			if event != nil {
				return append(json.RawMessage(nil), event...), nil
			}
		case err := <-stream.failures:
			if err != nil {
				return nil, err
			}
		case <-ctx.Done():
			_ = stream.Close()
			return nil, ctx.Err()
		case <-stream.done:
			select {
			case err := <-stream.failures:
				if err != nil {
					return nil, err
				}
			default:
			}
			return nil, io.EOF
		}
	}
}

func (stream *anthropicResponseStream) Close() error {
	var err error
	stream.closeOnce.Do(func() {
		close(stream.closed)
		stream.cancel()
		err = stream.body.Close()
	})
	return err
}

func (stream *anthropicResponseStream) FinalUsage() (modelgateway.Usage, bool) {
	stream.stateMu.RLock()
	defer stream.stateMu.RUnlock()
	if !stream.complete || stream.failed {
		return modelgateway.Usage{}, false
	}
	return stream.usage, true
}

func (stream *anthropicResponseStream) FinalContent() (json.RawMessage, bool) {
	stream.stateMu.RLock()
	defer stream.stateMu.RUnlock()
	if !stream.complete || stream.failed {
		return nil, false
	}
	return append(json.RawMessage(nil), stream.finalContent...), true
}

func (stream *anthropicResponseStream) FinalFinishReason() (string, bool) {
	stream.stateMu.RLock()
	defer stream.stateMu.RUnlock()
	return stream.stopReason, stream.complete && !stream.failed && stream.stopReason != ""
}

func (adapter *anthropicAdapter) generateStream(ctx context.Context, request modelgateway.NormalizedRequest, capabilities modelgateway.ModelCapabilities) (modelgateway.NormalizedResponse, error) {
	streamValue, err := adapter.Stream(ctx, request)
	if err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	stream, ok := streamValue.(*anthropicResponseStream)
	if !ok {
		_ = streamValue.Close()
		return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputSchema)
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
	content, contentReady := stream.FinalContent()
	usage, usageReady := stream.FinalUsage()
	finishReason, finishReady := stream.FinalFinishReason()
	if !contentReady || !usageReady || !finishReady || len(content) == 0 {
		return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputSchema)
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

func (stream *anthropicResponseStream) read() {
	defer close(stream.done)
	defer func() { _ = stream.Close() }()
	if stream.jsonMode {
		stream.readJSON()
		return
	}
	stream.readSSE()
}

func (stream *anthropicResponseStream) readJSON() {
	body, err := io.ReadAll(io.LimitReader(stream.body, modelgateway.MaximumResponseBytes+1))
	if err != nil {
		stream.fail(stream.readFailure(err, "anthropic response read failed"))
		return
	}
	if len(body) > modelgateway.MaximumResponseBytes {
		stream.fail(anthropicUnknownFailure(modelgateway.ErrOutputTooLarge))
		return
	}
	response, err := stream.adapter.decodeResponse(stream.request, stream.capabilities, body)
	if err != nil {
		stream.fail(err)
		return
	}
	if len(response.Content) == 0 {
		stream.fail(anthropicUnknownFailure(modelgateway.ErrOutputSchema))
		return
	}
	stream.stateMu.Lock()
	stream.providerID = response.ProviderRequestID
	stream.modelVersion = response.ModelVersion
	stream.stopReason = response.FinishReason
	stream.finalContent = append(json.RawMessage(nil), response.Content...)
	stream.usage = response.Usage
	stream.complete = true
	stream.stateMu.Unlock()
	fragment := string(response.Content)
	var text string
	if json.Unmarshal(response.Content, &text) == nil {
		fragment = text
	}
	event, encodeErr := encodeAnthropicStreamDelta(fragment)
	if encodeErr != nil {
		stream.fail(anthropicUnknownFailure(modelgateway.ErrOutputSchema))
		return
	}
	modelgateway.ReportActivityDelta(stream.activityContext, fragment)
	stream.send(event)
}

func (stream *anthropicResponseStream) readSSE() {
	reader := bufio.NewReaderSize(stream.body, 4096)
	var eventName string
	var data strings.Builder
	flush := func() (bool, error) {
		if data.Len() == 0 {
			eventName = ""
			return false, nil
		}
		payload := []byte(data.String())
		terminal, event, err := stream.observe(eventName, payload)
		data.Reset()
		eventName = ""
		if err != nil {
			return false, err
		}
		if len(event) != 0 && !stream.send(event) {
			return true, nil
		}
		return terminal, nil
	}
	for {
		lineBytes, readErr := readAnthropicSSELine(reader, modelgateway.MaximumResponseBytes)
		if errors.Is(readErr, modelgateway.ErrOutputTooLarge) {
			stream.fail(anthropicUnknownFailure(modelgateway.ErrOutputTooLarge))
			return
		}
		line := strings.TrimSuffix(string(lineBytes), "\r")
		if line == "" {
			terminal, flushErr := flush()
			if flushErr != nil {
				stream.fail(stream.readFailure(flushErr, "anthropic stream event invalid"))
				return
			}
			if terminal {
				return
			}
		} else if strings.HasPrefix(line, "event:") {
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			fragment := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			separatorLength := 0
			if data.Len() != 0 {
				separatorLength = 1
			}
			if data.Len()+separatorLength+len(fragment) > modelgateway.MaximumResponseBytes {
				stream.fail(anthropicUnknownFailure(modelgateway.ErrOutputTooLarge))
				return
			}
			if separatorLength != 0 {
				data.WriteByte('\n')
			}
			data.WriteString(fragment)
		}
		if errors.Is(readErr, io.EOF) {
			if data.Len() != 0 {
				terminal, flushErr := flush()
				if flushErr != nil {
					stream.fail(stream.readFailure(flushErr, "anthropic stream event invalid"))
					return
				}
				if terminal {
					return
				}
			}
			stream.fail(anthropicUnknownFailure(modelgateway.ErrOutputSchema))
			return
		}
		if readErr != nil {
			select {
			case <-stream.closed:
				return
			default:
			}
			stream.fail(stream.readFailure(readErr, "anthropic stream read failed"))
			return
		}
	}
}

func (stream *anthropicResponseStream) observe(eventName string, payload []byte) (bool, json.RawMessage, error) {
	if !utf8.Valid(payload) || !json.Valid(payload) {
		return false, nil, modelgateway.ErrOutputSchema
	}
	if stream.adapter.containsKey(string(payload)) {
		return false, nil, modelgateway.ErrCredentialDetected
	}
	var envelope struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(payload, &envelope) != nil || envelope.Type == "" || eventName != "" && eventName != envelope.Type {
		return false, nil, modelgateway.ErrOutputSchema
	}
	switch envelope.Type {
	case "ping":
		return false, nil, nil
	case "error":
		return false, nil, anthropicUnknownFailure(errors.New("anthropic provider returned an error"))
	case "message_start":
		return stream.observeMessageStart(payload)
	case "content_block_start":
		return stream.observeContentBlockStart(payload)
	case "content_block_delta":
		return stream.observeContentBlockDelta(payload)
	case "content_block_stop":
		return stream.observeContentBlockStop(payload)
	case "message_delta":
		return stream.observeMessageDelta(payload)
	case "message_stop":
		if err := stream.completeMessage(); err != nil {
			return false, nil, err
		}
		return true, nil, nil
	default:
		return false, nil, modelgateway.ErrOutputSchema
	}
}

func (stream *anthropicResponseStream) observeMessageStart(payload []byte) (bool, json.RawMessage, error) {
	var value struct {
		Message struct {
			ID    string          `json:"id"`
			Model string          `json:"model"`
			Role  string          `json:"role"`
			Usage json.RawMessage `json:"usage"`
		} `json:"message"`
	}
	if json.Unmarshal(payload, &value) != nil || value.Message.Role != "assistant" || !validAnthropicStreamString(value.Message.ID, modelgateway.MaximumToolCallIDBytes) || value.Message.Model != "" && !validAnthropicStreamString(value.Message.Model, modelgateway.MaximumToolCallIDBytes) || !anthropicUsageFieldsPresent(value.Message.Usage, "input_tokens") {
		return false, nil, modelgateway.ErrOutputSchema
	}
	var usage anthropicUsage
	if json.Unmarshal(value.Message.Usage, &usage) != nil || !validAnthropicUsage(usage) {
		return false, nil, modelgateway.ErrOutputSchema
	}
	stream.stateMu.Lock()
	defer stream.stateMu.Unlock()
	if stream.messageStarted || stream.complete {
		return false, nil, modelgateway.ErrOutputSchema
	}
	stream.messageStarted = true
	stream.providerID = value.Message.ID
	stream.modelVersion = value.Message.Model
	stream.inputTokens = usage.InputTokens
	stream.cacheReadTokens = cloneAnthropicTokenCount(usage.CacheReadInputTokens)
	stream.cacheWriteTokens = cloneAnthropicTokenCount(usage.CacheCreationInputTokens)
	stream.inputUsageFound = true
	return false, nil, nil
}

func (stream *anthropicResponseStream) observeContentBlockStart(payload []byte) (bool, json.RawMessage, error) {
	var value struct {
		Index        int                   `json:"index"`
		ContentBlock anthropicContentBlock `json:"content_block"`
	}
	if json.Unmarshal(payload, &value) != nil || value.Index < 0 || !stream.messageHasStarted() {
		return false, nil, modelgateway.ErrOutputSchema
	}
	if _, found := stream.blocks[value.Index]; found {
		return false, nil, modelgateway.ErrOutputSchema
	}
	block := &anthropicStreamBlock{typeName: value.ContentBlock.Type}
	stream.blocks[value.Index] = block
	switch value.ContentBlock.Type {
	case "text":
		if len(stream.request.ResponseSchema) != 0 {
			return false, nil, modelgateway.ErrOutputSchema
		}
		if value.ContentBlock.Text == "" {
			return false, nil, nil
		}
		event, err := stream.appendContent(value.ContentBlock.Text)
		return false, event, err
	case "tool_use":
		if len(stream.request.ResponseSchema) == 0 || value.ContentBlock.Name != "aor_response" || !validAnthropicStreamString(value.ContentBlock.ID, modelgateway.MaximumToolCallIDBytes) {
			return false, nil, modelgateway.ErrOutputSchema
		}
		if len(value.ContentBlock.Input) != 0 && !json.Valid(value.ContentBlock.Input) {
			return false, nil, modelgateway.ErrOutputSchema
		}
		block.toolName = value.ContentBlock.Name
		block.initialInput = append(json.RawMessage(nil), value.ContentBlock.Input...)
		return false, nil, nil
	case "thinking", "redacted_thinking":
		return false, nil, nil
	default:
		return false, nil, modelgateway.ErrOutputSchema
	}
}

func (stream *anthropicResponseStream) observeContentBlockDelta(payload []byte) (bool, json.RawMessage, error) {
	var value struct {
		Index int `json:"index"`
		Delta struct {
			Type        string `json:"type"`
			Text        string `json:"text"`
			PartialJSON string `json:"partial_json"`
		} `json:"delta"`
	}
	if json.Unmarshal(payload, &value) != nil || value.Index < 0 {
		return false, nil, modelgateway.ErrOutputSchema
	}
	block, found := stream.blocks[value.Index]
	if !found || block.stopped {
		return false, nil, modelgateway.ErrOutputSchema
	}
	switch value.Delta.Type {
	case "text_delta":
		if block.typeName != "text" {
			return false, nil, modelgateway.ErrOutputSchema
		}
		if value.Delta.Text == "" {
			return false, nil, nil
		}
		event, err := stream.appendContent(value.Delta.Text)
		return false, event, err
	case "input_json_delta":
		if block.typeName != "tool_use" || block.toolName != "aor_response" {
			return false, nil, modelgateway.ErrOutputSchema
		}
		block.hasDelta = true
		if value.Delta.PartialJSON == "" {
			return false, nil, nil
		}
		event, err := stream.appendContent(value.Delta.PartialJSON)
		return false, event, err
	case "thinking_delta", "signature_delta":
		if block.typeName != "thinking" && block.typeName != "redacted_thinking" {
			return false, nil, modelgateway.ErrOutputSchema
		}
		return false, nil, nil
	case "citations_delta":
		if block.typeName != "text" {
			return false, nil, modelgateway.ErrOutputSchema
		}
		return false, nil, nil
	default:
		return false, nil, modelgateway.ErrOutputSchema
	}
}

func (stream *anthropicResponseStream) observeContentBlockStop(payload []byte) (bool, json.RawMessage, error) {
	var value struct {
		Index int `json:"index"`
	}
	if json.Unmarshal(payload, &value) != nil || value.Index < 0 {
		return false, nil, modelgateway.ErrOutputSchema
	}
	block, found := stream.blocks[value.Index]
	if !found || block.stopped {
		return false, nil, modelgateway.ErrOutputSchema
	}
	block.stopped = true
	if block.typeName != "tool_use" || block.hasDelta {
		return false, nil, nil
	}
	if len(block.initialInput) == 0 {
		return false, nil, modelgateway.ErrOutputSchema
	}
	event, err := stream.appendContent(string(block.initialInput))
	return false, event, err
}

func (stream *anthropicResponseStream) observeMessageDelta(payload []byte) (bool, json.RawMessage, error) {
	var value struct {
		Delta struct {
			StopReason string `json:"stop_reason"`
		} `json:"delta"`
		Usage json.RawMessage `json:"usage"`
	}
	if json.Unmarshal(payload, &value) != nil || !validAnthropicStreamString(value.Delta.StopReason, 128) || !anthropicUsageFieldsPresent(value.Usage, "output_tokens") {
		return false, nil, modelgateway.ErrOutputSchema
	}
	var usage anthropicUsage
	if json.Unmarshal(value.Usage, &usage) != nil || !validAnthropicUsage(usage) {
		return false, nil, modelgateway.ErrOutputSchema
	}
	stream.stateMu.Lock()
	defer stream.stateMu.Unlock()
	if !stream.messageStarted || stream.stopReason != "" || stream.complete {
		return false, nil, modelgateway.ErrOutputSchema
	}
	stream.stopReason = value.Delta.StopReason
	stream.outputTokens = usage.OutputTokens
	if usage.CacheReadInputTokens != nil {
		stream.cacheReadTokens = cloneAnthropicTokenCount(usage.CacheReadInputTokens)
	}
	if usage.CacheCreationInputTokens != nil {
		stream.cacheWriteTokens = cloneAnthropicTokenCount(usage.CacheCreationInputTokens)
	}
	stream.outputUsageFound = true
	return false, nil, nil
}

func (stream *anthropicResponseStream) appendContent(fragment string) (json.RawMessage, error) {
	if !utf8.ValidString(fragment) || stream.adapter.containsKey(fragment) {
		return nil, modelgateway.ErrCredentialDetected
	}
	stream.stateMu.Lock()
	if len(fragment) > modelgateway.MaximumResponseBytes-len(stream.content) {
		stream.stateMu.Unlock()
		return nil, modelgateway.ErrOutputTooLarge
	}
	stream.content = append(stream.content, fragment...)
	stream.stateMu.Unlock()
	encoded, err := encodeAnthropicStreamDelta(fragment)
	if err != nil {
		return nil, modelgateway.ErrOutputSchema
	}
	modelgateway.ReportActivityDelta(stream.activityContext, fragment)
	return encoded, nil
}

func (stream *anthropicResponseStream) completeMessage() error {
	for _, block := range stream.blocks {
		if !block.stopped {
			return modelgateway.ErrOutputSchema
		}
	}
	stream.stateMu.Lock()
	defer stream.stateMu.Unlock()
	if !stream.messageStarted || stream.complete || stream.providerID == "" || stream.stopReason == "" || !stream.inputUsageFound || !stream.outputUsageFound || stream.inputTokens < 0 || stream.outputTokens < 0 || len(stream.content) == 0 {
		return modelgateway.ErrOutputSchema
	}
	content := append(json.RawMessage(nil), stream.content...)
	if !json.Valid(content) {
		encoded, err := json.Marshal(string(stream.content))
		if err != nil || len(encoded) > modelgateway.MaximumResponseBytes {
			return modelgateway.ErrOutputSchema
		}
		content = encoded
	}
	modelVersion := stream.modelVersion
	if modelVersion == "" {
		modelVersion = stream.capabilities.ActualModelVersion
	}
	if modelVersion == "" || stream.adapter.containsKey(modelVersion) || stream.adapter.containsKey(stream.providerID) || stream.adapter.containsKey(stream.stopReason) {
		return modelgateway.ErrCredentialDetected
	}
	stream.modelVersion = modelVersion
	stream.finalContent = content
	stream.usage = modelgateway.Usage{
		InputTokens: stream.inputTokens, OutputTokens: stream.outputTokens,
		CacheReadTokens: cloneAnthropicTokenCount(stream.cacheReadTokens), CacheWriteTokens: cloneAnthropicTokenCount(stream.cacheWriteTokens),
		ProviderRequestID: stream.providerID, ModelVersion: modelVersion,
	}
	stream.complete = true
	return nil
}

func (stream *anthropicResponseStream) messageHasStarted() bool {
	stream.stateMu.RLock()
	defer stream.stateMu.RUnlock()
	return stream.messageStarted && !stream.complete
}

func (stream *anthropicResponseStream) send(event json.RawMessage) bool {
	select {
	case stream.events <- append(json.RawMessage(nil), event...):
		return true
	case <-stream.closed:
		return false
	}
}

func (stream *anthropicResponseStream) fail(err error) {
	stream.stateMu.Lock()
	stream.failed = true
	stream.stateMu.Unlock()
	select {
	case stream.failures <- err:
	default:
	}
}

func (stream *anthropicResponseStream) readFailure(err error, message string) error {
	if contextErr := stream.requestContext.Err(); contextErr != nil {
		return anthropicContextFailure(stream.activityContext, stream.requestContext, contextErr)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return anthropicContextFailure(stream.activityContext, stream.requestContext, err)
	}
	var providerFailure *modelgateway.ProviderFailure
	if errors.As(err, &providerFailure) {
		return err
	}
	if errors.Is(err, modelgateway.ErrOutputSchema) || errors.Is(err, modelgateway.ErrOutputTooLarge) || errors.Is(err, modelgateway.ErrCredentialDetected) {
		return anthropicUnknownFailure(err)
	}
	return anthropicUnknownFailure(errors.New(message))
}

func validAnthropicStreamString(value string, maximum int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsAny(value, "\r\n\x00")
}

func encodeAnthropicStreamDelta(fragment string) (json.RawMessage, error) {
	encoded, err := json.Marshal(struct {
		Delta string `json:"delta"`
	}{Delta: fragment})
	return encoded, err
}

func readAnthropicSSELine(reader *bufio.Reader, maximum int) ([]byte, error) {
	line := make([]byte, 0, 256)
	for {
		fragment, prefix, err := reader.ReadLine()
		if len(fragment) > maximum-len(line) {
			return nil, modelgateway.ErrOutputTooLarge
		}
		line = append(line, fragment...)
		if err != nil {
			return line, err
		}
		if !prefix {
			return line, nil
		}
	}
}

func (adapter *anthropicAdapter) Cancel(ctx context.Context, providerRequestID string) error {
	if ctx == nil || providerRequestID == "" {
		return modelgateway.ErrInvalidRequest
	}
	return ctx.Err()
}

func (adapter *anthropicAdapter) NormalizeUsage(raw any) (modelgateway.Usage, error) {
	var usage anthropicUsage
	switch value := raw.(type) {
	case anthropicUsage:
		usage = value
	case []byte:
		if json.Unmarshal(value, &usage) != nil {
			return modelgateway.Usage{}, modelgateway.ErrInvalidRequest
		}
	case json.RawMessage:
		if json.Unmarshal(value, &usage) != nil {
			return modelgateway.Usage{}, modelgateway.ErrInvalidRequest
		}
	case modelgateway.Usage:
		if value.InputTokens < 0 || value.OutputTokens < 0 || value.CostMicros < 0 || negativeAnthropicTokenCount(value.CacheReadTokens) || negativeAnthropicTokenCount(value.CacheWriteTokens) {
			return modelgateway.Usage{}, modelgateway.ErrInvalidRequest
		}
		return value, nil
	default:
		encoded, err := json.Marshal(value)
		if err != nil || json.Unmarshal(encoded, &usage) != nil {
			return modelgateway.Usage{}, modelgateway.ErrInvalidRequest
		}
	}
	if !validAnthropicUsage(usage) {
		return modelgateway.Usage{}, modelgateway.ErrInvalidRequest
	}
	return modelgateway.Usage{
		InputTokens: usage.InputTokens, OutputTokens: usage.OutputTokens,
		CacheReadTokens: cloneAnthropicTokenCount(usage.CacheReadInputTokens), CacheWriteTokens: cloneAnthropicTokenCount(usage.CacheCreationInputTokens),
	}, nil
}

func validAnthropicUsage(usage anthropicUsage) bool {
	return usage.InputTokens >= 0 && usage.OutputTokens >= 0 && !negativeAnthropicTokenCount(usage.CacheCreationInputTokens) && !negativeAnthropicTokenCount(usage.CacheReadInputTokens)
}

func negativeAnthropicTokenCount(value *int64) bool {
	return value != nil && *value < 0
}

func cloneAnthropicTokenCount(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func anthropicContextFailure(parentCtx, requestCtx context.Context, fallback error) error {
	if parentErr := parentCtx.Err(); parentErr != nil {
		return parentErr
	}
	if requestErr := requestCtx.Err(); requestErr != nil {
		if errors.Is(requestErr, context.DeadlineExceeded) {
			return &modelgateway.ProviderFailure{Cause: context.DeadlineExceeded, Retryable: true, OutcomeKnown: true}
		}
		return requestErr
	}
	return fallback
}

func (adapter *anthropicAdapter) validateRequest(ctx context.Context, request modelgateway.NormalizedRequest, requireID bool) (modelgateway.ModelCapabilities, error) {
	capabilities, err := adapter.Capabilities(ctx, request.Model)
	if err != nil {
		return modelgateway.ModelCapabilities{}, err
	}
	if requireID && request.RequestID == "" || len(request.Messages) == 0 || len(request.Messages) > modelgateway.MaximumMessages || len(request.Tools) > modelgateway.MaximumTools || request.MaxOutputTokens <= 0 || request.MaxOutputTokens > capabilities.MaxOutputTokens || request.ThinkingBudget < 0 || request.ThinkingBudget >= request.MaxOutputTokens || request.Temperature < 0 || request.Temperature > 1 || request.TopP < 0 || request.TopP > 1 || request.TopK < 0 || request.TopK > modelgateway.MaximumTopK || !validAnthropicEffort(request.ReasoningEffort) || request.Seed != nil {
		return modelgateway.ModelCapabilities{}, modelgateway.ErrInvalidRequest
	}
	if len(request.Tools) != 0 && !capabilities.SupportsToolCalls || len(request.ResponseSchema) != 0 && (!capabilities.SupportsJSONSchema || !json.Valid(request.ResponseSchema)) {
		return modelgateway.ModelCapabilities{}, modelgateway.ErrProviderNotAllowed
	}
	for _, message := range request.Messages {
		if message.Validate() != nil || adapter.containsKey(message.Content) || adapter.containsKey(message.ToolCallID) {
			return modelgateway.ModelCapabilities{}, modelgateway.ErrInvalidRequest
		}
		for _, call := range message.ToolCalls {
			if adapter.containsKey(call.ID) || adapter.containsKey(call.Name) || adapter.containsKey(string(call.Arguments)) {
				return modelgateway.ModelCapabilities{}, modelgateway.ErrInvalidRequest
			}
		}
	}
	for _, tool := range request.Tools {
		if tool.Validate() != nil || adapter.containsKey(tool.Name) || adapter.containsKey(tool.Description) || adapter.containsKey(string(tool.Schema)) {
			return modelgateway.ModelCapabilities{}, modelgateway.ErrInvalidRequest
		}
	}
	if adapter.containsKey(string(request.ResponseSchema)) {
		return modelgateway.ModelCapabilities{}, modelgateway.ErrInvalidRequest
	}
	return capabilities, nil
}

func (adapter *anthropicAdapter) encodeRequest(request modelgateway.NormalizedRequest) ([]byte, error) {
	value := anthropicRequest{Model: request.Model, MaxTokens: request.MaxOutputTokens}
	if request.ThinkingBudget > 0 {
		value.Thinking = &anthropicThinking{Type: "enabled", BudgetTokens: request.ThinkingBudget}
	}
	if effort := anthropicEffort(request.ReasoningEffort); effort != "" {
		value.OutputConfig = &anthropicOutputConfig{Effort: effort}
	} else {
		value.Temperature = &request.Temperature
		value.TopP = &request.TopP
		if request.TopK > 0 {
			value.TopK = &request.TopK
		}
	}
	systems := make([]string, 0, 1)
	for _, message := range request.Messages {
		if message.Role == "system" {
			systems = append(systems, message.Content)
			continue
		}
		wire := anthropicMessage{Role: message.Role}
		switch message.Role {
		case "user", "assistant":
			if message.Content != "" {
				wire.Content = append(wire.Content, anthropicContentBlock{Type: "text", Text: message.Content})
			}
			for _, call := range message.ToolCalls {
				wire.Content = append(wire.Content, anthropicContentBlock{Type: "tool_use", ID: call.ID, Name: call.Name, Input: append(json.RawMessage(nil), call.Arguments...)})
			}
		case "tool":
			wire.Role = "user"
			wire.Content = []anthropicContentBlock{{Type: "tool_result", ToolUseID: message.ToolCallID, Content: message.Content}}
		default:
			return nil, modelgateway.ErrInvalidRequest
		}
		value.Messages = appendAnthropicMessage(value.Messages, wire)
	}
	value.System = strings.Join(systems, "\n\n")
	for _, tool := range request.Tools {
		schema := tool.Schema
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object"}`)
		}
		value.Tools = append(value.Tools, anthropicTool{Name: tool.Name, Description: tool.Description, InputSchema: append(json.RawMessage(nil), schema...)})
	}
	if len(request.ResponseSchema) != 0 && len(request.Tools) == 0 {
		value.Tools = append(value.Tools, anthropicTool{Name: "aor_response", Description: "Return the structured response.", InputSchema: append(json.RawMessage(nil), request.ResponseSchema...)})
		value.ToolChoice = &anthropicToolChoice{Type: "tool", Name: "aor_response"}
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > modelgateway.MaximumNormalizedRequestBytes {
		return nil, modelgateway.ErrInvalidRequest
	}
	return encoded, nil
}

func (adapter *anthropicAdapter) encodeRequestWithStream(request modelgateway.NormalizedRequest) ([]byte, error) {
	encoded, err := adapter.encodeRequest(request)
	if err != nil {
		return nil, err
	}
	var value anthropicRequest
	if err := json.Unmarshal(encoded, &value); err != nil {
		return nil, modelgateway.ErrInvalidRequest
	}
	value.Stream = true
	encoded, err = json.Marshal(value)
	if err != nil || len(encoded) > modelgateway.MaximumNormalizedRequestBytes {
		return nil, modelgateway.ErrInvalidRequest
	}
	return encoded, nil
}

func validAnthropicEffort(value string) bool {
	switch value {
	case "", "none", "low", "medium", "high", "xhigh", "max":
		return true
	default:
		return false
	}
}

func anthropicEffort(value string) string {
	switch value {
	case "low", "medium", "high", "xhigh", "max":
		return value
	default:
		return ""
	}
}

func appendAnthropicMessage(messages []anthropicMessage, next anthropicMessage) []anthropicMessage {
	if len(messages) != 0 && messages[len(messages)-1].Role == next.Role {
		messages[len(messages)-1].Content = append(messages[len(messages)-1].Content, next.Content...)
		return messages
	}
	return append(messages, next)
}

func (adapter *anthropicAdapter) decodeResponse(request modelgateway.NormalizedRequest, capabilities modelgateway.ModelCapabilities, body []byte) (modelgateway.NormalizedResponse, error) {
	if !utf8.Valid(body) || adapter.containsKey(string(body)) {
		return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrCredentialDetected)
	}
	var response anthropicResponse
	if json.Unmarshal(body, &response) != nil || response.ID == "" || response.Role != "assistant" || response.StopReason == "" || len(response.Content) == 0 || response.Usage == nil || !anthropicUsageFieldsPresentFromBody(body, "input_tokens", "output_tokens") || response.Usage.InputTokens < 0 || response.Usage.OutputTokens < 0 {
		return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputSchema)
	}
	if adapter.containsKey(response.ID) || adapter.containsKey(response.Model) || adapter.containsKey(response.StopReason) {
		return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrCredentialDetected)
	}
	texts := make([]string, 0, len(response.Content))
	toolCalls := make([]modelgateway.ToolCall, 0, len(response.Content))
	allowedTools := make(map[string]struct{}, len(request.Tools))
	for _, tool := range request.Tools {
		allowedTools[tool.Name] = struct{}{}
	}
	for _, block := range response.Content {
		switch block.Type {
		case "text":
			if block.Text == "" || !utf8.ValidString(block.Text) || adapter.containsKey(block.Text) {
				return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputSchema)
			}
			texts = append(texts, block.Text)
		case "tool_use":
			call := modelgateway.ToolCall{ID: block.ID, Name: block.Name, Arguments: append(json.RawMessage(nil), block.Input...)}
			if call.Validate() != nil || adapter.containsKey(call.ID) || adapter.containsKey(call.Name) || adapter.containsKey(string(call.Arguments)) {
				return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputSchema)
			}
			if call.Name == "aor_response" && len(request.Tools) == 0 {
				if !json.Valid(call.Arguments) {
					return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputSchema)
				}
				texts = append(texts, string(call.Arguments))
				continue
			}
			toolCalls = append(toolCalls, call)
			if _, found := allowedTools[call.Name]; !found {
				return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputSchema)
			}
		default:
			return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputSchema)
		}
	}
	var content json.RawMessage
	if len(toolCalls) == 0 {
		combined := strings.Join(texts, "")
		if combined == "" {
			return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputSchema)
		}
		if json.Valid([]byte(combined)) {
			content = json.RawMessage(combined)
		} else {
			encoded, err := json.Marshal(combined)
			if err != nil {
				return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputSchema)
			}
			content = encoded
		}
	}
	usage, err := adapter.NormalizeUsage(*response.Usage)
	if err != nil {
		return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(err)
	}
	usage.ProviderRequestID = response.ID
	usage.ModelVersion = response.Model
	modelVersion := response.Model
	if modelVersion == "" {
		modelVersion = capabilities.ActualModelVersion
	}
	return modelgateway.NormalizedResponse{
		RequestID: request.RequestID, ProviderRequestID: response.ID, ModelVersion: modelVersion,
		Content: content, ToolCalls: toolCalls, FinishReason: response.StopReason, Usage: usage,
	}, nil
}

func (adapter *anthropicAdapter) containsKey(value string) bool {
	return adapter.apiKey != "" && strings.Contains(value, adapter.apiKey)
}

func anthropicUsageFieldsPresentFromBody(body []byte, fields ...string) bool {
	var root map[string]json.RawMessage
	if json.Unmarshal(body, &root) != nil {
		return false
	}
	return anthropicUsageFieldsPresent(root["usage"], fields...)
}

func anthropicUsageFieldsPresent(encoded json.RawMessage, fields ...string) bool {
	if len(encoded) == 0 || string(encoded) == "null" {
		return false
	}
	var usage map[string]json.RawMessage
	if json.Unmarshal(encoded, &usage) != nil {
		return false
	}
	for _, field := range fields {
		value, found := usage[field]
		if !found || string(value) == "null" {
			return false
		}
	}
	return true
}

func anthropicHTTPFailure(status int) error {
	return &modelgateway.ProviderFailure{
		Cause:        fmt.Errorf("anthropic provider returned HTTP %d", status),
		Retryable:    status == http.StatusTooManyRequests || status >= http.StatusInternalServerError,
		OutcomeKnown: true,
	}
}

func anthropicUnknownFailure(cause error) error {
	return &modelgateway.ProviderFailure{Cause: cause, Retryable: true, OutcomeKnown: false}
}

var _ modelgateway.ModelAdapter = (*anthropicAdapter)(nil)
