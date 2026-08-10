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
	"time"
	"unicode/utf8"

	"github.com/akimisaka/aor/internal/modelgateway"
)

const anthropicVersion = "2023-06-01"

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
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

func newAnthropicAdapter(config anthropicConfig) (*anthropicAdapter, error) {
	if !validAPIKey(config.APIKey) || len(config.Models) == 0 || config.RequestTimeout <= 0 || config.RequestTimeout > 10*time.Minute {
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
	response, err := adapter.client.Do(httpRequest)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return modelgateway.NormalizedResponse{}, requestCtx.Err()
		}
		return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(errors.New("anthropic network request failed"))
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return modelgateway.NormalizedResponse{}, anthropicHTTPFailure(response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, modelgateway.MaximumResponseBytes+1))
	if err != nil || len(body) > modelgateway.MaximumResponseBytes {
		return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputTooLarge)
	}
	return adapter.decodeResponse(request, capabilities, body)
}

func (adapter *anthropicAdapter) Stream(context.Context, modelgateway.NormalizedRequest) (modelgateway.ResponseStream, error) {
	return nil, modelgateway.ErrProviderNotAllowed
}

func (adapter *anthropicAdapter) generateStream(ctx context.Context, request modelgateway.NormalizedRequest, capabilities modelgateway.ModelCapabilities) (modelgateway.NormalizedResponse, error) {
	payload, err := adapter.encodeRequestWithStream(request)
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
	httpRequest.Header.Set("Accept", "text/event-stream")
	response, err := adapter.client.Do(httpRequest)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return modelgateway.NormalizedResponse{}, requestCtx.Err()
		}
		return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(errors.New("anthropic network request failed"))
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return modelgateway.NormalizedResponse{}, anthropicHTTPFailure(response.StatusCode)
	}
	if !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
		body, readErr := io.ReadAll(io.LimitReader(response.Body, modelgateway.MaximumResponseBytes+1))
		if readErr != nil {
			if contextErr := requestCtx.Err(); contextErr != nil {
				return modelgateway.NormalizedResponse{}, contextErr
			}
			return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(errors.New("anthropic response read failed"))
		}
		if len(body) > modelgateway.MaximumResponseBytes {
			return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputTooLarge)
		}
		return adapter.decodeResponse(request, capabilities, body)
	}
	reader := bufio.NewReaderSize(response.Body, 4096)
	var eventName string
	var data strings.Builder
	var text strings.Builder
	var providerID, modelVersion, stopReason string
	var inputTokens, outputTokens int64
	var inputUsageFound, outputUsageFound bool
	flush := func() error {
		if data.Len() == 0 {
			eventName = ""
			return nil
		}
		payload := []byte(data.String())
		if !json.Valid(payload) || adapter.containsKey(string(payload)) {
			return anthropicUnknownFailure(modelgateway.ErrOutputSchema)
		}
		if eventName == "" {
			var envelope struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(payload, &envelope) == nil {
				eventName = envelope.Type
			}
		}
		switch eventName {
		case "message_start":
			var value struct {
				Message struct {
					ID    string          `json:"id"`
					Model string          `json:"model"`
					Usage json.RawMessage `json:"usage"`
				} `json:"message"`
			}
			if json.Unmarshal(payload, &value) != nil {
				return modelgateway.ErrOutputSchema
			}
			providerID, modelVersion = value.Message.ID, value.Message.Model
			if anthropicUsageFieldsPresent(value.Message.Usage, "input_tokens") {
				var usage anthropicUsage
				if json.Unmarshal(value.Message.Usage, &usage) != nil {
					return modelgateway.ErrOutputSchema
				}
				inputTokens = usage.InputTokens
				inputUsageFound = true
			}
		case "content_block_delta":
			var value struct {
				Delta struct {
					Type        string `json:"type"`
					Text        string `json:"text"`
					PartialJSON string `json:"partial_json"`
				} `json:"delta"`
			}
			if json.Unmarshal(payload, &value) != nil {
				return modelgateway.ErrOutputSchema
			}
			fragment := value.Delta.Text
			if value.Delta.Type == "input_json_delta" {
				fragment = value.Delta.PartialJSON
			}
			if fragment != "" {
				if text.Len()+len(fragment) > modelgateway.MaximumResponseBytes {
					return modelgateway.ErrOutputTooLarge
				}
				text.WriteString(fragment)
				modelgateway.ReportActivityDelta(ctx, fragment)
			}
		case "message_delta":
			var value struct {
				Delta struct {
					StopReason string `json:"stop_reason"`
				} `json:"delta"`
				Usage json.RawMessage `json:"usage"`
			}
			if json.Unmarshal(payload, &value) != nil {
				return modelgateway.ErrOutputSchema
			}
			stopReason = value.Delta.StopReason
			if anthropicUsageFieldsPresent(value.Usage, "output_tokens") {
				var usage anthropicUsage
				if json.Unmarshal(value.Usage, &usage) != nil {
					return modelgateway.ErrOutputSchema
				}
				outputTokens = usage.OutputTokens
				outputUsageFound = true
			}
		case "error":
			return anthropicUnknownFailure(errors.New("anthropic provider returned an error"))
		}
		data.Reset()
		eventName = ""
		return nil
	}
	for {
		lineBytes, readErr := readAnthropicSSELine(reader, modelgateway.MaximumResponseBytes)
		if errors.Is(readErr, modelgateway.ErrOutputTooLarge) {
			return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputTooLarge)
		}
		line := string(lineBytes)
		if line == "" {
			if flushErr := flush(); flushErr != nil {
				return modelgateway.NormalizedResponse{}, flushErr
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
				return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputTooLarge)
			}
			if separatorLength != 0 {
				data.WriteByte('\n')
			}
			data.WriteString(fragment)
		}
		if errors.Is(readErr, io.EOF) {
			if data.Len() != 0 {
				if flushErr := flush(); flushErr != nil {
					return modelgateway.NormalizedResponse{}, flushErr
				}
			}
			break
		}
		if readErr != nil {
			if errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded) {
				return modelgateway.NormalizedResponse{}, readErr
			}
			if contextErr := requestCtx.Err(); contextErr != nil {
				return modelgateway.NormalizedResponse{}, contextErr
			}
			return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(errors.New("anthropic stream read failed"))
		}
	}
	if providerID == "" || text.Len() == 0 || stopReason == "" || !inputUsageFound || !outputUsageFound || inputTokens < 0 || outputTokens < 0 {
		return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputSchema)
	}
	content := json.RawMessage(text.String())
	if !json.Valid(content) {
		content, err = json.Marshal(text.String())
		if err != nil {
			return modelgateway.NormalizedResponse{}, anthropicUnknownFailure(modelgateway.ErrOutputSchema)
		}
	}
	if modelVersion == "" {
		modelVersion = capabilities.ActualModelVersion
	}
	usage := modelgateway.Usage{InputTokens: inputTokens, OutputTokens: outputTokens, ProviderRequestID: providerID, ModelVersion: modelVersion}
	return modelgateway.NormalizedResponse{RequestID: request.RequestID, ProviderRequestID: providerID, ModelVersion: modelVersion, Content: content, FinishReason: stopReason, Usage: usage}, nil
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
		if value.InputTokens < 0 || value.OutputTokens < 0 || value.CostMicros < 0 {
			return modelgateway.Usage{}, modelgateway.ErrInvalidRequest
		}
		return value, nil
	default:
		encoded, err := json.Marshal(value)
		if err != nil || json.Unmarshal(encoded, &usage) != nil {
			return modelgateway.Usage{}, modelgateway.ErrInvalidRequest
		}
	}
	if usage.InputTokens < 0 || usage.OutputTokens < 0 {
		return modelgateway.Usage{}, modelgateway.ErrInvalidRequest
	}
	return modelgateway.Usage{InputTokens: usage.InputTokens, OutputTokens: usage.OutputTokens}, nil
}

func (adapter *anthropicAdapter) validateRequest(ctx context.Context, request modelgateway.NormalizedRequest, requireID bool) (modelgateway.ModelCapabilities, error) {
	capabilities, err := adapter.Capabilities(ctx, request.Model)
	if err != nil {
		return modelgateway.ModelCapabilities{}, err
	}
	if requireID && request.RequestID == "" || len(request.Messages) == 0 || len(request.Messages) > modelgateway.MaximumMessages || len(request.Tools) > modelgateway.MaximumTools || request.MaxOutputTokens <= 0 || request.MaxOutputTokens > capabilities.MaxOutputTokens || request.Temperature < 0 || request.Temperature > 1 || request.TopP < 0 || request.TopP > 1 || request.TopK < 0 || request.TopK > modelgateway.MaximumTopK || !validAnthropicEffort(request.ReasoningEffort) || request.Seed != nil {
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
