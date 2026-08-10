package openaicompatible

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/akimisaka/aor/internal/modelgateway"
)

const (
	maximumResponsesContinuationEntries = 128
	maximumResponsesContinuationBytes   = 8 << 20
)

func (a *Adapter) encodeResponsesRequest(request modelgateway.NormalizedRequest, stream bool) ([]byte, error) {
	if request.TopK != 0 {
		return nil, modelgateway.ErrProviderNotAllowed
	}
	value := responsesRequest{
		Model: request.Model, MaxOutputTokens: request.MaxOutputTokens,
		Store: false, Stream: stream,
	}
	if request.ReasoningEffort == "" || request.ReasoningEffort == "none" || !a.supportsReasoningEffort {
		temperature := request.Temperature
		value.Temperature = &temperature
		if request.TopP > 0 {
			topP := request.TopP
			value.TopP = &topP
		}
	}
	if a.supportsReasoningEffort && request.ReasoningEffort != "" {
		value.Reasoning = &responsesReasoning{Effort: request.ReasoningEffort}
	}
	for _, message := range request.Messages {
		switch message.Role {
		case "system", "user":
			value.Input = append(value.Input, responsesInputItem{Role: message.Role, Content: message.Content})
		case "assistant":
			if message.Content != "" {
				value.Input = append(value.Input, responsesInputItem{Role: message.Role, Content: message.Content})
				continue
			}
			if output, found := a.responsesContinuation(request, message.ToolCalls); found {
				for _, item := range output {
					value.Input = append(value.Input, responsesInputItem{raw: item})
				}
				continue
			}
			for _, call := range message.ToolCalls {
				value.Input = append(value.Input, responsesInputItem{
					Type: "function_call", CallID: call.ID, Name: call.Name, Arguments: string(call.Arguments),
				})
			}
		case "tool":
			value.Input = append(value.Input, responsesInputItem{
				Type: "function_call_output", CallID: message.ToolCallID, Output: message.Content,
			})
		default:
			return nil, modelgateway.ErrInvalidRequest
		}
	}
	for _, tool := range request.Tools {
		parameters := tool.Schema
		if len(parameters) == 0 {
			parameters = json.RawMessage(`{}`)
		}
		value.Tools = append(value.Tools, responsesTool{
			Type: "function", Name: tool.Name, Description: tool.Description, Parameters: parameters,
		})
	}
	if len(request.ResponseSchema) != 0 && !stream {
		providerSchema, err := compatibleResponseSchema(request.ResponseSchema)
		if err != nil {
			return nil, err
		}
		value.Text = &responsesText{Format: responsesTextFormat{
			Type: "json_schema", Name: "aor_response", Schema: providerSchema, Strict: true,
		}}
	}
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)) > a.maxRequestBytes {
		return nil, modelgateway.ErrInvalidRequest
	}
	return encoded, nil
}

func (a *Adapter) decodeResponsesResponse(request modelgateway.NormalizedRequest, capabilities modelgateway.ModelCapabilities, payload []byte) (modelgateway.NormalizedResponse, error) {
	if !utf8.Valid(payload) {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
	}
	if a.containsCredential(string(payload)) {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrCredentialDetected)
	}
	var response responsesResponse
	if json.Unmarshal(payload, &response) != nil || response.Usage == nil || !usageFieldsPresent(payload, "input_tokens", "output_tokens") || len(response.Output) > modelgateway.MaximumMessages {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
	}
	if !validResponsesIdentifier(response.ID) || !validResponsesField(response.Model, modelgateway.MaximumToolCallIDBytes, true) || response.Status != "completed" && response.Status != "incomplete" {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
	}

	var text strings.Builder
	toolCalls := make([]modelgateway.ToolCall, 0)
	for _, item := range response.Output {
		switch item.Type {
		case "reasoning":
			continue
		case "message":
			if item.Role != "assistant" && item.Role != "" {
				return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
			}
			for _, part := range item.Content {
				switch part.Type {
				case "output_text":
					text.WriteString(part.Text)
				case "refusal":
					if part.Refusal != "" {
						text.WriteString(part.Refusal)
					} else {
						text.WriteString(part.Text)
					}
				default:
					return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
				}
			}
		case "function_call":
			callID := item.CallID
			if callID == "" {
				callID = item.ID
			}
			toolCalls = append(toolCalls, modelgateway.ToolCall{
				ID: callID, Name: item.Name, Arguments: json.RawMessage(item.Arguments),
			})
		default:
			return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
		}
	}
	if text.Len() == 0 && response.OutputText != "" {
		text.WriteString(response.OutputText)
	}
	if text.Len() == 0 && len(toolCalls) == 0 || len(toolCalls) > modelgateway.MaximumToolCalls {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
	}
	if text.Len() > modelgateway.MaximumResponseBytes {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputTooLarge)
	}
	if !utf8.ValidString(text.String()) {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
	}
	if text.Len() != 0 && len(toolCalls) != 0 {
		if !json.Valid([]byte(text.String())) {
			text.Reset()
		} else {
			return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
		}
	}

	allowed := make(map[string]struct{}, len(request.Tools))
	for _, tool := range request.Tools {
		allowed[tool.Name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(toolCalls))
	outputBytes := 0
	for _, call := range toolCalls {
		callBytes := len(call.ID) + len(call.Name) + len(call.Arguments)
		if callBytes > modelgateway.MaximumResponseBytes-outputBytes || call.Validate() != nil {
			return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
		}
		outputBytes += callBytes
		if _, found := allowed[call.Name]; !found {
			return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
		}
		if _, found := seen[call.ID]; found {
			return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
		}
		seen[call.ID] = struct{}{}
	}
	var content json.RawMessage
	if text.Len() != 0 {
		if json.Valid([]byte(text.String())) {
			content = append(json.RawMessage(nil), text.String()...)
		} else {
			encoded, err := json.Marshal(text.String())
			if err != nil || len(encoded) > modelgateway.MaximumResponseBytes {
				return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputTooLarge)
			}
			content = encoded
		}
	}
	usage, err := a.NormalizeUsage(*response.Usage)
	if err != nil {
		return modelgateway.NormalizedResponse{}, unknownFailure(err)
	}
	usage.ProviderRequestID = response.ID
	usage.ModelVersion = response.Model
	modelVersion := response.Model
	if modelVersion == "" {
		modelVersion = capabilities.ActualModelVersion
		usage.ModelVersion = modelVersion
	}
	if len(toolCalls) != 0 {
		a.rememberResponsesContinuation(request, response.Output, toolCalls)
	}
	finishReason := "stop"
	if len(toolCalls) != 0 {
		finishReason = "tool_calls"
	} else if response.IncompleteDetails != nil && validResponsesField(response.IncompleteDetails.Reason, 128, false) {
		finishReason = response.IncompleteDetails.Reason
	} else if response.Status == "incomplete" {
		finishReason = "incomplete"
	}
	return modelgateway.NormalizedResponse{
		RequestID: request.RequestID, ProviderRequestID: response.ID, ModelVersion: modelVersion,
		Content: content, ToolCalls: toolCalls, FinishReason: finishReason, Usage: usage,
	}, nil
}

func validResponsesIdentifier(value string) bool {
	return validResponsesField(value, modelgateway.MaximumToolCallIDBytes, false)
}

func validResponsesField(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	return strings.TrimSpace(value) != "" && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsAny(value, "\r\n\x00")
}

func (a *Adapter) rememberResponsesContinuation(request modelgateway.NormalizedRequest, output []responsesOutputItem, calls []modelgateway.ToolCall) {
	if len(calls) == 0 {
		return
	}
	continuation := responsesContinuation{CallIDs: make([]string, len(calls)), Output: make([]json.RawMessage, len(output))}
	for index, call := range calls {
		continuation.CallIDs[index] = call.ID
	}
	for index, item := range output {
		continuation.Output[index] = append(json.RawMessage(nil), item.raw...)
		continuation.Size += len(item.raw)
	}
	key := responsesContinuationKey(request, calls[0].ID)
	a.mu.Lock()
	defer a.mu.Unlock()
	if previous, found := a.responsesContinuations[key]; found {
		a.responsesContinuationBytes -= previous.Size
	} else {
		a.responsesContinuationOrder = append(a.responsesContinuationOrder, key)
	}
	a.responsesContinuations[key] = continuation
	a.responsesContinuationBytes += continuation.Size
	for len(a.responsesContinuationOrder) > maximumResponsesContinuationEntries || a.responsesContinuationBytes > maximumResponsesContinuationBytes {
		key := a.responsesContinuationOrder[0]
		a.responsesContinuationOrder = a.responsesContinuationOrder[1:]
		a.responsesContinuationBytes -= a.responsesContinuations[key].Size
		delete(a.responsesContinuations, key)
	}
}

func (a *Adapter) responsesContinuation(request modelgateway.NormalizedRequest, calls []modelgateway.ToolCall) ([]json.RawMessage, bool) {
	if len(calls) == 0 {
		return nil, false
	}
	a.mu.Lock()
	continuation, found := a.responsesContinuations[responsesContinuationKey(request, calls[0].ID)]
	a.mu.Unlock()
	if !found || len(continuation.CallIDs) != len(calls) {
		return nil, false
	}
	for index, call := range calls {
		if continuation.CallIDs[index] != call.ID {
			return nil, false
		}
	}
	result := make([]json.RawMessage, len(continuation.Output))
	for index, item := range continuation.Output {
		result[index] = append(json.RawMessage(nil), item...)
	}
	return result, true
}

func responsesContinuationKey(request modelgateway.NormalizedRequest, callID string) string {
	return request.TenantID + "\x00" + request.ProjectID + "\x00" + request.TaskID + "\x00" + request.AgentInstanceID + "\x00" + request.Role + "\x00" + request.Model + "\x00" + callID
}

type responsesRequest struct {
	Model           string               `json:"model"`
	Input           []responsesInputItem `json:"input"`
	Tools           []responsesTool      `json:"tools,omitempty"`
	Text            *responsesText       `json:"text,omitempty"`
	Reasoning       *responsesReasoning  `json:"reasoning,omitempty"`
	MaxOutputTokens int                  `json:"max_output_tokens"`
	Temperature     *float64             `json:"temperature,omitempty"`
	TopP            *float64             `json:"top_p,omitempty"`
	Store           bool                 `json:"store"`
	Stream          bool                 `json:"stream,omitempty"`
}

type responsesInputItem struct {
	raw              json.RawMessage
	Type             string `json:"type,omitempty"`
	ID               string `json:"id,omitempty"`
	Role             string `json:"role,omitempty"`
	Content          string `json:"content,omitempty"`
	CallID           string `json:"call_id,omitempty"`
	Name             string `json:"name,omitempty"`
	Arguments        string `json:"arguments,omitempty"`
	Output           string `json:"output,omitempty"`
	EncryptedContent string `json:"encrypted_content,omitempty"`
}

func (item responsesInputItem) MarshalJSON() ([]byte, error) {
	if len(item.raw) != 0 {
		return append([]byte(nil), item.raw...), nil
	}
	type wire responsesInputItem
	return json.Marshal(wire(item))
}

type responsesTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters"`
}

type responsesText struct {
	Format responsesTextFormat `json:"format"`
}

type responsesTextFormat struct {
	Type   string          `json:"type"`
	Name   string          `json:"name"`
	Schema json.RawMessage `json:"schema"`
	Strict bool            `json:"strict"`
}

type responsesReasoning struct {
	Effort string `json:"effort"`
}

type responsesResponse struct {
	ID                string                `json:"id"`
	Model             string                `json:"model"`
	Status            string                `json:"status"`
	Output            []responsesOutputItem `json:"output"`
	OutputText        string                `json:"output_text,omitempty"`
	Usage             *responsesUsage       `json:"usage"`
	IncompleteDetails *struct {
		Reason string `json:"reason"`
	} `json:"incomplete_details"`
}

type responsesOutputItem struct {
	raw       json.RawMessage
	Type      string `json:"type"`
	ID        string `json:"id,omitempty"`
	Role      string `json:"role,omitempty"`
	CallID    string `json:"call_id,omitempty"`
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
	Content   []struct {
		Type    string `json:"type"`
		Text    string `json:"text,omitempty"`
		Refusal string `json:"refusal,omitempty"`
	} `json:"content,omitempty"`
}

func (item *responsesOutputItem) UnmarshalJSON(encoded []byte) error {
	type wire responsesOutputItem
	var decoded wire
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return err
	}
	*item = responsesOutputItem(decoded)
	item.raw = append(json.RawMessage(nil), encoded...)
	return nil
}

type responsesContinuation struct {
	CallIDs []string
	Output  []json.RawMessage
	Size    int
}

type responsesUsage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	TotalTokens  int64 `json:"total_tokens"`
}
