package agentruntime

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"unicode/utf8"

	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/toolbroker"
)

const terminalSubmissionTool = "repository.submission.commit"

// RunToolLoop executes a bounded native tool conversation. Each model and tool
// boundary retains the lease and slot checks enforced by Generate and InvokeTool.
func (r *Runtime) RunToolLoop(ctx context.Context, runID string, call ModelCall, maxToolRounds int) (modelgateway.NormalizedResponse, error) {
	if maxToolRounds < 0 || maxToolRounds > MaximumNativeToolRounds || validateModelCall(call) != nil {
		return modelgateway.NormalizedResponse{}, modelgateway.ErrInvalidRequest
	}
	lastCall := toolLoopModelCall(call, maxToolRounds)
	finalCall := toolLoopFinalModelCall(call)
	if validateModelCall(lastCall) != nil || validateModelCall(finalCall) != nil {
		return modelgateway.NormalizedResponse{}, modelgateway.ErrInvalidRequest
	}
	messages, allowed, err := r.toolLoopContext(runID)
	if err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	seenCallIDs := make(map[string]struct{})
	for round := 0; ; round++ {
		response, usedMessages, err := r.generateWithInterventions(ctx, runID, toolLoopModelCall(call, round), messages, false, true)
		if err != nil {
			if errors.Is(err, modelgateway.ErrOutputSchema) {
				return r.finalizeToolLoop(ctx, runID, finalCall, messages)
			}
			return modelgateway.NormalizedResponse{}, err
		}
		messages = usedMessages
		if len(response.ToolCalls) == 0 {
			if len(response.Content) == 0 || len(response.Content) > modelgateway.MaximumResponseBytes || !json.Valid(response.Content) {
				return r.finalizeToolLoop(ctx, runID, finalCall, messages)
			}
			if err := r.validateToolLoopOutput(runID, response.Content); err != nil {
				return r.finalizeToolLoop(ctx, runID, finalCall, messages)
			}
			response.RequestID = call.RequestID
			return response, nil
		}
		if err := validateNativeToolCalls(response, allowed, seenCallIDs); err != nil {
			return modelgateway.NormalizedResponse{}, err
		}
		if round >= maxToolRounds {
			return modelgateway.NormalizedResponse{}, ErrToolRoundsExhausted
		}
		messages = append(messages, modelgateway.Message{Role: "assistant", ToolCalls: cloneToolCalls(response.ToolCalls)})
		for _, nativeCall := range response.ToolCalls {
			result, err := r.InvokeTool(ctx, runID, ToolCall{
				RequestID:  nativeCall.ID,
				ToolID:     nativeCall.Name,
				Version:    allowed[nativeCall.Name],
				Parameters: append(json.RawMessage(nil), nativeCall.Arguments...),
			})
			if err != nil {
				return modelgateway.NormalizedResponse{}, err
			}
			content, err := nativeToolResultContent(result)
			if err != nil {
				return modelgateway.NormalizedResponse{}, err
			}
			if nativeCall.Name == terminalSubmissionTool {
				manifest, err := submissionManifestFromToolResult(content)
				if err != nil {
					return modelgateway.NormalizedResponse{}, err
				}
				if err := r.validateToolLoopOutput(runID, manifest); err != nil {
					return modelgateway.NormalizedResponse{}, err
				}
				response.Content = manifest
				response.ToolCalls = nil
				response.FinishReason = "tool_result"
				response.RequestID = call.RequestID
				return response, nil
			}
			messages = append(messages, modelgateway.Message{Role: "tool", ToolCallID: nativeCall.ID, Content: content})
		}
	}
}

func (r *Runtime) finalizeToolLoop(ctx context.Context, runID string, call ModelCall, messages []modelgateway.Message) (modelgateway.NormalizedResponse, error) {
	response, _, err := r.generateWithInterventions(ctx, runID, call, messages, true, false)
	if err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	if len(response.ToolCalls) != 0 || len(response.Content) == 0 {
		return modelgateway.NormalizedResponse{}, modelgateway.ErrOutputSchema
	}
	if err := r.validateToolLoopOutput(runID, response.Content); err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	response.RequestID = call.RequestID
	return response, nil
}

func (r *Runtime) validateToolLoopOutput(runID string, content json.RawMessage) error {
	r.mu.RLock()
	run := r.runs[runID]
	if run == nil {
		r.mu.RUnlock()
		return ErrRunNotFound
	}
	schema := append(json.RawMessage(nil), run.declaration.ResponseSchema...)
	validator := run.declaration.ResponseSemanticValidator
	r.mu.RUnlock()
	return validateAgentOutput(schema, validator, AgentOutput{Payload: append(json.RawMessage(nil), content...)})
}

func (r *Runtime) toolLoopContext(runID string) ([]modelgateway.Message, map[string]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	run := r.runs[runID]
	if run == nil {
		return nil, nil, ErrRunNotFound
	}
	if run.state != StateRunning || run.busy {
		return nil, nil, ErrRunBusy
	}
	allowed := make(map[string]string, len(run.declaration.Tools))
	for _, tool := range run.declaration.Tools {
		allowed[tool.Name] = tool.Version
	}
	return cloneMessages(run.prompt.Messages), allowed, nil
}

func toolLoopModelCall(call ModelCall, round int) ModelCall {
	if round == 0 {
		return call
	}
	suffix := "." + strconv.Itoa(round+1)
	call.RequestID += suffix
	call.ReservationID += suffix
	return call
}

func toolLoopFinalModelCall(call ModelCall) ModelCall {
	call.RequestID += ".final"
	call.ReservationID += ".final"
	return call
}

func validateNativeToolCalls(response modelgateway.NormalizedResponse, allowed map[string]string, seen map[string]struct{}) error {
	if len(response.Content) != 0 || len(response.ToolCalls) > modelgateway.MaximumToolCalls {
		return modelgateway.ErrOutputSchema
	}
	for _, call := range response.ToolCalls {
		if call.Validate() != nil {
			return modelgateway.ErrOutputSchema
		}
		if _, found := allowed[call.Name]; !found {
			return toolbroker.ErrUnknownTool
		}
		if _, found := seen[call.ID]; found {
			return modelgateway.ErrOutputSchema
		}
		seen[call.ID] = struct{}{}
	}
	return nil
}

func nativeToolResultContent(result toolbroker.ToolResult) (string, error) {
	if len(result.Output) == 0 || len(result.Output) > modelgateway.MaximumToolResultBytes || !utf8.Valid(result.Output) || !json.Valid(result.Output) {
		return "", ErrToolResultInvalid
	}
	return string(result.Output), nil
}

func submissionManifestFromToolResult(content string) (json.RawMessage, error) {
	var result struct {
		StructuredContent struct {
			Manifest json.RawMessage `json:"manifest"`
		} `json:"structuredContent"`
		IsError bool `json:"isError,omitempty"`
	}
	if json.Unmarshal([]byte(content), &result) != nil || result.IsError || len(result.StructuredContent.Manifest) == 0 || !json.Valid(result.StructuredContent.Manifest) {
		return nil, ErrToolResultInvalid
	}
	return append(json.RawMessage(nil), result.StructuredContent.Manifest...), nil
}

func cloneToolCalls(values []modelgateway.ToolCall) []modelgateway.ToolCall {
	result := append([]modelgateway.ToolCall(nil), values...)
	for index := range result {
		result[index].Arguments = append(json.RawMessage(nil), result[index].Arguments...)
	}
	return result
}
