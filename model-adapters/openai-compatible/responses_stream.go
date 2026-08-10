package openaicompatible

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/akimisaka/aor/internal/modelgateway"
)

func (a *Adapter) generateResponsesStream(ctx context.Context, request modelgateway.NormalizedRequest, capabilities modelgateway.ModelCapabilities) (modelgateway.NormalizedResponse, error) {
	body, err := a.encodeRequest(request, true)
	if err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	response, cancel, err := a.doWithAccept(ctx, body, "text/event-stream")
	if err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	defer cancel()
	defer response.Body.Close()
	if response.StatusCode < httpStatusOK || response.StatusCode >= httpStatusMultipleChoices {
		return modelgateway.NormalizedResponse{}, httpFailure(response.StatusCode)
	}
	requestContext := ctx
	if response.Request != nil {
		requestContext = response.Request.Context()
	}
	if !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, a.maxResponseBytes+1))
		if readErr != nil {
			if contextErr := requestContext.Err(); contextErr != nil {
				return modelgateway.NormalizedResponse{}, contextErr
			}
			return modelgateway.NormalizedResponse{}, unknownFailure(errors.New("responses body read failed"))
		}
		if int64(len(payload)) > a.maxResponseBytes {
			return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputTooLarge)
		}
		return a.decodeResponsesResponse(request, capabilities, payload)
	}
	reader := bufio.NewReaderSize(response.Body, 4096)
	var eventName string
	var data strings.Builder
	var completed json.RawMessage
	totalDeltaBytes := 0
	flush := func() error {
		if data.Len() == 0 {
			eventName = ""
			return nil
		}
		payload := []byte(data.String())
		if len(payload) > int(a.maxStreamEventBytes) || !json.Valid(payload) || a.containsCredential(string(payload)) {
			return unknownFailure(modelgateway.ErrOutputSchema)
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
		case "response.output_text.delta":
			var value struct {
				Delta string `json:"delta"`
			}
			if json.Unmarshal(payload, &value) != nil || value.Delta == "" {
				return modelgateway.ErrOutputSchema
			}
			if len(value.Delta) > modelgateway.MaximumResponseBytes-totalDeltaBytes {
				return modelgateway.ErrOutputTooLarge
			}
			totalDeltaBytes += len(value.Delta)
			modelgateway.ReportActivityDelta(ctx, value.Delta)
		case "response.function_call_arguments.delta":
			var value struct {
				Delta string `json:"delta"`
			}
			if json.Unmarshal(payload, &value) == nil && value.Delta != "" {
				if len(value.Delta) > modelgateway.MaximumResponseBytes-totalDeltaBytes {
					return modelgateway.ErrOutputTooLarge
				}
				totalDeltaBytes += len(value.Delta)
				modelgateway.ReportActivityDelta(ctx, value.Delta)
			}
		case "response.completed", "response.incomplete", "response.failed":
			var value struct {
				Response json.RawMessage `json:"response"`
			}
			if json.Unmarshal(payload, &value) != nil {
				return modelgateway.ErrOutputSchema
			}
			if len(value.Response) != 0 {
				completed = append(completed[:0], value.Response...)
			} else {
				completed = append(completed[:0], payload...)
			}
		case "error":
			return unknownFailure(errors.New("responses provider returned an error"))
		}
		data.Reset()
		eventName = ""
		return nil
	}
	for {
		lineBytes, readErr := readResponsesSSELine(reader, int(a.maxStreamEventBytes))
		if errors.Is(readErr, modelgateway.ErrOutputTooLarge) {
			return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputTooLarge)
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
			if data.Len()+separatorLength+len(fragment) > int(a.maxStreamEventBytes) {
				return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputTooLarge)
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
			if contextErr := requestContext.Err(); contextErr != nil {
				return modelgateway.NormalizedResponse{}, contextErr
			}
			return modelgateway.NormalizedResponse{}, unknownFailure(errors.New("responses stream read failed"))
		}
	}
	if len(completed) == 0 {
		return modelgateway.NormalizedResponse{}, unknownFailure(modelgateway.ErrOutputSchema)
	}
	return a.decodeResponsesResponse(request, capabilities, completed)
}

func readResponsesSSELine(reader *bufio.Reader, maximum int) ([]byte, error) {
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

const (
	httpStatusOK              = 200
	httpStatusMultipleChoices = 300
)
