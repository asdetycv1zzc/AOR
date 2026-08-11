package openaicompatible

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/akimisaka/aor/internal/modelgateway"
)

// responsesResponseStream emits normalized text deltas while retaining the
// terminal Responses object for final validation and budget settlement.
type responsesResponseStream struct {
	*responseStream
	request      modelgateway.NormalizedRequest
	capabilities modelgateway.ModelCapabilities
	deltaBytes   int
	summaryBytes int
	summaryItem  string
	summaryIndex int
	summarySet   bool
}

type responsesStreamError struct {
	Code string `json:"code"`
}

var _ modelgateway.ResponseStream = (*responsesResponseStream)(nil)
var _ modelgateway.UsageAwareStream = (*responsesResponseStream)(nil)
var _ modelgateway.FinalContentAwareStream = (*responsesResponseStream)(nil)

func (a *Adapter) newResponsesResponseStream(
	ctx context.Context,
	request modelgateway.NormalizedRequest,
	capabilities modelgateway.ModelCapabilities,
	response *http.Response,
	cancel context.CancelFunc,
) modelgateway.ResponseStream {
	jsonMode := !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream")
	maxEventBytes := a.maxStreamEventBytes
	if jsonMode {
		maxEventBytes = a.maxResponseBytes
	}
	requestContext := ctx
	if response.Request != nil {
		requestContext = response.Request.Context()
	}
	stream := &responsesResponseStream{
		responseStream: &responseStream{
			adapter: a, body: response.Body, cancel: cancel, maxEventBytes: maxEventBytes,
			events: make(chan json.RawMessage, 1), failures: make(chan error, 1),
			done: make(chan struct{}), closed: make(chan struct{}), activityContext: ctx,
			callerContext: ctx, requestContext: requestContext, jsonMode: jsonMode,
		},
		request: request, capabilities: capabilities,
	}
	go stream.readResponses()
	return stream
}

func (s *responsesResponseStream) readResponses() {
	defer close(s.done)
	defer func() { _ = s.Close() }()
	defer s.unregister()
	if s.jsonMode {
		s.readResponsesJSON()
		return
	}

	reader := bufio.NewReaderSize(s.body, 4096)
	eventName := ""
	data := make([]byte, 0, 256)
	flush := func() (bool, error) {
		if len(data) == 0 {
			eventName = ""
			return false, nil
		}
		payload := append(json.RawMessage(nil), data...)
		data = data[:0]
		name := eventName
		eventName = ""
		delta, terminal, err := s.observeResponsesEvent(name, payload)
		if err != nil {
			return false, err
		}
		if len(delta) != 0 {
			select {
			case s.events <- delta:
			case <-s.closed:
				return false, context.Canceled
			}
		}
		return terminal, nil
	}

	for {
		line, readErr := readStreamLine(reader, s.maxEventBytes)
		if errors.Is(readErr, modelgateway.ErrOutputTooLarge) {
			s.fail(unknownFailure(modelgateway.ErrOutputTooLarge))
			return
		}
		line = trimLine(line)
		if len(line) == 0 {
			terminal, err := flush()
			if err != nil {
				s.fail(responsesStreamFailure(err))
				return
			}
			if terminal {
				return
			}
		} else if value, found := strings.CutPrefix(string(line), "event:"); found {
			eventName = strings.TrimSpace(value)
		} else if value, found := strings.CutPrefix(string(line), "data:"); found {
			fragment := strings.TrimSpace(value)
			if fragment == "[DONE]" {
				s.fail(unknownFailure(modelgateway.ErrOutputSchema))
				return
			}
			separatorLength := 0
			if len(data) != 0 {
				separatorLength = 1
			}
			if int64(len(data)+separatorLength+len(fragment)) > s.maxEventBytes {
				s.fail(unknownFailure(modelgateway.ErrOutputTooLarge))
				return
			}
			if separatorLength != 0 {
				data = append(data, '\n')
			}
			data = append(data, fragment...)
		}

		if errors.Is(readErr, io.EOF) {
			if len(data) != 0 {
				terminal, err := flush()
				if err != nil {
					s.fail(responsesStreamFailure(err))
					return
				}
				if terminal {
					return
				}
			}
			if contextErr := adapterRequestContextError(s.callerContext, s.requestContext); contextErr != nil {
				s.fail(contextErr)
				return
			}
			s.fail(unknownFailure(modelgateway.ErrOutputSchema))
			return
		}
		if readErr != nil {
			if contextErr := adapterRequestContextError(s.callerContext, s.requestContext); contextErr != nil {
				s.fail(contextErr)
			} else {
				s.fail(unknownFailure(errors.New("responses stream read failed")))
			}
			return
		}
	}
}

func (s *responsesResponseStream) readResponsesJSON() {
	payload, err := io.ReadAll(io.LimitReader(s.body, s.maxEventBytes+1))
	if err != nil {
		if contextErr := adapterRequestContextError(s.callerContext, s.requestContext); contextErr != nil {
			s.fail(contextErr)
		} else {
			s.fail(unknownFailure(errors.New("responses body read failed")))
		}
		return
	}
	if int64(len(payload)) > s.maxEventBytes {
		s.fail(unknownFailure(modelgateway.ErrOutputTooLarge))
		return
	}
	if err := s.completeResponsesResponse(payload); err != nil {
		s.fail(responsesStreamFailure(err))
		return
	}
	s.stateMu.RLock()
	content := append([]byte(nil), s.content...)
	s.stateMu.RUnlock()
	modelgateway.ReportActivityDelta(s.activityContext, string(content))
	delta, _ := json.Marshal(struct {
		Delta string `json:"delta"`
	}{Delta: string(content)})
	select {
	case s.events <- delta:
	case <-s.closed:
	}
}

func (s *responsesResponseStream) observeResponsesEvent(eventName string, payload json.RawMessage) (json.RawMessage, bool, error) {
	if !json.Valid(payload) || !utf8.Valid(payload) {
		return nil, false, modelgateway.ErrOutputSchema
	}
	if s.adapter.containsCredential(string(payload)) {
		return nil, false, modelgateway.ErrCredentialDetected
	}
	var event struct {
		Type         string                `json:"type"`
		ID           string                `json:"id"`
		Model        string                `json:"model"`
		Delta        string                `json:"delta"`
		ItemID       string                `json:"item_id"`
		SummaryIndex *int                  `json:"summary_index"`
		Error        *responsesStreamError `json:"error"`
		Response     json.RawMessage       `json:"response"`
	}
	if json.Unmarshal(payload, &event) != nil {
		return nil, false, modelgateway.ErrOutputSchema
	}
	if event.Type != "" {
		eventName = event.Type
	}
	if eventName == "" {
		return nil, false, modelgateway.ErrOutputSchema
	}
	if err := s.observeResponsesMetadata(event.ID, event.Model, event.Response); err != nil {
		return nil, false, err
	}

	switch eventName {
	case "response.reasoning_summary_text.delta":
		if event.Delta == "" {
			return nil, false, nil
		}
		delta := event.Delta
		if s.summarySet && event.ItemID != "" && event.SummaryIndex != nil && (event.ItemID != s.summaryItem || *event.SummaryIndex != s.summaryIndex) {
			delta = "\n\n" + delta
		}
		if event.ItemID != "" && event.SummaryIndex != nil {
			s.summaryItem = event.ItemID
			s.summaryIndex = *event.SummaryIndex
			s.summarySet = true
		}
		if !utf8.ValidString(delta) || len(delta) > modelgateway.MaximumResponseBytes-s.summaryBytes {
			return nil, false, modelgateway.ErrOutputTooLarge
		}
		s.summaryBytes += len(delta)
		modelgateway.ReportActivityReasoningSummary(s.activityContext, delta)
		return nil, false, nil
	case "response.output_text.delta":
		if event.Delta == "" {
			return nil, false, nil
		}
		if !utf8.ValidString(event.Delta) || len(event.Delta) > modelgateway.MaximumResponseBytes-s.deltaBytes {
			return nil, false, modelgateway.ErrOutputTooLarge
		}
		s.deltaBytes += len(event.Delta)
		modelgateway.ReportActivityDelta(s.activityContext, event.Delta)
		delta, _ := json.Marshal(struct {
			Delta string `json:"delta"`
		}{Delta: event.Delta})
		return delta, false, nil
	case "response.completed", "response.incomplete":
		terminalResponse := event.Response
		if len(terminalResponse) == 0 {
			terminalResponse = payload
		}
		if err := s.completeResponsesResponse(terminalResponse); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	case "response.failed", "error":
		return nil, false, responsesEventFailure(eventName, event.Error, event.Response)
	}
	return nil, false, nil
}

func responsesEventFailure(eventName string, direct *responsesStreamError, response json.RawMessage) error {
	providerError := direct
	if providerError == nil && len(response) != 0 {
		var value struct {
			Error *responsesStreamError `json:"error"`
		}
		if json.Unmarshal(response, &value) != nil {
			return unknownFailure(modelgateway.ErrOutputSchema)
		}
		providerError = value.Error
	}
	code := "provider_error"
	if providerError != nil && providerError.Code != "" {
		code = strings.TrimSpace(providerError.Code)
	}
	if code == "" || len(code) > 128 || !utf8.ValidString(code) || strings.ContainsAny(code, "\r\n\x00") {
		return unknownFailure(modelgateway.ErrOutputSchema)
	}
	return &modelgateway.ProviderFailure{
		Cause:     fmt.Errorf("responses provider returned %s (%s)", eventName, code),
		Retryable: responsesErrorRetryable(code), OutcomeKnown: true,
	}
}

func responsesErrorRetryable(code string) bool {
	code = strings.ToLower(code)
	for _, marker := range []string{"server", "rate_limit", "timeout", "overload", "unavailable", "upstream", "temporar"} {
		if strings.Contains(code, marker) {
			return true
		}
	}
	return false
}

func (s *responsesResponseStream) observeResponsesMetadata(id, model string, rawResponse json.RawMessage) error {
	if len(rawResponse) != 0 {
		var response struct {
			ID    string `json:"id"`
			Model string `json:"model"`
		}
		if json.Unmarshal(rawResponse, &response) != nil {
			return modelgateway.ErrOutputSchema
		}
		if response.ID != "" {
			id = response.ID
		}
		if response.Model != "" {
			model = response.Model
		}
	}
	if id != "" && !validResponsesIdentifier(id) || !validResponsesField(model, modelgateway.MaximumToolCallIDBytes, true) {
		return modelgateway.ErrOutputSchema
	}
	if s.adapter.containsCredential(id) || s.adapter.containsCredential(model) {
		return modelgateway.ErrCredentialDetected
	}
	if id == "" && model == "" {
		return nil
	}

	s.adapter.mu.Lock()
	s.stateMu.Lock()
	previousID := s.providerID
	if id != "" {
		s.providerID = id
	}
	if model != "" {
		s.modelVersion = model
	}
	s.stateMu.Unlock()
	if id != "" && previousID != "" && previousID != id && s.adapter.active[previousID] == s.responseStream {
		delete(s.adapter.active, previousID)
	}
	if id != "" {
		s.adapter.active[id] = s.responseStream
	}
	s.adapter.mu.Unlock()
	return nil
}

func (s *responsesResponseStream) completeResponsesResponse(payload json.RawMessage) error {
	response, err := s.adapter.decodeResponsesResponse(s.request, s.capabilities, payload)
	if err != nil {
		return err
	}
	if err := s.observeResponsesMetadata(response.ProviderRequestID, response.ModelVersion, nil); err != nil {
		return err
	}
	s.stateMu.Lock()
	s.content = append(s.content[:0], response.Content...)
	s.usage = response.Usage
	s.usageFound = true
	s.finishReason = response.FinishReason
	s.complete = true
	s.stateMu.Unlock()
	return nil
}

func responsesStreamFailure(err error) error {
	var failure *modelgateway.ProviderFailure
	if errors.As(err, &failure) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return unknownFailure(err)
}
