package openaicompatible

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/akimisaka/aor/internal/modelgateway"
)

type responseStream struct {
	adapter         *Adapter
	body            io.ReadCloser
	cancel          context.CancelFunc
	maxEventBytes   int64
	events          chan json.RawMessage
	failures        chan error
	done            chan struct{}
	closed          chan struct{}
	closeOnce       sync.Once
	providerID      string
	modelVersion    string
	stateMu         sync.RWMutex
	content         []byte
	usage           modelgateway.Usage
	usageFound      bool
	complete        bool
	failed          bool
	finishReason    string
	activityContext context.Context
	requestContext  context.Context
	jsonMode        bool
}

type streamEvent struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Delta struct {
			Content *string `json:"content"`
		} `json:"delta"`
		Message struct {
			Content *string `json:"content"`
		} `json:"message"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
	Usage *chatUsage `json:"usage"`
}

var _ modelgateway.UsageAwareStream = (*responseStream)(nil)
var _ modelgateway.FinalContentAwareStream = (*responseStream)(nil)

func (s *responseStream) Recv(ctx context.Context) (json.RawMessage, error) {
	if ctx == nil {
		return nil, modelgateway.ErrInvalidRequest
	}
	for {
		select {
		case event := <-s.events:
			if event != nil {
				return append(json.RawMessage(nil), event...), nil
			}
		default:
		}
		select {
		case event := <-s.events:
			if event != nil {
				return append(json.RawMessage(nil), event...), nil
			}
		case err := <-s.failures:
			if err != nil {
				return nil, err
			}
		case <-ctx.Done():
			_ = s.Close()
			return nil, ctx.Err()
		case <-s.done:
			select {
			case err := <-s.failures:
				if err != nil {
					return nil, err
				}
			default:
			}
			return nil, io.EOF
		}
	}
}

func (s *responseStream) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.closed)
		s.cancel()
		err = s.body.Close()
	})
	return err
}

func (s *responseStream) read() {
	defer close(s.done)
	defer func() { _ = s.Close() }()
	defer s.unregister()
	if s.jsonMode {
		s.readJSON()
		return
	}

	reader := bufio.NewReaderSize(s.body, 4096)
	data := make([]byte, 0)
	for {
		line, err := readStreamLine(reader, s.maxEventBytes)
		if errors.Is(err, modelgateway.ErrOutputTooLarge) {
			s.fail(modelgateway.ErrOutputTooLarge)
			return
		}
		if err != nil && !errors.Is(err, io.EOF) {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				s.fail(err)
			} else if contextErr := s.requestContext.Err(); contextErr != nil {
				s.fail(contextErr)
			} else {
				s.fail(unknownFailure(errors.New("openai-compatible stream read failed")))
			}
			return
		}
		line = trimLine(line)
		if len(line) == 0 {
			if len(data) != 0 {
				if string(data) == "[DONE]" {
					s.stateMu.Lock()
					s.complete = true
					s.stateMu.Unlock()
					return
				}
				if !json.Valid(data) {
					s.fail(modelgateway.ErrOutputSchema)
					return
				}
				if s.adapter.containsCredential(string(data)) {
					s.fail(modelgateway.ErrCredentialDetected)
					return
				}
				delta, err := s.observe(data)
				if err != nil {
					s.fail(err)
					return
				}
				s.registerProviderID(data)
				if len(delta) != 0 {
					select {
					case s.events <- delta:
					case <-s.closed:
						return
					}
				}
				data = data[:0]
			}
		} else if bytes, found := strings.CutPrefix(string(line), "data:"); found {
			fragment := strings.TrimSpace(bytes)
			separatorLength := 0
			if len(data) != 0 {
				separatorLength = 1
			}
			if int64(len(data)+separatorLength+len(fragment)) > s.maxEventBytes {
				s.fail(modelgateway.ErrOutputTooLarge)
				return
			}
			if separatorLength != 0 {
				data = append(data, '\n')
			}
			data = append(data, fragment...)
		}
		if errors.Is(err, io.EOF) {
			if len(data) == 0 {
				s.stateMu.Lock()
				s.complete = true
				s.stateMu.Unlock()
				return
			}
			s.fail(modelgateway.ErrOutputSchema)
			return
		}
	}
}

func (s *responseStream) readJSON() {
	data, err := io.ReadAll(io.LimitReader(s.body, s.maxEventBytes+1))
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			s.fail(err)
		} else if contextErr := s.requestContext.Err(); contextErr != nil {
			s.fail(contextErr)
		} else {
			s.fail(unknownFailure(errors.New("openai-compatible response read failed")))
		}
		return
	}
	if int64(len(data)) > s.maxEventBytes {
		s.fail(modelgateway.ErrOutputTooLarge)
		return
	}
	if !json.Valid(data) {
		s.fail(modelgateway.ErrOutputSchema)
		return
	}
	if s.adapter.containsCredential(string(data)) {
		s.fail(modelgateway.ErrCredentialDetected)
		return
	}
	delta, err := s.observe(data)
	if err != nil {
		s.fail(err)
		return
	}
	s.registerProviderID(data)
	if len(delta) != 0 {
		select {
		case s.events <- delta:
		case <-s.closed:
			return
		}
	}
	s.stateMu.Lock()
	s.complete = true
	s.stateMu.Unlock()
}

func (s *responseStream) fail(err error) {
	s.stateMu.Lock()
	s.failed = true
	s.stateMu.Unlock()
	select {
	case s.failures <- err:
	default:
	}
}

func (s *responseStream) observe(data []byte) (json.RawMessage, error) {
	var event streamEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, modelgateway.ErrOutputSchema
	}
	if len(event.Choices) == 0 && event.Usage == nil {
		return nil, modelgateway.ErrOutputSchema
	}
	if s.adapter.containsCredential(event.ID) || s.adapter.containsCredential(event.Model) {
		return nil, modelgateway.ErrCredentialDetected
	}
	var delta strings.Builder
	for _, choice := range event.Choices {
		content := choice.Delta.Content
		if content == nil {
			content = choice.Message.Content
		}
		if content == nil {
			if choice.FinishReason != nil {
				s.stateMu.Lock()
				s.finishReason = *choice.FinishReason
				s.stateMu.Unlock()
			}
			continue
		}
		if !utf8.ValidString(*content) || s.adapter.containsCredential(*content) {
			return nil, modelgateway.ErrCredentialDetected
		}
		s.stateMu.Lock()
		if int64(len(s.content)+len(*content)) > modelgateway.MaximumResponseBytes {
			s.stateMu.Unlock()
			return nil, modelgateway.ErrOutputTooLarge
		}
		s.content = append(s.content, []byte(*content)...)
		if choice.FinishReason != nil {
			s.finishReason = *choice.FinishReason
		}
		s.stateMu.Unlock()
		delta.WriteString(*content)
		modelgateway.ReportActivityDelta(s.activityContext, *content)
	}
	if event.Usage != nil {
		if !usageFieldsPresent(data, "prompt_tokens", "completion_tokens") {
			return nil, modelgateway.ErrOutputSchema
		}
		usage, err := s.adapter.NormalizeUsage(*event.Usage)
		if err != nil {
			return nil, err
		}
		s.stateMu.Lock()
		if event.ID != "" {
			usage.ProviderRequestID = event.ID
		} else if s.providerID != "" {
			usage.ProviderRequestID = s.providerID
		}
		if event.Model != "" {
			usage.ModelVersion = event.Model
		} else if s.modelVersion != "" {
			usage.ModelVersion = s.modelVersion
		}
		s.usage = usage
		s.usageFound = true
		s.stateMu.Unlock()
	}
	if delta.Len() == 0 {
		return nil, nil
	}
	value, _ := json.Marshal(struct {
		Delta string `json:"delta"`
	}{Delta: delta.String()})
	return value, nil
}

func (s *responseStream) FinalFinishReason() (string, bool) {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.finishReason, s.complete && !s.failed && s.finishReason != ""
}

func (s *responseStream) FinalUsage() (modelgateway.Usage, bool) {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if !s.complete || s.failed || !s.usageFound {
		return modelgateway.Usage{}, false
	}
	return s.usage, true
}

func (s *responseStream) FinalContent() (json.RawMessage, bool) {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if !s.complete || s.failed {
		return nil, false
	}
	return append(json.RawMessage(nil), s.content...), true
}

func (s *responseStream) registerProviderID(data []byte) {
	var event struct {
		ID    string `json:"id"`
		Model string `json:"model"`
	}
	if json.Unmarshal(data, &event) != nil || event.ID == "" || s.adapter.containsCredential(event.ID) {
		return
	}
	s.adapter.mu.Lock()
	s.stateMu.Lock()
	s.providerID = event.ID
	if event.Model != "" {
		s.modelVersion = event.Model
	}
	s.stateMu.Unlock()
	s.adapter.active[event.ID] = s
	s.adapter.mu.Unlock()
}

func usageFieldsPresent(event []byte, fields ...string) bool {
	var root map[string]json.RawMessage
	if json.Unmarshal(event, &root) != nil {
		return false
	}
	encoded, found := root["usage"]
	if !found || string(encoded) == "null" {
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

func readStreamLine(reader *bufio.Reader, maximum int64) ([]byte, error) {
	line := make([]byte, 0, 256)
	for {
		fragment, prefix, err := reader.ReadLine()
		if int64(len(fragment)) > maximum-int64(len(line)) {
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

func (s *responseStream) unregister() {
	s.adapter.mu.Lock()
	s.stateMu.RLock()
	providerID := s.providerID
	s.stateMu.RUnlock()
	if providerID != "" && s.adapter.active[providerID] == s {
		delete(s.adapter.active, providerID)
	}
	s.adapter.mu.Unlock()
}

func trimLine(value []byte) []byte {
	line := strings.TrimSuffix(string(value), "\n")
	line = strings.TrimSuffix(line, "\r")
	return []byte(line)
}
