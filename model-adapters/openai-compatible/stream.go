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
	adapter       *Adapter
	body          io.ReadCloser
	cancel        context.CancelFunc
	maxEventBytes int64
	events        chan json.RawMessage
	failures      chan error
	done          chan struct{}
	closeOnce     sync.Once
	providerID    string
	stateMu       sync.RWMutex
	content       []byte
	usage         modelgateway.Usage
	usageFound    bool
	complete      bool
	failed        bool
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
		s.cancel()
		err = s.body.Close()
	})
	return err
}

func (s *responseStream) read() {
	defer close(s.done)
	defer func() { _ = s.Close() }()
	defer s.unregister()

	reader := bufio.NewReaderSize(s.body, int(s.maxEventBytes)+1)
	data := make([]byte, 0)
	for {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			s.fail(modelgateway.ErrOutputTooLarge)
			return
		}
		if err != nil && !errors.Is(err, io.EOF) {
			s.fail(unknownFailure(errors.New("openai-compatible stream read failed")))
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
				if err := s.observe(data); err != nil {
					s.fail(err)
					return
				}
				s.registerProviderID(data)
				select {
				case s.events <- append(json.RawMessage(nil), data...):
				case <-s.done:
					return
				}
				data = data[:0]
			}
		} else if bytes, found := strings.CutPrefix(string(line), "data:"); found {
			fragment := strings.TrimSpace(bytes)
			if int64(len(data)+len(fragment)) > s.maxEventBytes {
				s.fail(modelgateway.ErrOutputTooLarge)
				return
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

func (s *responseStream) fail(err error) {
	s.stateMu.Lock()
	s.failed = true
	s.stateMu.Unlock()
	select {
	case s.failures <- err:
	default:
	}
}

func (s *responseStream) observe(data []byte) error {
	var event streamEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return modelgateway.ErrOutputSchema
	}
	if len(event.Choices) == 0 && event.Usage == nil {
		return modelgateway.ErrOutputSchema
	}
	if s.adapter.containsCredential(event.ID) || s.adapter.containsCredential(event.Model) {
		return modelgateway.ErrCredentialDetected
	}
	for _, choice := range event.Choices {
		content := choice.Delta.Content
		if content == nil {
			content = choice.Message.Content
		}
		if content == nil {
			continue
		}
		if !utf8.ValidString(*content) || s.adapter.containsCredential(*content) {
			return modelgateway.ErrCredentialDetected
		}
		s.stateMu.Lock()
		s.content = append(s.content, []byte(*content)...)
		s.stateMu.Unlock()
	}
	if event.Usage != nil {
		usage, err := s.adapter.NormalizeUsage(*event.Usage)
		if err != nil {
			return err
		}
		s.stateMu.Lock()
		if event.ID != "" {
			usage.ProviderRequestID = event.ID
		} else if s.usage.ProviderRequestID != "" {
			usage.ProviderRequestID = s.usage.ProviderRequestID
		}
		if event.Model != "" {
			usage.ModelVersion = event.Model
		} else if s.usage.ModelVersion != "" {
			usage.ModelVersion = s.usage.ModelVersion
		}
		s.usage = usage
		s.usageFound = true
		s.stateMu.Unlock()
	}
	return nil
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
		ID string `json:"id"`
	}
	if json.Unmarshal(data, &event) != nil || event.ID == "" || s.adapter.containsCredential(event.ID) {
		return
	}
	s.adapter.mu.Lock()
	s.stateMu.Lock()
	s.providerID = event.ID
	s.stateMu.Unlock()
	s.adapter.active[event.ID] = s
	s.adapter.mu.Unlock()
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
