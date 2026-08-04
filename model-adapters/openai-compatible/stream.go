package openaicompatible

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"

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
}

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
					return
				}
				if !json.Valid(data) || s.adapter.containsCredential(string(data)) {
					s.fail(modelgateway.ErrOutputSchema)
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
				return
			}
			s.fail(modelgateway.ErrOutputSchema)
			return
		}
	}
}

func (s *responseStream) fail(err error) {
	select {
	case s.failures <- err:
	default:
	}
}

func (s *responseStream) registerProviderID(data []byte) {
	var event struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(data, &event) != nil || event.ID == "" || s.adapter.containsCredential(event.ID) {
		return
	}
	s.adapter.mu.Lock()
	s.providerID = event.ID
	s.adapter.active[event.ID] = s
	s.adapter.mu.Unlock()
}

func (s *responseStream) unregister() {
	s.adapter.mu.Lock()
	if s.providerID != "" && s.adapter.active[s.providerID] == s {
		delete(s.adapter.active, s.providerID)
	}
	s.adapter.mu.Unlock()
}

func trimLine(value []byte) []byte {
	line := strings.TrimSuffix(string(value), "\n")
	line = strings.TrimSuffix(line, "\r")
	return []byte(line)
}
