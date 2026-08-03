package eventing

import (
	"context"
	"encoding/json"
	"sync"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type InboxResult struct {
	Result    json.RawMessage
	Duplicate bool
}

type inboxRecord struct {
	requestSHA256 string
	done          chan struct{}
	result        json.RawMessage
	err           error
}

type MemoryInbox struct {
	mu      sync.Mutex
	records map[string]*inboxRecord
}

func NewMemoryInbox() *MemoryInbox {
	return &MemoryInbox{records: make(map[string]*inboxRecord)}
}

func (i *MemoryInbox) Process(ctx context.Context, tenantID, consumerID, messageID, requestSHA256 string, handler func(context.Context) ([]byte, error)) (InboxResult, error) {
	if tenantID == "" || consumerID == "" || messageID == "" || requestSHA256 == "" || handler == nil {
		return InboxResult{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "inbox"})
	}
	key := tenantID + "\x00" + consumerID + "\x00" + messageID
	i.mu.Lock()
	if existing := i.records[key]; existing != nil {
		if existing.requestSHA256 != requestSHA256 {
			i.mu.Unlock()
			return InboxResult{}, aorerrors.New(aorerrors.CodeIdempotencyConflict, "", nil)
		}
		done := existing.done
		i.mu.Unlock()
		select {
		case <-ctx.Done():
			return InboxResult{}, ctx.Err()
		case <-done:
			if existing.err != nil {
				return InboxResult{}, existing.err
			}
			return InboxResult{Result: cloneJSON(existing.result), Duplicate: true}, nil
		}
	}
	record := &inboxRecord{requestSHA256: requestSHA256, done: make(chan struct{})}
	i.records[key] = record
	i.mu.Unlock()

	result, err := handler(ctx)
	if err == nil && !json.Valid(result) {
		err = aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "inbox result"})
	}
	i.mu.Lock()
	if err != nil {
		delete(i.records, key)
		record.err = err
	} else {
		record.result = cloneJSON(result)
	}
	close(record.done)
	i.mu.Unlock()
	if err != nil {
		return InboxResult{}, err
	}
	return InboxResult{Result: cloneJSON(result)}, nil
}
