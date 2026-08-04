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

// Inbox records a completed message result at the database transaction
// boundary. It provides at-least-once handler invocation: a handler that
// performs an external side effect and crashes before completion can run again.
// External effects therefore need their own stable idempotency key.
type Inbox interface {
	Process(context.Context, string, string, string, string, func(context.Context) ([]byte, error)) (InboxResult, error)
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
	if err := validateInboxInput(ctx, tenantID, consumerID, messageID, requestSHA256, handler); err != nil {
		return InboxResult{}, err
	}
	key := tenantID + "\x00" + consumerID + "\x00" + messageID
	i.mu.Lock()
	if existing := i.records[key]; existing != nil {
		if existing.requestSHA256 != requestSHA256 {
			i.mu.Unlock()
			return InboxResult{}, aorerrors.New(aorerrors.CodeIdempotencyConflict, "", nil)
		}
		select {
		case <-existing.done:
			if existing.err != nil {
				retry := &inboxRecord{requestSHA256: requestSHA256, done: make(chan struct{})}
				i.records[key] = retry
				i.mu.Unlock()
				return i.process(ctx, key, retry, handler)
			}
			i.mu.Unlock()
			return InboxResult{Result: cloneJSON(existing.result), Duplicate: true}, nil
		default:
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
	}
	record := &inboxRecord{requestSHA256: requestSHA256, done: make(chan struct{})}
	i.records[key] = record
	i.mu.Unlock()
	return i.process(ctx, key, record, handler)
}

func (i *MemoryInbox) process(ctx context.Context, key string, record *inboxRecord, handler func(context.Context) ([]byte, error)) (InboxResult, error) {
	result, err := handler(ctx)
	if err == nil {
		err = validateInboxResult(result)
	}
	i.mu.Lock()
	if err != nil {
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

func validateInboxInput(ctx context.Context, tenantID, consumerID, messageID, requestSHA256 string, handler func(context.Context) ([]byte, error)) error {
	if ctx == nil || tenantID == "" || consumerID == "" || messageID == "" || requestSHA256 == "" || handler == nil {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "inbox"})
	}
	return ctx.Err()
}

func validateInboxResult(result []byte) error {
	if !json.Valid(result) {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "inbox result"})
	}
	return nil
}

var _ Inbox = (*MemoryInbox)(nil)
