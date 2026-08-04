package eventing

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func TestInboxRunsConcurrentDuplicateHandlerOnce(t *testing.T) {
	inbox := NewMemoryInbox()
	var calls atomic.Int64
	handler := func(context.Context) ([]byte, error) {
		calls.Add(1)
		return []byte(`{"status":"processed"}`), nil
	}
	var wait sync.WaitGroup
	errorsFound := make(chan error, 100)
	for index := 0; index < 100; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := inbox.Process(context.Background(), "tenant_1", "projection", "message_1", digestZero(), handler)
			if err != nil || string(result.Result) != `{"status":"processed"}` {
				errorsFound <- err
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatalf("duplicate processing failed: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("handler calls = %d", calls.Load())
	}
}

func TestInboxRejectsMessageIDWithDifferentDigest(t *testing.T) {
	inbox := NewMemoryInbox()
	if _, err := inbox.Process(context.Background(), "tenant_1", "projection", "message_1", digestZero(), func(context.Context) ([]byte, error) { return []byte(`{}`), nil }); err != nil {
		t.Fatal(err)
	}
	_, err := inbox.Process(context.Background(), "tenant_1", "projection", "message_1", digestOne(), func(context.Context) ([]byte, error) { return []byte(`{}`), nil })
	var typed *aorerrors.Error
	if !errors.As(err, &typed) || typed.Code != aorerrors.CodeIdempotencyConflict {
		t.Fatalf("message conflict = %#v", err)
	}
}

func TestInboxRetainsFailedMessageDigestForRetry(t *testing.T) {
	inbox := NewMemoryInbox()
	first := errors.New("handler result unknown")
	var calls atomic.Int64
	handler := func(context.Context) ([]byte, error) {
		if calls.Add(1) == 1 {
			return nil, first
		}
		return []byte(`{"status":"recovered"}`), nil
	}
	if _, err := inbox.Process(context.Background(), "tenant_1", "projection", "message_1", digestZero(), handler); !errors.Is(err, first) {
		t.Fatalf("first handler error = %v", err)
	}
	_, err := inbox.Process(context.Background(), "tenant_1", "projection", "message_1", digestOne(), handler)
	var typed *aorerrors.Error
	if !errors.As(err, &typed) || typed.Code != aorerrors.CodeIdempotencyConflict {
		t.Fatalf("changed failed message = %#v", err)
	}
	result, err := inbox.Process(context.Background(), "tenant_1", "projection", "message_1", digestZero(), handler)
	if err != nil || result.Duplicate || string(result.Result) != `{"status":"recovered"}` {
		t.Fatalf("recovered result = %#v error = %v", result, err)
	}
	duplicate, err := inbox.Process(context.Background(), "tenant_1", "projection", "message_1", digestZero(), handler)
	if err != nil || !duplicate.Duplicate || calls.Load() != 2 {
		t.Fatalf("duplicate result = %#v calls = %d error = %v", duplicate, calls.Load(), err)
	}
}
