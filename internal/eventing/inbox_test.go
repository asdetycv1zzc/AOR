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
