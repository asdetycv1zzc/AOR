package workflow

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

// MemoryActivityResultStore is useful for local development and deterministic
// tests. A production Worker should use PostgresActivityResultStore.
type MemoryActivityResultStore struct {
	mu      sync.RWMutex
	results map[string]memoryActivityResult
}

type memoryActivityResult struct {
	requestSHA256 string
	output        json.RawMessage
}

func NewMemoryActivityResultStore() *MemoryActivityResultStore {
	return &MemoryActivityResultStore{results: make(map[string]memoryActivityResult)}
}

func (store *MemoryActivityResultStore) Load(ctx context.Context, tenantID, key, requestSHA256 string) (json.RawMessage, bool, error) {
	if store == nil {
		return nil, false, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := activityStoreContext(ctx, tenantID, key, requestSHA256); err != nil {
		return nil, false, err
	}
	store.mu.RLock()
	result, found := store.results[tenantID+"\x00"+key]
	store.mu.RUnlock()
	if !found {
		return nil, false, nil
	}
	if result.requestSHA256 != requestSHA256 {
		return nil, false, aorerrors.New(aorerrors.CodeIdempotencyConflict, "", nil)
	}
	return append(json.RawMessage(nil), result.output...), true, nil
}

func (store *MemoryActivityResultStore) Save(ctx context.Context, tenantID, key, requestSHA256 string, output json.RawMessage) error {
	if store == nil {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := activityStoreContext(ctx, tenantID, key, requestSHA256); err != nil {
		return err
	}
	if !json.Valid(output) || len(output) > MaximumActivityResultBytes {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "activity result"})
	}
	outputDigest, err := canonicaljson.Digest(output)
	if err != nil {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "activity result"})
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	mapKey := tenantID + "\x00" + key
	if previous, found := store.results[mapKey]; found {
		previousDigest, digestErr := canonicaljson.Digest(previous.output)
		if previous.requestSHA256 != requestSHA256 || digestErr != nil || previousDigest != outputDigest {
			return aorerrors.New(aorerrors.CodeIdempotencyConflict, "", nil)
		}
		return nil
	}
	store.results[mapKey] = memoryActivityResult{requestSHA256: requestSHA256, output: append(json.RawMessage(nil), output...)}
	return nil
}

var _ ActivityResultStore = (*MemoryActivityResultStore)(nil)

func activityStoreContext(ctx context.Context, tenantID, key, requestSHA256 string) error {
	if ctx == nil {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenantID == "" || key == "" || requestSHA256 == "" {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "activity result"})
	}
	return nil
}
