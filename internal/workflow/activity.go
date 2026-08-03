package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/akimisaka/aor/internal/idempotency"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

// ActivityIdentity is the immutable identity assigned when a workflow schedules
// an activity. Retries must reuse it; attempt numbers are deliberately absent.
type ActivityIdentity struct {
	TenantID   string
	WorkflowID string
	ActivityID string
}

// Effect executes a side effect. Implementations must pass idempotencyKey to
// their external dependency so a retry after an unknown result is deduplicated.
type Effect interface {
	Execute(context.Context, string, json.RawMessage) (json.RawMessage, error)
}

type ActivityResult struct {
	Output         json.RawMessage
	IdempotencyKey string
	Duplicate      bool
}

type activityRecord struct {
	requestSHA256 string
	done          chan struct{}
	result        ActivityResult
	err           error
}

// ActivityExecutor coordinates local retries and hands every invocation of the
// same scheduled activity the exact same external idempotency key.
type ActivityExecutor struct {
	effect  Effect
	mu      sync.Mutex
	records map[string]*activityRecord
}

func NewActivityExecutor(effect Effect) *ActivityExecutor {
	return &ActivityExecutor{effect: effect, records: make(map[string]*activityRecord)}
}

func (e *ActivityExecutor) Execute(ctx context.Context, identity ActivityIdentity, input json.RawMessage) (ActivityResult, error) {
	if err := ctx.Err(); err != nil {
		return ActivityResult{}, err
	}
	if e == nil || e.effect == nil {
		return ActivityResult{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "workflow activity"})
	}
	key, requestDigest, err := activityKeys(identity, input)
	if err != nil {
		return ActivityResult{}, err
	}

	e.mu.Lock()
	if prior := e.records[key]; prior != nil {
		if prior.requestSHA256 != requestDigest {
			e.mu.Unlock()
			return ActivityResult{}, aorerrors.New(aorerrors.CodeIdempotencyConflict, "", nil)
		}
		select {
		case <-prior.done:
			if prior.err != nil {
				record := &activityRecord{requestSHA256: requestDigest, done: make(chan struct{})}
				e.records[key] = record
				e.mu.Unlock()
				return e.execute(ctx, key, record, input)
			}
			result := cloneActivityResult(prior.result)
			result.Duplicate = true
			e.mu.Unlock()
			return result, nil
		default:
			done := prior.done
			e.mu.Unlock()
			select {
			case <-ctx.Done():
				return ActivityResult{}, ctx.Err()
			case <-done:
				if prior.err != nil {
					return ActivityResult{}, prior.err
				}
				result := cloneActivityResult(prior.result)
				result.Duplicate = true
				return result, nil
			}
		}
	}
	record := &activityRecord{requestSHA256: requestDigest, done: make(chan struct{})}
	e.records[key] = record
	e.mu.Unlock()
	return e.execute(ctx, key, record, input)
}

func (e *ActivityExecutor) execute(ctx context.Context, key string, record *activityRecord, input json.RawMessage) (ActivityResult, error) {
	output, executeErr := e.effect.Execute(ctx, key, cloneActivityJSON(input))
	if executeErr == nil && !json.Valid(output) {
		executeErr = errors.New("workflow activity result is not JSON")
	}

	e.mu.Lock()
	if executeErr != nil {
		record.err = executeErr
	} else {
		record.result = ActivityResult{Output: cloneActivityJSON(output), IdempotencyKey: key}
	}
	close(record.done)
	e.mu.Unlock()
	if executeErr != nil {
		return ActivityResult{}, executeErr
	}
	return cloneActivityResult(record.result), nil
}

func activityKeys(identity ActivityIdentity, input json.RawMessage) (string, string, error) {
	if identity.TenantID == "" || identity.WorkflowID == "" || identity.ActivityID == "" || !json.Valid(input) {
		return "", "", aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "workflow activity"})
	}
	identityJSON, err := json.Marshal(identity)
	if err != nil {
		return "", "", err
	}
	identityDigest, err := idempotency.RequestDigest(identityJSON)
	if err != nil {
		return "", "", err
	}
	requestDigest, err := idempotency.RequestDigest(input)
	if err != nil {
		return "", "", err
	}
	return "aor-activity-" + identityDigest[len("sha256:"):], requestDigest, nil
}

func cloneActivityResult(result ActivityResult) ActivityResult {
	result.Output = cloneActivityJSON(result.Output)
	return result
}

func cloneActivityJSON(value json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), value...)
}
