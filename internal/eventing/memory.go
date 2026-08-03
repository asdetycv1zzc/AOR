package eventing

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type FailurePoint int

const (
	FailureNone FailurePoint = iota
	FailureBeforeCommit
	FailureAfterCommit
)

type StoreStats struct {
	Projections    int
	Events         int
	Outbox         int
	CommandResults int
	Approvals      int
}

type commandRecord struct {
	RequestSHA256 string
	Result        TransactionResult
}

type MemoryStore struct {
	mu          sync.Mutex
	projections map[string]Projection
	events      map[string]DomainEvent
	versions    map[string]string
	outbox      map[string]OutboxRecord
	commands    map[string]commandRecord
	approvals   map[string]ApprovalRecord
	failure     FailurePoint
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		projections: make(map[string]Projection), events: make(map[string]DomainEvent), versions: make(map[string]string), outbox: make(map[string]OutboxRecord), commands: make(map[string]commandRecord), approvals: make(map[string]ApprovalRecord),
	}
}

func (s *MemoryStore) Load(_ context.Context, tenantID, aggregateType, aggregateID string) (Projection, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	projection, found := s.projections[aggregateKey(tenantID, aggregateType, aggregateID)]
	return cloneProjection(projection), found, nil
}

func (s *MemoryStore) Lookup(_ context.Context, tenantID, principalID, idempotencyKey, requestSHA256 string) (TransactionResult, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lookupLocked(tenantID, principalID, idempotencyKey, requestSHA256)
}

func (s *MemoryStore) Execute(_ context.Context, request TransactionRequest) (TransactionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if result, found, err := s.lookupLocked(request.TenantID, request.PrincipalID, request.IdempotencyKey, request.RequestSHA256); found || err != nil {
		return result, err
	}
	if err := validateTransaction(request); err != nil {
		return TransactionResult{}, err
	}
	for _, update := range request.Updates {
		current := s.projections[aggregateKey(request.TenantID, update.AggregateType, update.AggregateID)]
		if current.Version != update.ExpectedVersion {
			return TransactionResult{}, aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"expectedVersion": update.ExpectedVersion, "actualVersion": current.Version})
		}
	}
	for _, event := range request.Events {
		if _, exists := s.events[event.EventID]; exists {
			return TransactionResult{}, aorerrors.New(aorerrors.CodeConflict, event.CorrelationID, map[string]any{"scope": "eventId"})
		}
		if _, exists := s.versions[versionKey(request.TenantID, event.AggregateType, event.AggregateID, event.AggregateVersion)]; exists {
			return TransactionResult{}, aorerrors.New(aorerrors.CodeStateVersionConflict, event.CorrelationID, nil)
		}
	}
	for _, approval := range request.Approvals {
		if _, exists := s.approvals[approval.ID]; exists {
			return TransactionResult{}, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "approvalId"})
		}
	}
	if s.consumeFailure(FailureBeforeCommit) {
		return TransactionResult{}, ErrInjectedFailure
	}
	for _, update := range request.Updates {
		s.projections[aggregateKey(request.TenantID, update.AggregateType, update.AggregateID)] = Projection{
			TenantID: update.TenantID, ProjectID: update.ProjectID, AggregateType: update.AggregateType, AggregateID: update.AggregateID, Version: update.NextVersion, State: cloneJSON(update.State),
		}
	}
	events := make([]DomainEvent, len(request.Events))
	for index, event := range request.Events {
		event = cloneEvent(event)
		s.events[event.EventID] = event
		s.versions[versionKey(request.TenantID, event.AggregateType, event.AggregateID, event.AggregateVersion)] = event.EventID
		outboxID := "outbox_" + event.EventID
		s.outbox[outboxID] = OutboxRecord{ID: outboxID, Event: event, NextAttempt: event.OccurredAt}
		events[index] = event
	}
	for _, approval := range request.Approvals {
		s.approvals[approval.ID] = cloneApproval(approval)
	}
	result := TransactionResult{Result: cloneJSON(request.Result), Events: events}
	s.commands[commandKey(request.TenantID, request.PrincipalID, request.IdempotencyKey)] = commandRecord{RequestSHA256: request.RequestSHA256, Result: result}
	if s.consumeFailure(FailureAfterCommit) {
		return TransactionResult{}, ErrCommitResultUnknown
	}
	return cloneResult(result), nil
}

func (s *MemoryStore) FailNext(point FailurePoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failure = point
}

func (s *MemoryStore) Stats() StoreStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return StoreStats{Projections: len(s.projections), Events: len(s.events), Outbox: len(s.outbox), CommandResults: len(s.commands), Approvals: len(s.approvals)}
}

func (s *MemoryStore) ListEvents(ctx context.Context, tenantID string) ([]DomainEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenantID == "" {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "event log tenant"})
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	events := make([]DomainEvent, 0, len(s.events))
	for _, event := range s.events {
		if event.TenantID == tenantID {
			events = append(events, cloneEvent(event))
		}
	}
	sort.Slice(events, func(left, right int) bool {
		if events[left].AggregateType != events[right].AggregateType {
			return events[left].AggregateType < events[right].AggregateType
		}
		if events[left].AggregateID != events[right].AggregateID {
			return events[left].AggregateID < events[right].AggregateID
		}
		if events[left].AggregateVersion != events[right].AggregateVersion {
			return events[left].AggregateVersion < events[right].AggregateVersion
		}
		return events[left].EventID < events[right].EventID
	})
	return events, nil
}

func (s *MemoryStore) ClaimOutbox(ctx context.Context, tenantID string, now time.Time, limit int, lease time.Duration) ([]OutboxClaim, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenantID == "" || now.IsZero() || limit <= 0 || lease <= 0 {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "outbox claim"})
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	ready := make([]OutboxRecord, 0, len(s.outbox))
	for _, record := range s.outbox {
		if record.Event.TenantID == tenantID && record.PublishedAt == nil && !record.NextAttempt.After(now) {
			ready = append(ready, cloneOutboxRecord(record))
		}
	}
	sort.Slice(ready, func(left, right int) bool {
		if ready[left].NextAttempt.Equal(ready[right].NextAttempt) {
			return ready[left].ID < ready[right].ID
		}
		return ready[left].NextAttempt.Before(ready[right].NextAttempt)
	})
	if len(ready) > limit {
		ready = ready[:limit]
	}
	claims := make([]OutboxClaim, len(ready))
	for index, record := range ready {
		record.Attempts++
		record.NextAttempt = now.Add(lease)
		s.outbox[record.ID] = cloneOutboxRecord(record)
		claims[index] = OutboxClaim{Record: cloneOutboxRecord(record), Attempt: record.Attempts}
	}
	return claims, nil
}

func (s *MemoryStore) MarkOutboxPublished(ctx context.Context, tenantID, outboxID string, attempt int, publishedAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenantID == "" || outboxID == "" || attempt <= 0 || publishedAt.IsZero() {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "outbox publish"})
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, found := s.outbox[outboxID]
	if !found || record.Event.TenantID != tenantID || record.PublishedAt != nil || record.Attempts != attempt {
		return ErrOutboxClaimLost
	}
	published := publishedAt
	record.PublishedAt = &published
	s.outbox[outboxID] = cloneOutboxRecord(record)
	return nil
}

func (s *MemoryStore) RetryOutbox(ctx context.Context, tenantID, outboxID string, attempt int, nextAttempt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenantID == "" || outboxID == "" || attempt <= 0 || nextAttempt.IsZero() {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "outbox retry"})
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, found := s.outbox[outboxID]
	if !found || record.Event.TenantID != tenantID || record.PublishedAt != nil || record.Attempts != attempt {
		return ErrOutboxClaimLost
	}
	record.NextAttempt = nextAttempt
	s.outbox[outboxID] = cloneOutboxRecord(record)
	return nil
}

func (s *MemoryStore) lookupLocked(tenantID, principalID, idempotencyKey, requestSHA256 string) (TransactionResult, bool, error) {
	record, found := s.commands[commandKey(tenantID, principalID, idempotencyKey)]
	if !found {
		return TransactionResult{}, false, nil
	}
	if record.RequestSHA256 != requestSHA256 {
		return TransactionResult{}, false, aorerrors.New(aorerrors.CodeIdempotencyConflict, "", nil)
	}
	result := cloneResult(record.Result)
	result.Duplicate = true
	return result, true, nil
}

func (s *MemoryStore) consumeFailure(point FailurePoint) bool {
	if s.failure != point {
		return false
	}
	s.failure = FailureNone
	return true
}

func validateTransaction(request TransactionRequest) error {
	if request.TenantID == "" || request.PrincipalID == "" || request.IdempotencyKey == "" || request.RequestSHA256 == "" || request.ResultSHA256 == "" || len(request.Updates) == 0 || len(request.Events) == 0 {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "transaction"})
	}
	updates := make(map[string]ProjectionUpdate, len(request.Updates))
	for _, update := range request.Updates {
		key := aggregateKey(request.TenantID, update.AggregateType, update.AggregateID)
		if update.TenantID != request.TenantID || update.ProjectID == "" || update.AggregateType == "" || update.AggregateID == "" || update.ExpectedVersion < 0 || update.NextVersion != update.ExpectedVersion+1 || len(update.State) == 0 {
			return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "projection update"})
		}
		if _, duplicate := updates[key]; duplicate {
			return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "duplicate aggregate update"})
		}
		updates[key] = update
	}
	seenEvents := make(map[string]bool, len(request.Events))
	for _, event := range request.Events {
		update, found := updates[aggregateKey(request.TenantID, event.AggregateType, event.AggregateID)]
		if !found || event.EventID == "" || seenEvents[event.EventID] || event.TenantID != update.TenantID || event.ProjectID != update.ProjectID || event.AggregateVersion != update.NextVersion || event.Type == "" || event.PayloadSHA256 == "" || event.OccurredAt.IsZero() || !json.Valid(event.Payload) {
			return aorerrors.New(aorerrors.CodeInvalidArgument, event.CorrelationID, map[string]any{"scope": "domain event"})
		}
		seenEvents[event.EventID] = true
	}
	if !json.Valid(request.Result) {
		return fmt.Errorf("transaction result is not JSON")
	}
	resultDigest, err := canonicaljson.Digest(request.Result)
	if err != nil || resultDigest != request.ResultSHA256 {
		return aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "transaction result"})
	}
	for _, event := range request.Events {
		digest, digestErr := canonicaljson.Digest(event.Payload)
		if digestErr != nil || digest != event.PayloadSHA256 {
			return aorerrors.New(aorerrors.CodeArtifactHashMismatch, event.CorrelationID, map[string]any{"scope": "event payload"})
		}
	}
	seenApprovals := make(map[string]bool, len(request.Approvals))
	for _, approval := range request.Approvals {
		if approval.ID == "" || seenApprovals[approval.ID] || approval.TenantID != request.TenantID || approval.ProjectID == "" || approval.ApprovalType == "" || approval.SubjectType == "" || approval.SubjectID == "" || approval.SubjectVersion < 1 || approval.SubjectSHA256 == "" || approval.PrincipalID == "" || approval.Reason == "" || approval.IssuedAt.IsZero() || approval.Signature == "" {
			return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "approval record"})
		}
		if approval.ExpiresAt != nil && !approval.ExpiresAt.After(approval.IssuedAt) {
			return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "approval expiry"})
		}
		if approval.RevokedAt != nil {
			return aorerrors.New(aorerrors.CodeApprovalRequired, "", map[string]any{"scope": "revoked approval"})
		}
		seenApprovals[approval.ID] = true
	}
	return nil
}

func commandKey(tenantID, principalID, key string) string {
	return tenantID + "\x00" + principalID + "\x00" + key
}

func aggregateKey(tenantID, aggregateType, aggregateID string) string {
	return tenantID + "\x00" + aggregateType + "\x00" + aggregateID
}

func versionKey(tenantID, aggregateType, aggregateID string, version int64) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%d", tenantID, aggregateType, aggregateID, version)
}

func cloneProjection(value Projection) Projection {
	value.State = cloneJSON(value.State)
	return value
}

func cloneEvent(value DomainEvent) DomainEvent {
	value.Payload = cloneJSON(value.Payload)
	return value
}

func cloneApproval(value ApprovalRecord) ApprovalRecord {
	if value.ExpiresAt != nil {
		expiresAt := *value.ExpiresAt
		value.ExpiresAt = &expiresAt
	}
	if value.RevokedAt != nil {
		revokedAt := *value.RevokedAt
		value.RevokedAt = &revokedAt
	}
	return value
}

func cloneOutboxRecord(value OutboxRecord) OutboxRecord {
	value.Event = cloneEvent(value.Event)
	if value.PublishedAt != nil {
		publishedAt := *value.PublishedAt
		value.PublishedAt = &publishedAt
	}
	return value
}

func cloneResult(value TransactionResult) TransactionResult {
	value.Result = cloneJSON(value.Result)
	value.Events = append([]DomainEvent(nil), value.Events...)
	for index := range value.Events {
		value.Events[index] = cloneEvent(value.Events[index])
	}
	return value
}

func cloneJSON(value json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), value...)
}

var _ OutboxStore = (*MemoryStore)(nil)
var _ EventLog = (*MemoryStore)(nil)
