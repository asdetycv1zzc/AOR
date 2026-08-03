package eventing

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

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
		s.outbox[event.EventID] = OutboxRecord{ID: "outbox_" + event.EventID, Event: event, NextAttempt: event.OccurredAt}
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
