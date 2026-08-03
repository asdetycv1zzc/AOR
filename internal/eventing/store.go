package eventing

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrInjectedFailure     = errors.New("injected transaction failure")
	ErrCommitResultUnknown = errors.New("transaction committed but result delivery is unknown")
)

type Projection struct {
	TenantID      string
	ProjectID     string
	AggregateType string
	AggregateID   string
	Version       int64
	State         json.RawMessage
}

type ProjectionUpdate struct {
	TenantID        string
	ProjectID       string
	AggregateType   string
	AggregateID     string
	ExpectedVersion int64
	NextVersion     int64
	State           json.RawMessage
}

type DomainEvent struct {
	EventID          string          `json:"eventId"`
	TenantID         string          `json:"tenantId"`
	ProjectID        string          `json:"projectId"`
	AggregateType    string          `json:"aggregateType"`
	AggregateID      string          `json:"aggregateId"`
	AggregateVersion int64           `json:"aggregateVersion"`
	Type             string          `json:"type"`
	Payload          json.RawMessage `json:"payload"`
	PayloadSHA256    string          `json:"payloadSha256"`
	OccurredAt       time.Time       `json:"occurredAt"`
	CorrelationID    string          `json:"correlationId"`
	CausationID      string          `json:"causationId,omitempty"`
}

type OutboxRecord struct {
	ID          string
	Event       DomainEvent
	PublishedAt *time.Time
	Attempts    int
	NextAttempt time.Time
}

type ApprovalRecord struct {
	ID             string
	TenantID       string
	ProjectID      string
	ApprovalType   string
	SubjectType    string
	SubjectID      string
	SubjectVersion int
	SubjectSHA256  string
	PrincipalID    string
	Reason         string
	IssuedAt       time.Time
	ExpiresAt      *time.Time
	RevokedAt      *time.Time
	Signature      string
}

type TransactionRequest struct {
	TenantID       string
	PrincipalID    string
	IdempotencyKey string
	RequestSHA256  string
	Updates        []ProjectionUpdate
	Events         []DomainEvent
	Approvals      []ApprovalRecord
	Result         json.RawMessage
	ResultSHA256   string
}

type TransactionResult struct {
	Result    json.RawMessage
	Events    []DomainEvent
	Duplicate bool
}

type Store interface {
	Load(ctx context.Context, tenantID, aggregateType, aggregateID string) (Projection, bool, error)
	Lookup(ctx context.Context, tenantID, principalID, idempotencyKey, requestSHA256 string) (TransactionResult, bool, error)
	Execute(ctx context.Context, request TransactionRequest) (TransactionResult, error)
}

// EventLog exposes the immutable event history needed to rebuild projections.
// Events are returned in deterministic aggregate/version order.
type EventLog interface {
	ListEvents(ctx context.Context, tenantID string) ([]DomainEvent, error)
}
