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
	Traceparent      string          `json:"traceparent,omitempty"`
	Tracestate       string          `json:"tracestate,omitempty"`
	TaskID           string          `json:"taskId,omitempty"`
	TaskIDReason     string          `json:"taskIdReason,omitempty"`
	AgentRunID       string          `json:"agentRunId,omitempty"`
	AgentRunReason   string          `json:"agentRunReason,omitempty"`
	// ReplayState is the authoritative projection state committed with this
	// event. It is internal transport metadata and is never accepted from an
	// external event payload.
	ReplayState       json.RawMessage `json:"-"`
	ReplayStateSHA256 string          `json:"-"`
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

type UserDecisionRecord struct {
	ID              string
	TenantID        string
	ProjectID       string
	ModuleTaskID    string
	AttemptSeriesID string
	Decision        string
	ReportSHA256    string
	PrincipalID     string
	ApprovalID      string
	CreatedAt       time.Time
}

type TransactionRequest struct {
	TenantID       string
	PrincipalID    string
	IdempotencyKey string
	RequestSHA256  string
	Updates        []ProjectionUpdate
	Events         []DomainEvent
	Approvals      []ApprovalRecord
	UserDecisions  []UserDecisionRecord
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

// ProjectionList exposes tenant- and project-scoped aggregate queries without
// allowing API callers to construct database predicates directly.
type ProjectionList interface {
	ListProjections(ctx context.Context, tenantID, projectID, aggregateType string) ([]Projection, error)
}

// ProjectionCatalog exposes the complete tenant projection inventory used by
// offline reconciliation. It is intentionally separate from Store so runtime
// command paths do not gain broad enumeration authority by accident.
type ProjectionCatalog interface {
	ListTenantProjections(ctx context.Context, tenantID string) ([]Projection, error)
}

// ReconciliationSnapshot binds the immutable event history and online
// projection catalogue to one storage snapshot. Production reconciliation
// must use this surface so concurrent commands cannot create a torn read.
type ReconciliationSnapshot struct {
	Events      []DomainEvent
	Projections []Projection
}

type ReconciliationSource interface {
	LoadReconciliationSnapshot(ctx context.Context, tenantID string) (ReconciliationSnapshot, error)
}
