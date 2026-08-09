package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/pkg/contracts"
)

var ErrProjectLifecycleSynchronization = errors.New("project lifecycle synchronization failed")

type projectLifecycleSignalClient interface {
	projectLifecycleClient
	SignalWorkflow(context.Context, string, string, string, interface{}) error
}

// ProjectLifecycleStore synchronizes committed project projections to their
// durable Temporal lifecycle. Database state remains authoritative. A failed
// synchronization is surfaced after commit, and the command's normal
// idempotent retry path retries synchronization from the stored result.
type ProjectLifecycleStore struct {
	store   eventing.Store
	starter *ProjectLifecycleStarter
	client  projectLifecycleSignalClient
}

func NewProjectLifecycleStore(store eventing.Store, client projectLifecycleSignalClient, taskQueue string) (*ProjectLifecycleStore, error) {
	if store == nil || client == nil {
		return nil, ErrInvalidProjectLifecycle
	}
	starter, err := NewProjectLifecycleStarter(client, taskQueue)
	if err != nil {
		return nil, err
	}
	return &ProjectLifecycleStore{store: store, starter: starter, client: client}, nil
}

func (store *ProjectLifecycleStore) Load(ctx context.Context, tenantID, aggregateType, aggregateID string) (eventing.Projection, bool, error) {
	return store.store.Load(ctx, tenantID, aggregateType, aggregateID)
}

func (store *ProjectLifecycleStore) Lookup(ctx context.Context, tenantID, principalID, idempotencyKey, requestSHA256 string) (eventing.TransactionResult, bool, error) {
	result, found, err := store.store.Lookup(ctx, tenantID, principalID, idempotencyKey, requestSHA256)
	if err != nil || !found {
		return result, found, err
	}
	if err := store.synchronize(ctx, result.Events); err != nil {
		return eventing.TransactionResult{}, false, err
	}
	return result, true, nil
}

func (store *ProjectLifecycleStore) Execute(ctx context.Context, request eventing.TransactionRequest) (eventing.TransactionResult, error) {
	result, err := store.store.Execute(ctx, request)
	if err != nil {
		return result, err
	}
	if err := store.synchronize(ctx, result.Events); err != nil {
		return eventing.TransactionResult{}, err
	}
	return result, nil
}

func (store *ProjectLifecycleStore) ListEvents(ctx context.Context, tenantID string) ([]eventing.DomainEvent, error) {
	eventLog, ok := store.store.(eventing.EventLog)
	if !ok {
		return nil, fmt.Errorf("%w: event log is unavailable", ErrProjectLifecycleSynchronization)
	}
	return eventLog.ListEvents(ctx, tenantID)
}

func (store *ProjectLifecycleStore) ListProjections(ctx context.Context, tenantID, projectID, aggregateType string) ([]eventing.Projection, error) {
	projections, ok := store.store.(eventing.ProjectionList)
	if !ok {
		return nil, fmt.Errorf("%w: projection list is unavailable", ErrProjectLifecycleSynchronization)
	}
	return projections.ListProjections(ctx, tenantID, projectID, aggregateType)
}

func (store *ProjectLifecycleStore) ListTenantProjections(ctx context.Context, tenantID string) ([]eventing.Projection, error) {
	catalog, ok := store.store.(eventing.ProjectionCatalog)
	if !ok {
		return nil, fmt.Errorf("%w: projection catalog is unavailable", ErrProjectLifecycleSynchronization)
	}
	return catalog.ListTenantProjections(ctx, tenantID)
}

func (store *ProjectLifecycleStore) synchronize(ctx context.Context, events []eventing.DomainEvent) error {
	if store == nil || store.store == nil || store.starter == nil || store.client == nil || ctx == nil {
		return ErrProjectLifecycleSynchronization
	}
	projectEvents := make([]eventing.DomainEvent, 0, len(events))
	for _, event := range events {
		if event.AggregateType == "project" {
			projectEvents = append(projectEvents, event)
		}
	}
	sort.Slice(projectEvents, func(left, right int) bool {
		if projectEvents[left].TenantID != projectEvents[right].TenantID {
			return projectEvents[left].TenantID < projectEvents[right].TenantID
		}
		if projectEvents[left].ProjectID != projectEvents[right].ProjectID {
			return projectEvents[left].ProjectID < projectEvents[right].ProjectID
		}
		return projectEvents[left].AggregateVersion < projectEvents[right].AggregateVersion
	})
	for _, event := range projectEvents {
		projection, err := lifecycleProjection(event)
		if err != nil {
			return err
		}
		input := ProjectLifecycleInput{
			TenantID: projection.TenantID, ProjectID: projection.ID, CreatedBy: projection.CreatedBy,
			GoalAgentCount: projection.GoalAgentCount, State: projection.State, ProjectVersion: projection.Version,
			PausedFrom: projection.PausedFromState, ProcessedEvents: projection.Version - 1,
		}
		started, err := store.starter.Ensure(ctx, input)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrProjectLifecycleSynchronization, err)
		}
		if !started.Duplicate || event.AggregateVersion == 1 {
			continue
		}
		signal := ProjectLifecycleEvent{
			EventID: event.EventID, Type: event.Type, AggregateVersion: event.AggregateVersion,
			State: projection.State, PayloadSHA256: event.PayloadSHA256, OccurredAt: event.OccurredAt,
		}
		if err := store.client.SignalWorkflow(ctx, started.WorkflowID, "", ProjectLifecycleSignalName, signal); err != nil {
			return fmt.Errorf("%w: signal project %s at version %d: %v", ErrProjectLifecycleSynchronization, event.ProjectID, event.AggregateVersion, err)
		}
	}
	return nil
}

type lifecycleProjectProjection struct {
	TenantID        string                 `json:"tenantId"`
	ID              string                 `json:"id"`
	CreatedBy       string                 `json:"createdBy"`
	GoalAgentCount  int                    `json:"goalAgentCount"`
	State           contracts.ProjectState `json:"state"`
	Version         int64                  `json:"version"`
	PausedFromState contracts.ProjectState `json:"pausedFromState,omitempty"`
}

func lifecycleProjection(event eventing.DomainEvent) (lifecycleProjectProjection, error) {
	if event.AggregateType != "project" || event.AggregateID != event.ProjectID || event.AggregateVersion < 1 {
		return lifecycleProjectProjection{}, ErrProjectLifecycleSynchronization
	}
	var payload struct {
		TenantID         string                     `json:"tenantId"`
		ProjectID        string                     `json:"projectId"`
		AggregateVersion int64                      `json:"aggregateVersion"`
		Projection       lifecycleProjectProjection `json:"projection"`
	}
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return lifecycleProjectProjection{}, fmt.Errorf("%w: decode project event: %v", ErrProjectLifecycleSynchronization, err)
	}
	projection := payload.Projection
	if payload.TenantID != event.TenantID || payload.ProjectID != event.ProjectID || payload.AggregateVersion != event.AggregateVersion ||
		projection.TenantID != event.TenantID || projection.ID != event.ProjectID || projection.Version != event.AggregateVersion {
		return lifecycleProjectProjection{}, ErrProjectLifecycleSynchronization
	}
	if err := validateProjectLifecycleInput(ProjectLifecycleInput{
		TenantID: projection.TenantID, ProjectID: projection.ID, CreatedBy: projection.CreatedBy,
		GoalAgentCount: projection.GoalAgentCount, State: projection.State, ProjectVersion: projection.Version,
		PausedFrom: projection.PausedFromState,
	}); err != nil {
		return lifecycleProjectProjection{}, fmt.Errorf("%w: %v", ErrProjectLifecycleSynchronization, err)
	}
	return projection, nil
}

var _ eventing.Store = (*ProjectLifecycleStore)(nil)
var _ eventing.EventLog = (*ProjectLifecycleStore)(nil)
var _ eventing.ProjectionList = (*ProjectLifecycleStore)(nil)
var _ eventing.ProjectionCatalog = (*ProjectLifecycleStore)(nil)
