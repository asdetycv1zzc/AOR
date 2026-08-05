package integration

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/google/uuid"
)

const integrationSummaryAggregate = "integration_summary"

type EventSummaryStore struct {
	store eventing.Store
	clock func() time.Time
}

func NewEventSummaryStore(store eventing.Store, clock func() time.Time) (*EventSummaryStore, error) {
	if store == nil {
		return nil, ErrWorkflowUnavailable
	}
	if clock == nil {
		clock = time.Now
	}
	return &EventSummaryStore{store: store, clock: clock}, nil
}

func (store *EventSummaryStore) Publish(ctx context.Context, summary PlanSupervisorSummary) error {
	if store == nil || store.store == nil || ctx == nil || ctx.Err() != nil || !validPlanSupervisorSummary(summary) {
		return ErrSummaryUnavailable
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	projection, found, err := store.store.Load(ctx, summary.TenantID, integrationSummaryAggregate, summary.IntegrationID)
	if err != nil {
		return err
	}
	if found {
		var prior PlanSupervisorSummary
		if projection.ProjectID != summary.ProjectID || json.Unmarshal(projection.State, &prior) != nil || !validPlanSupervisorSummary(prior) {
			return ErrSummaryUnavailable
		}
		if prior.SummarySHA256 == summary.SummarySHA256 {
			return nil
		}
	}
	expectedVersion := int64(0)
	if found {
		expectedVersion = projection.Version
	}
	payloadDigest, err := canonicaljson.Digest(encoded)
	if err != nil {
		return err
	}
	eventID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	occurredAt := store.clock().UTC()
	correlation := "corr_" + summary.SummarySHA256[len("sha256:"):len("sha256:")+32]
	event := eventing.DomainEvent{
		EventID: eventID.String(), TenantID: summary.TenantID, ProjectID: summary.ProjectID,
		AggregateType: integrationSummaryAggregate, AggregateID: summary.IntegrationID, AggregateVersion: expectedVersion + 1,
		Type: "io.aor.integration.summary-published.v1", Payload: encoded, PayloadSHA256: payloadDigest,
		OccurredAt: occurredAt, CorrelationID: correlation,
	}
	_, err = store.store.Execute(ctx, eventing.TransactionRequest{
		TenantID: summary.TenantID, PrincipalID: "service-integration",
		IdempotencyKey: "integration-summary:" + summary.IntegrationID + ":" + summary.SummarySHA256,
		RequestSHA256:  summary.SummarySHA256,
		Updates: []eventing.ProjectionUpdate{{
			TenantID: summary.TenantID, ProjectID: summary.ProjectID, AggregateType: integrationSummaryAggregate,
			AggregateID: summary.IntegrationID, ExpectedVersion: expectedVersion, NextVersion: expectedVersion + 1, State: encoded,
		}},
		Events: []eventing.DomainEvent{event}, Result: encoded, ResultSHA256: payloadDigest,
	})
	if err == nil {
		return nil
	}
	recovered, recoveredFound, loadErr := store.store.Load(ctx, summary.TenantID, integrationSummaryAggregate, summary.IntegrationID)
	if loadErr == nil && recoveredFound {
		var prior PlanSupervisorSummary
		if recovered.ProjectID == summary.ProjectID && json.Unmarshal(recovered.State, &prior) == nil && prior.SummarySHA256 == summary.SummarySHA256 {
			return nil
		}
	}
	return errors.Join(err, loadErr)
}

func validPlanSupervisorSummary(summary PlanSupervisorSummary) bool {
	if summary.SummaryVersion != 1 || summary.TenantID == "" || summary.ProjectID == "" || summary.IntegrationID == "" || !commitID(summary.BaseCommit) || len(summary.Modules) == 0 || !digestPattern(summary.SummarySHA256) || summary.CreatedAt.IsZero() {
		return false
	}
	digest, err := summaryDigest(summary)
	if err != nil || digest != summary.SummarySHA256 {
		return false
	}
	for _, evidence := range summary.EvidenceSHA256 {
		if !digestPattern(evidence) {
			return false
		}
	}
	switch summary.State {
	case SummaryReleaseCandidate:
		return commitID(summary.IntegrationCommit) && digestPattern(summary.RequestSHA256) && validCheckResults(summary.Checks, true)
	case SummaryReworkRequired:
		return summary.OwnerTaskID != "" && summary.Attempt >= 0 && summary.Attempt < 3
	case SummaryBlockedDecision:
		return summary.OwnerTaskID != "" && summary.Attempt == 3
	case SummaryMergePending:
		return summary.IntegrationCommit == ""
	default:
		return false
	}
}

var _ PlanSupervisorSummaryPublisher = (*EventSummaryStore)(nil)
