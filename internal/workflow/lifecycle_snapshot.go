package workflow

import (
	"context"
	"fmt"

	"go.temporal.io/sdk/converter"
)

type projectLifecycleQueryClient interface {
	QueryWorkflow(context.Context, string, string, string, ...interface{}) (converter.EncodedValue, error)
}

// TemporalProjectLifecycleHistory reads the workflow state that Temporal
// deterministically reconstructs from the durable lifecycle history.
type TemporalProjectLifecycleHistory struct {
	client projectLifecycleQueryClient
}

func NewTemporalProjectLifecycleHistory(client projectLifecycleQueryClient) (*TemporalProjectLifecycleHistory, error) {
	if client == nil {
		return nil, ErrInvalidProjectLifecycle
	}
	return &TemporalProjectLifecycleHistory{client: client}, nil
}

func (source *TemporalProjectLifecycleHistory) Snapshot(ctx context.Context, tenantID, projectID string) (ProjectLifecycleSnapshot, error) {
	if source == nil || source.client == nil || ctx == nil || !identifierPattern.MatchString(tenantID) || !identifierPattern.MatchString(projectID) {
		return ProjectLifecycleSnapshot{}, ErrInvalidProjectLifecycle
	}
	encoded, err := source.client.QueryWorkflow(ctx, projectLifecycleWorkflowID(tenantID, projectID), "", ProjectLifecycleQueryName)
	if err != nil {
		return ProjectLifecycleSnapshot{}, fmt.Errorf("query project lifecycle history: %w", err)
	}
	if encoded == nil || !encoded.HasValue() {
		return ProjectLifecycleSnapshot{}, fmt.Errorf("%w: lifecycle query returned no state", ErrInvalidProjectLifecycle)
	}
	var snapshot ProjectLifecycleSnapshot
	if err := encoded.Get(&snapshot); err != nil {
		return ProjectLifecycleSnapshot{}, fmt.Errorf("decode project lifecycle history: %w", err)
	}
	if snapshot.TenantID != tenantID || snapshot.ProjectID != projectID || snapshot.ProjectVersion < 1 ||
		snapshot.ProcessedEvents < 0 || snapshot.RejectedSignals < 0 || snapshot.BufferedEvents < 0 ||
		!validLifecycleState(snapshot.State) || snapshot.PausedFrom != "" && !validLifecycleState(snapshot.PausedFrom) {
		return ProjectLifecycleSnapshot{}, ErrInvalidProjectLifecycle
	}
	return snapshot, nil
}
