package projection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/akimisaka/aor/internal/eventing"
	aorworkflow "github.com/akimisaka/aor/internal/workflow"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

var ErrDurableConvergence = errors.New("workflow, PostgreSQL, and event bus states did not converge")

type DurableProjectSource interface {
	eventing.ReconciliationSource
}

type ProjectLifecycleHistory interface {
	Snapshot(context.Context, string, string) (aorworkflow.ProjectLifecycleSnapshot, error)
}

type PendingEventReplay interface {
	ReplayPending(context.Context, func(context.Context, eventing.JetStreamDelivery) error) (uint64, error)
}

type ProjectConvergenceReport struct {
	TenantID                   string `json:"tenantId"`
	ProjectID                  string `json:"projectId"`
	ProjectionReportSHA256     string `json:"projectionReportSha256"`
	PostgreSQLVersion          int64  `json:"postgresqlVersion"`
	PostgreSQLSHA256           string `json:"postgresqlSha256"`
	PostgreSQLProjectionSHA256 string `json:"postgresqlProjectionSha256"`
	WorkflowVersion            int64  `json:"workflowVersion"`
	WorkflowSHA256             string `json:"workflowSha256"`
	WorkflowProcessedEvents    int64  `json:"workflowProcessedEvents"`
	WorkflowRejectedSignals    int64  `json:"workflowRejectedSignals"`
	WorkflowBufferedEvents     int    `json:"workflowBufferedEvents"`
	EventBusVersion            int64  `json:"eventBusVersion"`
	EventBusSHA256             string `json:"eventBusSha256"`
	EventBusProjectionSHA256   string `json:"eventBusProjectionSha256"`
	EventBusReplayMessageCount uint64 `json:"eventBusReplayMessageCount"`
	Converged                  bool   `json:"converged"`
	ReportSHA256               string `json:"reportSha256"`
}

type lifecycleConvergenceState struct {
	TenantID   string                 `json:"tenantId"`
	ProjectID  string                 `json:"projectId"`
	State      contracts.ProjectState `json:"state"`
	Version    int64                  `json:"version"`
	PausedFrom contracts.ProjectState `json:"pausedFrom,omitempty"`
}

// VerifyProjectConvergence is an operator gate over the three durable views of
// project lifecycle state. The replay must be a fresh, beginning-positioned,
// tenant-scoped JetStream consumer filtered to the project aggregate subject.
func VerifyProjectConvergence(ctx context.Context, source DurableProjectSource, history ProjectLifecycleHistory, replay PendingEventReplay, tenantID, projectID string) (ProjectConvergenceReport, error) {
	if ctx == nil || source == nil || history == nil || replay == nil || tenantID == "" || projectID == "" {
		return ProjectConvergenceReport{}, fmt.Errorf("%w: all reconciliation inputs are required", ErrDurableConvergence)
	}
	snapshot, err := source.LoadReconciliationSnapshot(ctx, tenantID)
	if err != nil {
		return ProjectConvergenceReport{}, fmt.Errorf("%w: load PostgreSQL reconciliation snapshot: %v", ErrDurableConvergence, err)
	}
	projectionReport, err := verifyDurableSnapshot(snapshot, tenantID)
	if err != nil {
		return ProjectConvergenceReport{}, fmt.Errorf("%w: PostgreSQL projection verification: %v", ErrDurableConvergence, err)
	}
	online, found := projectProjection(snapshot.Projections, tenantID, projectID)
	if !found {
		return ProjectConvergenceReport{}, fmt.Errorf("%w: PostgreSQL project projection is missing", ErrDurableConvergence)
	}
	postgresState, err := lifecycleStateFromProjection(online.State, tenantID, projectID, online.Version)
	if err != nil {
		return ProjectConvergenceReport{}, err
	}
	postgresDigest, err := lifecycleStateDigest(postgresState)
	if err != nil {
		return ProjectConvergenceReport{}, err
	}
	postgresProjectionDigest, err := canonicaljson.Digest(online.State)
	if err != nil {
		return ProjectConvergenceReport{}, err
	}

	workflowSnapshot, err := history.Snapshot(ctx, tenantID, projectID)
	if err != nil {
		return ProjectConvergenceReport{}, fmt.Errorf("read Temporal lifecycle history: %w", err)
	}
	workflowState := lifecycleConvergenceState{
		TenantID: tenantID, ProjectID: projectID, State: workflowSnapshot.State,
		Version: workflowSnapshot.ProjectVersion, PausedFrom: workflowSnapshot.PausedFrom,
	}
	if err := validateLifecycleConvergenceState(workflowState); err != nil {
		return ProjectConvergenceReport{}, err
	}
	workflowDigest, err := lifecycleStateDigest(workflowState)
	if err != nil {
		return ProjectConvergenceReport{}, err
	}

	projector := New(map[string]Reducer{"project": StateReducer})
	messageCount, err := replay.ReplayPending(ctx, func(_ context.Context, delivery eventing.JetStreamDelivery) error {
		event, err := projectEventFromDelivery(delivery, tenantID)
		if err != nil {
			return err
		}
		_, err = projector.Apply(event)
		return err
	})
	if err != nil {
		return ProjectConvergenceReport{}, fmt.Errorf("replay JetStream project events: %w", err)
	}
	busState := lifecycleConvergenceState{TenantID: tenantID, ProjectID: projectID}
	busProjectionDigest := ""
	if snapshot, found := projector.Snapshot(tenantID, "project", projectID); found {
		busState, err = lifecycleStateFromProjection(snapshot.State, tenantID, projectID, snapshot.Version)
		if err != nil {
			return ProjectConvergenceReport{}, err
		}
		busProjectionDigest, err = canonicaljson.Digest(snapshot.State)
		if err != nil {
			return ProjectConvergenceReport{}, err
		}
	}
	busDigest := ""
	if busState.Version != 0 {
		busDigest, err = lifecycleStateDigest(busState)
		if err != nil {
			return ProjectConvergenceReport{}, err
		}
	}

	report := ProjectConvergenceReport{
		TenantID: tenantID, ProjectID: projectID, ProjectionReportSHA256: projectionReport.ReportSHA256,
		PostgreSQLVersion: postgresState.Version, PostgreSQLSHA256: postgresDigest, PostgreSQLProjectionSHA256: postgresProjectionDigest,
		WorkflowVersion: workflowState.Version, WorkflowSHA256: workflowDigest,
		WorkflowProcessedEvents: workflowSnapshot.ProcessedEvents, WorkflowRejectedSignals: workflowSnapshot.RejectedSignals,
		WorkflowBufferedEvents: workflowSnapshot.BufferedEvents,
		EventBusVersion:        busState.Version, EventBusSHA256: busDigest, EventBusProjectionSHA256: busProjectionDigest,
		EventBusReplayMessageCount: messageCount,
	}
	report.Converged = report.PostgreSQLVersion == report.WorkflowVersion && report.PostgreSQLVersion == report.EventBusVersion &&
		report.PostgreSQLSHA256 == report.WorkflowSHA256 && report.PostgreSQLSHA256 == report.EventBusSHA256 &&
		report.PostgreSQLProjectionSHA256 == report.EventBusProjectionSHA256 &&
		report.WorkflowProcessedEvents == report.WorkflowVersion-1 && report.WorkflowBufferedEvents == 0
	report.ReportSHA256, err = projectConvergenceDigest(report)
	if err != nil {
		return ProjectConvergenceReport{}, err
	}
	if !report.Converged {
		return report, fmt.Errorf("%w: report %s", ErrDurableConvergence, report.ReportSHA256)
	}
	return report, nil
}

func projectProjection(projections []eventing.Projection, tenantID, projectID string) (eventing.Projection, bool) {
	for _, projection := range projections {
		if projection.TenantID == tenantID && projection.ProjectID == projectID && projection.AggregateType == "project" && projection.AggregateID == projectID {
			projection.State = append(json.RawMessage(nil), projection.State...)
			return projection, true
		}
	}
	return eventing.Projection{}, false
}

func lifecycleStateFromProjection(raw json.RawMessage, tenantID, projectID string, version int64) (lifecycleConvergenceState, error) {
	var projection struct {
		TenantID        string                 `json:"tenantId"`
		ID              string                 `json:"id"`
		State           contracts.ProjectState `json:"state"`
		Version         int64                  `json:"version"`
		PausedFromState contracts.ProjectState `json:"pausedFromState,omitempty"`
	}
	if err := json.Unmarshal(raw, &projection); err != nil {
		return lifecycleConvergenceState{}, fmt.Errorf("decode project lifecycle projection: %w", err)
	}
	state := lifecycleConvergenceState{
		TenantID: projection.TenantID, ProjectID: projection.ID, State: projection.State,
		Version: projection.Version, PausedFrom: projection.PausedFromState,
	}
	if state.TenantID != tenantID || state.ProjectID != projectID || state.Version != version {
		return lifecycleConvergenceState{}, fmt.Errorf("%w: project lifecycle projection identity mismatch", ErrDurableConvergence)
	}
	if err := validateLifecycleConvergenceState(state); err != nil {
		return lifecycleConvergenceState{}, err
	}
	return state, nil
}

func projectEventFromDelivery(delivery eventing.JetStreamDelivery, tenantID string) (eventing.DomainEvent, error) {
	external := delivery.Event
	if delivery.TenantID != tenantID || !strings.HasSuffix(delivery.Subject, ".project") || external.Validate() != nil {
		return eventing.DomainEvent{}, fmt.Errorf("%w: invalid project event replay envelope", ErrDurableConvergence)
	}
	var payload struct {
		TenantID         string          `json:"tenantId"`
		ProjectID        string          `json:"projectId"`
		AggregateVersion int64           `json:"aggregateVersion"`
		Projection       json.RawMessage `json:"projection"`
	}
	if err := json.Unmarshal(external.Data, &payload); err != nil || payload.TenantID != tenantID || payload.ProjectID != external.ProjectID || payload.AggregateVersion < 1 || !json.Valid(payload.Projection) {
		return eventing.DomainEvent{}, fmt.Errorf("%w: invalid project event replay payload", ErrDurableConvergence)
	}
	if _, err := lifecycleStateFromProjection(payload.Projection, tenantID, payload.ProjectID, payload.AggregateVersion); err != nil {
		return eventing.DomainEvent{}, err
	}
	payloadDigest, err := canonicaljson.Digest(external.Data)
	if err != nil {
		return eventing.DomainEvent{}, err
	}
	return eventing.DomainEvent{
		EventID: external.ID, TenantID: tenantID, ProjectID: payload.ProjectID, AggregateType: "project", AggregateID: payload.ProjectID,
		AggregateVersion: payload.AggregateVersion, Type: external.Type, Payload: append(json.RawMessage(nil), external.Data...),
		PayloadSHA256: payloadDigest, OccurredAt: external.Time, Traceparent: external.Traceparent, Tracestate: external.Tracestate,
		TaskID: external.TaskID, TaskIDReason: external.TaskIDReason, AgentRunID: external.AgentRunID, AgentRunReason: external.AgentRunReason,
	}, nil
}

func validateLifecycleConvergenceState(state lifecycleConvergenceState) error {
	if state.TenantID == "" || state.ProjectID == "" || state.Version < 1 {
		return fmt.Errorf("%w: invalid lifecycle state identity", ErrDurableConvergence)
	}
	validState := func(value contracts.ProjectState) bool {
		switch value {
		case contracts.ProjectCreated, contracts.ProjectGoalNegotiating, contracts.ProjectGoalSuspended,
			contracts.ProjectPlanning, contracts.ProjectExecuting, contracts.ProjectIntegrating,
			contracts.ProjectGlobalAudit, contracts.ProjectBlockedUserDecision, contracts.ProjectPaused,
			contracts.ProjectCompleted, contracts.ProjectAborted, contracts.ProjectFailedSystem, contracts.ProjectArchived:
			return true
		default:
			return false
		}
	}
	if !validState(state.State) || state.PausedFrom != "" && !validState(state.PausedFrom) {
		return fmt.Errorf("%w: invalid lifecycle state", ErrDurableConvergence)
	}
	return nil
}

func lifecycleStateDigest(state lifecycleConvergenceState) (string, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(payload)
}

func projectConvergenceDigest(report ProjectConvergenceReport) (string, error) {
	report.ReportSHA256 = ""
	payload, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(payload)
}
