package workflow

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	temporalclient "go.temporal.io/sdk/client"
)

const (
	globalAuditBatchSize        = 8
	globalAuditPollInterval     = time.Second
	globalAuditFailureBackoff   = 5 * time.Second
	globalAuditWorkflowIDPrefix = "aor-global-audit-"
	globalAuditActivityIDPrefix = "global-audit-"
)

var (
	ErrInvalidGlobalAuditScheduler    = errors.New("invalid global audit scheduler configuration")
	ErrGlobalAuditSchedulerRunning    = errors.New("global audit scheduler is already running")
	ErrGlobalAuditSchedulerNotRunning = errors.New("global audit scheduler is not running")
)

type GlobalAuditCandidate struct {
	TenantID       string
	ProjectID      string
	ProjectVersion int64
	Traceparent    string
	Tracestate     string
}

type GlobalAuditCandidateSource interface {
	GlobalAuditCandidates(context.Context, int) ([]GlobalAuditCandidate, error)
}

type GlobalAuditRequestStore interface {
	EnsureGlobalAuditRequest(context.Context, GlobalAuditCandidate, string) (string, error)
}

type PostgresGlobalAuditRequests struct {
	database *sql.DB
}

func NewPostgresGlobalAuditRequests(database *sql.DB) (*PostgresGlobalAuditRequests, error) {
	if database == nil {
		return nil, ErrInvalidGlobalAuditScheduler
	}
	return &PostgresGlobalAuditRequests{database: database}, nil
}

func (store *PostgresGlobalAuditRequests) GlobalAuditCandidates(ctx context.Context, limit int) ([]GlobalAuditCandidate, error) {
	if store == nil || store.database == nil || ctx == nil || limit < 1 || limit > 64 {
		return nil, ErrInvalidGlobalAuditScheduler
	}
	rows, err := store.database.QueryContext(ctx, `
SELECT tenant_id::text, project_id::text, project_version
FROM aor_global_audit_candidates($1)`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	candidates := make([]GlobalAuditCandidate, 0, limit)
	for rows.Next() {
		var candidate GlobalAuditCandidate
		if err := rows.Scan(&candidate.TenantID, &candidate.ProjectID, &candidate.ProjectVersion); err != nil {
			return nil, err
		}
		if !validGlobalAuditCandidate(candidate) {
			return nil, ErrInvalidGlobalAuditScheduler
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range candidates {
		candidates[index].Traceparent, candidates[index].Tracestate = loadSchedulerTrace(ctx, store.database, candidates[index].TenantID, candidates[index].ProjectID, "")
	}
	return candidates, nil
}

func (store *PostgresGlobalAuditRequests) EnsureGlobalAuditRequest(ctx context.Context, candidate GlobalAuditCandidate, workflowID string) (string, error) {
	if store == nil || store.database == nil || ctx == nil || !validGlobalAuditCandidate(candidate) || !identifierPattern.MatchString(workflowID) {
		return "", ErrInvalidGlobalAuditScheduler
	}
	runID, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	var durableRunID string
	err = store.database.QueryRowContext(ctx, `
SELECT aor_ensure_global_audit_request($1::uuid, $2::uuid, $3, $4::uuid, $5)`,
		candidate.TenantID, candidate.ProjectID, candidate.ProjectVersion, runID.String(), workflowID).Scan(&durableRunID)
	if err != nil {
		return "", err
	}
	if !validUUIDv7(durableRunID) {
		return "", ErrInvalidGlobalAuditScheduler
	}
	return durableRunID, nil
}

type GlobalAuditStarter struct {
	client    executionWorkflowClient
	requests  GlobalAuditRequestStore
	taskQueue string
}

func NewGlobalAuditStarter(client executionWorkflowClient, requests GlobalAuditRequestStore, taskQueue string) (*GlobalAuditStarter, error) {
	if client == nil || requests == nil || !identifierPattern.MatchString(taskQueue) {
		return nil, ErrInvalidGlobalAuditScheduler
	}
	return &GlobalAuditStarter{client: client, requests: requests, taskQueue: taskQueue}, nil
}

func (starter *GlobalAuditStarter) Ensure(ctx context.Context, candidate GlobalAuditCandidate) (ProjectExecutionStartResult, error) {
	if starter == nil || starter.client == nil || starter.requests == nil || ctx == nil || !validGlobalAuditCandidate(candidate) {
		return ProjectExecutionStartResult{}, ErrInvalidGlobalAuditScheduler
	}
	workflowID := globalAuditWorkflowID(candidate)
	runID, err := starter.requests.EnsureGlobalAuditRequest(ctx, candidate, workflowID)
	if err != nil {
		return ProjectExecutionStartResult{}, err
	}
	payload, err := json.Marshal(struct {
		Action string `json:"action"`
		RunID  string `json:"runId"`
	}{Action: GlobalAuditActivityAction, RunID: runID})
	if err != nil {
		return ProjectExecutionStartResult{}, err
	}
	input := executionInputWithTrace(ctx, ExecutionInput{
		TenantID: candidate.TenantID, ProjectID: candidate.ProjectID, TaskID: runID,
		ActivityID: globalAuditActivityID(runID), Payload: payload,
	}, candidate.Traceparent, candidate.Tracestate)
	run, err := starter.client.ExecuteWorkflow(ctx, temporalclient.StartWorkflowOptions{
		ID: workflowID, TaskQueue: starter.taskQueue,
		WorkflowIDReusePolicy:                    enumspb.WORKFLOW_ID_REUSE_POLICY_ALLOW_DUPLICATE_FAILED_ONLY,
		WorkflowExecutionErrorWhenAlreadyStarted: true,
	}, ProjectExecutionWorkflowName, input)
	if err != nil {
		var alreadyStarted *serviceerror.WorkflowExecutionAlreadyStarted
		if errors.As(err, &alreadyStarted) {
			return ProjectExecutionStartResult{WorkflowID: workflowID, RunID: runID, Duplicate: true}, nil
		}
		return ProjectExecutionStartResult{}, fmt.Errorf("start global audit workflow: %w", err)
	}
	result := ProjectExecutionStartResult{WorkflowID: workflowID, RunID: runID}
	if run != nil {
		result.RunID = run.GetRunID()
	}
	return result, nil
}

type GlobalAuditDispatchResult struct {
	Eligible  int
	Started   int
	Duplicate int
	Failed    int
}

type GlobalAuditScheduler struct {
	source  GlobalAuditCandidateSource
	starter *GlobalAuditStarter
	running atomic.Bool
}

func NewGlobalAuditScheduler(source GlobalAuditCandidateSource, starter *GlobalAuditStarter) (*GlobalAuditScheduler, error) {
	if source == nil || starter == nil {
		return nil, ErrInvalidGlobalAuditScheduler
	}
	return &GlobalAuditScheduler{source: source, starter: starter}, nil
}

func (scheduler *GlobalAuditScheduler) DispatchOnce(ctx context.Context) (GlobalAuditDispatchResult, error) {
	if scheduler == nil || scheduler.source == nil || scheduler.starter == nil || ctx == nil {
		return GlobalAuditDispatchResult{}, ErrInvalidGlobalAuditScheduler
	}
	candidates, err := scheduler.source.GlobalAuditCandidates(ctx, globalAuditBatchSize)
	if err != nil {
		return GlobalAuditDispatchResult{}, err
	}
	result := GlobalAuditDispatchResult{Eligible: len(candidates)}
	var dispatchErr error
	for _, candidate := range candidates {
		started, startErr := scheduler.starter.Ensure(ctx, candidate)
		if startErr != nil {
			result.Failed++
			dispatchErr = errors.Join(dispatchErr, startErr)
			continue
		}
		if started.Duplicate {
			result.Duplicate++
		} else {
			result.Started++
		}
	}
	return result, dispatchErr
}

func (scheduler *GlobalAuditScheduler) Run(ctx context.Context) error {
	if scheduler == nil || ctx == nil {
		return ErrInvalidGlobalAuditScheduler
	}
	if !scheduler.running.CompareAndSwap(false, true) {
		return ErrGlobalAuditSchedulerRunning
	}
	defer scheduler.running.Store(false)
	for {
		_, dispatchErr := scheduler.DispatchOnce(ctx)
		wait := globalAuditPollInterval
		if dispatchErr != nil {
			wait = globalAuditFailureBackoff
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (scheduler *GlobalAuditScheduler) Ready() error {
	if scheduler == nil || !scheduler.running.Load() {
		return ErrGlobalAuditSchedulerNotRunning
	}
	return nil
}

func validGlobalAuditCandidate(candidate GlobalAuditCandidate) bool {
	return validUUID(candidate.TenantID) && validUUID(candidate.ProjectID) && candidate.ProjectVersion > 0
}

func validUUIDv7(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value && parsed != uuid.Nil && parsed.Version() == 7
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value && parsed != uuid.Nil
}

func globalAuditWorkflowID(candidate GlobalAuditCandidate) string {
	digest := sha256.Sum256([]byte(candidate.TenantID + "\x00" + candidate.ProjectID + "\x00" + fmt.Sprint(candidate.ProjectVersion)))
	return globalAuditWorkflowIDPrefix + hex.EncodeToString(digest[:])
}

func globalAuditActivityID(runID string) string {
	digest := sha256.Sum256([]byte(runID))
	return globalAuditActivityIDPrefix + hex.EncodeToString(digest[:])
}

var _ GlobalAuditCandidateSource = (*PostgresGlobalAuditRequests)(nil)
var _ GlobalAuditRequestStore = (*PostgresGlobalAuditRequests)(nil)
