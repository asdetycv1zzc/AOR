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
	ModuleAuditActivityAction   = "module-audit.run"
	moduleAuditBatchSize        = 8
	moduleAuditPollInterval     = time.Second
	moduleAuditFailureBackoff   = 5 * time.Second
	moduleAuditWorkflowIDPrefix = "aor-module-audit-"
	moduleAuditActivityIDPrefix = "module-audit-"
)

var (
	ErrInvalidModuleAuditScheduler    = errors.New("invalid module audit scheduler configuration")
	ErrModuleAuditSchedulerRunning    = errors.New("module audit scheduler is already running")
	ErrModuleAuditSchedulerNotRunning = errors.New("module audit scheduler is not running")
)

type ModuleAuditCandidate struct {
	TenantID        string
	ProjectID       string
	TaskID          string
	TaskVersion     int64
	AttemptSeriesID string
	Attempt         int
	Traceparent     string
	Tracestate      string
}

type ModuleAuditCandidateSource interface {
	ModuleAuditCandidates(context.Context, int) ([]ModuleAuditCandidate, error)
}

type ModuleAuditRequestStore interface {
	EnsureModuleAuditRequest(context.Context, ModuleAuditCandidate, string) (string, error)
}

type PostgresModuleAuditRequests struct {
	database *sql.DB
}

func NewPostgresModuleAuditRequests(database *sql.DB) (*PostgresModuleAuditRequests, error) {
	if database == nil {
		return nil, ErrInvalidModuleAuditScheduler
	}
	return &PostgresModuleAuditRequests{database: database}, nil
}

func (store *PostgresModuleAuditRequests) ModuleAuditCandidates(ctx context.Context, limit int) ([]ModuleAuditCandidate, error) {
	if store == nil || store.database == nil || ctx == nil || limit < 1 || limit > 64 {
		return nil, ErrInvalidModuleAuditScheduler
	}
	rows, err := store.database.QueryContext(ctx, `
SELECT tenant_id::text, project_id::text, task_id::text, task_version,
       attempt_series_id::text, attempt
FROM aor_module_audit_candidates($1)`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	candidates := make([]ModuleAuditCandidate, 0, limit)
	for rows.Next() {
		var candidate ModuleAuditCandidate
		if err := rows.Scan(&candidate.TenantID, &candidate.ProjectID, &candidate.TaskID, &candidate.TaskVersion, &candidate.AttemptSeriesID, &candidate.Attempt); err != nil {
			return nil, err
		}
		if !validModuleAuditCandidate(candidate) {
			return nil, ErrInvalidModuleAuditScheduler
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
		candidates[index].Traceparent, candidates[index].Tracestate = loadSchedulerTrace(ctx, store.database, candidates[index].TenantID, candidates[index].ProjectID, candidates[index].TaskID)
	}
	return candidates, nil
}

func (store *PostgresModuleAuditRequests) EnsureModuleAuditRequest(ctx context.Context, candidate ModuleAuditCandidate, workflowID string) (string, error) {
	if store == nil || store.database == nil || ctx == nil || !validModuleAuditCandidate(candidate) || !identifierPattern.MatchString(workflowID) {
		return "", ErrInvalidModuleAuditScheduler
	}
	runID, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	var durableRunID string
	err = store.database.QueryRowContext(ctx, `
SELECT aor_ensure_module_audit_request($1::uuid, $2::uuid, $3::uuid, $4, $5::uuid, $6, $7::uuid, $8)`,
		candidate.TenantID, candidate.ProjectID, candidate.TaskID, candidate.TaskVersion,
		candidate.AttemptSeriesID, candidate.Attempt, runID.String(), workflowID).Scan(&durableRunID)
	if err != nil {
		return "", err
	}
	if !validUUIDv7(durableRunID) {
		return "", ErrInvalidModuleAuditScheduler
	}
	return durableRunID, nil
}

type ModuleAuditStarter struct {
	client    executionWorkflowClient
	requests  ModuleAuditRequestStore
	taskQueue string
}

func NewModuleAuditStarter(client executionWorkflowClient, requests ModuleAuditRequestStore, taskQueue string) (*ModuleAuditStarter, error) {
	if client == nil || requests == nil || !identifierPattern.MatchString(taskQueue) {
		return nil, ErrInvalidModuleAuditScheduler
	}
	return &ModuleAuditStarter{client: client, requests: requests, taskQueue: taskQueue}, nil
}

func (starter *ModuleAuditStarter) Ensure(ctx context.Context, candidate ModuleAuditCandidate) (ProjectExecutionStartResult, error) {
	if starter == nil || starter.client == nil || starter.requests == nil || ctx == nil || !validModuleAuditCandidate(candidate) {
		return ProjectExecutionStartResult{}, ErrInvalidModuleAuditScheduler
	}
	workflowID := moduleAuditWorkflowID(candidate)
	runID, err := starter.requests.EnsureModuleAuditRequest(ctx, candidate, workflowID)
	if err != nil {
		return ProjectExecutionStartResult{}, err
	}
	payload, err := json.Marshal(struct {
		Action string `json:"action"`
		RunID  string `json:"runId"`
	}{Action: ModuleAuditActivityAction, RunID: runID})
	if err != nil {
		return ProjectExecutionStartResult{}, err
	}
	input := executionInputWithTrace(ctx, ExecutionInput{
		TenantID: candidate.TenantID, ProjectID: candidate.ProjectID, TaskID: candidate.TaskID,
		ActivityID: moduleAuditActivityID(runID), Payload: payload,
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
		return ProjectExecutionStartResult{}, fmt.Errorf("start module audit workflow: %w", err)
	}
	result := ProjectExecutionStartResult{WorkflowID: workflowID, RunID: runID}
	if run != nil {
		result.RunID = run.GetRunID()
	}
	return result, nil
}

type ModuleAuditDispatchResult struct {
	Eligible  int
	Started   int
	Duplicate int
	Failed    int
}

type ModuleAuditScheduler struct {
	source  ModuleAuditCandidateSource
	starter *ModuleAuditStarter
	running atomic.Bool
}

func NewModuleAuditScheduler(source ModuleAuditCandidateSource, starter *ModuleAuditStarter) (*ModuleAuditScheduler, error) {
	if source == nil || starter == nil {
		return nil, ErrInvalidModuleAuditScheduler
	}
	return &ModuleAuditScheduler{source: source, starter: starter}, nil
}

func (scheduler *ModuleAuditScheduler) DispatchOnce(ctx context.Context) (ModuleAuditDispatchResult, error) {
	if scheduler == nil || scheduler.source == nil || scheduler.starter == nil || ctx == nil {
		return ModuleAuditDispatchResult{}, ErrInvalidModuleAuditScheduler
	}
	candidates, err := scheduler.source.ModuleAuditCandidates(ctx, moduleAuditBatchSize)
	if err != nil {
		return ModuleAuditDispatchResult{}, err
	}
	result := ModuleAuditDispatchResult{Eligible: len(candidates)}
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

func (scheduler *ModuleAuditScheduler) Run(ctx context.Context) error {
	if scheduler == nil || ctx == nil {
		return ErrInvalidModuleAuditScheduler
	}
	if !scheduler.running.CompareAndSwap(false, true) {
		return ErrModuleAuditSchedulerRunning
	}
	defer scheduler.running.Store(false)
	for {
		_, dispatchErr := scheduler.DispatchOnce(ctx)
		wait := moduleAuditPollInterval
		if dispatchErr != nil {
			wait = moduleAuditFailureBackoff
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

func (scheduler *ModuleAuditScheduler) Ready() error {
	if scheduler == nil || !scheduler.running.Load() {
		return ErrModuleAuditSchedulerNotRunning
	}
	return nil
}

func validModuleAuditCandidate(candidate ModuleAuditCandidate) bool {
	return validUUID(candidate.TenantID) && validUUID(candidate.ProjectID) && validUUID(candidate.TaskID) &&
		candidate.TaskVersion > 0 && validUUID(candidate.AttemptSeriesID) && candidate.Attempt >= 1 && candidate.Attempt <= 3
}

func moduleAuditWorkflowID(candidate ModuleAuditCandidate) string {
	digest := sha256.Sum256([]byte(candidate.TenantID + "\x00" + candidate.ProjectID + "\x00" + candidate.TaskID + "\x00" + fmt.Sprint(candidate.TaskVersion) + "\x00" + candidate.AttemptSeriesID + "\x00" + fmt.Sprint(candidate.Attempt)))
	return moduleAuditWorkflowIDPrefix + hex.EncodeToString(digest[:])
}

func moduleAuditActivityID(runID string) string {
	digest := sha256.Sum256([]byte(runID))
	return moduleAuditActivityIDPrefix + hex.EncodeToString(digest[:])
}

var _ ModuleAuditCandidateSource = (*PostgresModuleAuditRequests)(nil)
var _ ModuleAuditRequestStore = (*PostgresModuleAuditRequests)(nil)
