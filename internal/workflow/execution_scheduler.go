package workflow

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	temporalclient "go.temporal.io/sdk/client"
)

const (
	ExecutionActivityAction         = "execution.execute"
	readyExecutionBatchSize         = 8
	readyExecutionPollInterval      = time.Second
	readyExecutionFailureBackoff    = 5 * time.Second
	executionWorkflowIdentityPrefix = "aor-execution-"
)

var (
	ErrInvalidExecutionScheduler    = errors.New("invalid execution scheduler configuration")
	ErrExecutionSchedulerNotRunning = errors.New("execution scheduler is not running")
	ErrExecutionSchedulerRunning    = errors.New("execution scheduler is already running")
)

type ReadyExecution struct {
	TenantID     string
	ProjectID    string
	TaskID       string
	TaskVersion  int64
	TaskState    contracts.ModuleTaskState
	FencingToken int64
	Recovery     bool
	Traceparent  string
	Tracestate   string
}

type ReadyExecutionSource interface {
	ReadyExecutions(context.Context, int) ([]ReadyExecution, error)
}

type PostgresReadyExecutionSource struct {
	database *sql.DB
}

func NewPostgresReadyExecutionSource(database *sql.DB) (*PostgresReadyExecutionSource, error) {
	if database == nil {
		return nil, ErrInvalidExecutionScheduler
	}
	return &PostgresReadyExecutionSource{database: database}, nil
}

func (source *PostgresReadyExecutionSource) ReadyExecutions(ctx context.Context, limit int) ([]ReadyExecution, error) {
	if source == nil || source.database == nil || ctx == nil || limit < 1 || limit > 64 {
		return nil, ErrInvalidExecutionScheduler
	}
	rows, err := source.database.QueryContext(ctx, `
SELECT tenant_id::text, project_id::text, task_id::text, state_version
       , task_state, fencing_token, recovery
FROM aor_ready_execution_tasks_v2($1)`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ready := make([]ReadyExecution, 0, limit)
	for rows.Next() {
		var item ReadyExecution
		if err := rows.Scan(&item.TenantID, &item.ProjectID, &item.TaskID, &item.TaskVersion, &item.TaskState, &item.FencingToken, &item.Recovery); err != nil {
			return nil, err
		}
		if !validReadyExecution(item) {
			return nil, ErrInvalidExecutionScheduler
		}
		ready = append(ready, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range ready {
		ready[index].Traceparent, ready[index].Tracestate = loadSchedulerTrace(ctx, source.database, ready[index].TenantID, ready[index].ProjectID, ready[index].TaskID)
	}
	return ready, nil
}

type executionWorkflowClient interface {
	ExecuteWorkflow(context.Context, temporalclient.StartWorkflowOptions, interface{}, ...interface{}) (temporalclient.WorkflowRun, error)
}

type ProjectExecutionStarter struct {
	client    executionWorkflowClient
	taskQueue string
}

type ProjectExecutionStartResult struct {
	WorkflowID string
	RunID      string
	Duplicate  bool
}

func NewProjectExecutionStarter(client executionWorkflowClient, taskQueue string) (*ProjectExecutionStarter, error) {
	if client == nil || !identifierPattern.MatchString(taskQueue) {
		return nil, ErrInvalidExecutionScheduler
	}
	return &ProjectExecutionStarter{client: client, taskQueue: taskQueue}, nil
}

func (starter *ProjectExecutionStarter) Ensure(ctx context.Context, ready ReadyExecution) (ProjectExecutionStartResult, error) {
	ready = normalizeReadyExecution(ready)
	if starter == nil || starter.client == nil || ctx == nil || !validReadyExecution(ready) {
		return ProjectExecutionStartResult{}, ErrInvalidExecutionScheduler
	}
	// One task version identifies one READY_EXECUTION opportunity. Rework gets a
	// new version, while repeated scans and controller restarts reuse this ID.
	identity := readyExecutionIdentity(ready)
	executionPrefix := "exec_"
	activityPrefix := "execute_"
	if ready.Recovery {
		executionPrefix = "recover_"
		activityPrefix = "recover_"
	}
	executionID := executionPrefix + identity
	activityID := activityPrefix + identity
	payload, err := json.Marshal(struct {
		Action      string `json:"action"`
		ExecutionID string `json:"executionId"`
		Recovery    bool   `json:"recovery,omitempty"`
	}{Action: ExecutionActivityAction, ExecutionID: executionID, Recovery: ready.Recovery})
	if err != nil {
		return ProjectExecutionStartResult{}, err
	}
	workflowID := executionWorkflowIdentityPrefix + identity
	input := executionInputWithTrace(ctx, ExecutionInput{
		TenantID: ready.TenantID, ProjectID: ready.ProjectID, TaskID: ready.TaskID,
		ActivityID: activityID, Payload: payload,
	}, ready.Traceparent, ready.Tracestate)
	run, err := starter.client.ExecuteWorkflow(ctx, temporalclient.StartWorkflowOptions{
		ID: workflowID, TaskQueue: starter.taskQueue,
		WorkflowIDReusePolicy:                    enumspb.WORKFLOW_ID_REUSE_POLICY_ALLOW_DUPLICATE_FAILED_ONLY,
		WorkflowExecutionErrorWhenAlreadyStarted: true,
	}, ProjectExecutionWorkflowName, input)
	if err != nil {
		var alreadyStarted *serviceerror.WorkflowExecutionAlreadyStarted
		if errors.As(err, &alreadyStarted) {
			return ProjectExecutionStartResult{WorkflowID: workflowID, RunID: alreadyStarted.RunId, Duplicate: true}, nil
		}
		return ProjectExecutionStartResult{}, fmt.Errorf("start project execution workflow: %w", err)
	}
	result := ProjectExecutionStartResult{WorkflowID: workflowID}
	if run != nil {
		result.RunID = run.GetRunID()
	}
	return result, nil
}

type ExecutionDispatchResult struct {
	Eligible  int
	Started   int
	Duplicate int
	Failed    int
}

type ReadyExecutionScheduler struct {
	source  ReadyExecutionSource
	starter *ProjectExecutionStarter
	running atomic.Bool
}

func NewReadyExecutionScheduler(source ReadyExecutionSource, starter *ProjectExecutionStarter) (*ReadyExecutionScheduler, error) {
	if source == nil || starter == nil {
		return nil, ErrInvalidExecutionScheduler
	}
	return &ReadyExecutionScheduler{source: source, starter: starter}, nil
}

func (scheduler *ReadyExecutionScheduler) DispatchOnce(ctx context.Context) (ExecutionDispatchResult, error) {
	if scheduler == nil || scheduler.source == nil || scheduler.starter == nil || ctx == nil {
		return ExecutionDispatchResult{}, ErrInvalidExecutionScheduler
	}
	ready, err := scheduler.source.ReadyExecutions(ctx, readyExecutionBatchSize)
	if err != nil {
		return ExecutionDispatchResult{}, err
	}
	result := ExecutionDispatchResult{Eligible: len(ready)}
	var dispatchErr error
	for _, item := range ready {
		started, startErr := scheduler.starter.Ensure(ctx, item)
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

func (scheduler *ReadyExecutionScheduler) Run(ctx context.Context) error {
	if scheduler == nil || ctx == nil {
		return ErrInvalidExecutionScheduler
	}
	if !scheduler.running.CompareAndSwap(false, true) {
		return ErrExecutionSchedulerRunning
	}
	defer scheduler.running.Store(false)
	for {
		_, dispatchErr := scheduler.DispatchOnce(ctx)
		wait := readyExecutionPollInterval
		if dispatchErr != nil {
			wait = readyExecutionFailureBackoff
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

func (scheduler *ReadyExecutionScheduler) Ready() error {
	if scheduler == nil || !scheduler.running.Load() {
		return ErrExecutionSchedulerNotRunning
	}
	return nil
}

func validReadyExecution(ready ReadyExecution) bool {
	ready = normalizeReadyExecution(ready)
	if !identifierPattern.MatchString(ready.TenantID) || !identifierPattern.MatchString(ready.ProjectID) ||
		!identifierPattern.MatchString(ready.TaskID) || ready.TaskVersion <= 0 {
		return false
	}
	if ready.TaskState == contracts.TaskExecuting {
		return ready.Recovery && ready.FencingToken > 0
	}
	return ready.TaskState == contracts.TaskReadyExecution && !ready.Recovery && ready.FencingToken >= 0
}

func normalizeReadyExecution(ready ReadyExecution) ReadyExecution {
	if ready.TaskState == "" {
		ready.TaskState = contracts.TaskReadyExecution
	}
	return ready
}

func readyExecutionIdentity(ready ReadyExecution) string {
	digest := sha256.Sum256([]byte(ready.TenantID + "\x00" + ready.ProjectID + "\x00" + ready.TaskID + "\x00" + strconv.FormatInt(ready.TaskVersion, 10) + "\x00" + string(ready.TaskState) + "\x00" + strconv.FormatInt(ready.FencingToken, 10)))
	return hex.EncodeToString(digest[:])
}

var _ ReadyExecutionSource = (*PostgresReadyExecutionSource)(nil)
