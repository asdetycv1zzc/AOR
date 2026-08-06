package workflow

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	temporalclient "go.temporal.io/sdk/client"
)

const (
	IntegrationActivityAction   = "integration.run"
	integrationBatchSize        = 8
	integrationPollInterval     = time.Second
	integrationFailureBackoff   = 5 * time.Second
	integrationWorkflowIDPrefix = "aor-integration-"
	integrationActivityIDPrefix = "integration-"
)

var (
	ErrInvalidIntegrationScheduler    = errors.New("invalid integration scheduler configuration")
	ErrIntegrationSchedulerRunning    = errors.New("integration scheduler is already running")
	ErrIntegrationSchedulerNotRunning = errors.New("integration scheduler is not running")
)

type IntegrationCandidate struct {
	TenantID       string
	ProjectID      string
	ProjectVersion int64
	IntegrationID  string
	Traceparent    string
	Tracestate     string
}

type IntegrationCandidateSource interface {
	IntegrationCandidates(context.Context, int) ([]IntegrationCandidate, error)
}

type IntegrationRequestStore interface {
	EnsureIntegrationRequest(context.Context, IntegrationCandidate, string) (string, error)
}

type PostgresIntegrationRequests struct {
	database *sql.DB
}

func NewPostgresIntegrationRequests(database *sql.DB) (*PostgresIntegrationRequests, error) {
	if database == nil {
		return nil, ErrInvalidIntegrationScheduler
	}
	return &PostgresIntegrationRequests{database: database}, nil
}

func (store *PostgresIntegrationRequests) IntegrationCandidates(ctx context.Context, limit int) ([]IntegrationCandidate, error) {
	if store == nil || store.database == nil || ctx == nil || limit < 1 || limit > 64 {
		return nil, ErrInvalidIntegrationScheduler
	}
	rows, err := store.database.QueryContext(ctx, `
SELECT tenant_id::text, project_id::text, project_version,
       COALESCE(integration_id::text, '')
FROM aor_integration_candidates($1)`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	candidates := make([]IntegrationCandidate, 0, limit)
	for rows.Next() {
		var candidate IntegrationCandidate
		if err := rows.Scan(&candidate.TenantID, &candidate.ProjectID, &candidate.ProjectVersion, &candidate.IntegrationID); err != nil {
			return nil, err
		}
		if !validIntegrationCandidate(candidate) {
			return nil, ErrInvalidIntegrationScheduler
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

func (store *PostgresIntegrationRequests) EnsureIntegrationRequest(ctx context.Context, candidate IntegrationCandidate, workflowID string) (string, error) {
	if store == nil || store.database == nil || ctx == nil || !validIntegrationCandidate(candidate) || !identifierPattern.MatchString(workflowID) {
		return "", ErrInvalidIntegrationScheduler
	}
	integrationID := candidate.IntegrationID
	if integrationID == "" {
		generated, err := uuid.NewV7()
		if err != nil {
			return "", err
		}
		integrationID = generated.String()
	}
	var durableIntegrationID string
	err := store.database.QueryRowContext(ctx, `
SELECT aor_ensure_integration_request($1::uuid, $2::uuid, $3, $4::uuid, $5)`,
		candidate.TenantID, candidate.ProjectID, candidate.ProjectVersion,
		integrationID, workflowID).Scan(&durableIntegrationID)
	if err != nil {
		return "", err
	}
	validDurableID := validUUIDv7(durableIntegrationID)
	if candidate.IntegrationID != "" {
		validDurableID = durableIntegrationID == candidate.IntegrationID && validUUID(durableIntegrationID)
	}
	if !validDurableID {
		return "", ErrInvalidIntegrationScheduler
	}
	return durableIntegrationID, nil
}

type IntegrationStarter struct {
	client    executionWorkflowClient
	requests  IntegrationRequestStore
	taskQueue string
}

func NewIntegrationStarter(client executionWorkflowClient, requests IntegrationRequestStore, taskQueue string) (*IntegrationStarter, error) {
	if client == nil || requests == nil || !identifierPattern.MatchString(taskQueue) {
		return nil, ErrInvalidIntegrationScheduler
	}
	return &IntegrationStarter{client: client, requests: requests, taskQueue: taskQueue}, nil
}

func (starter *IntegrationStarter) Ensure(ctx context.Context, candidate IntegrationCandidate) (ProjectExecutionStartResult, error) {
	if starter == nil || starter.client == nil || starter.requests == nil || ctx == nil || !validIntegrationCandidate(candidate) {
		return ProjectExecutionStartResult{}, ErrInvalidIntegrationScheduler
	}
	workflowID := integrationWorkflowID(candidate)
	integrationID, err := starter.requests.EnsureIntegrationRequest(ctx, candidate, workflowID)
	if err != nil {
		return ProjectExecutionStartResult{}, err
	}
	payload, err := json.Marshal(struct {
		Action        string `json:"action"`
		IntegrationID string `json:"integrationId"`
	}{Action: IntegrationActivityAction, IntegrationID: integrationID})
	if err != nil {
		return ProjectExecutionStartResult{}, err
	}
	input := executionInputWithTrace(ctx, ExecutionInput{
		TenantID: candidate.TenantID, ProjectID: candidate.ProjectID, TaskID: integrationID,
		ActivityID: integrationActivityID(integrationID), Payload: payload,
	}, candidate.Traceparent, candidate.Tracestate)
	run, err := starter.client.ExecuteWorkflow(ctx, temporalclient.StartWorkflowOptions{
		ID: workflowID, TaskQueue: starter.taskQueue,
		WorkflowIDReusePolicy:                    enumspb.WORKFLOW_ID_REUSE_POLICY_ALLOW_DUPLICATE_FAILED_ONLY,
		WorkflowExecutionErrorWhenAlreadyStarted: true,
	}, ProjectExecutionWorkflowName, input)
	if err != nil {
		var alreadyStarted *serviceerror.WorkflowExecutionAlreadyStarted
		if errors.As(err, &alreadyStarted) {
			return ProjectExecutionStartResult{WorkflowID: workflowID, RunID: integrationID, Duplicate: true}, nil
		}
		return ProjectExecutionStartResult{}, fmt.Errorf("start integration workflow: %w", err)
	}
	result := ProjectExecutionStartResult{WorkflowID: workflowID, RunID: integrationID}
	if run != nil {
		result.RunID = run.GetRunID()
	}
	return result, nil
}

type IntegrationDispatchResult struct {
	Eligible  int
	Started   int
	Duplicate int
	Failed    int
}

type IntegrationScheduler struct {
	source  IntegrationCandidateSource
	starter *IntegrationStarter
	running atomic.Bool
	status  sync.RWMutex
	lastErr error
}

func NewIntegrationScheduler(source IntegrationCandidateSource, starter *IntegrationStarter) (*IntegrationScheduler, error) {
	if source == nil || starter == nil {
		return nil, ErrInvalidIntegrationScheduler
	}
	return &IntegrationScheduler{source: source, starter: starter}, nil
}

func (scheduler *IntegrationScheduler) DispatchOnce(ctx context.Context) (IntegrationDispatchResult, error) {
	if scheduler == nil || scheduler.source == nil || scheduler.starter == nil || ctx == nil {
		return IntegrationDispatchResult{}, ErrInvalidIntegrationScheduler
	}
	candidates, err := scheduler.source.IntegrationCandidates(ctx, integrationBatchSize)
	if err != nil {
		return IntegrationDispatchResult{}, err
	}
	result := IntegrationDispatchResult{Eligible: len(candidates)}
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

func (scheduler *IntegrationScheduler) Run(ctx context.Context) error {
	if scheduler == nil || ctx == nil {
		return ErrInvalidIntegrationScheduler
	}
	if !scheduler.running.CompareAndSwap(false, true) {
		return ErrIntegrationSchedulerRunning
	}
	defer scheduler.running.Store(false)
	for {
		_, dispatchErr := scheduler.DispatchOnce(ctx)
		scheduler.status.Lock()
		scheduler.lastErr = dispatchErr
		scheduler.status.Unlock()
		wait := integrationPollInterval
		if dispatchErr != nil {
			wait = integrationFailureBackoff
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

func (scheduler *IntegrationScheduler) Ready() error {
	if scheduler == nil || !scheduler.running.Load() {
		return ErrIntegrationSchedulerNotRunning
	}
	scheduler.status.RLock()
	defer scheduler.status.RUnlock()
	return scheduler.lastErr
}

func validIntegrationCandidate(candidate IntegrationCandidate) bool {
	return validUUID(candidate.TenantID) && validUUID(candidate.ProjectID) && candidate.ProjectVersion > 0 &&
		(candidate.IntegrationID == "" || validUUID(candidate.IntegrationID))
}

func integrationWorkflowID(candidate IntegrationCandidate) string {
	digest := sha256.Sum256([]byte(candidate.TenantID + "\x00" + candidate.ProjectID + "\x00" + fmt.Sprint(candidate.ProjectVersion)))
	return integrationWorkflowIDPrefix + hex.EncodeToString(digest[:])
}

func integrationActivityID(integrationID string) string {
	digest := sha256.Sum256([]byte(integrationID))
	return integrationActivityIDPrefix + hex.EncodeToString(digest[:])
}

var _ IntegrationCandidateSource = (*PostgresIntegrationRequests)(nil)
var _ IntegrationRequestStore = (*PostgresIntegrationRequests)(nil)
