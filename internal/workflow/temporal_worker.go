package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.temporal.io/sdk/activity"
	temporalclient "go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	temporalworker "go.temporal.io/sdk/worker"
	temporalworkflow "go.temporal.io/sdk/workflow"

	"github.com/akimisaka/aor/internal/observability"
)

const (
	ProjectExecutionWorkflowName = "aor.project.execution.v1"
	ExecuteActivityName          = "aor.activity.execute.v1"
	GlobalAuditActivityAction    = "global-audit.run"
	WorkerBuildID                = "aor-worker-v2"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)

var (
	ErrInvalidExecution = errors.New("invalid workflow execution input")
	ErrWorkerNotStarted = errors.New("workflow worker is not started")
)

// ExecutionInput is the immutable input recorded in Temporal history. Payload
// is opaque to the workflow and is interpreted only by the activity boundary.
type ExecutionInput struct {
	TenantID    string          `json:"tenantId"`
	ProjectID   string          `json:"projectId"`
	TaskID      string          `json:"taskId"`
	ActivityID  string          `json:"activityId"`
	Payload     json.RawMessage `json:"payload"`
	Traceparent string          `json:"traceparent,omitempty"`
	Tracestate  string          `json:"tracestate,omitempty"`
}

type ExecutionOutput struct {
	Output         json.RawMessage `json:"output"`
	IdempotencyKey string          `json:"idempotencyKey"`
	Duplicate      bool            `json:"duplicate,omitempty"`
}

type executionInputContextKey struct{}

// ExecutionInputFromContext exposes the immutable activity identity to a
// controlled effect implementation. It is set only by Activities.Execute.
func ExecutionInputFromContext(ctx context.Context) (ExecutionInput, bool) {
	input, ok := ctx.Value(executionInputContextKey{}).(ExecutionInput)
	if !ok {
		return ExecutionInput{}, false
	}
	input.Payload = append(json.RawMessage(nil), input.Payload...)
	return input, true
}

func (input ExecutionInput) Validate() error {
	if !identifierPattern.MatchString(input.TenantID) || !identifierPattern.MatchString(input.ProjectID) ||
		!identifierPattern.MatchString(input.TaskID) || !identifierPattern.MatchString(input.ActivityID) ||
		len(input.Payload) == 0 || len(input.Payload) > MaximumActivityResultBytes || !json.Valid(input.Payload) {
		return ErrInvalidExecution
	}
	if input.Traceparent == "" {
		if input.Tracestate != "" {
			return ErrInvalidExecution
		}
	} else if _, err := observability.ParseTraceParent(input.Traceparent, input.Tracestate); err != nil {
		return ErrInvalidExecution
	}
	return nil
}

func executionInputWithTrace(ctx context.Context, input ExecutionInput, persistedTraceparent, persistedTracestate string) ExecutionInput {
	trace, found := observability.TraceFromContext(ctx)
	if found {
		traceparent, err := trace.TraceParent()
		if err == nil {
			input.Traceparent = traceparent
			input.Tracestate = trace.TraceState
			return input
		}
	}
	if _, err := observability.ParseTraceParent(persistedTraceparent, persistedTracestate); err == nil {
		input.Traceparent = persistedTraceparent
		input.Tracestate = persistedTracestate
	}
	return input
}

// ProjectExecutionWorkflow only coordinates durable activity execution. It
// deliberately has no access to network, files, clocks, or external services.
func ProjectExecutionWorkflow(ctx temporalworkflow.Context, input ExecutionInput) (ExecutionOutput, error) {
	if err := input.Validate(); err != nil {
		return ExecutionOutput{}, temporal.NewNonRetryableApplicationError(err.Error(), "AORInvalidArgument", nil)
	}
	options := temporalworkflow.ActivityOptions{
		TaskQueue:              temporalworkflow.GetInfo(ctx).TaskQueueName,
		ScheduleToCloseTimeout: time.Hour,
		StartToCloseTimeout:    30 * time.Minute,
		HeartbeatTimeout:       30 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    time.Second,
			BackoffCoefficient: 2,
			MaximumInterval:    time.Minute,
			MaximumAttempts:    3,
			NonRetryableErrorTypes: []string{
				"AORInvalidArgument", "AORPolicyDenied", "AORSandboxUnavailable",
			},
		},
	}
	activityContext := temporalworkflow.WithActivityOptions(ctx, options)
	var output ExecutionOutput
	if err := temporalworkflow.ExecuteActivity(activityContext, ExecuteActivityName, input).Get(activityContext, &output); err != nil {
		return ExecutionOutput{}, err
	}
	return output, nil
}

// Activities is registered as a single, explicitly named Temporal activity.
// The executor preserves a stable idempotency key across Temporal retries.
type Activities struct {
	executor *ActivityExecutor
}

func NewActivities(effect Effect) (*Activities, error) {
	return NewActivitiesWithStore(effect, nil)
}

func NewActivitiesWithStore(effect Effect, store ActivityResultStore) (*Activities, error) {
	if effect == nil {
		return nil, ErrInvalidExecution
	}
	return &Activities{executor: NewDurableActivityExecutor(effect, store)}, nil
}

func (activities *Activities) Execute(ctx context.Context, input ExecutionInput) (ExecutionOutput, error) {
	if activities == nil || activities.executor == nil {
		return ExecutionOutput{}, temporal.NewNonRetryableApplicationError("activity service unavailable", "AORSandboxUnavailable", nil)
	}
	if err := input.Validate(); err != nil {
		return ExecutionOutput{}, temporal.NewNonRetryableApplicationError(err.Error(), "AORInvalidArgument", nil)
	}
	if input.Traceparent != "" {
		trace, err := observability.ParseTraceParent(input.Traceparent, input.Tracestate)
		if err != nil {
			return ExecutionOutput{}, temporal.NewNonRetryableApplicationError(err.Error(), "AORInvalidArgument", nil)
		}
		ctx, err = observability.ContextWithTrace(ctx, trace)
		if err != nil {
			return ExecutionOutput{}, temporal.NewNonRetryableApplicationError(err.Error(), "AORInvalidArgument", nil)
		}
	}
	info := activity.GetInfo(ctx)
	identity := ActivityIdentity{TenantID: input.TenantID, WorkflowID: info.WorkflowExecution.ID, ActivityID: input.ActivityID}
	ctx = context.WithValue(ctx, executionInputContextKey{}, input)
	result, err := activities.executor.Execute(ctx, identity, input.Payload)
	if err != nil {
		return ExecutionOutput{}, classifyActivityError(err)
	}
	return ExecutionOutput{Output: append(json.RawMessage(nil), result.Output...), IdempotencyKey: result.IdempotencyKey, Duplicate: result.Duplicate}, nil
}

func classifyActivityError(err error) error {
	if err == nil {
		return nil
	}
	// Input and policy errors are expected to be represented by callers using
	// typed Temporal application errors. Unknown errors remain retryable.
	var typed interface{ NonRetryable() bool }
	if errors.As(err, &typed) && typed.NonRetryable() {
		return temporal.NewNonRetryableApplicationError(err.Error(), "AORPolicyDenied", nil)
	}
	return err
}

// TemporalWorker owns registration and lifecycle for a deterministic worker.
// Registration happens in a fixed order and is complete before Start returns.
type TemporalWorker struct {
	client  temporalclient.Client
	worker  temporalworker.Worker
	started atomic.Bool
	stop    sync.Once
}

func NewTemporalWorker(client temporalclient.Client, taskQueue, buildID string, activities *Activities) (*TemporalWorker, error) {
	if client == nil || !identifierPattern.MatchString(taskQueue) || activities == nil {
		return nil, ErrInvalidExecution
	}
	if strings.TrimSpace(buildID) == "" {
		buildID = WorkerBuildID
	}
	if !identifierPattern.MatchString(buildID) {
		return nil, ErrInvalidExecution
	}
	workerOptions := temporalworker.Options{
		Identity:                               "aor-worker/" + buildID,
		BuildID:                                buildID,
		UseBuildIDForVersioning:                true,
		MaxConcurrentActivityExecutionSize:     8,
		MaxConcurrentWorkflowTaskExecutionSize: 8,
		DisableRegistrationAliasing:            true,
	}
	instance := temporalworker.New(client, taskQueue, workerOptions)
	instance.RegisterWorkflowWithOptions(ProjectLifecycleWorkflow, temporalworkflow.RegisterOptions{Name: ProjectLifecycleWorkflowName})
	instance.RegisterWorkflowWithOptions(ProjectExecutionWorkflow, temporalworkflow.RegisterOptions{Name: ProjectExecutionWorkflowName})
	instance.RegisterActivityWithOptions(activities.Execute, activity.RegisterOptions{Name: ExecuteActivityName})
	return &TemporalWorker{client: client, worker: instance}, nil
}

func (worker *TemporalWorker) Start() error {
	if worker == nil || worker.worker == nil {
		return ErrInvalidExecution
	}
	if worker.started.Swap(true) {
		return nil
	}
	if err := worker.worker.Start(); err != nil {
		worker.started.Store(false)
		return fmt.Errorf("start temporal worker: %w", err)
	}
	return nil
}

func (worker *TemporalWorker) Stop() {
	if worker == nil || worker.worker == nil {
		return
	}
	worker.stop.Do(func() {
		if worker.started.Load() {
			worker.worker.Stop()
			worker.started.Store(false)
		}
	})
}

func (worker *TemporalWorker) Started() bool {
	return worker != nil && worker.started.Load()
}

func (worker *TemporalWorker) Ready() error {
	if worker == nil || worker.worker == nil || !worker.started.Load() {
		return ErrWorkerNotStarted
	}
	return nil
}
