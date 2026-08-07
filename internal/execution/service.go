package execution

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/aop"
	"github.com/akimisaka/aor/pkg/contracts"
)

var (
	ErrInvalidRequest       = errors.New("invalid execution request")
	ErrExecutionUnavailable = errors.New("execution dependency unavailable")
	ErrTaskNotReady         = errors.New("module task is not ready for execution")
	ErrDependencyNotReady   = errors.New("module dependency has not passed audit")
	ErrAssignmentInvalid    = errors.New("executor assignment is invalid")
	ErrPreparationInvalid   = errors.New("executor runtime preparation is invalid")
	ErrSubmissionInvalid    = errors.New("repository submission is invalid")
	ErrExecutionInProgress  = errors.New("executor run is already in progress")
)

const (
	RepositoryCreateWorkspace = "repository.workspace.create"
	RepositoryReadFile        = "repository.file.read"
	RepositoryWriteFile       = "repository.file.write"
	RepositoryDeleteFile      = "repository.file.delete"
	RepositorySubmit          = "repository.submission.commit"
)

type Request struct {
	ExecutionID string
	TenantID    string
	ProjectID   string
	TaskID      string
}

type Result struct {
	Task            state.ModuleTask
	Submission      contracts.SubmissionManifest
	AgentInstanceID string
	SandboxID       string
	LeaseID         string
	FencingToken    int64
	Duplicate       bool
}

type LeaseTaskRequest struct {
	ExecutionID     string
	TenantID        string
	ProjectID       string
	TaskID          string
	AgentInstanceID string
	ExpectedVersion int64
	FencingToken    int64
	Recover         bool
}

type SubmitTaskRequest struct {
	ExecutionID     string
	TenantID        string
	ProjectID       string
	TaskID          string
	ExpectedVersion int64
	FencingToken    int64
	ModuleSpecRef   contracts.SpecRef
	AttemptSeriesID string
	Submission      contracts.SubmissionManifest
}

// TaskAuthority is the sole state-changing boundary used by the coordinator.
// Implementations must use optimistic concurrency and durable idempotency.
type TaskAuthority interface {
	Project(context.Context, string, string) (state.Project, bool, error)
	Task(context.Context, string, string, string) (state.ModuleTask, bool, error)
	Tasks(context.Context, string, string) ([]state.ModuleTask, error)
	LeaseExecution(context.Context, LeaseTaskRequest) (state.ModuleTask, bool, error)
	SubmitExecution(context.Context, SubmitTaskRequest) (state.ModuleTask, bool, error)
}

type ModuleSpecSource interface {
	ModuleSpec(context.Context, string, string, string, contracts.SpecRef) (contracts.ModuleSpec, error)
}

type AssignmentRequest struct {
	ExecutionID string
	Project     state.Project
	Task        state.ModuleTask
	ModuleSpec  contracts.ModuleSpec
	Recover     bool
}

type Assignment struct {
	AgentInstanceID string
	SandboxID       string
	FencingToken    int64
}

// AssignmentAuthority must atomically reserve one active Executor per task.
// A repeated ExecutionID returns the same assignment; a competing ID fails.
type AssignmentAuthority interface {
	Assign(context.Context, AssignmentRequest) (Assignment, error)
}

type PreparationRequest struct {
	ExecutionID string
	Project     state.Project
	Task        state.ModuleTask
	ModuleSpec  contracts.ModuleSpec
	Assignment  Assignment
	Attempt     int
	BaseCommit  string
}

type PreparedRun struct {
	Declaration   agentruntime.Declaration
	Lease         agentruntime.AgentLease
	ModelCall     agentruntime.ModelCall
	MaxToolRounds int
}

// RuntimePreparer resolves trusted prompt, context, budget, model, tool and
// operational lease facts after the task has entered EXECUTING.
type RuntimePreparer interface {
	Prepare(context.Context, PreparationRequest) (PreparedRun, error)
}

type AgentRuntime interface {
	Declare(agentruntime.Declaration) error
	Queue(string) error
	AssignLease(context.Context, string, agentruntime.AgentLease) error
	Start(context.Context, string) error
	Heartbeat(context.Context, string) error
	RunToolLoop(context.Context, string, agentruntime.ModelCall, int) (modelgateway.NormalizedResponse, error)
	Complete(context.Context, string, agentruntime.AgentOutput) (agentruntime.AcceptedResult, error)
	AcceptedResult(string) (agentruntime.AcceptedResult, bool)
	Fail(string) error
}

type WorkspaceBaseResolver interface {
	ResolveWorkspaceBaseCommit(context.Context, string, string, string, string, int) (string, error)
}

type SubmissionSource interface {
	Submission(context.Context, string, string, string, int) (repository.Submission, bool, error)
}

type Config struct {
	Tasks       TaskAuthority
	Specs       ModuleSpecSource
	Assignments AssignmentAuthority
	Preparer    RuntimePreparer
	Runtime     AgentRuntime
	Bases       WorkspaceBaseResolver
	Submissions SubmissionSource
}

type Service struct {
	tasks       TaskAuthority
	specs       ModuleSpecSource
	assignments AssignmentAuthority
	preparer    RuntimePreparer
	runtime     AgentRuntime
	bases       WorkspaceBaseResolver
	submissions SubmissionSource
}

func New(config Config) (*Service, error) {
	if config.Tasks == nil || config.Specs == nil || config.Assignments == nil || config.Preparer == nil || config.Runtime == nil || config.Bases == nil || config.Submissions == nil {
		return nil, ErrExecutionUnavailable
	}
	return &Service{
		tasks: config.Tasks, specs: config.Specs, assignments: config.Assignments,
		preparer: config.Preparer, runtime: config.Runtime, bases: config.Bases,
		submissions: config.Submissions,
	}, nil
}

func (service *Service) Execute(ctx context.Context, request Request) (Result, error) {
	if service == nil || ctx == nil || ctx.Err() != nil || !validID(request.ExecutionID) || !validID(request.TenantID) || !validID(request.ProjectID) || !validID(request.TaskID) {
		return Result{}, ErrInvalidRequest
	}
	project, found, err := service.tasks.Project(ctx, request.TenantID, request.ProjectID)
	if err != nil {
		return Result{}, err
	}
	if !found {
		return Result{}, ErrTaskNotReady
	}
	task, found, err := service.tasks.Task(ctx, request.TenantID, request.ProjectID, request.TaskID)
	if err != nil {
		return Result{}, err
	}
	if !found {
		return Result{}, ErrTaskNotReady
	}
	allTasks, err := service.tasks.Tasks(ctx, request.TenantID, request.ProjectID)
	if err != nil {
		return Result{}, err
	}
	module, err := service.specs.ModuleSpec(ctx, request.TenantID, request.ProjectID, task.ModuleID, task.ModuleSpecRef)
	if err != nil {
		return Result{}, err
	}
	if err := validateScope(request, project, task, module, allTasks); err != nil {
		return Result{}, err
	}

	switch task.State {
	case contracts.TaskSubmitted:
		return service.completedResult(ctx, task, task.Attempt, true)
	case contracts.TaskReadyExecution, contracts.TaskExecuting:
	default:
		return Result{}, ErrTaskNotReady
	}

	attempt := task.Attempt + 1
	baseCommit := ""
	if task.State == contracts.TaskExecuting {
		baseCommit, err = service.bases.ResolveWorkspaceBaseCommit(ctx, request.TenantID, request.ProjectID, request.TaskID, task.AttemptSeriesID, attempt)
		if err != nil {
			return Result{}, err
		}
		if submission, exists, lookupErr := service.submissions.Submission(ctx, request.TenantID, request.TaskID, task.AttemptSeriesID, attempt); lookupErr != nil {
			return Result{}, lookupErr
		} else if exists {
			if validateSubmission(submission, task, attempt, baseCommit, "", "") == nil {
				result, commitErr := service.commitSubmission(ctx, request, task, submission.Manifest, true)
				if commitErr == nil {
					return result, nil
				}
				// A submission produced by an expired generation is retained for
				// diagnosis, but must not prevent a fresh fenced execution.
				if !errors.Is(commitErr, ErrSubmissionInvalid) {
					return Result{}, commitErr
				}
			}
		}
	}

	assignment, err := service.assignments.Assign(ctx, AssignmentRequest{
		ExecutionID: request.ExecutionID, Project: project, Task: task, ModuleSpec: module,
		Recover: task.State == contracts.TaskExecuting,
	})
	if err != nil {
		return Result{}, err
	}
	if err := validateAssignment(task, assignment); err != nil {
		return Result{}, err
	}
	if task.State == contracts.TaskReadyExecution {
		task, _, err = service.tasks.LeaseExecution(ctx, LeaseTaskRequest{
			ExecutionID: request.ExecutionID, TenantID: request.TenantID, ProjectID: request.ProjectID,
			TaskID: request.TaskID, AgentInstanceID: assignment.AgentInstanceID,
			ExpectedVersion: task.Version, FencingToken: assignment.FencingToken, Recover: false,
		})
		if err != nil {
			return Result{}, err
		}
		if task.State != contracts.TaskExecuting || task.FencingToken != assignment.FencingToken || task.ModuleSpecRef != moduleRef(module) {
			return Result{}, ErrAssignmentInvalid
		}
	} else {
		// A recovered assignment is created at the next generation before the
		// task transition.  The transition then fences the expired generation.
		if assignment.FencingToken > task.FencingToken {
			task, _, err = service.tasks.LeaseExecution(ctx, LeaseTaskRequest{
				ExecutionID: request.ExecutionID, TenantID: request.TenantID, ProjectID: request.ProjectID,
				TaskID: request.TaskID, AgentInstanceID: assignment.AgentInstanceID,
				ExpectedVersion: task.Version, FencingToken: assignment.FencingToken, Recover: true,
			})
			if err != nil {
				return Result{}, err
			}
		} else if assignment.FencingToken < task.FencingToken {
			return Result{}, ErrAssignmentInvalid
		}
		if task.State != contracts.TaskExecuting || task.FencingToken != assignment.FencingToken || task.ModuleSpecRef != moduleRef(module) {
			return Result{}, ErrAssignmentInvalid
		}
	}
	if assignment.FencingToken != task.FencingToken {
		return Result{}, ErrAssignmentInvalid
	}
	if baseCommit == "" {
		baseCommit, err = service.bases.ResolveWorkspaceBaseCommit(ctx, request.TenantID, request.ProjectID, request.TaskID, task.AttemptSeriesID, attempt)
		if err != nil {
			return Result{}, err
		}
	}

	prepared, err := service.preparer.Prepare(ctx, PreparationRequest{
		ExecutionID: request.ExecutionID, Project: project, Task: task, ModuleSpec: module,
		Assignment: assignment, Attempt: attempt, BaseCommit: baseCommit,
	})
	if err != nil {
		return Result{}, err
	}
	if err := validatePreparedRun(request, project, task, module, assignment, attempt, prepared); err != nil {
		return Result{}, err
	}

	manifest, accepted, err := service.run(ctx, prepared)
	if err != nil {
		return Result{}, err
	}
	submission, found, err := service.submissions.Submission(ctx, request.TenantID, request.TaskID, task.AttemptSeriesID, attempt)
	if err != nil {
		return Result{}, err
	}
	if !found || !reflect.DeepEqual(submission.Manifest, manifest) {
		return Result{}, ErrSubmissionInvalid
	}
	if err := validateSubmission(submission, task, attempt, baseCommit, assignment.AgentInstanceID, prepared.Lease.LeaseID); err != nil {
		return Result{}, err
	}
	if err := validateAccepted(accepted, prepared, manifest); err != nil {
		return Result{}, err
	}
	result, err := service.commitSubmission(ctx, request, task, manifest, false)
	if err != nil {
		return Result{}, err
	}
	result.SandboxID = assignment.SandboxID
	return result, nil
}

func (service *Service) run(ctx context.Context, prepared PreparedRun) (contracts.SubmissionManifest, agentruntime.AcceptedResult, error) {
	runID := prepared.Declaration.RunID
	if err := service.runtime.Declare(prepared.Declaration); err != nil {
		if errors.Is(err, agentruntime.ErrRunExists) {
			if accepted, found := service.runtime.AcceptedResult(runID); found {
				manifest, decodeErr := decodeManifest(accepted.Payload)
				return manifest, accepted, decodeErr
			}
			return contracts.SubmissionManifest{}, agentruntime.AcceptedResult{}, ErrExecutionInProgress
		}
		return contracts.SubmissionManifest{}, agentruntime.AcceptedResult{}, err
	}
	completed := false
	defer func() {
		if !completed {
			_ = service.runtime.Fail(runID)
		}
	}()
	if err := service.runtime.Queue(runID); err != nil {
		return contracts.SubmissionManifest{}, agentruntime.AcceptedResult{}, err
	}
	if err := service.runtime.AssignLease(ctx, runID, prepared.Lease); err != nil {
		return contracts.SubmissionManifest{}, agentruntime.AcceptedResult{}, err
	}
	if err := service.runtime.Start(ctx, runID); err != nil {
		return contracts.SubmissionManifest{}, agentruntime.AcceptedResult{}, err
	}
	runContext, cancelRun := context.WithCancel(ctx)
	heartbeatDone := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(time.Duration(agentruntime.DefaultHeartbeatSeconds) * time.Second / 2)
		defer ticker.Stop()
		for {
			select {
			case <-runContext.Done():
				heartbeatDone <- nil
				return
			case <-ticker.C:
				heartbeatContext, cancel := context.WithTimeout(runContext, 10*time.Second)
				heartbeatErr := service.runtime.Heartbeat(heartbeatContext, runID)
				cancel()
				if heartbeatErr != nil {
					if runContext.Err() != nil {
						heartbeatDone <- nil
						return
					}
					heartbeatDone <- heartbeatErr
					cancelRun()
					return
				}
			}
		}
	}()
	response, err := service.runtime.RunToolLoop(runContext, runID, prepared.ModelCall, prepared.MaxToolRounds)
	cancelRun()
	heartbeatErr := <-heartbeatDone
	if err != nil {
		return contracts.SubmissionManifest{}, agentruntime.AcceptedResult{}, err
	}
	if heartbeatErr != nil {
		return contracts.SubmissionManifest{}, agentruntime.AcceptedResult{}, heartbeatErr
	}
	manifest, err := decodeManifest(response.Content)
	if err != nil {
		return contracts.SubmissionManifest{}, agentruntime.AcceptedResult{}, err
	}
	accepted, err := service.runtime.Complete(ctx, runID, agentruntime.AgentOutput{Intent: aop.IntentSubmitImplementation, Payload: append(json.RawMessage(nil), response.Content...)})
	if err != nil {
		return contracts.SubmissionManifest{}, agentruntime.AcceptedResult{}, err
	}
	completed = true
	return manifest, accepted, nil
}

func (service *Service) commitSubmission(ctx context.Context, request Request, task state.ModuleTask, manifest contracts.SubmissionManifest, duplicate bool) (Result, error) {
	outcome, commandDuplicate, err := service.tasks.SubmitExecution(ctx, SubmitTaskRequest{
		ExecutionID: request.ExecutionID, TenantID: request.TenantID, ProjectID: request.ProjectID,
		TaskID: request.TaskID, ExpectedVersion: task.Version, FencingToken: task.FencingToken,
		ModuleSpecRef: task.ModuleSpecRef, AttemptSeriesID: task.AttemptSeriesID, Submission: manifest,
	})
	if err != nil {
		return Result{}, err
	}
	if outcome.State != contracts.TaskSubmitted || outcome.Attempt != manifest.Attempt || outcome.FencingToken != task.FencingToken || outcome.ModuleSpecRef != task.ModuleSpecRef || outcome.AttemptSeriesID != task.AttemptSeriesID {
		return Result{}, ErrSubmissionInvalid
	}
	return Result{
		Task: outcome, Submission: manifest, AgentInstanceID: manifest.AgentIdentity.AgentInstanceID,
		LeaseID: manifest.AgentIdentity.LeaseID, FencingToken: outcome.FencingToken,
		Duplicate: duplicate || commandDuplicate,
	}, nil
}

func (service *Service) completedResult(ctx context.Context, task state.ModuleTask, attempt int, duplicate bool) (Result, error) {
	base, err := service.bases.ResolveWorkspaceBaseCommit(ctx, task.TenantID, task.ProjectID, task.ID, task.AttemptSeriesID, attempt)
	if err != nil {
		return Result{}, err
	}
	submission, found, err := service.submissions.Submission(ctx, task.TenantID, task.ID, task.AttemptSeriesID, attempt)
	if err != nil {
		return Result{}, err
	}
	if !found || validateSubmission(submission, task, attempt, base, "", "") != nil {
		return Result{}, ErrSubmissionInvalid
	}
	return Result{
		Task: task, Submission: submission.Manifest, AgentInstanceID: submission.Manifest.AgentIdentity.AgentInstanceID,
		LeaseID: submission.Manifest.AgentIdentity.LeaseID, FencingToken: task.FencingToken, Duplicate: duplicate,
	}, nil
}

func validateScope(request Request, project state.Project, task state.ModuleTask, module contracts.ModuleSpec, tasks []state.ModuleTask) error {
	if project.TenantID != request.TenantID || project.ID != request.ProjectID || project.State != contracts.ProjectExecuting || project.Goal == nil || project.Goal.Status != contracts.GoalApproved || project.Goal.ApprovedBy == "" || project.Plan == nil || project.Plan.Validate() != nil {
		return ErrTaskNotReady
	}
	if task.TenantID != request.TenantID || task.ProjectID != request.ProjectID || task.ID != request.TaskID || task.ModuleID == "" || task.ModuleSpecRef.Validate() != nil || task.AttemptSeriesID == "" || task.Attempt < 0 || task.Attempt > 3 || len(task.BlockingTaskIDs) != 0 {
		return ErrTaskNotReady
	}
	if module.Validate() != nil || module.ProjectID != project.ID || module.ModuleID != task.ModuleID || module.ModuleSpecVersion != task.ModuleSpecRef.Version || module.SHA256 != task.ModuleSpecRef.SHA256 || module.PlanVersion != project.Plan.Version || len(module.AllowedPaths) == 0 || len(module.AcceptanceCriteria) == 0 || len(module.TestRequirements) == 0 {
		return ErrTaskNotReady
	}
	if task.State == contracts.TaskSubmitted && (task.Attempt < 1 || task.Attempt > 3) || task.State != contracts.TaskSubmitted && task.Attempt >= 3 {
		return ErrTaskNotReady
	}
	return validateDependencies(task, module, tasks)
}

func validateDependencies(task state.ModuleTask, module contracts.ModuleSpec, tasks []state.ModuleTask) error {
	byModule := make(map[string]state.ModuleTask, len(tasks))
	declared := make(map[string]bool, len(module.Dependencies))
	for _, dependency := range module.Dependencies {
		if dependency == "" || dependency == module.ModuleID || declared[dependency] {
			return ErrDependencyNotReady
		}
		declared[dependency] = true
	}
	for _, candidate := range tasks {
		if candidate.TenantID != task.TenantID || candidate.ProjectID != task.ProjectID || candidate.ID == "" || candidate.ModuleID == "" {
			return ErrDependencyNotReady
		}
		if _, duplicate := byModule[candidate.ModuleID]; duplicate {
			return ErrDependencyNotReady
		}
		byModule[candidate.ModuleID] = candidate
	}
	current, found := byModule[module.ModuleID]
	if !found || current.ID != task.ID {
		return ErrDependencyNotReady
	}
	for dependency := range declared {
		candidate, found := byModule[dependency]
		if !found || candidate.State != contracts.TaskPassed && candidate.State != contracts.TaskIntegrated || !contains(candidate.DependentTaskIDs, task.ID) {
			return ErrDependencyNotReady
		}
	}
	for _, candidate := range tasks {
		if candidate.ID != task.ID && contains(candidate.DependentTaskIDs, task.ID) && !declared[candidate.ModuleID] {
			return ErrDependencyNotReady
		}
	}
	return nil
}

func validateAssignment(task state.ModuleTask, assignment Assignment) error {
	if !validID(assignment.AgentInstanceID) || !validID(assignment.SandboxID) || assignment.FencingToken < 1 {
		return ErrAssignmentInvalid
	}
	if task.State == contracts.TaskReadyExecution && assignment.FencingToken <= task.FencingToken || task.State == contracts.TaskExecuting && assignment.FencingToken < task.FencingToken {
		return ErrAssignmentInvalid
	}
	return nil
}

func validatePreparedRun(request Request, project state.Project, task state.ModuleTask, module contracts.ModuleSpec, assignment Assignment, attempt int, prepared PreparedRun) error {
	declaration := prepared.Declaration
	lease := prepared.Lease
	envelope := declaration.Envelope
	goalRef := contracts.SpecRef{Version: project.Goal.Version, SHA256: project.Goal.SHA256}
	if declaration.RunID != request.ExecutionID || declaration.TenantID != request.TenantID || declaration.ProjectID != request.ProjectID || declaration.TaskID != request.TaskID || declaration.AgentInstanceID != assignment.AgentInstanceID || declaration.Role != agentruntime.RoleExecutor || lease.LeaseID == "" || lease.AgentInstanceID != assignment.AgentInstanceID || lease.TenantID != request.TenantID || lease.ProjectID != request.ProjectID || lease.TaskID != request.TaskID || lease.Role != agentruntime.RoleExecutor || lease.FencingToken != task.FencingToken || prepared.MaxToolRounds < 2 || prepared.MaxToolRounds > agentruntime.MaximumNativeToolRounds {
		return ErrPreparationInvalid
	}
	if envelope.ProjectID != request.ProjectID || envelope.TaskID != request.TaskID || envelope.Intent != aop.IntentSubmitImplementation || envelope.Scope != aop.ScopeTask || envelope.GoalSpec == nil || *envelope.GoalSpec != goalRef || envelope.PlanSpec == nil || *envelope.PlanSpec != *project.Plan || envelope.ModuleSpec == nil || *envelope.ModuleSpec != task.ModuleSpecRef || envelope.AttemptSeriesID != task.AttemptSeriesID || envelope.Attempt != attempt || envelope.ExpectedAggregateVersion != task.Version || envelope.Sender.AgentInstanceID != assignment.AgentInstanceID || envelope.Sender.Role != string(agentruntime.RoleExecutor) || envelope.Sender.LeaseID != lease.LeaseID {
		return ErrPreparationInvalid
	}
	if len(lease.Capabilities) != 1 || lease.Capabilities[0] != "model.generate" || !hasRepositoryTools(declaration) || !hasKnowledgeContext(declaration, module.KnowledgeRefs) {
		return ErrPreparationInvalid
	}
	return nil
}

func validateSubmission(submission repository.Submission, task state.ModuleTask, attempt int, baseCommit, agentID, leaseID string) error {
	manifest := submission.Manifest
	workspace := submission.Workspace
	if manifest.Validate() != nil || manifest.ProjectID != task.ProjectID || manifest.ModuleTaskID != task.ID || manifest.AttemptSeriesID != task.AttemptSeriesID || manifest.Attempt != attempt || manifest.ModuleSpecRef != task.ModuleSpecRef || manifest.BaseCommit != baseCommit || manifest.AgentIdentity.Role != string(agentruntime.RoleExecutor) || agentID != "" && manifest.AgentIdentity.AgentInstanceID != agentID || leaseID != "" && manifest.AgentIdentity.LeaseID != leaseID {
		return ErrSubmissionInvalid
	}
	if workspace.TenantID != task.TenantID || workspace.ProjectID != task.ProjectID || workspace.TaskID != task.ID || workspace.AttemptSeriesID != task.AttemptSeriesID || workspace.Attempt != attempt || workspace.BaseCommit != baseCommit || workspace.ModuleSpecRef != task.ModuleSpecRef || workspace.AgentIdentity.AgentInstanceID != manifest.AgentIdentity.AgentInstanceID || workspace.AgentIdentity.LeaseID != manifest.AgentIdentity.LeaseID {
		return ErrSubmissionInvalid
	}
	return nil
}

func validateAccepted(accepted agentruntime.AcceptedResult, prepared PreparedRun, manifest contracts.SubmissionManifest) error {
	if accepted.RunID != prepared.Declaration.RunID || accepted.Intent != aop.IntentSubmitImplementation || accepted.ExpectedAggregateVersion != prepared.Declaration.Envelope.ExpectedAggregateVersion || accepted.LeaseID != prepared.Lease.LeaseID || accepted.FencingToken != prepared.Lease.FencingToken {
		return ErrSubmissionInvalid
	}
	decoded, err := decodeManifest(accepted.Payload)
	if err != nil || !reflect.DeepEqual(decoded, manifest) {
		return ErrSubmissionInvalid
	}
	return nil
}

func decodeManifest(content []byte) (contracts.SubmissionManifest, error) {
	if len(content) == 0 || len(content) > agentruntime.MaximumAgentOutputBytes {
		return contracts.SubmissionManifest{}, ErrSubmissionInvalid
	}
	var manifest contracts.SubmissionManifest
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return contracts.SubmissionManifest{}, ErrSubmissionInvalid
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || manifest.Validate() != nil {
		return contracts.SubmissionManifest{}, ErrSubmissionInvalid
	}
	return manifest, nil
}

func hasRepositoryTools(declaration agentruntime.Declaration) bool {
	required := map[string]bool{
		RepositoryCreateWorkspace: false, RepositoryReadFile: false, RepositoryWriteFile: false,
		RepositoryDeleteFile: false, RepositorySubmit: false,
	}
	for _, tool := range declaration.Tools {
		if _, found := required[tool.Name]; found && tool.Version != "" {
			required[tool.Name] = true
		}
	}
	for _, found := range required {
		if !found {
			return false
		}
	}
	return true
}

func hasKnowledgeContext(declaration agentruntime.Declaration, required []string) bool {
	if len(required) == 0 {
		return true
	}
	envelopeRefs := make(map[string]bool, len(declaration.Envelope.KnowledgeRefs))
	contextRefs := make(map[string]bool)
	for _, reference := range declaration.Envelope.KnowledgeRefs {
		envelopeRefs[reference] = true
	}
	for _, item := range declaration.ContextManifest.Items {
		if item.Kind == agentruntime.ContextKnowledgeSnippet {
			contextRefs[item.Reference] = true
		}
	}
	for _, reference := range required {
		if !envelopeRefs[reference] || !contextRefs[reference] {
			return false
		}
	}
	return true
}

func moduleRef(module contracts.ModuleSpec) contracts.SpecRef {
	return contracts.SpecRef{Version: module.ModuleSpecVersion, SHA256: module.SHA256}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func validID(value string) bool {
	return strings.TrimSpace(value) == value && value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00/\\")
}
