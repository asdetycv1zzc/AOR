package integration

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

var (
	ErrWorkflowUnavailable = errors.New("integration workflow dependency unavailable")
	ErrModulesNotReady     = errors.New("required modules are not ready for integration")
	ErrSummaryUnavailable  = errors.New("plan supervisor summary unavailable")
)

const (
	SummaryReleaseCandidate = "RELEASE_CANDIDATE"
	SummaryReworkRequired   = "REWORK_REQUIRED"
	SummaryBlockedDecision  = "BLOCKED_USER_DECISION"
	SummaryMergePending     = "MERGE_PENDING"
)

// TaskLister is satisfied by orchestrator.Service and keeps module-state reads
// behind the authoritative projection boundary.
type TaskLister interface {
	Tasks(context.Context, string, string) ([]state.ModuleTask, error)
}

type PlanSupervisorSummaryPublisher interface {
	Publish(context.Context, PlanSupervisorSummary) error
}

type WorkflowConfig struct {
	Queue     *Queue
	Tasks     TaskLister
	Checks    MergeVerifier
	Summaries PlanSupervisorSummaryPublisher
	Clock     func() time.Time
}

type Workflow struct {
	queue     *Queue
	tasks     TaskLister
	checks    MergeVerifier
	summaries PlanSupervisorSummaryPublisher
	clock     func() time.Time
}

type ModuleOutcome struct {
	TaskID           string                    `json:"taskId"`
	ModuleID         string                    `json:"moduleId"`
	State            contracts.ModuleTaskState `json:"state"`
	Version          int64                     `json:"version"`
	Attempt          int                       `json:"attempt"`
	SubmissionCommit string                    `json:"submissionCommit,omitempty"`
	EvidenceSHA256   string                    `json:"evidenceSha256,omitempty"`
}

type PlanSupervisorSummary struct {
	SummaryVersion    int             `json:"summaryVersion"`
	TenantID          string          `json:"tenantId"`
	ProjectID         string          `json:"projectId"`
	IntegrationID     string          `json:"integrationId"`
	State             string          `json:"state"`
	OwnerTaskID       string          `json:"ownerTaskId,omitempty"`
	Attempt           int             `json:"attempt"`
	BaseCommit        string          `json:"baseCommit"`
	IntegrationCommit string          `json:"integrationCommit,omitempty"`
	RequestSHA256     string          `json:"requestSha256,omitempty"`
	Modules           []ModuleOutcome `json:"modules"`
	Checks            []CheckResult   `json:"checks,omitempty"`
	Deviations        []string        `json:"deviations"`
	Risks             []string        `json:"risks"`
	EvidenceSHA256    []string        `json:"evidenceSha256"`
	SummarySHA256     string          `json:"summarySha256"`
	CreatedAt         time.Time       `json:"createdAt"`
}

type WorkflowResult struct {
	Merge   MergeResult
	Summary PlanSupervisorSummary
}

func (summary PlanSupervisorSummary) Validate() error {
	if !validPlanSupervisorSummary(summary) {
		return ErrSummaryUnavailable
	}
	return nil
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error) {
	if config.Queue == nil || config.Tasks == nil || config.Checks == nil || config.Summaries == nil {
		return nil, ErrWorkflowUnavailable
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Workflow{queue: config.Queue, tasks: config.Tasks, checks: config.Checks, summaries: config.Summaries, clock: config.Clock}, nil
}

// Run advances one recoverable integration attempt. The queue owns the
// durable attempt CAS; this coordinator only derives the next valid request
// from that authoritative state.
func (workflow *Workflow) Run(ctx context.Context, request Request) (WorkflowResult, error) {
	if workflow == nil || workflow.queue == nil || workflow.tasks == nil || workflow.checks == nil || workflow.summaries == nil || ctx == nil || ctx.Err() != nil {
		return WorkflowResult{}, ErrWorkflowUnavailable
	}
	if request.TenantID == "" || request.ProjectID == "" || request.IntegrationID == "" {
		return WorkflowResult{}, ErrInvalidRequest
	}
	request = cloneRequest(request)
	integrationTask, found, err := workflow.queue.Task(ctx, request.TenantID, request.IntegrationID)
	if err != nil {
		return WorkflowResult{}, err
	}
	if found && integrationTask.ProjectID != request.ProjectID {
		return WorkflowResult{}, ErrAttemptState
	}
	if found && integrationTask.State == TaskDone {
		return workflow.recoverCompleted(ctx, request, integrationTask)
	}

	tasks, err := workflow.tasks.Tasks(ctx, request.TenantID, request.ProjectID)
	if err != nil {
		return WorkflowResult{}, err
	}
	modules, err := validateWorkflowCandidates(request, tasks)
	if err != nil {
		return WorkflowResult{}, err
	}
	if found {
		request, err = workflow.bindAttempt(ctx, request, integrationTask)
		if err != nil {
			merge := mergeResultForTask(integrationTask)
			summary, summaryErr := workflow.publishSummary(ctx, request, modules, merge, integrationTask)
			if summaryErr != nil {
				return WorkflowResult{Merge: merge, Summary: summary}, errors.Join(err, summaryErr)
			}
			return WorkflowResult{Merge: merge, Summary: summary}, err
		}
	}

	merged, mergeErr := workflow.queue.MergeWithChecks(ctx, request, workflow.checks)
	latest, latestFound, taskErr := workflow.queue.Task(ctx, request.TenantID, request.IntegrationID)
	if taskErr != nil {
		return WorkflowResult{Merge: merged}, errors.Join(mergeErr, taskErr)
	}
	if !latestFound {
		if mergeErr == nil {
			mergeErr = ErrImmutable
		}
		return WorkflowResult{Merge: merged}, mergeErr
	}
	summary, summaryErr := workflow.publishSummary(ctx, request, modules, merged, latest)
	if summaryErr != nil {
		return WorkflowResult{Merge: merged, Summary: summary}, errors.Join(mergeErr, summaryErr)
	}
	return WorkflowResult{Merge: merged, Summary: summary}, mergeErr
}

func (workflow *Workflow) bindAttempt(ctx context.Context, request Request, task IntegrationTask) (Request, error) {
	switch task.State {
	case TaskReworkRequired:
		if task.Attempt >= 3 {
			return request, ErrAttemptsExhausted
		}
		if !integrationAttemptReady(request, task) {
			return request, ErrModulesNotReady
		}
		started, _, err := workflow.queue.StartAttempt(ctx, StartAttemptRequest{
			TenantID: task.TenantID, ProjectID: task.ProjectID, IntegrationID: task.ID,
			OwnerTaskID: task.OwnerTaskID, Attempt: task.Attempt + 1, ExpectedVersion: task.Version,
		})
		if err != nil {
			return request, err
		}
		request.OwnerTaskID = started.OwnerTaskID
		request.Attempt = started.Attempt
	case TaskExecuting, TaskMergeReserved:
		request.OwnerTaskID = task.OwnerTaskID
		request.Attempt = task.Attempt
	case TaskBlockedUserDecision:
		request.OwnerTaskID = task.OwnerTaskID
		request.Attempt = task.Attempt
		return request, ErrAttemptsExhausted
	default:
		return request, ErrAttemptState
	}
	return request, nil
}

func integrationAttemptReady(request Request, task IntegrationTask) bool {
	for _, check := range task.Conflict.Checks {
		if check.Status == CheckError {
			return true
		}
	}
	if task.Conflict.BaseCommit != "" && task.Conflict.BaseCommit != request.BaseCommit {
		return true
	}
	var current, previous *Candidate
	for index := range request.Candidates {
		if request.Candidates[index].TaskID == task.OwnerTaskID {
			current = &request.Candidates[index]
			break
		}
	}
	for index := range task.Conflict.Candidates {
		if task.Conflict.Candidates[index].TaskID == task.OwnerTaskID {
			previous = &task.Conflict.Candidates[index]
			break
		}
	}
	return current != nil && previous != nil && !reflect.DeepEqual(canonicalCandidates([]Candidate{*current}), canonicalCandidates([]Candidate{*previous}))
}

func (workflow *Workflow) recoverCompleted(ctx context.Context, request Request, task IntegrationTask) (WorkflowResult, error) {
	merged, found, err := workflow.queue.Result(ctx, request.TenantID, request.IntegrationID)
	if err != nil {
		return WorkflowResult{}, err
	}
	if !found || merged.Pending || !commitID(merged.Commit) {
		return WorkflowResult{}, ErrImmutable
	}
	tasks, err := workflow.tasks.Tasks(ctx, request.TenantID, request.ProjectID)
	if err != nil {
		return WorkflowResult{}, err
	}
	modules, err := completedModuleOutcomes(merged.Candidates, tasks, request.TenantID, request.ProjectID)
	if err != nil {
		return WorkflowResult{}, err
	}
	merged.Duplicate = true
	summary, summaryErr := workflow.publishSummary(ctx, request, modules, merged, task)
	return WorkflowResult{Merge: merged, Summary: summary}, summaryErr
}

func completedModuleOutcomes(candidates []Candidate, tasks []state.ModuleTask, tenantID, projectID string) ([]ModuleOutcome, error) {
	if len(candidates) == 0 || len(tasks) == 0 {
		return nil, ErrImmutable
	}
	byTask := make(map[string]state.ModuleTask, len(tasks))
	for _, task := range tasks {
		if task.TenantID != tenantID || task.ProjectID != projectID || task.ID == "" || task.ModuleID == "" {
			return nil, ErrImmutable
		}
		if _, duplicate := byTask[task.ID]; duplicate {
			return nil, ErrImmutable
		}
		byTask[task.ID] = task
	}
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		task, found := byTask[candidate.TaskID]
		if !found || candidate.ModuleID != task.ModuleID || candidate.ModuleSpecRef != task.ModuleSpecRef || !candidate.AuditPassed {
			return nil, ErrImmutable
		}
		if _, duplicate := seen[candidate.TaskID]; duplicate {
			return nil, ErrImmutable
		}
		seen[candidate.TaskID] = struct{}{}
	}
	return moduleOutcomes(candidates, tasks), nil
}

func validateWorkflowCandidates(request Request, tasks []state.ModuleTask) ([]ModuleOutcome, error) {
	if len(tasks) == 0 || len(request.Candidates) == 0 {
		return nil, ErrModulesNotReady
	}
	byID := make(map[string]state.ModuleTask, len(tasks))
	requiredPassed := make(map[string]state.ModuleTask, len(tasks))
	for _, task := range tasks {
		if task.TenantID != request.TenantID || task.ProjectID != request.ProjectID || task.ID == "" || task.ModuleID == "" {
			return nil, ErrModulesNotReady
		}
		if _, duplicate := byID[task.ID]; duplicate {
			return nil, ErrModulesNotReady
		}
		byID[task.ID] = task
		switch task.State {
		case contracts.TaskPassed:
			requiredPassed[task.ID] = task
		case contracts.TaskIntegrated, contracts.TaskCanceled, contracts.TaskSuperseded:
		default:
			return nil, ErrModulesNotReady
		}
	}
	seen := make(map[string]struct{}, len(request.Candidates))
	for _, candidate := range request.Candidates {
		task, exists := requiredPassed[candidate.TaskID]
		if !exists || candidate.ModuleID != task.ModuleID || candidate.ModuleSpecRef != task.ModuleSpecRef || !candidate.AuditPassed {
			return nil, ErrModulesNotReady
		}
		if _, duplicate := seen[candidate.TaskID]; duplicate {
			return nil, ErrModulesNotReady
		}
		seen[candidate.TaskID] = struct{}{}
	}
	if len(seen) != len(requiredPassed) {
		return nil, ErrModulesNotReady
	}
	return moduleOutcomes(request.Candidates, tasks), nil
}

func moduleOutcomes(candidates []Candidate, tasks []state.ModuleTask) []ModuleOutcome {
	byTask := make(map[string]Candidate, len(candidates))
	for _, candidate := range candidates {
		byTask[candidate.TaskID] = candidate
	}
	modules := make([]ModuleOutcome, 0, len(tasks))
	for _, task := range tasks {
		if task.State == contracts.TaskCanceled || task.State == contracts.TaskSuperseded {
			continue
		}
		candidate := byTask[task.ID]
		modules = append(modules, ModuleOutcome{
			TaskID: task.ID, ModuleID: task.ModuleID, State: task.State, Version: task.Version, Attempt: task.Attempt,
			SubmissionCommit: candidate.SubmissionCommit, EvidenceSHA256: candidate.EvidenceSHA256,
		})
	}
	sort.Slice(modules, func(left, right int) bool { return modules[left].TaskID < modules[right].TaskID })
	return modules
}

func mergeResultForTask(task IntegrationTask) MergeResult {
	return MergeResult{
		TenantID: task.TenantID, ProjectID: task.ProjectID, IntegrationID: task.ID,
		OwnerTaskID: task.OwnerTaskID, Attempt: task.Attempt, Audit: cloneAudit(task.Conflict),
	}
}

func (workflow *Workflow) publishSummary(ctx context.Context, request Request, modules []ModuleOutcome, merged MergeResult, task IntegrationTask) (PlanSupervisorSummary, error) {
	stateName := SummaryMergePending
	switch task.State {
	case TaskDone:
		stateName = SummaryReleaseCandidate
	case TaskReworkRequired:
		stateName = SummaryReworkRequired
	case TaskBlockedUserDecision:
		stateName = SummaryBlockedDecision
	}
	deviations := make([]string, 0, len(merged.Audit.Findings))
	risks := make([]string, 0, len(merged.Audit.Findings))
	for _, finding := range merged.Audit.Findings {
		deviations = append(deviations, finding.Category+": "+finding.Summary)
		if finding.Severity == "BLOCKING" {
			risks = append(risks, finding.Summary)
		}
	}
	evidence := make([]string, 0, len(modules)+len(merged.Checks)+1)
	if digestPattern(merged.Audit.EvidenceSHA256) {
		evidence = append(evidence, merged.Audit.EvidenceSHA256)
	}
	for _, module := range modules {
		if digestPattern(module.EvidenceSHA256) {
			evidence = append(evidence, module.EvidenceSHA256)
		}
	}
	checks := merged.Checks
	if len(checks) == 0 {
		checks = merged.Audit.Checks
	}
	for _, check := range checks {
		if digestPattern(check.EvidenceSHA256) {
			evidence = append(evidence, check.EvidenceSHA256)
		}
	}
	createdAt := merged.Audit.CreatedAt
	if createdAt.IsZero() {
		createdAt = workflow.clock().UTC()
	}
	summary := PlanSupervisorSummary{
		SummaryVersion: 1, TenantID: request.TenantID, ProjectID: request.ProjectID, IntegrationID: request.IntegrationID,
		State: stateName, OwnerTaskID: task.OwnerTaskID, Attempt: task.Attempt, BaseCommit: request.BaseCommit,
		IntegrationCommit: merged.Commit, RequestSHA256: merged.RequestDigest, Modules: append([]ModuleOutcome(nil), modules...),
		Checks: cloneChecks(checks), Deviations: uniqueStrings(deviations), Risks: uniqueStrings(risks),
		EvidenceSHA256: uniqueStrings(evidence), CreatedAt: createdAt,
	}
	digest, err := summaryDigest(summary)
	if err != nil {
		return PlanSupervisorSummary{}, err
	}
	summary.SummarySHA256 = digest
	if err := workflow.summaries.Publish(ctx, summary); err != nil {
		return summary, errors.Join(ErrSummaryUnavailable, err)
	}
	return summary, nil
}

func summaryDigest(summary PlanSupervisorSummary) (string, error) {
	summary.SummarySHA256 = ""
	encoded, err := json.Marshal(summary)
	if err != nil {
		return "", err
	}
	return canonicaljson.DigestObjectWithoutFields(encoded, "summarySha256")
}
