package audit

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/akimisaka/aor/internal/observability"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

var (
	ErrInvalidAuditRequest     = errors.New("invalid module audit request")
	ErrAuditServiceUnavailable = errors.New("module audit dependency unavailable")
	ErrTaskNotAuditable        = errors.New("module task is not auditable")
	ErrSubmissionNotAuditable  = errors.New("submission is not auditable")
	ErrModuleSpecNotAuditable  = errors.New("module specification is not auditable")
	ErrAuditFactsInvalid       = errors.New("authoritative audit facts are invalid")
	ErrAuditPolicyChanged      = errors.New("audit policy changed during the run")
	ErrAuditAuthorization      = errors.New("module audit authorization denied")
	ErrAuditInProgress         = errors.New("another module audit run owns the submission")
	ErrAuditRecoveryConflict   = errors.New("module audit recovery checkpoint conflicts")
)

var coordinatorIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:@/+~-]{1,256}$`)

const (
	coordinationDeterministic = "DETERMINISTIC_AUDIT"
	coordinationLLM           = "LLM_AUDIT"
	coordinationCompleted     = "COMPLETED"
	outcomeDeterministicFail  = "DETERMINISTIC_FAILURE"
	outcomeLLMSuccess         = "LLM_SUCCESS"
	outcomeLLMFailure         = "LLM_FAILURE"
)

type Coordination struct {
	TenantID            string
	ProjectID           string
	TaskID              string
	AttemptSeriesID     string
	Attempt             int
	SubmissionID        string
	AuditRunID          string
	InputSHA256         string
	Facts               RuntimeFacts
	State               string
	DeterministicSHA256 string
	EvidenceSHA256      string
	Outcome             string
}

type CoordinationStore interface {
	Get(context.Context, string, string, string, int) (Coordination, bool, error)
	Claim(context.Context, Coordination) (Coordination, bool, error)
	MarkDeterministic(context.Context, Coordination, string) (Coordination, error)
	Complete(context.Context, Coordination, string, string) (Coordination, error)
}

type ModuleAuditRequest struct {
	AuditRunID string
	TenantID   string
	ProjectID  string
	TaskID     string
	SandboxID  string
}

type ModuleAuditResult struct {
	Task      state.ModuleTask
	Evidence  contracts.EvidenceBundle
	Duplicate bool
}

type ModuleAuditServiceConfig struct {
	Tasks       TaskAuthority
	Inputs      InputSource
	Pipeline    *Pipeline
	Evidence    EvidenceStore
	Signer      Signer
	Checkpoints CoordinationStore
}

type ModuleAuditService struct {
	tasks       TaskAuthority
	inputs      InputSource
	pipeline    *Pipeline
	evidence    EvidenceStore
	signer      Signer
	checkpoints CoordinationStore
}

func NewModuleAuditService(config ModuleAuditServiceConfig) (*ModuleAuditService, error) {
	if config.Tasks == nil || config.Inputs == nil || config.Pipeline == nil || config.Evidence == nil || config.Signer == nil || config.Checkpoints == nil {
		return nil, ErrAuditServiceUnavailable
	}
	return &ModuleAuditService{
		tasks: config.Tasks, inputs: config.Inputs, pipeline: config.Pipeline,
		evidence: config.Evidence, signer: config.Signer, checkpoints: config.Checkpoints,
	}, nil
}

func (service *ModuleAuditService) Run(ctx context.Context, request ModuleAuditRequest) (result ModuleAuditResult, resultErr error) {
	if service == nil || service.tasks == nil || service.inputs == nil || service.pipeline == nil ||
		service.evidence == nil || service.signer == nil || service.checkpoints == nil ||
		ctx == nil || ctx.Err() != nil || !validAuditRunID(request.AuditRunID) ||
		!validCoordinatorID(request.TenantID) || !validCoordinatorID(request.ProjectID) || !validCoordinatorID(request.TaskID) {
		return ModuleAuditResult{}, ErrInvalidAuditRequest
	}
	ctx, traceSpan := observability.StartSpan(ctx, observability.SpanAuditCheck, observability.Correlation{
		ProjectID: request.ProjectID, WorkflowIDReason: observability.ReasonUnavailable,
		TaskID: request.TaskID, AgentRunID: request.AuditRunID,
	}, map[string]string{"aor.audit.pipeline.version": service.pipeline.version})
	attempt := 0
	defer func() {
		observability.EndSpan(ctx, traceSpan, resultErr, observability.TraceOutcome{
			Attempt: attempt, SecurityDenied: errors.Is(resultErr, ErrAuditAuthorization),
		}, nil)
	}()
	project, found, err := service.tasks.Project(ctx, request.TenantID, request.ProjectID)
	if err != nil {
		return ModuleAuditResult{}, err
	}
	if !found {
		return ModuleAuditResult{}, ErrTaskNotAuditable
	}
	task, found, err := service.tasks.Task(ctx, request.TenantID, request.ProjectID, request.TaskID)
	if err != nil {
		return ModuleAuditResult{}, err
	}
	if !found || task.Attempt < 1 || task.Attempt > 3 || task.AttemptSeriesID == "" || task.ModuleSpecRef.Validate() != nil {
		return ModuleAuditResult{}, ErrTaskNotAuditable
	}
	attempt = task.Attempt
	checkpoint, checkpointFound, err := service.checkpoints.Get(ctx, task.TenantID, task.ID, task.AttemptSeriesID, task.Attempt)
	if err != nil {
		return ModuleAuditResult{}, err
	}
	if checkpointFound && (checkpoint.AuditRunID != request.AuditRunID || !checkpointMatchesTask(checkpoint, task)) {
		return ModuleAuditResult{}, ErrAuditInProgress
	}
	if !checkpointFound && task.State != contracts.TaskSubmitted {
		return ModuleAuditResult{}, ErrAuditRecoveryConflict
	}
	var pinned *RuntimeFacts
	if checkpointFound {
		facts := checkpoint.Facts
		pinned = &facts
	} else if !validCoordinatorID(request.SandboxID) {
		return ModuleAuditResult{}, ErrInvalidAuditRequest
	}
	prepared, err := service.inputs.Load(ctx, InputRequest{
		AuditRunID: request.AuditRunID, SandboxID: request.SandboxID,
		Project: project, Task: task, Pinned: pinned,
	})
	if err != nil {
		return ModuleAuditResult{}, err
	}
	if !checkpointFound {
		checkpoint, _, err = service.checkpoints.Claim(ctx, Coordination{
			TenantID: task.TenantID, ProjectID: task.ProjectID, TaskID: task.ID,
			AttemptSeriesID: task.AttemptSeriesID, Attempt: task.Attempt,
			SubmissionID: prepared.Input.SubmissionID, AuditRunID: request.AuditRunID,
			InputSHA256: prepared.InputSHA256, Facts: prepared.Facts, State: coordinationDeterministic,
		})
		if err != nil {
			return ModuleAuditResult{}, err
		}
		checkpointFound = true
	}
	if !checkpointFound || checkpoint.InputSHA256 != prepared.InputSHA256 || checkpoint.SubmissionID != prepared.Input.SubmissionID || checkpoint.Facts != prepared.Facts {
		return ModuleAuditResult{}, ErrAuditRecoveryConflict
	}
	bundle, evidenceFound, err := service.evidence.Get(ctx, task.TenantID, task.ProjectID, task.ID, task.AttemptSeriesID, task.Attempt)
	if err != nil {
		return ModuleAuditResult{}, err
	}
	if evidenceFound {
		if err := service.verifyEvidence(ctx, bundle, prepared.Input); err != nil {
			return ModuleAuditResult{}, err
		}
		return service.finishEvidence(ctx, request, task, checkpoint, bundle, true)
	}
	if checkpoint.State == coordinationCompleted || taskTerminalAfterAudit(task.State) {
		return ModuleAuditResult{}, ErrAuditRecoveryConflict
	}
	duplicate := false
	if task.State == contracts.TaskSubmitted {
		task, duplicate, err = service.commitOrObserve(ctx, request, task, prepared.Facts.PolicyDigest, state.TaskCommand{
			Type: state.TaskCommandStartAudit, SubmissionValidated: true,
			AuditEvidenceSHA256: prepared.InputSHA256,
		}, func(value state.ModuleTask) bool {
			return value.State == contracts.TaskDeterministicAudit || value.State == contracts.TaskLLMAudit
		})
		if err != nil {
			return ModuleAuditResult{}, err
		}
	}
	if task.State != contracts.TaskDeterministicAudit && task.State != contracts.TaskLLMAudit {
		return ModuleAuditResult{}, ErrTaskNotAuditable
	}
	pipelineResult, runErr := service.pipeline.RunWithDeterministicGate(ctx, prepared.Input, func(gateContext context.Context, gateDigest string) error {
		current, exists, loadErr := service.tasks.Task(gateContext, request.TenantID, request.ProjectID, request.TaskID)
		if loadErr != nil {
			return loadErr
		}
		if !exists {
			return ErrTaskNotAuditable
		}
		if current.State == contracts.TaskDeterministicAudit {
			current, _, loadErr = service.commitOrObserve(gateContext, request, current, prepared.Facts.PolicyDigest, state.TaskCommand{
				Type: state.TaskCommandDeterministicSuccess, AuditEvidenceSHA256: gateDigest,
			}, func(value state.ModuleTask) bool { return value.State == contracts.TaskLLMAudit })
			if loadErr != nil {
				return loadErr
			}
		}
		if current.State != contracts.TaskLLMAudit {
			return ErrAuditRecoveryConflict
		}
		checkpoint, loadErr = service.checkpoints.MarkDeterministic(gateContext, checkpoint, gateDigest)
		return loadErr
	})
	if pipelineResult.Bundle.ManifestSHA256 != "" {
		if err := service.verifyEvidence(ctx, pipelineResult.Bundle, prepared.Input); err != nil {
			return ModuleAuditResult{}, err
		}
		finished, finishErr := service.finishEvidence(ctx, request, task, checkpoint, pipelineResult.Bundle, duplicate)
		if finishErr != nil {
			return ModuleAuditResult{}, finishErr
		}
		if runErr == nil || errors.Is(runErr, ErrDeterministicGate) {
			return finished, nil
		}
		return ModuleAuditResult{}, runErr
	}
	if runErr != nil {
		return ModuleAuditResult{}, runErr
	}
	return ModuleAuditResult{}, ErrAuditRecoveryConflict
}

func (service *ModuleAuditService) finishEvidence(ctx context.Context, request ModuleAuditRequest, task state.ModuleTask, checkpoint Coordination, bundle contracts.EvidenceBundle, duplicate bool) (ModuleAuditResult, error) {
	outcome, command, valid := evidenceOutcome(bundle)
	if !valid {
		return ModuleAuditResult{}, ErrAuditRecoveryConflict
	}
	if outcome != outcomeDeterministicFail && checkpoint.State == coordinationDeterministic {
		return ModuleAuditResult{}, ErrAuditRecoveryConflict
	}
	completed, err := service.checkpoints.Complete(ctx, checkpoint, bundle.ManifestSHA256, outcome)
	if err != nil {
		return ModuleAuditResult{}, err
	}
	if completed.EvidenceSHA256 != bundle.ManifestSHA256 || completed.Outcome != outcome {
		return ModuleAuditResult{}, ErrAuditRecoveryConflict
	}
	current, found, err := service.tasks.Task(ctx, request.TenantID, request.ProjectID, request.TaskID)
	if err != nil {
		return ModuleAuditResult{}, err
	}
	if !found {
		return ModuleAuditResult{}, ErrTaskNotAuditable
	}
	if auditFailureOutcome(outcome) && current.State == contracts.TaskReworkRequired {
		current, queueDuplicate, queueErr := service.queueRework(ctx, request, current, checkpoint.Facts.PolicyDigest, bundle.ManifestSHA256)
		if queueErr != nil {
			return ModuleAuditResult{}, queueErr
		}
		return ModuleAuditResult{Task: current, Evidence: cloneBundle(bundle), Duplicate: duplicate || queueDuplicate}, nil
	}
	if auditOutcomeReached(current, outcome) {
		return ModuleAuditResult{Task: current, Evidence: cloneBundle(bundle), Duplicate: true}, nil
	}
	expectedState := contracts.TaskDeterministicAudit
	if outcome != outcomeDeterministicFail {
		expectedState = contracts.TaskLLMAudit
	}
	if current.State != expectedState {
		return ModuleAuditResult{}, ErrAuditRecoveryConflict
	}
	current, commandDuplicate, err := service.commitOrObserve(ctx, request, current, checkpoint.Facts.PolicyDigest, command, func(value state.ModuleTask) bool {
		return auditOutcomeReached(value, outcome)
	})
	if err != nil {
		return ModuleAuditResult{}, err
	}
	if auditFailureOutcome(outcome) && current.State == contracts.TaskReworkRequired {
		var queueDuplicate bool
		current, queueDuplicate, err = service.queueRework(ctx, request, current, checkpoint.Facts.PolicyDigest, bundle.ManifestSHA256)
		if err != nil {
			return ModuleAuditResult{}, err
		}
		commandDuplicate = commandDuplicate || queueDuplicate
	}
	return ModuleAuditResult{Task: current, Evidence: cloneBundle(bundle), Duplicate: duplicate || commandDuplicate}, nil
}

func (service *ModuleAuditService) queueRework(ctx context.Context, request ModuleAuditRequest, task state.ModuleTask, policyDigest, evidenceSHA256 string) (state.ModuleTask, bool, error) {
	return service.commitOrObserve(ctx, request, task, policyDigest, state.TaskCommand{
		Type: state.TaskCommandQueueRework, AuditEvidenceSHA256: evidenceSHA256,
	}, func(value state.ModuleTask) bool {
		return reworkExecutionStarted(value)
	})
}

func (service *ModuleAuditService) commitOrObserve(ctx context.Context, request ModuleAuditRequest, task state.ModuleTask, policyDigest string, command state.TaskCommand, reached func(state.ModuleTask) bool) (state.ModuleTask, bool, error) {
	updated, duplicate, err := service.tasks.Commit(ctx, TaskCommitRequest{
		AuditRunID: request.AuditRunID, TenantID: request.TenantID, ProjectID: request.ProjectID,
		TaskID: request.TaskID, ExpectedVersion: task.Version, PolicyDigest: policyDigest, Command: command,
	})
	if err == nil {
		if !reached(updated) {
			return state.ModuleTask{}, false, ErrAuditRecoveryConflict
		}
		return updated, duplicate, nil
	}
	current, found, loadErr := service.tasks.Task(ctx, request.TenantID, request.ProjectID, request.TaskID)
	if loadErr == nil && found && reached(current) {
		return current, true, nil
	}
	if loadErr != nil {
		return state.ModuleTask{}, false, loadErr
	}
	return state.ModuleTask{}, false, err
}

func (service *ModuleAuditService) verifyEvidence(ctx context.Context, bundle contracts.EvidenceBundle, input DeterministicInput) error {
	if bundle.Validate() != nil || bundle.ProjectID != input.Manifest.ProjectID || bundle.TaskID != input.Manifest.ModuleTaskID ||
		bundle.AttemptSeriesID != input.Manifest.AttemptSeriesID || bundle.Attempt != input.Manifest.Attempt ||
		bundle.SpecVersion != input.ModuleSpecRef.Version || bundle.BaseCommit != input.Manifest.BaseCommit ||
		bundle.SubmissionCommit != input.Manifest.HeadCommit || bundle.PolicyBundleDigest != input.PolicyDigest ||
		bundle.ExecutionPlatform != input.Platform || bundle.IsolationLevel != input.Isolation ||
		bundle.SandboxAttestation != input.SandboxAttestation {
		return ErrAuditRecoveryConflict
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(encoded, "manifestSha256", "signature")
	if err != nil || digest != bundle.ManifestSHA256 || bundle.Signature == nil {
		return ErrAuditRecoveryConflict
	}
	signature := *bundle.Signature
	unsigned := cloneBundle(bundle)
	unsigned.Signature = nil
	payload, err := json.Marshal(unsigned)
	if err != nil || service.signer.Verify(ctx, payload, &signature) != nil {
		return ErrAuditRecoveryConflict
	}
	return nil
}

func evidenceOutcome(bundle contracts.EvidenceBundle) (string, state.TaskCommand, bool) {
	command := state.TaskCommand{AuditEvidenceSHA256: bundle.ManifestSHA256}
	if bundle.LLMAudit.Verdict == "NOT_RUN" {
		for _, check := range bundle.Checks {
			if check.Status != "PASS" {
				command.Type = state.TaskCommandDeterministicFailure
				return outcomeDeterministicFail, command, true
			}
		}
		return "", state.TaskCommand{}, false
	}
	command.FreshAuditor = true
	command.BlindAuditContext = true
	if bundle.LLMAudit.Verdict == "PASS" && bundle.PassesAuditGate() {
		command.Type = state.TaskCommandLLMSuccess
		command.NoBlockingFindings = true
		return outcomeLLMSuccess, command, true
	}
	if bundle.LLMAudit.Verdict == "FAIL" || bundle.LLMAudit.Verdict == "INCONCLUSIVE" || bundle.LLMAudit.Verdict == "PASS" {
		command.Type = state.TaskCommandLLMFailure
		return outcomeLLMFailure, command, true
	}
	return "", state.TaskCommand{}, false
}

func auditOutcomeReached(task state.ModuleTask, outcome string) bool {
	switch outcome {
	case outcomeLLMSuccess:
		return task.State == contracts.TaskPassed || task.State == contracts.TaskIntegrated
	case outcomeDeterministicFail, outcomeLLMFailure:
		return task.State == contracts.TaskReworkRequired || reworkExecutionStarted(task) || task.State == contracts.TaskBlockedUserDecision
	default:
		return false
	}
}

func reworkExecutionStarted(task state.ModuleTask) bool {
	return task.State == contracts.TaskReadyExecution || task.State == contracts.TaskExecuting
}

func auditFailureOutcome(outcome string) bool {
	return outcome == outcomeDeterministicFail || outcome == outcomeLLMFailure
}

func checkpointMatchesTask(checkpoint Coordination, task state.ModuleTask) bool {
	return checkpoint.TenantID == task.TenantID && checkpoint.ProjectID == task.ProjectID && checkpoint.TaskID == task.ID &&
		checkpoint.AttemptSeriesID == task.AttemptSeriesID && checkpoint.Attempt == task.Attempt
}

func taskTerminalAfterAudit(value contracts.ModuleTaskState) bool {
	return value == contracts.TaskReworkRequired || value == contracts.TaskBlockedUserDecision || value == contracts.TaskPassed || value == contracts.TaskIntegrated
}

func validCoordinatorID(value string) bool {
	return coordinatorIDPattern.MatchString(value) && !strings.ContainsAny(value, "\x00\r\n")
}
