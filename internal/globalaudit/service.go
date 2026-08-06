package globalaudit

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/observability"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/aop"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

var (
	ErrInvalidRequest     = errors.New("invalid global audit request")
	ErrProjectNotReady    = errors.New("project is not ready for global audit")
	ErrRuntimeUnavailable = errors.New("global auditor runtime unavailable")
	ErrRunInProgress      = errors.New("global audit run is already in progress")
)

type Request struct {
	RunID     string
	TenantID  string
	ProjectID string
}

type Result struct {
	Report         Report
	EvidenceSHA256 string
	Followups      FollowupResult
	Duplicate      bool
}

type FollowupCreator interface {
	Create(context.Context, Report, string) (FollowupResult, error)
}

type ProjectReader interface {
	Project(context.Context, string, string) (state.Project, bool, error)
}

type PreparedRun struct {
	Declaration        agentruntime.Declaration
	Lease              agentruntime.AgentLease
	ModelCall          agentruntime.ModelCall
	MaxToolRounds      int
	ReleaseCommit      string
	RequiredCriteria   []string
	ExecutionPlatform  contracts.ExecutionPlatform
	IsolationLevel     contracts.IsolationLevel
	SandboxImageDigest string
	Environment        EnvironmentSession
}

// Preparer must load the approved GoalSpec, published PlanSpec, integrated
// release, deterministic integration evidence, policy, prompt and lease from
// authoritative services. Request fields are identities, not evidence.
type Preparer interface {
	Prepare(context.Context, Request, state.Project) (PreparedRun, error)
	Release(context.Context, PreparedRun) error
}

type Runtime interface {
	Declare(agentruntime.Declaration) error
	Queue(string) error
	AssignLease(context.Context, string, agentruntime.AgentLease) error
	Start(context.Context, string) error
	RunToolLoop(context.Context, string, agentruntime.ModelCall, int) (modelgateway.NormalizedResponse, error)
	Complete(context.Context, string, agentruntime.AgentOutput) (agentruntime.AcceptedResult, error)
	AcceptedResult(string) (agentruntime.AcceptedResult, bool)
	Fail(string) error
}

type Config struct {
	Projects        ProjectReader
	Preparer        Preparer
	Runtime         Runtime
	Store           Store
	Signer          Signer
	Followups       FollowupCreator
	PipelineVersion string
}

type Service struct {
	projects        ProjectReader
	preparer        Preparer
	runtime         Runtime
	store           Store
	signer          Signer
	followups       FollowupCreator
	pipelineVersion string
}

func New(config Config) (*Service, error) {
	if config.Projects == nil || config.Preparer == nil || config.Runtime == nil || config.Store == nil || config.Signer == nil || config.Followups == nil || !versionPattern.MatchString(config.PipelineVersion) {
		return nil, ErrRuntimeUnavailable
	}
	return &Service{
		projects: config.Projects, preparer: config.Preparer, runtime: config.Runtime,
		store: config.Store, signer: config.Signer, followups: config.Followups, pipelineVersion: config.PipelineVersion,
	}, nil
}

func (service *Service) Run(ctx context.Context, request Request) (result Result, err error) {
	if service == nil || ctx == nil || ctx.Err() != nil || !uuidV7(request.RunID) || !canonicalUUID(request.TenantID) || !canonicalUUID(request.ProjectID) {
		return Result{}, ErrInvalidRequest
	}
	ctx, traceSpan := observability.StartSpan(ctx, observability.SpanAuditCheck, observability.Correlation{
		ProjectID: request.ProjectID, WorkflowIDReason: observability.ReasonUnavailable,
		TaskIDReason: observability.ReasonNotApplicable, AgentRunID: request.RunID,
	}, map[string]string{"aor.audit.pipeline.version": service.pipelineVersion})
	defer func() { observability.EndSpan(ctx, traceSpan, err, observability.TraceOutcome{}, nil) }()
	project, found, err := service.projects.Project(ctx, request.TenantID, request.ProjectID)
	if err != nil {
		return Result{}, err
	}
	if !found {
		return Result{}, ErrProjectNotReady
	}
	if report, exists, lookupErr := service.store.Get(ctx, request.TenantID, request.RunID); lookupErr != nil {
		return Result{}, lookupErr
	} else if exists {
		if !reportMatchesProject(report, project) {
			return Result{}, ErrInvalidReport
		}
		return service.finish(ctx, report, resultFor(report, true).EvidenceSHA256, true)
	}
	if !validProject(project, request) {
		return Result{}, ErrProjectNotReady
	}

	prepared, err := service.preparer.Prepare(ctx, request, project)
	if err != nil {
		return Result{}, err
	}
	activeEnvironment := prepared.Environment.ID != ""
	releasedEnvironment := false
	releaseEnvironment := func() error {
		if !activeEnvironment || releasedEnvironment {
			return nil
		}
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		releaseErr := service.preparer.Release(cleanupContext, prepared)
		cancel()
		if releaseErr == nil {
			releasedEnvironment = true
		}
		return releaseErr
	}
	defer func() {
		if !activeEnvironment || releasedEnvironment {
			return
		}
		if cleanupErr := releaseEnvironment(); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()
	if err := validatePreparedRun(request, project, prepared); err != nil {
		return Result{}, err
	}
	accepted, err := service.execute(ctx, prepared)
	if err != nil {
		return Result{}, err
	}
	var decision Decision
	if err := decodeStrict(accepted.Payload, &decision); err != nil {
		return Result{}, ErrInvalidReport
	}
	if err := releaseEnvironment(); err != nil {
		return Result{}, err
	}
	report := Report{
		ReportVersion: ReportVersion, RunID: request.RunID, TenantID: request.TenantID, ProjectID: request.ProjectID,
		GoalSpecRef: projectGoalRef(project), PlanSpecRef: *project.Plan, ReleaseCommit: prepared.ReleaseCommit,
		PipelineVersion: service.pipelineVersion, ExecutionPlatform: prepared.ExecutionPlatform,
		IsolationLevel: prepared.IsolationLevel, SandboxImageDigest: prepared.SandboxImageDigest,
		AuditorAgentID: prepared.Declaration.AgentInstanceID,
		ModelIdentity:  prepared.ModelCall.Provider + "/" + prepared.ModelCall.Model,
		PromptDigest:   accepted.PromptDigest, ContextManifestDigest: accepted.ContextDigest,
		Verdict: decision.Verdict, FocusResults: decision.FocusResults, CriteriaResults: decision.CriteriaResults,
		Findings: decision.Findings, ResidualRisks: decision.ResidualRisks, Confidence: decision.Confidence,
		StartedAt: prepared.Lease.IssuedAt, CompletedAt: accepted.AcceptedAt,
	}
	report, err = Finalize(ctx, report, service.signer)
	if err != nil || !criteriaMatch(prepared.RequiredCriteria, report.CriteriaResults) {
		return Result{}, ErrInvalidReport
	}
	if report.Verdict == "PASS" && !report.PassesGate() {
		report.Verdict = "FAIL"
		report, err = Finalize(ctx, report, service.signer)
		if err != nil {
			return Result{}, err
		}
	}
	evidenceSHA256, err := service.store.Put(ctx, report)
	if err != nil {
		if recovered, exists, recoveryErr := service.store.Get(ctx, request.TenantID, request.RunID); recoveryErr == nil && exists && sameReport(recovered, report) {
			return service.finish(ctx, recovered, resultFor(recovered, true).EvidenceSHA256, true)
		}
		return Result{}, err
	}
	return service.finish(ctx, report, evidenceSHA256, false)
}

func (service *Service) finish(ctx context.Context, report Report, evidenceSHA256 string, duplicate bool) (Result, error) {
	followups, err := service.followups.Create(ctx, report, evidenceSHA256)
	if err != nil {
		return Result{}, err
	}
	return Result{Report: report, EvidenceSHA256: evidenceSHA256, Followups: followups, Duplicate: duplicate}, nil
}

func (service *Service) execute(ctx context.Context, prepared PreparedRun) (acceptedResult agentruntime.AcceptedResult, resultErr error) {
	runID := prepared.Declaration.RunID
	ctx, traceSpan := observability.StartSpan(ctx, observability.SpanAuditLLM, observability.Correlation{
		ProjectID: prepared.Declaration.ProjectID, WorkflowIDReason: observability.ReasonUnavailable,
		TaskIDReason: observability.ReasonNotApplicable, AgentRunID: runID,
	}, map[string]string{
		"aor.agent.id":         prepared.Declaration.AgentInstanceID,
		"aor.agent.role":       string(prepared.Declaration.Role),
		"aor.policy.version":   prepared.Declaration.PolicyVersion,
		"aor.prompt.version":   prepared.Declaration.PromptBundle.Version,
		"gen_ai.provider.name": prepared.ModelCall.Provider,
		"gen_ai.request.model": prepared.ModelCall.Model,
	})
	var modelResponse modelgateway.NormalizedResponse
	defer func() {
		attributes := map[string]string{
			"gen_ai.response.model":      modelResponse.ModelVersion,
			"gen_ai.usage.input_tokens":  strconv.FormatInt(modelResponse.Usage.InputTokens, 10),
			"gen_ai.usage.output_tokens": strconv.FormatInt(modelResponse.Usage.OutputTokens, 10),
		}
		if modelResponse.ModelVersion == "" {
			attributes["gen_ai.response.model"] = "UNAVAILABLE"
		}
		observability.EndSpan(ctx, traceSpan, resultErr, observability.TraceOutcome{}, attributes)
	}()
	if err := service.runtime.Declare(prepared.Declaration); err != nil {
		if errors.Is(err, agentruntime.ErrRunExists) {
			accepted, found := service.runtime.AcceptedResult(runID)
			if !found || !validAcceptedResult(accepted, prepared) {
				return agentruntime.AcceptedResult{}, ErrRunInProgress
			}
			return accepted, nil
		}
		return agentruntime.AcceptedResult{}, err
	}
	fail := func(cause error) (agentruntime.AcceptedResult, error) {
		_ = service.runtime.Fail(runID)
		return agentruntime.AcceptedResult{}, cause
	}
	if err := service.runtime.Queue(runID); err != nil {
		return fail(err)
	}
	if err := service.runtime.AssignLease(ctx, runID, prepared.Lease); err != nil {
		return fail(err)
	}
	if err := service.runtime.Start(ctx, runID); err != nil {
		return fail(err)
	}
	modelResponse, err := service.runtime.RunToolLoop(ctx, runID, prepared.ModelCall, prepared.MaxToolRounds)
	if err != nil {
		return fail(err)
	}
	if modelResponse.RequestID != prepared.ModelCall.RequestID || modelResponse.ModelVersion != prepared.ModelCall.Model || len(modelResponse.Content) == 0 {
		return fail(ErrInvalidReport)
	}
	accepted, err := service.runtime.Complete(ctx, runID, agentruntime.AgentOutput{Intent: aop.IntentReportGlobalAudit, Payload: append(json.RawMessage(nil), modelResponse.Content...)})
	if err != nil {
		return fail(err)
	}
	if !validAcceptedResult(accepted, prepared) {
		return agentruntime.AcceptedResult{}, ErrInvalidReport
	}
	return accepted, nil
}

func validatePreparedRun(request Request, project state.Project, prepared PreparedRun) error {
	declaration := prepared.Declaration
	envelope := declaration.Envelope
	goalRef := projectGoalRef(project)
	if declaration.RunID != request.RunID || declaration.TenantID != request.TenantID || declaration.ProjectID != request.ProjectID || declaration.TaskID != "" ||
		declaration.Role != agentruntime.RoleGlobalAuditor || declaration.AgentInstanceID == "" || envelope.ProjectID != request.ProjectID || envelope.TaskID != "" ||
		envelope.Scope != aop.ScopeProject || envelope.Intent != aop.IntentReportGlobalAudit || envelope.ExpectedAggregateVersion != project.Version ||
		envelope.GoalSpec == nil || *envelope.GoalSpec != goalRef || envelope.PlanSpec == nil || *envelope.PlanSpec != *project.Plan || envelope.ModuleSpec != nil ||
		envelope.Sender.AgentInstanceID != declaration.AgentInstanceID || envelope.Sender.Role != string(agentruntime.RoleGlobalAuditor) ||
		prepared.Lease.AgentInstanceID != declaration.AgentInstanceID || prepared.Lease.TenantID != request.TenantID || prepared.Lease.ProjectID != request.ProjectID ||
		prepared.Lease.TaskID != "" || prepared.Lease.Role != agentruntime.RoleGlobalAuditor || prepared.Lease.LeaseID != envelope.Sender.LeaseID ||
		prepared.ModelCall.RequestID == "" || !safeText(prepared.ModelCall.Provider, 256) || !safeText(prepared.ModelCall.Model, 256) ||
		prepared.MaxToolRounds < 1 || prepared.MaxToolRounds > agentruntime.MaximumNativeToolRounds || !commitPattern.MatchString(prepared.ReleaseCommit) ||
		prepared.ExecutionPlatform != contracts.PlatformLinux || prepared.IsolationLevel != contracts.IsolationContainer || !digestPattern.MatchString(prepared.SandboxImageDigest) ||
		!validEnvironmentSession(prepared.Environment) || prepared.Environment.Facts.ExecutionPlatform != prepared.ExecutionPlatform ||
		prepared.Environment.Facts.IsolationLevel != prepared.IsolationLevel || prepared.Environment.Facts.SandboxImageDigest != prepared.SandboxImageDigest ||
		!validCriteria(prepared.RequiredCriteria) || declaration.ResponseSchemaRef != DecisionSchemaReference || !sameDecisionSchema(declaration.ResponseSchema) ||
		!readOnlyTools(declaration.Tools) {
		return ErrInvalidRequest
	}
	return nil
}

func validAcceptedResult(accepted agentruntime.AcceptedResult, prepared PreparedRun) bool {
	return accepted.RunID == prepared.Declaration.RunID && accepted.Intent == aop.IntentReportGlobalAudit && len(accepted.Payload) > 0 &&
		digestPattern.MatchString(accepted.PromptDigest) && accepted.ContextDigest == prepared.Declaration.ContextManifest.SHA256 &&
		!accepted.AcceptedAt.IsZero() && !accepted.AcceptedAt.Before(prepared.Lease.IssuedAt)
}

func globalAuditResponseSemanticValidator(requiredCriteria []string) func(json.RawMessage) error {
	required := append([]string(nil), requiredCriteria...)
	return func(content json.RawMessage) error {
		var decision Decision
		if err := decodeStrict(content, &decision); err != nil || validateDecision(decision) != nil || !criteriaMatch(required, decision.CriteriaResults) {
			return ErrInvalidReport
		}
		return nil
	}
}

func validProject(project state.Project, request Request) bool {
	return project.TenantID == request.TenantID && project.ID == request.ProjectID && project.State == contracts.ProjectGlobalAudit &&
		project.Version > 0 && project.Goal != nil && project.Goal.Status == contracts.GoalApproved && project.Goal.ApprovedBy != "" &&
		project.Goal.ApprovalRecordID != "" && project.Plan != nil && project.Plan.Validate() == nil
}

func reportMatchesProject(report Report, project state.Project) bool {
	return report.Validate() == nil && report.TenantID == project.TenantID && report.ProjectID == project.ID &&
		report.GoalSpecRef == projectGoalRef(project) && project.Plan != nil && report.PlanSpecRef == *project.Plan
}

func projectGoalRef(project state.Project) contracts.SpecRef {
	if project.Goal == nil {
		return contracts.SpecRef{}
	}
	return contracts.SpecRef{Version: project.Goal.Version, SHA256: project.Goal.SHA256}
}

func validCriteria(criteria []string) bool {
	if len(criteria) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(criteria))
	for _, criterion := range criteria {
		if !safeText(criterion, 4096) {
			return false
		}
		if _, exists := seen[criterion]; exists {
			return false
		}
		seen[criterion] = struct{}{}
	}
	return true
}

func criteriaMatch(required []string, results []contracts.CriterionResult) bool {
	if len(required) != len(results) {
		return false
	}
	expected := append([]string(nil), required...)
	actual := make([]string, len(results))
	for index := range results {
		actual[index] = results[index].CriterionID
	}
	sort.Strings(expected)
	sort.Strings(actual)
	for index := range expected {
		if expected[index] != actual[index] {
			return false
		}
	}
	return true
}

func sameDecisionSchema(value json.RawMessage) bool {
	expected, expectedErr := canonicaljson.Digest(decisionSchema)
	actual, actualErr := canonicaljson.Digest(value)
	return expectedErr == nil && actualErr == nil && expected == actual
}

func readOnlyTools(tools []modelgateway.ToolDefinition) bool {
	allowed := map[string]struct{}{
		"artifact.read": {}, "knowledge.read_range": {}, "knowledge.search": {}, "repository.file.read": {},
	}
	seen := make(map[string]struct{}, len(tools))
	hasRepositoryRead := false
	for _, tool := range tools {
		if _, found := allowed[tool.Name]; !found || tool.Version == "" || tool.Validate() != nil {
			return false
		}
		if _, duplicate := seen[tool.Name]; duplicate {
			return false
		}
		seen[tool.Name] = struct{}{}
		hasRepositoryRead = hasRepositoryRead || tool.Name == requiredGlobalAuditRepositoryTool
	}
	return hasRepositoryRead
}

func resultFor(report Report, duplicate bool) Result {
	encoded, _ := json.Marshal(report)
	return Result{Report: report, EvidenceSHA256: digestBytes(encoded), Duplicate: duplicate}
}

func sameReport(left, right Report) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes)
}
