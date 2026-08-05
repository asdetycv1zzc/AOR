package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/leaseauthority"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/observability"
	"github.com/akimisaka/aor/pkg/aop"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/akimisaka/aor/prompts"
)

var (
	ErrRuntimeAuditorUnavailable = errors.New("module auditor runtime unavailable")
	ErrRuntimeAuditorInProgress  = errors.New("module auditor run is already in progress")
	ErrRuntimeAuditorOutput      = errors.New("module auditor output is invalid")
)

// ModuleAuditReferences are immutable control-plane references required to
// bind an auditor declaration. They are resolved from authoritative state;
// BlindAuditInput remains limited to submission and deterministic evidence.
type ModuleAuditReferences struct {
	TenantID           string
	ProjectVersion     int64
	TaskVersion        int64
	GoalSpec           contracts.SpecRef
	PlanSpec           contracts.SpecRef
	DataClassification string
}

type ModuleAuditReferenceSource interface {
	Resolve(context.Context, BlindAuditInput) (ModuleAuditReferences, error)
}

type ModuleAuditRuntime interface {
	Declare(agentruntime.Declaration) error
	Queue(string) error
	AssignLease(context.Context, string, agentruntime.AgentLease) error
	Start(context.Context, string) error
	RunToolLoop(context.Context, string, agentruntime.ModelCall, int) (modelgateway.NormalizedResponse, error)
	Complete(context.Context, string, agentruntime.AgentOutput) (agentruntime.AcceptedResult, error)
	AcceptedResult(string) (agentruntime.AcceptedResult, bool)
	Fail(string) error
}

type ModuleAuditLeaseIssuer interface {
	Issue(context.Context, authn.Principal, leaseauthority.GrantRequest) (authz.CapabilityLease, error)
}

type RuntimeAuditorFactoryConfig struct {
	Runtime       ModuleAuditRuntime
	References    ModuleAuditReferenceSource
	Leases        ModuleAuditLeaseIssuer
	Routes        goalplan.ModelRoute
	Tools         []modelgateway.ToolDefinition
	LeaseTTL      time.Duration
	MaxToolRounds int
	Clock         func() time.Time
}

type RuntimeAuditorFactory struct {
	runtime    ModuleAuditRuntime
	references ModuleAuditReferenceSource
	leases     ModuleAuditLeaseIssuer
	route      goalplan.ModelRoute
	tools      []modelgateway.ToolDefinition
	leaseTTL   time.Duration
	maxRounds  int
	clock      func() time.Time
}

func NewRuntimeAuditorFactory(config RuntimeAuditorFactoryConfig) (*RuntimeAuditorFactory, error) {
	if config.Runtime == nil || config.References == nil || config.Leases == nil || !validModuleAuditRoute(config.Routes) {
		return nil, ErrRuntimeAuditorUnavailable
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.LeaseTTL == 0 {
		config.LeaseTTL = 5 * time.Minute
	}
	if config.LeaseTTL < time.Duration(agentruntime.DefaultHeartbeatSeconds*agentruntime.MissedHeartbeatLimit)*time.Second || config.LeaseTTL > 15*time.Minute {
		return nil, ErrRuntimeAuditorUnavailable
	}
	if config.MaxToolRounds == 0 {
		config.MaxToolRounds = agentruntime.MaximumNativeToolRounds
	}
	if config.MaxToolRounds < 1 || config.MaxToolRounds > agentruntime.MaximumNativeToolRounds {
		return nil, ErrRuntimeAuditorUnavailable
	}
	tools, err := moduleAuditTools(config.Tools)
	if err != nil {
		return nil, err
	}
	return &RuntimeAuditorFactory{runtime: config.Runtime, references: config.References, leases: config.Leases, route: cloneModelRoute(config.Routes), tools: tools, leaseTTL: config.LeaseTTL, maxRounds: config.MaxToolRounds, clock: config.Clock}, nil
}

func (factory *RuntimeAuditorFactory) New(ctx context.Context) (Auditor, error) {
	if factory == nil || factory.runtime == nil || factory.references == nil || factory.leases == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrRuntimeAuditorUnavailable
	}
	return &runtimeAuditor{factory: factory}, nil
}

type runtimeAuditor struct{ factory *RuntimeAuditorFactory }

type moduleAuditResponse struct {
	Verdict         string                      `json:"verdict"`
	Findings        []contracts.AuditFinding    `json:"findings"`
	CriteriaResults []contracts.CriterionResult `json:"criteriaResults"`
	ResidualRisks   []string                    `json:"residualRisks"`
	Confidence      float64                     `json:"confidence"`
}

func (auditor *runtimeAuditor) Audit(ctx context.Context, input BlindAuditInput) (LLMAuditResult, error) {
	if auditor == nil || auditor.factory == nil || ctx == nil || ctx.Err() != nil || validateBlindInput(input) != nil || !validAuditRunID(input.AuditRunID) || input.TenantID == "" || input.AttemptSeriesID == "" {
		return LLMAuditResult{}, ErrBlindContext
	}
	refs, err := auditor.factory.references.Resolve(ctx, input)
	if err != nil {
		return LLMAuditResult{}, err
	}
	if err := validModuleAuditReferences(refs, input); err != nil {
		return LLMAuditResult{}, err
	}
	prepared, err := auditor.prepare(ctx, input, refs)
	if err != nil {
		return LLMAuditResult{}, err
	}
	accepted, err := auditor.execute(ctx, prepared)
	if err != nil {
		return LLMAuditResult{}, err
	}
	if accepted.RunID != prepared.declaration.RunID || accepted.Intent != aop.IntentReportLLMAudit || accepted.ContextDigest != prepared.declaration.ContextManifest.SHA256 || !validAuditDigest(accepted.PromptDigest) || len(accepted.Payload) == 0 {
		return LLMAuditResult{}, ErrRuntimeAuditorOutput
	}
	var response moduleAuditResponse
	if err := decodeStrictAudit(accepted.Payload, &response); err != nil {
		return LLMAuditResult{}, ErrRuntimeAuditorOutput
	}
	if response.Findings == nil || response.CriteriaResults == nil || response.ResidualRisks == nil || math.IsNaN(response.Confidence) || math.IsInf(response.Confidence, 0) || response.Confidence < 0 || response.Confidence > 1 || !criteriaMatch(input.RequiredCriteria, response.CriteriaResults) {
		return LLMAuditResult{}, ErrRuntimeAuditorOutput
	}
	for _, finding := range response.Findings {
		if finding.Validate() != nil {
			return LLMAuditResult{}, ErrRuntimeAuditorOutput
		}
	}
	for _, criterion := range response.CriteriaResults {
		if criterion.Validate() != nil {
			return LLMAuditResult{}, ErrRuntimeAuditorOutput
		}
	}
	for _, risk := range response.ResidualRisks {
		if strings.TrimSpace(risk) != risk || risk == "" || strings.ContainsAny(risk, "\x00\r\n") {
			return LLMAuditResult{}, ErrRuntimeAuditorOutput
		}
	}
	return LLMAuditResult{AuditorRunID: input.AuditRunID, ModelIdentity: prepared.modelCall.Provider + "/" + prepared.modelCall.Model, PromptDigest: accepted.PromptDigest, ContextDigest: accepted.ContextDigest, Verdict: response.Verdict, Findings: response.Findings, CriteriaResults: response.CriteriaResults, ResidualRisks: response.ResidualRisks, Confidence: response.Confidence}, nil
}

type preparedModuleAudit struct {
	declaration agentruntime.Declaration
	lease       agentruntime.AgentLease
	modelCall   agentruntime.ModelCall
}

func (auditor *runtimeAuditor) prepare(ctx context.Context, input BlindAuditInput, refs ModuleAuditReferences) (preparedModuleAudit, error) {
	bundle, err := loadModuleAuditorPrompt()
	if err != nil {
		return preparedModuleAudit{}, ErrRuntimeAuditorUnavailable
	}
	items, err := moduleAuditContextItems(input, refs)
	if err != nil {
		return preparedModuleAudit{}, err
	}
	manifest := agentruntime.ContextManifest{ManifestID: stableModuleAuditID("module-audit-context-", input.AuditRunID), Version: "1", Role: agentruntime.RoleModuleAuditor, Items: items}
	manifest.SHA256 = agentruntime.DigestContextManifest(manifest)
	if err := agentruntime.ValidateContextManifest(manifest); err != nil {
		return preparedModuleAudit{}, err
	}
	responseDigest, err := canonicaljson.Digest(moduleAuditDecisionSchema)
	if err != nil {
		return preparedModuleAudit{}, err
	}
	parameterDigest, err := moduleAuditParameterDigest(input, refs, bundle, manifest, responseDigest, auditor.factory.route, auditor.factory.tools)
	if err != nil {
		return preparedModuleAudit{}, err
	}
	agentID := stableModuleAuditID("module-auditor-", input.AuditRunID, input.TaskID)
	principal := authn.Principal{ID: agentID, Type: authn.PrincipalAgentInstance, Role: string(agentruntime.RoleModuleAuditor), TenantID: refs.TenantID, ProjectID: input.ProjectID}
	leaseContext, err := authn.ContextWithPrincipal(ctx, principal)
	if err != nil {
		return preparedModuleAudit{}, ErrRuntimeAuditorUnavailable
	}
	resource := authz.Resource{Type: "model", ID: auditor.factory.route.Provider + "/" + auditor.factory.route.Model}
	lease, err := auditor.factory.leases.Issue(leaseContext, principal, leaseauthority.GrantRequest{TenantID: refs.TenantID, ProjectID: input.ProjectID, TaskID: input.TaskID, Action: authz.ActionModelGenerate, Resource: resource, ParameterDigest: parameterDigest, BudgetAccountID: input.ProjectID, IdempotencyKey: stableModuleAuditID("module-audit-lease-", input.AuditRunID, parameterDigest), TTL: auditor.factory.leaseTTL})
	if err != nil {
		return preparedModuleAudit{}, err
	}
	now := auditor.factory.clock().UTC()
	if !validModuleAuditLease(lease, principal, input, refs, resource, parameterDigest, now) {
		return preparedModuleAudit{}, ErrRuntimeAuditorUnavailable
	}
	trace, found := observability.TraceFromContext(ctx)
	if !found {
		trace, err = observability.NewRootTraceContext(false)
		if err != nil {
			return preparedModuleAudit{}, err
		}
	}
	traceparent, err := trace.TraceParent()
	if err != nil {
		return preparedModuleAudit{}, err
	}
	goalRef, planRef, moduleRef := refs.GoalSpec, refs.PlanSpec, input.ModuleSpecRef
	envelope := aop.Envelope{AOPVersion: aop.Version, MessageID: stableModuleAuditID("module-audit-message-", input.AuditRunID), IdempotencyKey: stableModuleAuditID("module-audit-aop-", input.AuditRunID), CorrelationID: stableModuleAuditID("module-audit-correlation-", refs.TenantID, input.ProjectID, input.AuditRunID), ProjectID: input.ProjectID, GoalSpec: &goalRef, PlanSpec: &planRef, ModuleSpec: &moduleRef, TaskID: input.TaskID, AttemptSeriesID: input.AttemptSeriesID, Attempt: input.Attempt, Sender: aop.Sender{AgentInstanceID: agentID, Role: string(agentruntime.RoleModuleAuditor), Provider: auditor.factory.route.Provider, Model: auditor.factory.route.Model, LeaseID: lease.ID}, Scope: aop.ScopeTask, Intent: aop.IntentReportLLMAudit, ExpectedAggregateVersion: refs.TaskVersion, ArtifactRefs: []string{}, KnowledgeRefs: []string{}, BudgetContext: &aop.BudgetContext{AccountID: input.ProjectID, ReservationID: stableModuleAuditID("module-audit-reservation-", input.AuditRunID, parameterDigest)}, TraceContext: &aop.TraceContext{Traceparent: traceparent, Tracestate: trace.TraceState}, CreatedAt: lease.IssuedAt, ExpiresAt: lease.ExpiresAt}
	if envelope.Validate(now) != nil {
		return preparedModuleAudit{}, ErrRuntimeAuditorUnavailable
	}
	declaration := agentruntime.Declaration{RunID: input.AuditRunID, Envelope: envelope, TenantID: refs.TenantID, ProjectID: input.ProjectID, TaskID: input.TaskID, AgentInstanceID: agentID, Role: agentruntime.RoleModuleAuditor, PromptBundle: bundle, ContextManifest: manifest, ResponseSchemaRef: ModuleAuditDecisionSchemaReference, ResponseSchema: ModuleAuditDecisionSchema(), Tools: cloneModelTools(auditor.factory.tools), ToolSchemaDigest: agentruntime.DigestToolDefinitions(auditor.factory.tools), PolicyVersion: lease.PolicyVersion, PolicyDigest: lease.PolicyVersion, DataClassification: refs.DataClassification}
	if _, err := agentruntime.AssemblePrompt(bundle, manifest, declaration.ResponseSchemaRef, declaration.ResponseSchema); err != nil {
		return preparedModuleAudit{}, err
	}
	return preparedModuleAudit{declaration: declaration, lease: toAgentLease(lease), modelCall: agentruntime.ModelCall{RequestID: stableModuleAuditID("module-audit-request-", input.AuditRunID, parameterDigest), Provider: auditor.factory.route.Provider, Model: auditor.factory.route.Model, ReservationID: stableModuleAuditID("module-audit-reservation-", input.AuditRunID, parameterDigest), MaxOutputTokens: auditor.factory.route.MaxOutputTokens, Temperature: auditor.factory.route.Temperature, Seed: cloneSeed(auditor.factory.route.Seed), ProviderPolicy: auditor.factory.route.ProviderPolicy, CachePolicy: auditor.factory.route.CachePolicy, WorstCaseCostMicros: auditor.factory.route.WorstCaseCostMicros, MaxAttempts: auditor.factory.route.MaxAttempts}}, nil
}

func (auditor *runtimeAuditor) execute(ctx context.Context, prepared preparedModuleAudit) (agentruntime.AcceptedResult, error) {
	runID := prepared.declaration.RunID
	if err := auditor.factory.runtime.Declare(prepared.declaration); err != nil {
		if errors.Is(err, agentruntime.ErrRunExists) {
			accepted, found := auditor.factory.runtime.AcceptedResult(runID)
			if !found || accepted.RunID != runID || accepted.Intent != aop.IntentReportLLMAudit {
				return agentruntime.AcceptedResult{}, ErrRuntimeAuditorInProgress
			}
			return accepted, nil
		}
		return agentruntime.AcceptedResult{}, err
	}
	fail := func(cause error) (agentruntime.AcceptedResult, error) {
		_ = auditor.factory.runtime.Fail(runID)
		return agentruntime.AcceptedResult{}, cause
	}
	if err := auditor.factory.runtime.Queue(runID); err != nil {
		return fail(err)
	}
	if err := auditor.factory.runtime.AssignLease(ctx, runID, prepared.lease); err != nil {
		return fail(err)
	}
	if err := auditor.factory.runtime.Start(ctx, runID); err != nil {
		return fail(err)
	}
	response, err := auditor.factory.runtime.RunToolLoop(ctx, runID, prepared.modelCall, auditor.factory.maxRounds)
	if err != nil {
		return fail(err)
	}
	if response.RequestID != prepared.modelCall.RequestID || response.ModelVersion != prepared.modelCall.Model || len(response.Content) == 0 || len(response.ToolCalls) != 0 {
		return fail(ErrRuntimeAuditorOutput)
	}
	accepted, err := auditor.factory.runtime.Complete(ctx, runID, agentruntime.AgentOutput{Intent: aop.IntentReportLLMAudit, Payload: append(json.RawMessage(nil), response.Content...)})
	if err != nil {
		return fail(err)
	}
	return accepted, nil
}

func moduleAuditContextItems(input BlindAuditInput, refs ModuleAuditReferences) ([]agentruntime.ContextItem, error) {
	goal, err := json.Marshal(refs.GoalSpec)
	if err != nil {
		return nil, err
	}
	diff, err := json.Marshal(struct {
		BaseCommit       string   `json:"baseCommit"`
		SubmissionCommit string   `json:"submissionCommit"`
		ChangedFiles     []string `json:"changedFiles"`
	}{input.BaseCommit, input.SubmissionCommit, append([]string(nil), input.ChangedFiles...)})
	if err != nil {
		return nil, err
	}
	checks, err := json.Marshal(input.DeterministicChecks)
	if err != nil {
		return nil, err
	}
	return []agentruntime.ContextItem{
		moduleAuditContextItem("goal", agentruntime.ContextGoalReference, "goal://"+refs.GoalSpec.SHA256, refs.GoalSpec.SHA256, goal, agentruntime.TrustProjectApproved),
		moduleAuditContextItem("module", agentruntime.ContextModuleReference, "module://"+input.ModuleSpecRef.SHA256, input.ModuleSpecRef.SHA256, mustJSON(input.ModuleSpecRef), agentruntime.TrustProjectApproved),
		moduleAuditContextItem("diff", agentruntime.ContextDeterministicDiff, "git://diff/"+input.BaseCommit+"/"+input.SubmissionCommit, "", diff, agentruntime.TrustCurated),
		moduleAuditContextItem("checks", agentruntime.ContextDeterministicResult, "audit://deterministic/"+input.AuditRunID, "", checks, agentruntime.TrustCurated),
	}, nil
}

func moduleAuditContextItem(label string, kind agentruntime.ContextKind, reference, source string, content []byte, trust agentruntime.TrustLevel) agentruntime.ContextItem {
	return agentruntime.ContextItem{ID: stableModuleAuditID("module-audit-context-item-", label, reference), Kind: kind, Reference: reference, SHA256: agentruntime.DigestContextContent(string(content)), SourceSHA256: source, Trust: trust, Content: string(content)}
}

func loadModuleAuditorPrompt() (agentruntime.PromptBundle, error) {
	return prompts.LoadBaseline(agentruntime.RoleModuleAuditor)
}

func decodeStrictAudit(encoded []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ErrRuntimeAuditorOutput
	}
	return nil
}

func moduleAuditParameterDigest(input BlindAuditInput, refs ModuleAuditReferences, bundle agentruntime.PromptBundle, manifest agentruntime.ContextManifest, responseDigest string, route goalplan.ModelRoute, tools []modelgateway.ToolDefinition) (string, error) {
	value := struct {
		AuditRunID, TenantID, ProjectID, TaskID, AttemptSeriesID, BaseCommit, SubmissionCommit string
		Attempt                                                                                int
		ProjectVersion, TaskVersion                                                            int64
		ModuleSpec, GoalSpec, PlanSpec                                                         contracts.SpecRef
		Criteria                                                                               []string
		PromptDigest, ContextDigest, ResponseDigest, ToolDigest                                string
		Route                                                                                  goalplan.ModelRoute
	}{input.AuditRunID, refs.TenantID, input.ProjectID, input.TaskID, input.AttemptSeriesID, input.BaseCommit, input.SubmissionCommit, input.Attempt, refs.ProjectVersion, refs.TaskVersion, input.ModuleSpecRef, refs.GoalSpec, refs.PlanSpec, append([]string(nil), input.RequiredCriteria...), bundle.SHA256, manifest.SHA256, responseDigest, agentruntime.DigestToolDefinitions(tools), route}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func validModuleAuditReferences(refs ModuleAuditReferences, input BlindAuditInput) error {
	if refs.TenantID != input.TenantID || refs.ProjectVersion < 1 || refs.TaskVersion < 1 || refs.GoalSpec.Validate() != nil || refs.PlanSpec.Validate() != nil || refs.DataClassification == "" || !moduleAuditClassification(refs.DataClassification) {
		return ErrRuntimeAuditorUnavailable
	}
	return nil
}

func validModuleAuditRoute(route goalplan.ModelRoute) bool {
	return route.Provider != "" && strings.TrimSpace(route.Provider) == route.Provider && len(route.Provider) <= 128 && route.Model != "" && strings.TrimSpace(route.Model) == route.Model && len(route.Model) <= 256 && route.MaxOutputTokens > 0 && !math.IsNaN(route.Temperature) && !math.IsInf(route.Temperature, 0) && route.Temperature >= 0 && route.Temperature <= 2 && route.WorstCaseCostMicros >= 0 && route.MaxAttempts >= 1 && route.MaxAttempts <= 3 && len(route.ProviderPolicy) <= 256 && len(route.CachePolicy) <= 128
}

func moduleAuditClassification(value string) bool {
	switch value {
	case "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED":
		return true
	default:
		return false
	}
}

func moduleAuditTools(tools []modelgateway.ToolDefinition) ([]modelgateway.ToolDefinition, error) {
	allowed := map[string]struct{}{"artifact.read": {}, "knowledge.read_range": {}, "knowledge.search": {}, "repository.file.read": {}}
	result := cloneModelTools(tools)
	seen := make(map[string]struct{}, len(result))
	for _, tool := range result {
		if _, ok := allowed[tool.Name]; !ok || tool.Version == "" || tool.Validate() != nil {
			return nil, ErrRuntimeAuditorUnavailable
		}
		if _, ok := seen[tool.Name]; ok {
			return nil, ErrRuntimeAuditorUnavailable
		}
		seen[tool.Name] = struct{}{}
	}
	return result, nil
}

func cloneModelTools(tools []modelgateway.ToolDefinition) []modelgateway.ToolDefinition {
	result := append([]modelgateway.ToolDefinition(nil), tools...)
	for index := range result {
		result[index].Schema = append(json.RawMessage(nil), result[index].Schema...)
	}
	return result
}

func cloneModelRoute(route goalplan.ModelRoute) goalplan.ModelRoute {
	if route.Seed == nil {
		return route
	}
	seed := *route.Seed
	route.Seed = &seed
	return route
}

func cloneSeed(seed *int64) *int64 {
	if seed == nil {
		return nil
	}
	value := *seed
	return &value
}

func validModuleAuditLease(lease authz.CapabilityLease, principal authn.Principal, input BlindAuditInput, refs ModuleAuditReferences, resource authz.Resource, parameterDigest string, now time.Time) bool {
	return lease.ValidateShape() == nil && lease.State == authz.LeaseActive && !lease.IsExpired(now) && lease.AgentInstanceID == principal.ID && lease.PrincipalID == principal.ID && lease.PrincipalType == principal.Type && lease.TenantID == refs.TenantID && lease.ProjectID == input.ProjectID && lease.ProjectVersion == refs.ProjectVersion && lease.TaskID == input.TaskID && lease.TaskVersion == refs.TaskVersion && lease.SpecDigest == input.ModuleSpecRef.SHA256 && lease.Role == string(agentruntime.RoleModuleAuditor) && lease.Action == authz.ActionModelGenerate && reflect.DeepEqual(lease.Resource, resource) && lease.ParameterDigest == parameterDigest && len(lease.Capabilities) == 1 && lease.Capabilities[0] == authz.ActionModelGenerate && lease.HeartbeatIntervalSeconds == agentruntime.DefaultHeartbeatSeconds && lease.BudgetAccountID == input.ProjectID && validAuditDigest(lease.PolicyVersion) && lease.ExpiresAt.Sub(lease.IssuedAt) <= 15*time.Minute
}

func toAgentLease(lease authz.CapabilityLease) agentruntime.AgentLease {
	return agentruntime.AgentLease{LeaseID: lease.ID, AgentInstanceID: lease.AgentInstanceID, TenantID: lease.TenantID, ProjectID: lease.ProjectID, TaskID: lease.TaskID, Role: agentruntime.Role(lease.Role), IssuedAt: lease.IssuedAt, ExpiresAt: lease.ExpiresAt, LastHeartbeatAt: lease.LastHeartbeatAt, HeartbeatIntervalSeconds: int(lease.HeartbeatIntervalSeconds), Capabilities: append([]string(nil), lease.Capabilities...), PolicyVersion: lease.PolicyVersion, BudgetAccountID: lease.BudgetAccountID, Nonce: lease.Nonce, FencingToken: lease.FencingToken, Signature: lease.Signature}
}

func stableModuleAuditID(prefix string, values ...string) string {
	digest := sha256.New()
	for _, value := range values {
		_, _ = digest.Write([]byte(value))
		_, _ = digest.Write([]byte{0})
	}
	return prefix + hex.EncodeToString(digest.Sum(nil))
}

func validAuditDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

var _ AuditorFactory = (*RuntimeAuditorFactory)(nil)
