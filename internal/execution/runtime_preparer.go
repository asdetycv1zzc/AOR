package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/knowledge"
	"github.com/akimisaka/aor/internal/leaseauthority"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/observability"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/internal/toolbroker"
	"github.com/akimisaka/aor/pkg/aop"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/akimisaka/aor/prompts"
)

type executionLeaseIssuer interface {
	IssueExecution(context.Context, authn.Principal, leaseauthority.GrantRequest, int64) (authz.CapabilityLease, error)
}

type runtimeAssignmentBinder interface {
	BindRuntime(context.Context, RuntimeBindingRequest) error
}

type KnowledgeContextSource interface {
	Context(context.Context, authn.Principal, string, string, []string) ([]agentruntime.ContextItem, error)
}

type ExecutorRuntimePreparerConfig struct {
	Knowledge     KnowledgeContextSource
	PriorEvidence PriorAuditEvidenceSource
	Leases        executionLeaseIssuer
	Assignments   runtimeAssignmentBinder
	Tools         []toolbroker.ToolDescriptor
	Route         goalplan.ModelRoute
	LeaseTTL      time.Duration
	MaxToolRounds int
	Clock         func() time.Time
}

type ExecutorRuntimePreparer struct {
	knowledge     KnowledgeContextSource
	priorEvidence PriorAuditEvidenceSource
	leases        executionLeaseIssuer
	assignments   runtimeAssignmentBinder
	tools         []modelgateway.ToolDefinition
	route         goalplan.ModelRoute
	leaseTTL      time.Duration
	maxToolRounds int
	clock         func() time.Time
}

func NewExecutorRuntimePreparer(config ExecutorRuntimePreparerConfig) (*ExecutorRuntimePreparer, error) {
	if config.Knowledge == nil || config.PriorEvidence == nil || config.Leases == nil || config.Assignments == nil || !validExecutionModelRoute(config.Route) {
		return nil, ErrPreparationInvalid
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.LeaseTTL == 0 {
		config.LeaseTTL = 5 * time.Minute
	}
	if config.LeaseTTL < time.Duration(agentruntime.DefaultHeartbeatSeconds*agentruntime.MissedHeartbeatLimit)*time.Second || config.LeaseTTL > 15*time.Minute {
		return nil, ErrPreparationInvalid
	}
	if config.MaxToolRounds == 0 {
		config.MaxToolRounds = agentruntime.MaximumNativeToolRounds
	}
	if config.MaxToolRounds < 2 || config.MaxToolRounds > agentruntime.MaximumNativeToolRounds {
		return nil, ErrPreparationInvalid
	}
	tools, err := executorToolDefinitions(config.Tools)
	if err != nil {
		return nil, err
	}
	return &ExecutorRuntimePreparer{
		knowledge: config.Knowledge, priorEvidence: config.PriorEvidence, leases: config.Leases, assignments: config.Assignments,
		tools: tools, route: cloneExecutionRoute(config.Route), leaseTTL: config.LeaseTTL,
		maxToolRounds: config.MaxToolRounds, clock: config.Clock,
	}, nil
}

func (preparer *ExecutorRuntimePreparer) Prepare(ctx context.Context, request PreparationRequest) (PreparedRun, error) {
	if preparer == nil || ctx == nil || ctx.Err() != nil || !validPreparationRequest(request) {
		return PreparedRun{}, ErrPreparationInvalid
	}
	project := request.Project
	task := request.Task
	module := request.ModuleSpec
	route, resolved := goalplan.ResolveProjectModelRoute(project, agentruntime.RoleExecutor, preparer.route)
	if !resolved {
		return PreparedRun{}, ErrPreparationInvalid
	}
	goalRef := contracts.SpecRef{Version: project.Goal.Version, SHA256: project.Goal.SHA256}
	planRef := *project.Plan
	if goalRef.Validate() != nil || planRef.Validate() != nil || module.Validate() != nil || request.BaseCommit == "" || !validCommit(request.BaseCommit) {
		return PreparedRun{}, ErrPreparationInvalid
	}
	bundle, err := prompts.LoadBaseline(agentruntime.RoleExecutor)
	if err != nil {
		return PreparedRun{}, ErrPreparationInvalid
	}
	items, knowledgeRefs, err := preparer.contextItems(ctx, request, goalRef, planRef)
	if err != nil {
		return PreparedRun{}, err
	}
	manifest := agentruntime.ContextManifest{
		ManifestID: stableExecutionID("context_", request.ExecutionID, request.Task.ID, strconv.FormatInt(task.Version, 10)),
		Version:    "1", Role: agentruntime.RoleExecutor, Items: items,
	}
	manifest.SHA256 = agentruntime.DigestContextManifest(manifest)
	if err := agentruntime.ValidateContextManifest(manifest); err != nil {
		return PreparedRun{}, ErrPreparationInvalid
	}
	responseSchema := json.RawMessage(executorSubmissionSchema)
	responseDigest, err := canonicaljson.Digest(responseSchema)
	if err != nil {
		return PreparedRun{}, ErrPreparationInvalid
	}
	parameterDigest, err := executionParameterDigest(request, bundle.SHA256, manifest.SHA256, responseDigest, route, preparer.tools, knowledgeRefs)
	if err != nil {
		return PreparedRun{}, ErrPreparationInvalid
	}
	agentID := request.Assignment.AgentInstanceID
	principal := authn.Principal{ID: agentID, Type: authn.PrincipalAgentInstance, Role: authn.RoleExecutor, TenantID: request.Project.TenantID, ProjectID: request.Project.ID}
	leaseContext, err := authn.ContextWithPrincipal(ctx, principal)
	if err != nil {
		return PreparedRun{}, ErrPreparationInvalid
	}
	now := preparer.clock().UTC()
	lease, err := preparer.leases.IssueExecution(leaseContext, principal, leaseauthority.GrantRequest{
		TenantID: request.Project.TenantID, ProjectID: request.Project.ID, TaskID: task.ID,
		Action: authz.ActionModelGenerate, Resource: authz.Resource{Type: "model", ID: route.Provider + "/" + route.Model},
		ParameterDigest: parameterDigest, BudgetAccountID: request.Project.ID,
		IdempotencyKey: stableExecutionID("execution-lease_", request.ExecutionID, parameterDigest), TTL: preparer.leaseTTL,
	}, task.FencingToken)
	if err != nil {
		return PreparedRun{}, err
	}
	if !validExecutorLease(lease, principal, request, parameterDigest, now) {
		return PreparedRun{}, ErrPreparationInvalid
	}
	if err := preparer.assignments.BindRuntime(ctx, RuntimeBindingRequest{
		ExecutionID: request.ExecutionID, TenantID: request.Project.TenantID, ProjectID: request.Project.ID,
		TaskID: task.ID, AttemptSeriesID: task.AttemptSeriesID, AgentInstanceID: agentID,
		FencingToken: task.FencingToken, LeaseID: lease.ID, Provider: route.Provider,
		Model: route.Model, PromptVersion: bundle.Version,
	}); err != nil {
		return PreparedRun{}, err
	}
	trace, ok := observability.TraceFromContext(ctx)
	if !ok {
		trace, err = observability.NewRootTraceContext(false)
		if err != nil {
			return PreparedRun{}, err
		}
	}
	traceparent, err := trace.TraceParent()
	if err != nil {
		return PreparedRun{}, ErrPreparationInvalid
	}
	requestID := stableExecutionID("modelreq_", request.ExecutionID, parameterDigest)
	reservationID := stableExecutionID("modelres_", request.ExecutionID, parameterDigest)
	envelope := aop.Envelope{
		AOPVersion: aop.Version, MessageID: stableExecutionID("msg_", request.ExecutionID, parameterDigest),
		IdempotencyKey: stableExecutionID("aop_", request.ExecutionID, parameterDigest),
		CorrelationID:  stableExecutionID("corr_", request.Project.TenantID, request.Project.ID, request.ExecutionID),
		ProjectID:      request.Project.ID, GoalSpec: &goalRef, PlanSpec: &planRef, ModuleSpec: &task.ModuleSpecRef,
		TaskID: task.ID, AttemptSeriesID: task.AttemptSeriesID, Attempt: request.Attempt,
		Sender: aop.Sender{AgentInstanceID: agentID, Role: string(agentruntime.RoleExecutor), Provider: route.Provider, Model: route.Model, LeaseID: lease.ID},
		Scope:  aop.ScopeTask, Intent: aop.IntentSubmitImplementation, ExpectedAggregateVersion: task.Version,
		ArtifactRefs:  []string{executionArtifactRef("goal", goalRef), executionArtifactRef("plan", planRef), executionArtifactRef("module", task.ModuleSpecRef)},
		KnowledgeRefs: append([]string(nil), knowledgeRefs...), BudgetContext: &aop.BudgetContext{AccountID: request.Project.ID, ReservationID: reservationID},
		TraceContext: &aop.TraceContext{Traceparent: traceparent, Tracestate: trace.TraceState}, CreatedAt: lease.IssuedAt, ExpiresAt: lease.ExpiresAt,
	}
	if envelope.Validate(now) != nil {
		return PreparedRun{}, ErrPreparationInvalid
	}
	declaration := agentruntime.Declaration{
		RunID: request.ExecutionID, Envelope: envelope, TenantID: request.Project.TenantID, ProjectID: request.Project.ID,
		TaskID: task.ID, AgentInstanceID: agentID, Role: agentruntime.RoleExecutor, PromptBundle: bundle,
		ContextManifest: manifest, ResponseSchemaRef: "urn:aor:execution:submission-manifest:v1", ResponseSchema: responseSchema,
		ResponseSemanticValidator: executorResponseSemanticValidator(task, request.Attempt, request.BaseCommit, agentID, lease.ID),
		Tools:                     cloneExecutionTools(preparer.tools), ToolSchemaDigest: agentruntime.DigestToolDefinitions(preparer.tools),
		PolicyVersion: lease.PolicyVersion, PolicyDigest: lease.PolicyVersion, DataClassification: request.Project.DataClassification,
	}
	if _, err := agentruntime.AssemblePrompt(bundle, manifest, declaration.ResponseSchemaRef, responseSchema); err != nil {
		return PreparedRun{}, ErrPreparationInvalid
	}
	return PreparedRun{
		Declaration: declaration, Lease: executionAgentLease(lease),
		ModelCall: agentruntime.ModelCall{RequestID: requestID, Provider: route.Provider, Model: route.Model, ReservationID: reservationID,
			ReasoningEffort: route.ReasoningEffort, ContextWindowTokens: route.ContextWindowTokens, CompactionThresholdTokens: route.CompactionThresholdTokens, MaxOutputTokens: route.MaxOutputTokens, ThinkingBudget: route.ThinkingBudget, Temperature: route.Temperature, Seed: cloneExecutionSeed(route.Seed),
			ProviderPolicy: route.ProviderPolicy, CachePolicy: route.CachePolicy,
			WorstCaseCostMicros: route.WorstCaseCostMicros, MaxAttempts: route.MaxAttempts},
		MaxToolRounds: preparer.maxToolRounds,
	}, nil
}

func executorResponseSemanticValidator(task state.ModuleTask, attempt int, baseCommit, agentID, leaseID string) func(json.RawMessage) error {
	return func(content json.RawMessage) error {
		manifest, err := decodeManifest(content)
		if err != nil || manifest.ProjectID != task.ProjectID || manifest.ModuleTaskID != task.ID ||
			manifest.AttemptSeriesID != task.AttemptSeriesID || manifest.Attempt != attempt ||
			manifest.ModuleSpecRef != task.ModuleSpecRef || manifest.BaseCommit != baseCommit ||
			manifest.AgentIdentity.AgentInstanceID != agentID || manifest.AgentIdentity.LeaseID != leaseID {
			return ErrSubmissionInvalid
		}
		return nil
	}
}

func (preparer *ExecutorRuntimePreparer) contextItems(ctx context.Context, request PreparationRequest, goalRef, planRef contracts.SpecRef) ([]agentruntime.ContextItem, []string, error) {
	goalContent, err := json.Marshal(struct {
		Version int    `json:"version"`
		SHA256  string `json:"sha256"`
	}{goalRef.Version, goalRef.SHA256})
	if err != nil {
		return nil, nil, ErrPreparationInvalid
	}
	planContent, err := json.Marshal(struct {
		Version int    `json:"version"`
		SHA256  string `json:"sha256"`
	}{planRef.Version, planRef.SHA256})
	if err != nil {
		return nil, nil, ErrPreparationInvalid
	}
	moduleContent, err := json.Marshal(request.ModuleSpec)
	if err != nil || len(moduleContent) > agentruntime.MaximumContextItemBytes {
		return nil, nil, ErrPreparationInvalid
	}
	taskContent, err := json.Marshal(struct {
		ExecutionID      string   `json:"executionId"`
		TaskID           string   `json:"taskId"`
		AttemptSeriesID  string   `json:"attemptSeriesId"`
		Attempt          int      `json:"attempt"`
		Version          int64    `json:"version"`
		FencingToken     int64    `json:"fencingToken"`
		BaseCommit       string   `json:"baseCommit"`
		AllowedPaths     []string `json:"allowedPaths"`
		TestRequirements []string `json:"testRequirements"`
	}{request.ExecutionID, request.Task.ID, request.Task.AttemptSeriesID, request.Attempt, request.Task.Version, request.Task.FencingToken, request.BaseCommit, request.ModuleSpec.AllowedPaths, request.ModuleSpec.TestRequirements})
	if err != nil || len(taskContent) > agentruntime.MaximumContextItemBytes {
		return nil, nil, ErrPreparationInvalid
	}
	items := []agentruntime.ContextItem{
		executionContextItem("goal", agentruntime.ContextGoalReference, executionArtifactRef("goal", goalRef), goalRef.SHA256, string(goalContent), agentruntime.TrustProjectApproved),
		executionContextItem("plan", agentruntime.ContextPlanReference, executionArtifactRef("plan", planRef), planRef.SHA256, string(planContent), agentruntime.TrustProjectApproved),
		executionContextItem("module", agentruntime.ContextModuleReference, executionArtifactRef("module", request.Task.ModuleSpecRef), request.Task.ModuleSpecRef.SHA256, string(moduleContent), agentruntime.TrustProjectApproved),
		executionContextItem("task", agentruntime.ContextTaskState, "aor://task/"+request.Task.ID, "", string(taskContent), agentruntime.TrustProjectApproved),
	}
	if request.Attempt > 1 {
		feedback, feedbackErr := loadReworkFeedback(ctx, preparer.priorEvidence, request)
		if feedbackErr != nil {
			return nil, nil, feedbackErr
		}
		items = append(items, feedback)
	}
	principal := authn.Principal{ID: request.Assignment.AgentInstanceID, Type: authn.PrincipalAgentInstance, Role: authn.RoleExecutor, TenantID: request.Project.TenantID, ProjectID: request.Project.ID}
	knowledgeItems, err := preparer.knowledge.Context(ctx, principal, request.Project.TenantID, request.Project.ID, request.ModuleSpec.KnowledgeRefs)
	if err != nil {
		return nil, nil, err
	}
	items = append(items, knowledgeItems...)
	refs := append([]string(nil), request.ModuleSpec.KnowledgeRefs...)
	return items, refs, nil
}

// KnowledgeServiceContextSource turns immutable Knowledge Service references
// into bounded, line-addressed runtime context items.
type KnowledgeServiceContextSource struct {
	Service *knowledge.Service
}

func (source KnowledgeServiceContextSource) Context(ctx context.Context, principal authn.Principal, tenantID, projectID string, refs []string) ([]agentruntime.ContextItem, error) {
	if source.Service == nil {
		if len(refs) == 0 {
			return nil, nil
		}
		return nil, ErrPreparationInvalid
	}
	items := make([]agentruntime.ContextItem, 0, len(refs))
	access := knowledge.Access{Principal: principal, TenantID: tenantID, ProjectID: projectID}
	for _, reference := range refs {
		if strings.TrimSpace(reference) != reference || reference == "" || len(reference) > 2048 {
			return nil, ErrPreparationInvalid
		}
		search, err := source.Service.Search(ctx, knowledge.SearchRequest{Access: access, Path: reference, Limit: 1})
		if err != nil || len(search.References) != 1 || search.References[0].Path != reference {
			return nil, ErrPreparationInvalid
		}
		ref := search.References[0]
		line := ref.LineStart
		for line <= ref.LineEnd {
			page, readErr := source.Service.ReadRange(ctx, knowledge.ReadRangeRequest{Access: access, Reference: ref, LineStart: line, LineEnd: ref.LineEnd})
			if readErr != nil || page.NextLine != 0 && page.NextLine <= line {
				return nil, ErrPreparationInvalid
			}
			end := page.Reference.LineEnd
			if end < line || end-line+1 > 200 || len(page.Content) > agentruntime.MaximumContextItemBytes {
				return nil, ErrPreparationInvalid
			}
			items = append(items, agentruntime.ContextItem{
				ID:   stableExecutionID("ctx_knowledge_", tenantID, projectID, reference, strconv.Itoa(line)),
				Kind: agentruntime.ContextKnowledgeSnippet, Reference: reference, Revision: page.Reference.Revision,
				SHA256: agentruntime.DigestContextContent(page.Content), SourceSHA256: page.Reference.SHA256,
				LineStart: page.Reference.LineStart, LineEnd: page.Reference.LineEnd,
				Trust: agentruntime.TrustLevel(page.Reference.TrustLevel), Content: page.Content,
			})
			if page.NextLine == 0 {
				break
			}
			line = page.NextLine
		}
	}
	return items, nil
}

func executorToolDefinitions(descriptors []toolbroker.ToolDescriptor) ([]modelgateway.ToolDefinition, error) {
	required := map[string]bool{RepositoryCreateWorkspace: false, RepositoryReadFile: false, RepositoryWriteFile: false, RepositoryDeleteFile: false, RepositorySubmit: false}
	byID := make(map[string]toolbroker.ToolDescriptor, len(descriptors))
	for _, descriptor := range descriptors {
		if _, needed := required[descriptor.ToolID]; !needed {
			continue
		}
		if _, duplicate := byID[descriptor.ToolID]; duplicate || descriptor.Validate() != nil || !containsString(descriptor.AllowedRoles, authn.RoleExecutor) {
			return nil, ErrPreparationInvalid
		}
		byID[descriptor.ToolID] = descriptor
	}
	tools := make([]modelgateway.ToolDefinition, 0, len(required))
	for name := range required {
		descriptor, found := byID[name]
		if !found {
			return nil, ErrPreparationInvalid
		}
		required[name] = true
		tools = append(tools, modelgateway.ToolDefinition{Name: descriptor.ToolID, Version: descriptor.Version, Schema: append(json.RawMessage(nil), descriptor.InputSchema...)})
	}
	sort.Slice(tools, func(left, right int) bool { return tools[left].Name < tools[right].Name })
	return tools, nil
}

func validPreparationRequest(request PreparationRequest) bool {
	return validID(request.ExecutionID) && request.Project.TenantID != "" && request.Project.ID != "" && request.Project.TenantID == request.Task.TenantID && request.Project.ID == request.Task.ProjectID && request.Task.ID != "" && request.Task.State == contracts.TaskExecuting && request.Task.Version > 0 && request.Task.FencingToken > 0 && request.Task.AttemptSeriesID != "" && request.Attempt >= 1 && request.Attempt <= 3 && request.Task.Attempt == request.Attempt-1 && request.Assignment.AgentInstanceID != "" && request.Assignment.FencingToken == request.Task.FencingToken && request.ModuleSpec.ModuleID == request.Task.ModuleID && request.ModuleSpec.SHA256 == request.Task.ModuleSpecRef.SHA256 && request.ModuleSpec.ModuleSpecVersion == request.Task.ModuleSpecRef.Version && request.Project.Goal != nil && request.Project.Goal.Status == contracts.GoalApproved && request.Project.Goal.ApprovedBy != "" && request.Project.Plan != nil && request.Project.State == contracts.ProjectExecuting
}

func validExecutionModelRoute(route goalplan.ModelRoute) bool {
	return strings.TrimSpace(route.Provider) == route.Provider && route.Provider != "" && len(route.Provider) <= 128 && strings.TrimSpace(route.Model) == route.Model && route.Model != "" && len(route.Model) <= 256 && state.ValidModelReasoningEffort(route.Provider, route.ReasoningEffort) && (route.ContextWindowTokens == 0 || route.ContextWindowTokens > route.MaxOutputTokens && route.ContextWindowTokens <= 10_000_000) && (route.CompactionThresholdTokens == 0 || route.ContextWindowTokens > 0 && route.CompactionThresholdTokens > route.MaxOutputTokens && route.CompactionThresholdTokens <= route.ContextWindowTokens*9/10) && route.MaxOutputTokens > 0 && route.MaxOutputTokens <= 1_000_000 && route.ThinkingBudget >= 0 && route.ThinkingBudget < route.MaxOutputTokens && !math.IsNaN(route.Temperature) && !math.IsInf(route.Temperature, 0) && route.Temperature >= 0 && route.Temperature <= 2 && route.ProviderPolicy != "" && len(route.ProviderPolicy) <= 256 && route.CachePolicy != "" && len(route.CachePolicy) <= 128 && route.WorstCaseCostMicros >= 0 && route.MaxAttempts >= 1 && route.MaxAttempts <= 5
}

func validCommit(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, runeValue := range value {
		if !(runeValue >= '0' && runeValue <= '9' || runeValue >= 'a' && runeValue <= 'f') {
			return false
		}
	}
	return true
}

func executionParameterDigest(request PreparationRequest, promptDigest, contextDigest, responseDigest string, route goalplan.ModelRoute, tools []modelgateway.ToolDefinition, knowledgeRefs []string) (string, error) {
	encoded, err := json.Marshal(struct {
		ExecutionID    string                        `json:"executionId"`
		TenantID       string                        `json:"tenantId"`
		ProjectID      string                        `json:"projectId"`
		TaskID         string                        `json:"taskId"`
		Attempt        int                           `json:"attempt"`
		ProjectVersion int64                         `json:"projectVersion"`
		TaskVersion    int64                         `json:"taskVersion"`
		SpecRef        contracts.SpecRef             `json:"specRef"`
		FencingToken   int64                         `json:"fencingToken"`
		BaseCommit     string                        `json:"baseCommit"`
		PromptDigest   string                        `json:"promptDigest"`
		ContextDigest  string                        `json:"contextDigest"`
		ResponseDigest string                        `json:"responseDigest"`
		Route          goalplan.ModelRoute           `json:"route"`
		Tools          []modelgateway.ToolDefinition `json:"tools"`
		KnowledgeRefs  []string                      `json:"knowledgeRefs"`
	}{request.ExecutionID, request.Project.TenantID, request.Project.ID, request.Task.ID, request.Attempt, request.Project.Version, request.Task.Version, request.Task.ModuleSpecRef, request.Task.FencingToken, request.BaseCommit, promptDigest, contextDigest, responseDigest, route, tools, knowledgeRefs})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func executionContextItem(name string, kind agentruntime.ContextKind, reference, sourceDigest, content string, trust agentruntime.TrustLevel) agentruntime.ContextItem {
	return agentruntime.ContextItem{ID: stableExecutionID("ctx_", name, reference), Kind: kind, Reference: reference, SHA256: agentruntime.DigestContextContent(content), SourceSHA256: sourceDigest, Trust: trust, Content: content}
}

func executionArtifactRef(kind string, ref contracts.SpecRef) string {
	return "artifact://" + kind + "/" + ref.SHA256
}

func stableExecutionID(prefix string, values ...string) string {
	digest := sha256.New()
	for _, value := range values {
		_, _ = digest.Write([]byte(value))
		_, _ = digest.Write([]byte{0})
	}
	return prefix + hex.EncodeToString(digest.Sum(nil))
}

func cloneExecutionRoute(route goalplan.ModelRoute) goalplan.ModelRoute {
	if route.Seed == nil {
		return route
	}
	seed := *route.Seed
	route.Seed = &seed
	return route
}

func cloneExecutionSeed(seed *int64) *int64 {
	if seed == nil {
		return nil
	}
	value := *seed
	return &value
}

func cloneExecutionTools(tools []modelgateway.ToolDefinition) []modelgateway.ToolDefinition {
	result := make([]modelgateway.ToolDefinition, len(tools))
	for index, tool := range tools {
		result[index] = tool
		result[index].Schema = append(json.RawMessage(nil), tool.Schema...)
	}
	return result
}

func executionAgentLease(lease authz.CapabilityLease) agentruntime.AgentLease {
	return agentruntime.AgentLease{LeaseID: lease.ID, AgentInstanceID: lease.AgentInstanceID, TenantID: lease.TenantID, ProjectID: lease.ProjectID, TaskID: lease.TaskID, Role: agentruntime.Role(lease.Role), IssuedAt: lease.IssuedAt, ExpiresAt: lease.ExpiresAt, LastHeartbeatAt: lease.LastHeartbeatAt, HeartbeatIntervalSeconds: int(lease.HeartbeatIntervalSeconds), Capabilities: append([]string(nil), lease.Capabilities...), PolicyVersion: lease.PolicyVersion, BudgetAccountID: lease.BudgetAccountID, Nonce: lease.Nonce, FencingToken: lease.FencingToken, Signature: lease.Signature}
}

func validExecutorLease(lease authz.CapabilityLease, principal authn.Principal, request PreparationRequest, parameterDigest string, now time.Time) bool {
	return lease.ValidateShape() == nil && lease.State == authz.LeaseActive && !lease.IsExpired(now) && lease.AgentInstanceID == principal.ID && lease.PrincipalID == principal.ID && lease.PrincipalType == principal.Type && lease.TenantID == request.Project.TenantID && lease.ProjectID == request.Project.ID && lease.ProjectVersion == request.Project.Version && lease.TaskID == request.Task.ID && lease.TaskVersion == request.Task.Version && lease.SpecDigest == request.Task.ModuleSpecRef.SHA256 && lease.Role == authn.RoleExecutor && lease.Action == authz.ActionModelGenerate && lease.ParameterDigest == parameterDigest && len(lease.Capabilities) == 1 && lease.Capabilities[0] == authz.ActionModelGenerate && lease.HeartbeatIntervalSeconds == agentruntime.DefaultHeartbeatSeconds && lease.BudgetAccountID == request.Project.ID && lease.FencingToken == request.Task.FencingToken && lease.ExpiresAt.Sub(lease.IssuedAt) <= 15*time.Minute
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

// Knowledge service access is read-only and receives the authenticated agent
// identity explicitly for every immutable reference lookup.
var _ KnowledgeContextSource = KnowledgeServiceContextSource{}

const executorSubmissionSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:aor:execution:submission-manifest:v1","type":"object","additionalProperties":false,"required":["submissionVersion","projectId","moduleTaskId","attemptSeriesId","attempt","moduleSpecRef","baseCommit","headCommit","changedFiles","deletedFiles","createdFiles","claimedCriteria","localTestEvidenceRefs","agentIdentity","createdAt","sha256"],"properties":{"submissionVersion":{"const":1},"projectId":{"type":"string","minLength":1,"maxLength":256},"moduleTaskId":{"type":"string","minLength":1,"maxLength":256},"attemptSeriesId":{"type":"string","minLength":1,"maxLength":256},"attempt":{"type":"integer","minimum":1,"maximum":3},"moduleSpecRef":{"$ref":"#/$defs/specRef"},"baseCommit":{"$ref":"#/$defs/commit"},"headCommit":{"$ref":"#/$defs/commit"},"changedFiles":{"$ref":"#/$defs/paths"},"deletedFiles":{"$ref":"#/$defs/paths"},"createdFiles":{"$ref":"#/$defs/paths"},"claimedCriteria":{"type":"array","items":{"type":"string","minLength":1}},"localTestEvidenceRefs":{"type":"array","items":{"type":"string","minLength":1,"maxLength":4096}},"agentIdentity":{"$ref":"#/$defs/agentIdentity"},"createdAt":{"type":"string","format":"date-time"},"sha256":{"$ref":"#/$defs/sha256"},"signature":{"$ref":"#/$defs/signature"}},"$defs":{"sha256":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},"commit":{"type":"string","pattern":"^[0-9a-f]{40}$"},"paths":{"type":"array","uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":4096,"not":{"pattern":"(^|/)\\.\\.(/|$)"}}},"specRef":{"type":"object","additionalProperties":false,"required":["version","sha256"],"properties":{"version":{"type":"integer","minimum":1},"sha256":{"$ref":"#/$defs/sha256"}}},"agentIdentity":{"type":"object","additionalProperties":false,"required":["agentInstanceId","role","leaseId"],"properties":{"agentInstanceId":{"type":"string","minLength":1,"maxLength":256},"role":{"const":"EXECUTOR"},"provider":{"type":"string","minLength":1,"maxLength":256},"model":{"type":"string","minLength":1,"maxLength":256},"leaseId":{"type":"string","minLength":1,"maxLength":256}}},"signature":{"type":"object","additionalProperties":false,"required":["type","kid","jws"],"properties":{"type":{"type":"string","minLength":1},"kid":{"type":"string","minLength":1},"jws":{"type":"string","minLength":1}}}}}`
