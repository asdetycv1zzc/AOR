package globalaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/goalplan"
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

const requiredGlobalAuditRepositoryTool = "repository.file.read"

type InputSnapshot struct {
	GoalSpec                  contracts.GoalSpec
	GoalArtifactURI           string
	PlanSpec                  contracts.PlanSpec
	PlanArtifactURI           string
	IntegrationEvidence       json.RawMessage
	IntegrationEvidenceURI    string
	IntegrationEvidenceSHA256 string
	ReleaseCommit             string
	ArtifactRefs              []string
	ExecutionPlatform         contracts.ExecutionPlatform
	IsolationLevel            contracts.IsolationLevel
	SandboxImageDigest        string
}

// InputSource resolves immutable project inputs and integration evidence from
// authoritative storage. Request values are lookup keys only.
type InputSource interface {
	Load(context.Context, Request, state.Project) (InputSnapshot, error)
}

type AgentRegistration struct {
	TenantID            string
	ProjectID           string
	ProjectVersion      int64
	RunID               string
	AgentInstanceID     string
	Provider            string
	Model               string
	PromptBundleVersion string
}

type AgentRegistry interface {
	Register(context.Context, AgentRegistration) error
}

type globalAuditLeaseIssuer interface {
	Issue(context.Context, authn.Principal, leaseauthority.GrantRequest) (authz.CapabilityLease, error)
}

type PreparerConfig struct {
	Inputs        InputSource
	Agents        AgentRegistry
	Environment   EnvironmentSource
	Leases        globalAuditLeaseIssuer
	Tools         []toolbroker.ToolDescriptor
	Route         goalplan.ModelRoute
	LeaseTTL      time.Duration
	MaxToolRounds int
	Clock         func() time.Time
}

type AuthoritativePreparer struct {
	inputs        InputSource
	agents        AgentRegistry
	environment   EnvironmentSource
	leases        globalAuditLeaseIssuer
	tools         []modelgateway.ToolDefinition
	route         goalplan.ModelRoute
	leaseTTL      time.Duration
	maxToolRounds int
	clock         func() time.Time
}

func NewAuthoritativePreparer(config PreparerConfig) (*AuthoritativePreparer, error) {
	if config.Inputs == nil || config.Agents == nil || config.Environment == nil || config.Leases == nil || !validGlobalAuditRoute(config.Route) {
		return nil, ErrRuntimeUnavailable
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.LeaseTTL == 0 {
		config.LeaseTTL = 5 * time.Minute
	}
	if config.LeaseTTL < time.Duration(agentruntime.DefaultHeartbeatSeconds*agentruntime.MissedHeartbeatLimit)*time.Second || config.LeaseTTL > 15*time.Minute {
		return nil, ErrRuntimeUnavailable
	}
	if config.MaxToolRounds == 0 {
		config.MaxToolRounds = agentruntime.MaximumNativeToolRounds
	}
	if config.MaxToolRounds < 2 || config.MaxToolRounds > agentruntime.MaximumNativeToolRounds {
		return nil, ErrRuntimeUnavailable
	}
	tools, err := globalAuditToolDefinitions(config.Tools)
	if err != nil {
		return nil, err
	}
	return &AuthoritativePreparer{
		inputs: config.Inputs, agents: config.Agents, environment: config.Environment, leases: config.Leases, tools: tools,
		route: cloneGlobalAuditRoute(config.Route), leaseTTL: config.LeaseTTL,
		maxToolRounds: config.MaxToolRounds, clock: config.Clock,
	}, nil
}

func (preparer *AuthoritativePreparer) Prepare(ctx context.Context, request Request, project state.Project) (prepared PreparedRun, err error) {
	if preparer == nil || ctx == nil || ctx.Err() != nil || !uuidV7(request.RunID) || !validProject(project, request) || project.PromptBundleVersion != prompts.BaselineVersion {
		return PreparedRun{}, ErrInvalidRequest
	}
	input, err := preparer.inputs.Load(ctx, request, project)
	if err != nil {
		return PreparedRun{}, err
	}
	environment, err := preparer.environment.Acquire(ctx, request, project, input.ReleaseCommit)
	if err != nil {
		return PreparedRun{}, err
	}
	acquired := environment.ID != ""
	defer func() {
		if !acquired {
			return
		}
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		cleanupErr := preparer.environment.Release(cleanupContext, environment)
		cancel()
		if cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()
	input.ExecutionPlatform = environment.Facts.ExecutionPlatform
	input.IsolationLevel = environment.Facts.IsolationLevel
	input.SandboxImageDigest = environment.Facts.SandboxImageDigest
	goalJSON, planJSON, criteria, artifactRefs, err := validateGlobalAuditInput(project, input)
	if err != nil {
		return PreparedRun{}, err
	}
	bundle, err := prompts.LoadBaseline(agentruntime.RoleGlobalAuditor)
	if err != nil {
		return PreparedRun{}, ErrRuntimeUnavailable
	}
	items, err := globalAuditContextItems(request, project, input, goalJSON, planJSON)
	if err != nil {
		return PreparedRun{}, err
	}
	manifest := agentruntime.ContextManifest{
		ManifestID: stableGlobalAuditID("context_", request.RunID, projectGoalRef(project).SHA256, project.Plan.SHA256, input.ReleaseCommit),
		Version:    "1", Role: agentruntime.RoleGlobalAuditor, Items: items,
	}
	manifest.SHA256 = agentruntime.DigestContextManifest(manifest)
	if err := agentruntime.ValidateContextManifest(manifest); err != nil {
		return PreparedRun{}, ErrInvalidRequest
	}
	responseDigest, err := canonicaljson.Digest(decisionSchema)
	if err != nil {
		return PreparedRun{}, ErrInvalidRequest
	}
	parameterDigest, err := globalAuditParameterDigest(request, project, input, bundle.SHA256, manifest.SHA256, responseDigest, preparer.route, preparer.tools)
	if err != nil {
		return PreparedRun{}, ErrInvalidRequest
	}
	agentID := request.ProjectID + ":" + string(agentruntime.RoleGlobalAuditor) + ":" + request.RunID
	if err := preparer.agents.Register(ctx, AgentRegistration{
		TenantID: request.TenantID, ProjectID: request.ProjectID, ProjectVersion: project.Version,
		RunID: request.RunID, AgentInstanceID: agentID, Provider: preparer.route.Provider,
		Model: preparer.route.Model, PromptBundleVersion: bundle.Version,
	}); err != nil {
		return PreparedRun{}, err
	}
	principal := authn.Principal{
		ID: agentID, Type: authn.PrincipalAgentInstance, Role: authn.RoleGlobalAuditor,
		TenantID: request.TenantID, ProjectID: request.ProjectID,
	}
	leaseContext, err := authn.ContextWithPrincipal(ctx, principal)
	if err != nil {
		return PreparedRun{}, ErrInvalidRequest
	}
	resource := authz.Resource{Type: "model", ID: preparer.route.Provider + "/" + preparer.route.Model}
	lease, err := preparer.leases.Issue(leaseContext, principal, leaseauthority.GrantRequest{
		TenantID: request.TenantID, ProjectID: request.ProjectID,
		Action: authz.ActionModelGenerate, Resource: resource, ParameterDigest: parameterDigest,
		BudgetAccountID: project.ID, IdempotencyKey: stableGlobalAuditID("global-audit-lease_", request.RunID, parameterDigest),
		TTL: preparer.leaseTTL,
	})
	if err != nil {
		return PreparedRun{}, err
	}
	now := preparer.clock().UTC()
	if !validGlobalAuditLease(lease, principal, project, resource, parameterDigest, now) {
		return PreparedRun{}, ErrInvalidRequest
	}
	trace, found := observability.TraceFromContext(ctx)
	if !found {
		trace, err = observability.NewRootTraceContext(false)
		if err != nil {
			return PreparedRun{}, err
		}
	}
	traceparent, err := trace.TraceParent()
	if err != nil {
		return PreparedRun{}, ErrInvalidRequest
	}
	requestID := stableGlobalAuditID("modelreq_", request.RunID, parameterDigest)
	reservationID := stableGlobalAuditID("modelres_", request.RunID, parameterDigest)
	goalRef := projectGoalRef(project)
	planRef := *project.Plan
	envelope := aop.Envelope{
		AOPVersion: aop.Version, MessageID: stableGlobalAuditID("msg_", request.RunID, parameterDigest),
		IdempotencyKey: stableGlobalAuditID("aop_", request.RunID, parameterDigest),
		CorrelationID:  stableGlobalAuditID("corr_", request.TenantID, request.ProjectID, request.RunID),
		ProjectID:      request.ProjectID, GoalSpec: &goalRef, PlanSpec: &planRef,
		Sender: aop.Sender{AgentInstanceID: agentID, Role: string(agentruntime.RoleGlobalAuditor), Provider: preparer.route.Provider, Model: preparer.route.Model, LeaseID: lease.ID},
		Scope:  aop.ScopeProject, Intent: aop.IntentReportGlobalAudit, ExpectedAggregateVersion: project.Version,
		ArtifactRefs: artifactRefs, KnowledgeRefs: []string{},
		BudgetContext: &aop.BudgetContext{AccountID: project.ID, ReservationID: reservationID},
		TraceContext:  &aop.TraceContext{Traceparent: traceparent, Tracestate: trace.TraceState},
		CreatedAt:     lease.IssuedAt, ExpiresAt: lease.ExpiresAt,
	}
	if envelope.Validate(now) != nil {
		return PreparedRun{}, ErrInvalidRequest
	}
	declaration := agentruntime.Declaration{
		RunID: request.RunID, Envelope: envelope, TenantID: request.TenantID, ProjectID: request.ProjectID,
		AgentInstanceID: agentID, Role: agentruntime.RoleGlobalAuditor, PromptBundle: bundle,
		ContextManifest: manifest, ResponseSchemaRef: DecisionSchemaReference, ResponseSchema: DecisionSchema(),
		ResponseSemanticValidator: globalAuditResponseSemanticValidator(criteria),
		Tools:                     cloneGlobalAuditTools(preparer.tools), ToolSchemaDigest: agentruntime.DigestToolDefinitions(preparer.tools),
		PolicyVersion: lease.PolicyVersion, PolicyDigest: lease.PolicyVersion, DataClassification: project.DataClassification,
	}
	if _, err := agentruntime.AssemblePrompt(bundle, manifest, declaration.ResponseSchemaRef, declaration.ResponseSchema); err != nil {
		return PreparedRun{}, ErrInvalidRequest
	}
	prepared = PreparedRun{
		Declaration: declaration, Lease: globalAuditAgentLease(lease),
		ModelCall: agentruntime.ModelCall{
			RequestID: requestID, Provider: preparer.route.Provider, Model: preparer.route.Model, ReservationID: reservationID,
			MaxOutputTokens: preparer.route.MaxOutputTokens, Temperature: preparer.route.Temperature, Seed: cloneGlobalAuditSeed(preparer.route.Seed),
			ProviderPolicy: preparer.route.ProviderPolicy, CachePolicy: preparer.route.CachePolicy,
			WorstCaseCostMicros: preparer.route.WorstCaseCostMicros, MaxAttempts: preparer.route.MaxAttempts,
		},
		MaxToolRounds: preparer.maxToolRounds, ReleaseCommit: input.ReleaseCommit,
		RequiredCriteria: criteria, ExecutionPlatform: input.ExecutionPlatform,
		IsolationLevel: input.IsolationLevel, SandboxImageDigest: input.SandboxImageDigest,
		Environment: environment,
	}
	acquired = false
	return prepared, nil
}

func (preparer *AuthoritativePreparer) Release(ctx context.Context, prepared PreparedRun) error {
	if preparer == nil || preparer.environment == nil || ctx == nil || ctx.Err() != nil {
		return ErrInvalidRequest
	}
	return preparer.environment.Release(ctx, prepared.Environment)
}

func validateGlobalAuditInput(project state.Project, input InputSnapshot) ([]byte, []byte, []string, []string, error) {
	goalJSON, goalErr := json.Marshal(input.GoalSpec)
	planJSON, planErr := json.Marshal(input.PlanSpec)
	goalRef := projectGoalRef(project)
	if goalErr != nil || planErr != nil || contracts.ValidateGoalJSON(goalJSON) != nil || contracts.ValidatePlanJSON(planJSON) != nil ||
		input.GoalSpec.Status != contracts.GoalApproved || input.GoalSpec.ApprovedBy == nil || input.GoalSpec.ApprovedBy.ActorID != project.Goal.ApprovedBy ||
		input.GoalSpec.Content.ProjectID != project.ID || input.GoalSpec.Content.Version != goalRef.Version || input.GoalSpec.ContentSHA256 != goalRef.SHA256 ||
		input.PlanSpec.ProjectID != project.ID || input.PlanSpec.GoalSpecRef != goalRef || input.PlanSpec.SHA256 != project.Plan.SHA256 ||
		!safeText(input.GoalArtifactURI, 2048) || !safeText(input.PlanArtifactURI, 2048) || !safeText(input.IntegrationEvidenceURI, 2048) ||
		!commitPattern.MatchString(input.ReleaseCommit) ||
		input.ExecutionPlatform != contracts.PlatformLinux || input.IsolationLevel != contracts.IsolationContainer || !digestPattern.MatchString(input.SandboxImageDigest) ||
		len(input.IntegrationEvidence) == 0 || len(input.IntegrationEvidence) > agentruntime.MaximumContextBytes || !json.Valid(input.IntegrationEvidence) ||
		!digestPattern.MatchString(input.IntegrationEvidenceSHA256) || agentruntime.DigestContextContent(string(input.IntegrationEvidence)) != input.IntegrationEvidenceSHA256 {
		return nil, nil, nil, nil, ErrInvalidRequest
	}
	criteria := make([]string, 0, len(input.GoalSpec.Content.AcceptanceCriteria))
	seenCriteria := make(map[string]struct{}, len(input.GoalSpec.Content.AcceptanceCriteria))
	for _, criterion := range input.GoalSpec.Content.AcceptanceCriteria {
		if !safeText(criterion.ID, 4096) {
			return nil, nil, nil, nil, ErrInvalidRequest
		}
		if _, duplicate := seenCriteria[criterion.ID]; duplicate {
			return nil, nil, nil, nil, ErrInvalidRequest
		}
		seenCriteria[criterion.ID] = struct{}{}
		criteria = append(criteria, criterion.ID)
	}
	if !validCriteria(criteria) {
		return nil, nil, nil, nil, ErrInvalidRequest
	}
	sort.Strings(criteria)
	artifactRefs := append([]string{input.GoalArtifactURI, input.PlanArtifactURI, input.IntegrationEvidenceURI}, input.ArtifactRefs...)
	sort.Strings(artifactRefs)
	artifactRefs = compactGlobalAuditRefs(artifactRefs)
	if len(artifactRefs) < 3 || len(artifactRefs) > 256 {
		return nil, nil, nil, nil, ErrInvalidRequest
	}
	for _, reference := range artifactRefs {
		if !safeText(reference, 4096) {
			return nil, nil, nil, nil, ErrInvalidRequest
		}
	}
	return goalJSON, planJSON, criteria, artifactRefs, nil
}

func globalAuditContextItems(request Request, project state.Project, input InputSnapshot, goalJSON, planJSON []byte) ([]agentruntime.ContextItem, error) {
	items := make([]agentruntime.ContextItem, 0, 8)
	items = appendGlobalAuditChunks(items, "goal", agentruntime.ContextGoalReference, input.GoalArtifactURI, strconv.Itoa(project.Goal.Version), project.Goal.SHA256, agentruntime.TrustProjectApproved, string(goalJSON))
	items = appendGlobalAuditChunks(items, "plan", agentruntime.ContextPlanReference, input.PlanArtifactURI, strconv.Itoa(project.Plan.Version), project.Plan.SHA256, agentruntime.TrustProjectApproved, string(planJSON))
	items = appendGlobalAuditChunks(items, "integration", agentruntime.ContextDeterministicResult, input.IntegrationEvidenceURI, "1", input.IntegrationEvidenceSHA256, agentruntime.TrustCurated, string(input.IntegrationEvidence))
	releaseJSON, err := json.Marshal(struct {
		ReleaseCommit string   `json:"releaseCommit"`
		ArtifactRefs  []string `json:"artifactRefs"`
	}{input.ReleaseCommit, append([]string(nil), input.ArtifactRefs...)})
	if err != nil || len(releaseJSON) > agentruntime.MaximumContextItemBytes {
		return nil, ErrInvalidRequest
	}
	items = append(items, agentruntime.ContextItem{
		ID: stableGlobalAuditID("ctx_release_", request.RunID, input.ReleaseCommit), Kind: agentruntime.ContextTaskState,
		Reference: "aor://project/" + request.ProjectID + "/release/" + input.ReleaseCommit, Revision: input.ReleaseCommit,
		SHA256: agentruntime.DigestContextContent(string(releaseJSON)), Trust: agentruntime.TrustCurated, Content: string(releaseJSON),
	})
	if len(items) > agentruntime.MaximumContextItems {
		return nil, ErrInvalidRequest
	}
	return items, nil
}

func appendGlobalAuditChunks(items []agentruntime.ContextItem, name string, kind agentruntime.ContextKind, reference, revision, sourceDigest string, trust agentruntime.TrustLevel, content string) []agentruntime.ContextItem {
	chunks := splitGlobalAuditContext(content)
	for index, chunk := range chunks {
		chunkRevision := revision
		chunkReference := reference
		if len(chunks) > 1 {
			chunkRevision += ":" + strconv.Itoa(index+1) + "/" + strconv.Itoa(len(chunks))
			chunkReference += "#aor-context-chunk-" + strconv.Itoa(index+1)
		}
		items = append(items, agentruntime.ContextItem{
			ID: stableGlobalAuditID("ctx_", name, sourceDigest, strconv.Itoa(index)), Kind: kind,
			Reference: chunkReference, Revision: chunkRevision, SHA256: agentruntime.DigestContextContent(chunk),
			SourceSHA256: sourceDigest, Trust: trust, Content: chunk,
		})
	}
	return items
}

func splitGlobalAuditContext(content string) []string {
	if len(content) <= agentruntime.MaximumContextItemBytes {
		return []string{content}
	}
	chunks := make([]string, 0, len(content)/agentruntime.MaximumContextItemBytes+1)
	for start := 0; start < len(content); {
		end := start + agentruntime.MaximumContextItemBytes
		if end >= len(content) {
			end = len(content)
		} else {
			for end > start && !utf8.RuneStart(content[end]) {
				end--
			}
		}
		chunks = append(chunks, content[start:end])
		start = end
	}
	return chunks
}

func globalAuditToolDefinitions(descriptors []toolbroker.ToolDescriptor) ([]modelgateway.ToolDefinition, error) {
	allowed := map[string]struct{}{
		"artifact.read": {}, "knowledge.read_range": {}, "knowledge.search": {}, requiredGlobalAuditRepositoryTool: {},
	}
	byID := make(map[string]toolbroker.ToolDescriptor, len(allowed))
	for _, descriptor := range descriptors {
		if _, accepted := allowed[descriptor.ToolID]; !accepted {
			continue
		}
		if _, duplicate := byID[descriptor.ToolID]; duplicate || descriptor.Validate() != nil || descriptor.SideEffect != toolbroker.SideEffectNone ||
			descriptor.FilesystemAccess != toolbroker.FilesystemNone && descriptor.FilesystemAccess != toolbroker.FilesystemRead ||
			!globalAuditRoleAllowed(descriptor.AllowedRoles) {
			return nil, ErrRuntimeUnavailable
		}
		byID[descriptor.ToolID] = descriptor
	}
	if _, found := byID[requiredGlobalAuditRepositoryTool]; !found {
		return nil, ErrRuntimeUnavailable
	}
	tools := make([]modelgateway.ToolDefinition, 0, len(byID))
	for _, descriptor := range byID {
		schema := append(json.RawMessage(nil), descriptor.InputSchema...)
		description := ""
		if descriptor.ToolID == requiredGlobalAuditRepositoryTool {
			schema = json.RawMessage(`{"type":"object","required":["commit","path"],"properties":{"commit":{"type":"string","pattern":"^[0-9a-f]{40}$"},"path":{"type":"string","minLength":1,"maxLength":4096}},"additionalProperties":false}`)
			description = "Read one file from the release commit supplied in the audit context"
		}
		tools = append(tools, modelgateway.ToolDefinition{
			Name: descriptor.ToolID, Version: descriptor.Version, Description: description, Schema: schema,
		})
	}
	sort.Slice(tools, func(left, right int) bool { return tools[left].Name < tools[right].Name })
	return tools, nil
}

func globalAuditRoleAllowed(roles []string) bool {
	for _, role := range roles {
		if role == authn.RoleGlobalAuditor {
			return true
		}
	}
	return false
}

func globalAuditParameterDigest(request Request, project state.Project, input InputSnapshot, promptDigest, contextDigest, responseDigest string, route goalplan.ModelRoute, tools []modelgateway.ToolDefinition) (string, error) {
	encoded, err := json.Marshal(struct {
		RunID                     string                        `json:"runId"`
		TenantID                  string                        `json:"tenantId"`
		ProjectID                 string                        `json:"projectId"`
		ProjectVersion            int64                         `json:"projectVersion"`
		GoalSpecRef               contracts.SpecRef             `json:"goalSpecRef"`
		PlanSpecRef               contracts.SpecRef             `json:"planSpecRef"`
		ReleaseCommit             string                        `json:"releaseCommit"`
		IntegrationEvidenceSHA256 string                        `json:"integrationEvidenceSha256"`
		PromptDigest              string                        `json:"promptDigest"`
		ContextDigest             string                        `json:"contextDigest"`
		ResponseDigest            string                        `json:"responseDigest"`
		Route                     goalplan.ModelRoute           `json:"route"`
		Tools                     []modelgateway.ToolDefinition `json:"tools"`
	}{
		request.RunID, request.TenantID, request.ProjectID, project.Version, projectGoalRef(project), *project.Plan,
		input.ReleaseCommit, input.IntegrationEvidenceSHA256,
		promptDigest, contextDigest, responseDigest, route, tools,
	})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func validGlobalAuditRoute(route goalplan.ModelRoute) bool {
	return strings.TrimSpace(route.Provider) == route.Provider && route.Provider != "" && len(route.Provider) <= 128 &&
		strings.TrimSpace(route.Model) == route.Model && route.Model != "" && len(route.Model) <= 256 &&
		route.MaxOutputTokens > 0 && !math.IsNaN(route.Temperature) && !math.IsInf(route.Temperature, 0) && route.Temperature >= 0 && route.Temperature <= 2 &&
		safeText(route.ProviderPolicy, 256) && safeText(route.CachePolicy, 128) && route.WorstCaseCostMicros >= 0 && route.MaxAttempts >= 1 && route.MaxAttempts <= 5
}

func validGlobalAuditLease(lease authz.CapabilityLease, principal authn.Principal, project state.Project, resource authz.Resource, parameterDigest string, now time.Time) bool {
	return lease.ValidateShape() == nil && lease.State == authz.LeaseActive && !lease.IsExpired(now) &&
		lease.AgentInstanceID == principal.ID && lease.PrincipalID == principal.ID && lease.PrincipalType == principal.Type &&
		lease.TenantID == project.TenantID && lease.ProjectID == project.ID && lease.ProjectVersion == project.Version &&
		lease.TaskID == "" && lease.TaskVersion == 0 && lease.SpecDigest == "" && lease.Role == authn.RoleGlobalAuditor &&
		lease.Action == authz.ActionModelGenerate && reflect.DeepEqual(lease.Resource, resource) && lease.ParameterDigest == parameterDigest &&
		len(lease.Capabilities) == 1 && lease.Capabilities[0] == authz.ActionModelGenerate &&
		lease.HeartbeatIntervalSeconds == agentruntime.DefaultHeartbeatSeconds && lease.BudgetAccountID == project.ID &&
		digestPattern.MatchString(lease.PolicyVersion) && lease.FencingToken > 0 && lease.ExpiresAt.Sub(lease.IssuedAt) <= 15*time.Minute
}

func globalAuditAgentLease(lease authz.CapabilityLease) agentruntime.AgentLease {
	return agentruntime.AgentLease{
		LeaseID: lease.ID, AgentInstanceID: lease.AgentInstanceID, TenantID: lease.TenantID, ProjectID: lease.ProjectID,
		Role: agentruntime.Role(lease.Role), IssuedAt: lease.IssuedAt, ExpiresAt: lease.ExpiresAt,
		LastHeartbeatAt: lease.LastHeartbeatAt, HeartbeatIntervalSeconds: int(lease.HeartbeatIntervalSeconds),
		Capabilities: append([]string(nil), lease.Capabilities...), PolicyVersion: lease.PolicyVersion,
		BudgetAccountID: lease.BudgetAccountID, Nonce: lease.Nonce, FencingToken: lease.FencingToken, Signature: lease.Signature,
	}
}

func compactGlobalAuditRefs(refs []string) []string {
	if len(refs) == 0 {
		return nil
	}
	result := refs[:0]
	for _, reference := range refs {
		if len(result) == 0 || result[len(result)-1] != reference {
			result = append(result, reference)
		}
	}
	return result
}

func stableGlobalAuditID(prefix string, values ...string) string {
	digest := sha256.New()
	for _, value := range values {
		_, _ = digest.Write([]byte(value))
		_, _ = digest.Write([]byte{0})
	}
	return prefix + hex.EncodeToString(digest.Sum(nil))
}

func cloneGlobalAuditRoute(route goalplan.ModelRoute) goalplan.ModelRoute {
	route.Seed = cloneGlobalAuditSeed(route.Seed)
	return route
}

func cloneGlobalAuditSeed(seed *int64) *int64 {
	if seed == nil {
		return nil
	}
	value := *seed
	return &value
}

func cloneGlobalAuditTools(tools []modelgateway.ToolDefinition) []modelgateway.ToolDefinition {
	result := make([]modelgateway.ToolDefinition, len(tools))
	for index, tool := range tools {
		result[index] = tool
		result[index].Schema = append(json.RawMessage(nil), tool.Schema...)
	}
	return result
}

var _ Preparer = (*AuthoritativePreparer)(nil)
