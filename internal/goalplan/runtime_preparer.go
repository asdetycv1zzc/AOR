package goalplan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/leaseauthority"
	"github.com/akimisaka/aor/internal/observability"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/aop"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/akimisaka/aor/prompts"
)

type ModelRoute struct {
	Provider            string
	Model               string
	MaxOutputTokens     int
	Temperature         float64
	Seed                *int64
	ProviderPolicy      string
	CachePolicy         string
	WorstCaseCostMicros int64
	MaxAttempts         int
}

type runtimeProjectReader interface {
	Project(context.Context, string, string) (state.Project, bool, error)
}

type runtimeTaskReader interface {
	Task(context.Context, string, string, string) (state.ModuleTask, bool, error)
}

type runtimeLeaseIssuer interface {
	Issue(context.Context, authn.Principal, leaseauthority.GrantRequest) (authz.CapabilityLease, error)
}

type RuntimePreparerConfig struct {
	Artifacts ArtifactStore
	Projects  runtimeProjectReader
	Tasks     runtimeTaskReader
	Leases    runtimeLeaseIssuer
	Routes    map[agentruntime.Role]ModelRoute
	LeaseTTL  time.Duration
	Clock     func() time.Time
}

type AuthoritativeRuntimePreparer struct {
	artifacts ArtifactStore
	projects  runtimeProjectReader
	tasks     runtimeTaskReader
	leases    runtimeLeaseIssuer
	routes    map[agentruntime.Role]ModelRoute
	leaseTTL  time.Duration
	clock     func() time.Time
}

func NewAuthoritativeRuntimePreparer(config RuntimePreparerConfig) (*AuthoritativeRuntimePreparer, error) {
	if config.Artifacts == nil || config.Projects == nil || config.Tasks == nil || config.Leases == nil {
		return nil, ErrInvalidRequest
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.LeaseTTL == 0 {
		config.LeaseTTL = 5 * time.Minute
	}
	if config.LeaseTTL < time.Duration(agentruntime.DefaultHeartbeatSeconds*agentruntime.MissedHeartbeatLimit)*time.Second || config.LeaseTTL > 15*time.Minute {
		return nil, ErrInvalidRequest
	}
	routes := make(map[agentruntime.Role]ModelRoute, 4)
	for _, role := range []agentruntime.Role{
		agentruntime.RoleGoalProposer, agentruntime.RoleGoalChallenger,
		agentruntime.RolePlanSupervisor, agentruntime.RoleModulePlanner,
	} {
		route, found := config.Routes[role]
		if !found || !validModelRoute(route) {
			return nil, ErrInvalidRequest
		}
		if route.Seed != nil {
			seed := *route.Seed
			route.Seed = &seed
		}
		routes[role] = route
	}
	return &AuthoritativeRuntimePreparer{
		artifacts: config.Artifacts, projects: config.Projects, tasks: config.Tasks,
		leases: config.Leases, routes: routes, leaseTTL: config.LeaseTTL, clock: config.Clock,
	}, nil
}

func (preparer *AuthoritativeRuntimePreparer) Prepare(ctx context.Context, request AgentInvocation) (RuntimeInvocation, error) {
	if preparer == nil || ctx == nil || !validAgentInvocation(request) || request.Stage != "MODULE_SPEC" && len(request.Payload) != 0 {
		return RuntimeInvocation{}, ErrInvalidRequest
	}
	project, found, err := preparer.projects.Project(ctx, request.TenantID, request.ProjectID)
	if err != nil {
		return RuntimeInvocation{}, err
	}
	if !found || project.TenantID != request.TenantID || project.ID != request.ProjectID || project.Version < 1 || project.PromptBundleVersion != prompts.BaselineVersion {
		return RuntimeInvocation{}, ErrInvalidRequest
	}
	artifacts, err := preparer.loadInputs(ctx, request)
	if err != nil {
		return RuntimeInvocation{}, err
	}
	stage, err := preparer.stageContext(ctx, request, project, artifacts)
	if err != nil {
		return RuntimeInvocation{}, err
	}
	bundle, err := prompts.LoadBaseline(request.Role)
	if err != nil {
		return RuntimeInvocation{}, ErrInvalidRequest
	}
	manifest := agentruntime.ContextManifest{
		ManifestID: stableRuntimeID("context_", request.TenantID, request.ProjectID, request.TaskID, request.InvocationID),
		Version:    "1", Role: request.Role, Items: stage.items,
	}
	manifest.SHA256 = agentruntime.DigestContextManifest(manifest)
	if err := agentruntime.ValidateContextManifest(manifest); err != nil {
		return RuntimeInvocation{}, ErrInvalidRequest
	}
	responseSchema, err := responseSchemaFor(request.Stage)
	if err != nil {
		return RuntimeInvocation{}, err
	}
	responseDigest, err := canonicaljson.Digest(responseSchema.Document)
	if err != nil {
		return RuntimeInvocation{}, ErrInvalidRequest
	}
	route := preparer.routes[request.Role]
	parameterDigest, err := runtimeParameterDigest(request, project.Version, stage.taskVersion, stage.specDigest, bundle.SHA256, manifest.SHA256, responseDigest, route)
	if err != nil {
		return RuntimeInvocation{}, ErrInvalidRequest
	}
	agentID := runtimeAgentID(request)
	principal := authn.Principal{
		ID: agentID, Type: authn.PrincipalAgentInstance, Role: string(request.Role),
		TenantID: request.TenantID, ProjectID: request.ProjectID,
	}
	leaseContext, err := authn.ContextWithPrincipal(ctx, principal)
	if err != nil {
		return RuntimeInvocation{}, ErrInvalidRequest
	}
	resource := authz.Resource{Type: "model", ID: route.Provider + "/" + route.Model}
	lease, err := preparer.leases.Issue(leaseContext, principal, leaseauthority.GrantRequest{
		TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		Action: authz.ActionModelGenerate, Resource: resource, ParameterDigest: parameterDigest,
		BudgetAccountID: project.ID,
		IdempotencyKey:  stableRuntimeID("goalplan-lease_", request.InvocationID, parameterDigest),
		TTL:             preparer.leaseTTL,
	})
	if err != nil {
		return RuntimeInvocation{}, err
	}
	now := preparer.clock().UTC()
	if !validIssuedRuntimeLease(lease, principal, project, request, stage, resource, parameterDigest, now) {
		return RuntimeInvocation{}, ErrInvalidRequest
	}
	trace, ok := observability.TraceFromContext(ctx)
	if !ok {
		trace, err = observability.NewRootTraceContext(false)
		if err != nil {
			return RuntimeInvocation{}, err
		}
	}
	traceparent, err := trace.TraceParent()
	if err != nil {
		return RuntimeInvocation{}, ErrInvalidRequest
	}
	requestID := stableRuntimeID("modelreq_", request.InvocationID, parameterDigest)
	reservationID := stableRuntimeID("modelres_", request.InvocationID, parameterDigest)
	artifactRefs := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		artifactRefs = append(artifactRefs, artifact.URI)
	}
	sort.Strings(artifactRefs)
	envelope := aop.Envelope{
		AOPVersion: aop.Version, MessageID: stableRuntimeID("msg_", request.InvocationID, parameterDigest),
		IdempotencyKey: stableRuntimeID("aop_", request.InvocationID, parameterDigest),
		CorrelationID:  stableRuntimeID("corr_", request.TenantID, request.ProjectID, request.InvocationID),
		ProjectID:      request.ProjectID, GoalSpec: stage.goalRef, PlanSpec: stage.planRef, TaskID: request.TaskID,
		Sender: aop.Sender{
			AgentInstanceID: agentID, Role: string(request.Role), Provider: route.Provider,
			Model: route.Model, LeaseID: lease.ID,
		},
		Scope: stage.scope, Intent: expectedRuntimeIntent(request), ExpectedAggregateVersion: stage.expectedVersion,
		ArtifactRefs: artifactRefs, KnowledgeRefs: []string{},
		BudgetContext: &aop.BudgetContext{AccountID: project.ID, ReservationID: reservationID},
		TraceContext:  &aop.TraceContext{Traceparent: traceparent, Tracestate: trace.TraceState},
		CreatedAt:     lease.IssuedAt, ExpiresAt: lease.ExpiresAt,
	}
	if envelope.Validate(now) != nil {
		return RuntimeInvocation{}, ErrInvalidRequest
	}
	declaration := agentruntime.Declaration{
		RunID: request.InvocationID, Envelope: envelope,
		TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		AgentInstanceID: agentID, Role: request.Role, PromptBundle: bundle, ContextManifest: manifest,
		ResponseSchemaRef: responseSchema.Reference, ResponseSchema: responseSchema.Document,
		Tools: nil, ToolSchemaDigest: agentruntime.DigestToolDefinitions(nil),
		PolicyVersion: lease.PolicyVersion, PolicyDigest: lease.PolicyVersion,
		DataClassification: project.DataClassification,
	}
	if _, err := agentruntime.AssemblePrompt(bundle, manifest, responseSchema.Reference, responseSchema.Document); err != nil {
		return RuntimeInvocation{}, ErrInvalidRequest
	}
	prepared := RuntimeInvocation{
		Declaration: declaration, Lease: runtimeAgentLease(lease), Intent: expectedRuntimeIntent(request),
		ModelCall: agentruntime.ModelCall{
			RequestID: requestID, Provider: route.Provider, Model: route.Model, ReservationID: reservationID,
			MaxOutputTokens: route.MaxOutputTokens, Temperature: route.Temperature, Seed: cloneSeed(route.Seed),
			ProviderPolicy: route.ProviderPolicy, CachePolicy: route.CachePolicy,
			WorstCaseCostMicros: route.WorstCaseCostMicros, MaxAttempts: route.MaxAttempts,
		},
	}
	if err := validateRuntimeInvocation(request, prepared); err != nil {
		return RuntimeInvocation{}, err
	}
	return prepared, nil
}

type preparedStageContext struct {
	items           []agentruntime.ContextItem
	goalRef         *contracts.SpecRef
	planRef         *contracts.SpecRef
	scope           aop.Scope
	expectedVersion int64
	taskVersion     int64
	specDigest      string
}

func (preparer *AuthoritativeRuntimePreparer) stageContext(ctx context.Context, request AgentInvocation, project state.Project, artifacts map[ArtifactKind]SpecArtifact) (preparedStageContext, error) {
	stage := preparedStageContext{scope: aop.ScopeProject, expectedVersion: project.Version}
	appendArtifact := func(kind ArtifactKind, contextKind agentruntime.ContextKind, trust agentruntime.TrustLevel) error {
		artifact := artifacts[kind]
		item, err := runtimeArtifactContext(artifact, contextKind, trust)
		if err != nil {
			return err
		}
		stage.items = append(stage.items, item)
		return nil
	}
	switch request.Stage {
	case "GOAL_DRAFT":
		if err := appendArtifact(ArtifactUserMessage, agentruntime.ContextUserInput, agentruntime.TrustExternalUntrusted); err != nil {
			return preparedStageContext{}, err
		}
		for _, kind := range []ArtifactKind{ArtifactGoalDraft, ArtifactGoalApproved} {
			artifact, exists := artifacts[kind]
			if !exists {
				continue
			}
			if !projectGoalMatches(project, artifact, kind == ArtifactGoalApproved) {
				return preparedStageContext{}, ErrInvalidRequest
			}
			trust := agentruntime.TrustGeneratedUnreviewed
			if project.Goal.ApprovedBy != "" {
				trust = agentruntime.TrustProjectApproved
			}
			if err := appendArtifact(kind, agentruntime.ContextGoalReference, trust); err != nil {
				return preparedStageContext{}, err
			}
			ref := runtimeArtifactRef(artifact)
			stage.goalRef = &ref
		}
	case "GOAL_CHALLENGE":
		if err := appendArtifact(ArtifactUserMessage, agentruntime.ContextUserInput, agentruntime.TrustExternalUntrusted); err != nil {
			return preparedStageContext{}, err
		}
		draft := artifacts[ArtifactGoalDraft]
		if err := appendArtifact(ArtifactGoalDraft, agentruntime.ContextGoalReference, agentruntime.TrustGeneratedUnreviewed); err != nil {
			return preparedStageContext{}, err
		}
		ref := runtimeArtifactRef(draft)
		stage.goalRef = &ref
	case "GOAL_REVISION":
		if err := appendArtifact(ArtifactUserMessage, agentruntime.ContextUserInput, agentruntime.TrustExternalUntrusted); err != nil {
			return preparedStageContext{}, err
		}
		draft := artifacts[ArtifactGoalDraft]
		challenge, err := decodeChallengeArtifact(artifacts[ArtifactGoalChallenge])
		if err != nil || challenge.ProjectID != request.ProjectID || challenge.GoalSpecRef != runtimeArtifactRef(draft) {
			return preparedStageContext{}, ErrInvalidRequest
		}
		if err := appendArtifact(ArtifactGoalDraft, agentruntime.ContextGoalReference, agentruntime.TrustGeneratedUnreviewed); err != nil {
			return preparedStageContext{}, err
		}
		if err := appendArtifact(ArtifactGoalChallenge, agentruntime.ContextPriorFinding, agentruntime.TrustGeneratedUnreviewed); err != nil {
			return preparedStageContext{}, err
		}
		ref := runtimeArtifactRef(draft)
		stage.goalRef = &ref
	case "PLAN_DRAFT":
		goal := artifacts[ArtifactGoalApproved]
		if !projectGoalMatches(project, goal, true) {
			return preparedStageContext{}, ErrInvalidRequest
		}
		if _, err := decodeGoalArtifact(goal); err != nil {
			return preparedStageContext{}, ErrInvalidRequest
		}
		if err := appendArtifact(ArtifactGoalApproved, agentruntime.ContextGoalReference, agentruntime.TrustProjectApproved); err != nil {
			return preparedStageContext{}, err
		}
		ref := runtimeArtifactRef(goal)
		stage.goalRef = &ref
	case "MODULE_SPEC":
		goal, planArtifact := artifacts[ArtifactGoalApproved], artifacts[ArtifactPlanSpec]
		if !projectGoalMatches(project, goal, true) || len(request.Payload) == 0 || len(request.Payload) > agentruntime.MaximumContextItemBytes || !json.Valid(request.Payload) {
			return preparedStageContext{}, ErrInvalidRequest
		}
		goalRef := runtimeArtifactRef(goal)
		plan, err := decodePlanArtifact(planArtifact, goalRef)
		if err != nil {
			return preparedStageContext{}, ErrInvalidRequest
		}
		var module contracts.PlanModule
		if err := decodeStrict(request.Payload, &module); err != nil {
			return preparedStageContext{}, ErrInvalidRequest
		}
		planned, found := findRuntimeModule(plan.Modules, module.ModuleID)
		if !found || !reflect.DeepEqual(planned, module) {
			return preparedStageContext{}, ErrInvalidRequest
		}
		task, found, err := preparer.tasks.Task(ctx, request.TenantID, request.ProjectID, request.TaskID)
		planRef := runtimeArtifactRef(planArtifact)
		if err != nil {
			return preparedStageContext{}, err
		}
		if !found || task.TenantID != request.TenantID || task.ProjectID != request.ProjectID || task.ID != request.TaskID ||
			task.State != contracts.TaskPlanning || task.Version < 1 || task.ModuleID != module.ModuleID ||
			task.PlanningSpecRef != planRef || task.ModuleSpecRef != (contracts.SpecRef{}) {
			return preparedStageContext{}, ErrInvalidRequest
		}
		if err := appendArtifact(ArtifactGoalApproved, agentruntime.ContextGoalReference, agentruntime.TrustProjectApproved); err != nil {
			return preparedStageContext{}, err
		}
		if err := appendArtifact(ArtifactPlanSpec, agentruntime.ContextPlanReference, agentruntime.TrustGeneratedUnreviewed); err != nil {
			return preparedStageContext{}, err
		}
		stage.items = append(stage.items, agentruntime.ContextItem{
			ID: stableRuntimeID("ctx_", request.TaskID, "assignment"), Kind: agentruntime.ContextTaskState,
			Reference: "aor://task/" + request.TaskID, Revision: strconv.FormatInt(task.Version, 10),
			SHA256: agentruntime.DigestContextContent(string(request.Payload)),
			Trust:  agentruntime.TrustGeneratedUnreviewed, Content: string(request.Payload),
		})
		stage.goalRef, stage.planRef = &goalRef, &planRef
		stage.scope, stage.expectedVersion = aop.ScopeTask, task.Version
		stage.taskVersion, stage.specDigest = task.Version, task.PlanningSpecRef.SHA256
	default:
		return preparedStageContext{}, ErrInvalidRequest
	}
	return stage, nil
}

func (preparer *AuthoritativeRuntimePreparer) loadInputs(ctx context.Context, request AgentInvocation) (map[ArtifactKind]SpecArtifact, error) {
	if !validRuntimeInputKinds(request) {
		return nil, ErrInvalidRequest
	}
	artifacts := make(map[ArtifactKind]SpecArtifact, len(request.Inputs))
	for _, pointer := range request.Inputs {
		if !pointer.Kind.Valid() || pointer.SpecID == "" || pointer.Version < 1 || pointer.URI == "" || pointer.ContentSHA256 == "" {
			return nil, ErrInvalidRequest
		}
		if _, duplicate := artifacts[pointer.Kind]; duplicate {
			return nil, ErrInvalidRequest
		}
		artifact, found, err := preparer.artifacts.Get(ctx, request.TenantID, request.ProjectID, pointer.Kind, pointer.SpecID, pointer.Version)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, ErrArtifactNotFound
		}
		if artifact.TenantID != request.TenantID || artifact.ProjectID != request.ProjectID || artifact.Kind != pointer.Kind ||
			artifact.SpecID != pointer.SpecID || artifact.Version != pointer.Version || artifact.URI != pointer.URI ||
			artifact.ContentSHA256 != pointer.ContentSHA256 || len(artifact.Content) == 0 || verifyArtifact(artifact) != nil {
			return nil, ErrInvalidRequest
		}
		artifacts[pointer.Kind] = artifact
	}
	return artifacts, nil
}

func validRuntimeInputKinds(request AgentInvocation) bool {
	counts := make(map[ArtifactKind]int, len(request.Inputs))
	for _, input := range request.Inputs {
		counts[input.Kind]++
	}
	exact := func(expected ...ArtifactKind) bool {
		if len(request.Inputs) != len(expected) {
			return false
		}
		for _, kind := range expected {
			if counts[kind] != 1 {
				return false
			}
		}
		return true
	}
	switch request.Stage {
	case "GOAL_DRAFT":
		return exact(ArtifactUserMessage) || exact(ArtifactUserMessage, ArtifactGoalDraft) || exact(ArtifactUserMessage, ArtifactGoalApproved)
	case "GOAL_CHALLENGE":
		return exact(ArtifactUserMessage, ArtifactGoalDraft)
	case "GOAL_REVISION":
		return exact(ArtifactUserMessage, ArtifactGoalDraft, ArtifactGoalChallenge)
	case "PLAN_DRAFT":
		return exact(ArtifactGoalApproved)
	case "MODULE_SPEC":
		return exact(ArtifactGoalApproved, ArtifactPlanSpec)
	default:
		return false
	}
}

func runtimeArtifactContext(artifact SpecArtifact, kind agentruntime.ContextKind, trust agentruntime.TrustLevel) (agentruntime.ContextItem, error) {
	if len(artifact.Content) > agentruntime.MaximumContextItemBytes {
		return agentruntime.ContextItem{}, ErrInvalidRequest
	}
	item := agentruntime.ContextItem{
		ID:   stableRuntimeID("ctx_", string(artifact.Kind), artifact.SpecID, strconv.Itoa(artifact.Version)),
		Kind: kind, Reference: artifact.URI, Revision: strconv.Itoa(artifact.Version),
		SHA256: agentruntime.DigestContextContent(string(artifact.Content)), Trust: trust, Content: string(artifact.Content),
	}
	if kind == agentruntime.ContextGoalReference || kind == agentruntime.ContextPlanReference || kind == agentruntime.ContextModuleReference {
		item.SourceSHA256 = artifact.ContentSHA256
	}
	return item, nil
}

func runtimeArtifactRef(artifact SpecArtifact) contracts.SpecRef {
	return contracts.SpecRef{Version: artifact.Version, SHA256: artifact.ContentSHA256}
}

func projectGoalMatches(project state.Project, artifact SpecArtifact, requireApproved bool) bool {
	if project.Goal == nil || project.Goal.ID != artifact.SpecID || project.Goal.Version != artifact.Version || project.Goal.SHA256 != artifact.ContentSHA256 {
		return false
	}
	return !requireApproved || project.Goal.ApprovedBy != ""
}

func findRuntimeModule(modules []contracts.PlanModule, moduleID string) (contracts.PlanModule, bool) {
	for _, module := range modules {
		if module.ModuleID == moduleID {
			return module, true
		}
	}
	return contracts.PlanModule{}, false
}

func validModelRoute(route ModelRoute) bool {
	return route.Provider != "" && len(route.Provider) <= 128 && route.Model != "" && len(route.Model) <= 256 &&
		route.MaxOutputTokens > 0 && !math.IsNaN(route.Temperature) && !math.IsInf(route.Temperature, 0) &&
		route.Temperature >= 0 && route.Temperature <= 2 && route.ProviderPolicy != "" && len(route.ProviderPolicy) <= 256 &&
		route.CachePolicy != "" && len(route.CachePolicy) <= 128 && route.WorstCaseCostMicros >= 0 &&
		route.MaxAttempts >= 1 && route.MaxAttempts <= 3
}

func runtimeParameterDigest(request AgentInvocation, projectVersion, taskVersion int64, specDigest, promptDigest, contextDigest, responseDigest string, route ModelRoute) (string, error) {
	encoded, err := json.Marshal(struct {
		InvocationID   string            `json:"invocationId"`
		TenantID       string            `json:"tenantId"`
		ProjectID      string            `json:"projectId"`
		TaskID         string            `json:"taskId,omitempty"`
		Role           agentruntime.Role `json:"role"`
		Stage          string            `json:"stage"`
		ProjectVersion int64             `json:"projectVersion"`
		TaskVersion    int64             `json:"taskVersion"`
		SpecDigest     string            `json:"specDigest,omitempty"`
		PromptDigest   string            `json:"promptDigest"`
		ContextDigest  string            `json:"contextDigest"`
		ResponseDigest string            `json:"responseDigest"`
		Route          ModelRoute        `json:"route"`
	}{
		request.InvocationID, request.TenantID, request.ProjectID, request.TaskID, request.Role, request.Stage,
		projectVersion, taskVersion, specDigest, promptDigest, contextDigest, responseDigest, route,
	})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func validIssuedRuntimeLease(lease authz.CapabilityLease, principal authn.Principal, project state.Project, request AgentInvocation, stage preparedStageContext, resource authz.Resource, parameterDigest string, now time.Time) bool {
	return lease.ValidateShape() == nil && lease.State == authz.LeaseActive && !lease.IsExpired(now) &&
		lease.AgentInstanceID == principal.ID && lease.PrincipalID == principal.ID && lease.PrincipalType == principal.Type &&
		lease.TenantID == request.TenantID && lease.ProjectID == request.ProjectID && lease.ProjectVersion == project.Version &&
		lease.TaskID == request.TaskID && lease.TaskVersion == stage.taskVersion && lease.SpecDigest == stage.specDigest &&
		lease.Role == string(request.Role) && lease.Action == authz.ActionModelGenerate && reflect.DeepEqual(lease.Resource, resource) &&
		lease.ParameterDigest == parameterDigest && len(lease.Capabilities) == 1 && lease.Capabilities[0] == authz.ActionModelGenerate &&
		lease.HeartbeatIntervalSeconds == agentruntime.DefaultHeartbeatSeconds && lease.BudgetAccountID == project.ID &&
		(contracts.SpecRef{Version: 1, SHA256: lease.PolicyVersion}).Validate() == nil
}

func runtimeAgentLease(lease authz.CapabilityLease) agentruntime.AgentLease {
	return agentruntime.AgentLease{
		LeaseID: lease.ID, AgentInstanceID: lease.AgentInstanceID, TenantID: lease.TenantID,
		ProjectID: lease.ProjectID, TaskID: lease.TaskID, Role: agentruntime.Role(lease.Role),
		IssuedAt: lease.IssuedAt, ExpiresAt: lease.ExpiresAt, LastHeartbeatAt: lease.LastHeartbeatAt,
		HeartbeatIntervalSeconds: int(lease.HeartbeatIntervalSeconds), Capabilities: append([]string(nil), lease.Capabilities...),
		PolicyVersion: lease.PolicyVersion, BudgetAccountID: lease.BudgetAccountID, Nonce: lease.Nonce,
		FencingToken: lease.FencingToken, Signature: lease.Signature,
	}
}

func runtimeAgentID(request AgentInvocation) string {
	if request.TaskID == "" {
		return request.ProjectID + ":" + string(request.Role)
	}
	return request.ProjectID + ":" + string(request.Role) + ":" + request.TaskID
}

func stableRuntimeID(prefix string, parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(part))
	}
	return prefix + hex.EncodeToString(hash.Sum(nil))
}

func cloneSeed(seed *int64) *int64 {
	if seed == nil {
		return nil
	}
	value := *seed
	return &value
}

var _ RuntimeInvocationPreparer = (*AuthoritativeRuntimePreparer)(nil)
