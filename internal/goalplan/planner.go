package goalplan

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

const maximumPlanModules = 1000

type Planner struct {
	artifacts ArtifactStore
	invoker   AgentInvoker
	projects  ProjectCommander
	clock     func() time.Time
}

func NewPlanner(artifacts ArtifactStore, invoker AgentInvoker, projects ProjectCommander, clock func() time.Time) (*Planner, error) {
	if artifacts == nil || invoker == nil || projects == nil {
		return nil, ErrInvalidRequest
	}
	if clock == nil {
		clock = time.Now
	}
	return &Planner{artifacts: artifacts, invoker: invoker, projects: projects, clock: clock}, nil
}

func (p *Planner) BuildAndPublish(ctx context.Context, request PlanningRequest) (PlanningResult, error) {
	project, found, err := p.projects.Project(ctx, request.TenantID, request.ProjectID)
	if err != nil || !found {
		if err != nil {
			return PlanningResult{}, err
		}
		return PlanningResult{}, ErrInvalidRequest
	}
	if err := validatePlanningRequest(request, project.Version, project.State, project.Goal, project.Plan); err != nil {
		return PlanningResult{}, err
	}
	goalArtifact, found, err := p.artifacts.Get(ctx, request.TenantID, request.ProjectID, ArtifactGoalApproved, request.GoalSpecID, request.GoalRef.Version)
	if err != nil || !found {
		if err != nil {
			return PlanningResult{}, err
		}
		return PlanningResult{}, ErrArtifactNotFound
	}
	if _, err := decodeGoalArtifact(goalArtifact); err != nil {
		return PlanningResult{}, err
	}

	plan, planArtifact, err := p.loadOrGeneratePlan(ctx, request, goalArtifact)
	if err != nil {
		return PlanningResult{}, err
	}
	if len(plan.Modules) > maximumPlanModules || len(request.ModuleTaskIDs) != len(plan.Modules) || len(request.AttemptSeriesIDs) != len(plan.Modules) || len(request.ModuleSpecVersions) != len(plan.Modules) {
		return PlanningResult{}, ErrInvalidRequest
	}
	if err := validatePlanningAssignments(plan, request); err != nil {
		return PlanningResult{}, err
	}
	if project.Version == request.ExpectedProjectVersion+1 && (project.Plan == nil || *project.Plan != (contracts.SpecRef{Version: plan.PlanSpecVersion, SHA256: plan.SHA256})) {
		return PlanningResult{}, ErrInvalidRequest
	}
	moduleSpecs := make(map[string]contracts.ModuleSpec, len(plan.Modules))
	moduleArtifacts := make(map[string]SpecArtifact, len(plan.Modules))
	modules := append([]contracts.PlanModule(nil), plan.Modules...)
	sort.Slice(modules, func(left, right int) bool { return modules[left].ModuleID < modules[right].ModuleID })
	for _, module := range modules {
		if request.ModuleTaskIDs[module.ModuleID] == "" || request.AttemptSeriesIDs[module.ModuleID] == "" || request.ModuleSpecVersions[module.ModuleID] < 1 {
			return PlanningResult{}, ErrInvalidRequest
		}
		moduleSpec, artifact, moduleErr := p.loadOrGenerateModule(ctx, request, goalArtifact, planArtifact, plan, module, request.RetainedModules[module.ModuleID])
		if moduleErr != nil {
			return PlanningResult{}, moduleErr
		}
		moduleSpecs[module.ModuleID] = moduleSpec
		moduleArtifacts[module.ModuleID] = artifact
	}
	analysis, analysisContent, err := analyzePlan(plan, planArtifact.CreatedAt)
	if err != nil {
		return PlanningResult{}, err
	}
	analysisArtifact, err := p.artifacts.Put(ctx, SpecArtifact{
		TenantID: request.TenantID, ProjectID: request.ProjectID, Kind: ArtifactPlanAnalysis, SpecID: request.PlanSpecID + "-analysis",
		Version: plan.PlanSpecVersion, ContentSHA256: analysis.SHA256, Content: analysisContent, CreatedBy: planArtifact.CreatedBy, SourceRunID: planArtifact.SourceRunID,
	})
	if err != nil {
		return PlanningResult{}, err
	}
	dag := make(map[string][]string, len(plan.Modules))
	tasks := make([]orchestrator.PlanTaskDefinition, 0, len(modules))
	for _, module := range modules {
		dag[module.ModuleID] = append([]string(nil), module.Dependencies...)
		tasks = append(tasks, orchestrator.PlanTaskDefinition{
			ModuleID: module.ModuleID, TaskID: request.ModuleTaskIDs[module.ModuleID],
			ModuleSpecRef:   contracts.SpecRef{Version: moduleSpecs[module.ModuleID].ModuleSpecVersion, SHA256: moduleSpecs[module.ModuleID].SHA256},
			AttemptSeriesID: request.AttemptSeriesIDs[module.ModuleID], Retain: request.RetainedModules[module.ModuleID],
		})
	}
	publication, err := p.projects.PublishPlan(ctx, orchestrator.PublishPlanRequest{
		TenantID: request.TenantID, ProjectID: request.ProjectID, PrincipalID: planArtifact.CreatedBy,
		IdempotencyKey: request.IdempotencyKey, ExpectedProjectVersion: request.ExpectedProjectVersion,
		GoalSpecRef: request.GoalRef, PlanRef: contracts.SpecRef{Version: plan.PlanSpecVersion, SHA256: plan.SHA256}, DAG: dag, Tasks: tasks,
	})
	if err != nil {
		return PlanningResult{}, err
	}
	return PlanningResult{Plan: plan, PlanArtifact: planArtifact, ModuleSpecs: moduleSpecs, ModuleArtifacts: moduleArtifacts, Analysis: analysis, AnalysisArtifact: analysisArtifact, Publication: publication}, nil
}

func (p *Planner) loadOrGeneratePlan(ctx context.Context, request PlanningRequest, goal SpecArtifact) (contracts.PlanSpec, SpecArtifact, error) {
	if artifact, found, err := p.artifacts.Get(ctx, request.TenantID, request.ProjectID, ArtifactPlanSpec, request.PlanSpecID, request.PlanVersion); err != nil {
		return contracts.PlanSpec{}, SpecArtifact{}, err
	} else if found {
		plan, decodeErr := decodePlanArtifact(artifact, request.GoalRef)
		return plan, artifact, decodeErr
	}
	record, err := p.invoker.Invoke(ctx, AgentInvocation{
		InvocationID: request.IdempotencyKey + ":plan-supervisor", TenantID: request.TenantID, ProjectID: request.ProjectID,
		Role: agentruntime.RolePlanSupervisor, Stage: "PLAN_DRAFT", Inputs: []ArtifactPointer{artifactPointer(goal)},
	})
	if err != nil {
		return contracts.PlanSpec{}, SpecArtifact{}, err
	}
	plan, content, err := normalizePlanRecord(record, request.ProjectID, request.GoalRef, request.PlanVersion)
	if err != nil {
		return contracts.PlanSpec{}, SpecArtifact{}, err
	}
	artifact, err := p.artifacts.Put(ctx, SpecArtifact{
		TenantID: request.TenantID, ProjectID: request.ProjectID, Kind: ArtifactPlanSpec, SpecID: request.PlanSpecID,
		Version: plan.PlanSpecVersion, ContentSHA256: plan.SHA256, Content: content, CreatedBy: record.AgentInstanceID, SourceRunID: record.RunID,
	})
	return plan, artifact, err
}

func (p *Planner) loadOrGenerateModule(ctx context.Context, request PlanningRequest, goal, planArtifact SpecArtifact, plan contracts.PlanSpec, module contracts.PlanModule, retain bool) (contracts.ModuleSpec, SpecArtifact, error) {
	moduleVersion := request.ModuleSpecVersions[module.ModuleID]
	if artifact, found, err := p.artifacts.Get(ctx, request.TenantID, request.ProjectID, ArtifactModuleSpec, module.ModuleID, moduleVersion); err != nil {
		return contracts.ModuleSpec{}, SpecArtifact{}, err
	} else if found {
		moduleSpec, decodeErr := decodeModuleArtifact(artifact, plan, module, !retain)
		return moduleSpec, artifact, decodeErr
	} else if retain {
		return contracts.ModuleSpec{}, SpecArtifact{}, ErrArtifactNotFound
	}
	payload, _ := json.Marshal(module)
	record, err := p.invoker.Invoke(ctx, AgentInvocation{
		InvocationID: request.IdempotencyKey + ":module-planner:" + module.ModuleID, TenantID: request.TenantID, ProjectID: request.ProjectID,
		Role: agentruntime.RoleModulePlanner, Stage: "MODULE_SPEC", Inputs: []ArtifactPointer{artifactPointer(goal), artifactPointer(planArtifact)}, Payload: payload,
	})
	if err != nil {
		return contracts.ModuleSpec{}, SpecArtifact{}, err
	}
	moduleSpec, content, err := normalizeModuleRecord(record, request.ProjectID, plan, module, moduleVersion)
	if err != nil {
		return contracts.ModuleSpec{}, SpecArtifact{}, err
	}
	artifact, err := p.artifacts.Put(ctx, SpecArtifact{
		TenantID: request.TenantID, ProjectID: request.ProjectID, Kind: ArtifactModuleSpec, SpecID: module.ModuleID,
		Version: moduleSpec.ModuleSpecVersion, ContentSHA256: moduleSpec.SHA256, Content: content, CreatedBy: record.AgentInstanceID, SourceRunID: record.RunID,
	})
	return moduleSpec, artifact, err
}

func normalizePlanRecord(record AgentRecord, projectID string, goalRef contracts.SpecRef, planVersion int) (contracts.PlanSpec, []byte, error) {
	if record.RunID == "" || record.AgentInstanceID == "" || record.Role != agentruntime.RolePlanSupervisor || len(record.Payload) == 0 {
		return contracts.PlanSpec{}, nil, ErrAgentOutput
	}
	var plan contracts.PlanSpec
	if err := decodeStrict(record.Payload, &plan); err != nil {
		return contracts.PlanSpec{}, nil, ErrAgentOutput
	}
	plan.PlanSpecVersion = planVersion
	plan.ProjectID = projectID
	plan.GoalSpecRef = goalRef
	plan.SHA256 = ""
	if len(plan.Modules) > maximumPlanModules {
		return contracts.PlanSpec{}, nil, ErrAgentOutput
	}
	if err := validatePlanShape(plan); err != nil || validatePlanOwnership(plan) != nil {
		return contracts.PlanSpec{}, nil, ErrAgentOutput
	}
	content, err := json.Marshal(plan)
	if err != nil {
		return contracts.PlanSpec{}, nil, err
	}
	plan.SHA256, err = canonicaljson.DigestObjectWithoutFields(content, "sha256", "signature")
	if err != nil {
		return contracts.PlanSpec{}, nil, err
	}
	if err := plan.Validate(); err != nil {
		return contracts.PlanSpec{}, nil, err
	}
	content, err = json.Marshal(plan)
	if err != nil || contracts.ValidatePlanJSON(content) != nil {
		return contracts.PlanSpec{}, nil, ErrAgentOutput
	}
	return plan, content, nil
}

func normalizeModuleRecord(record AgentRecord, projectID string, plan contracts.PlanSpec, planned contracts.PlanModule, moduleVersion int) (contracts.ModuleSpec, []byte, error) {
	if record.RunID == "" || record.AgentInstanceID == "" || record.Role != agentruntime.RoleModulePlanner || len(record.Payload) == 0 {
		return contracts.ModuleSpec{}, nil, ErrAgentOutput
	}
	var module contracts.ModuleSpec
	if err := decodeStrict(record.Payload, &module); err != nil {
		return contracts.ModuleSpec{}, nil, ErrAgentOutput
	}
	module.ModuleSpecVersion = moduleVersion
	module.ProjectID = projectID
	module.PlanVersion = plan.PlanSpecVersion
	module.ModuleID = planned.ModuleID
	module.Name = planned.Name
	module.ExecutionPlatform = planned.ExecutionPlatform
	module.SandboxLevel = planned.SandboxLevel
	module.Dependencies = cloneStrings(planned.Dependencies)
	module.AllowedPaths = cloneStrings(planned.OwnedPaths)
	module.ForbiddenPaths = cloneStrings(planned.ForbiddenPaths)
	module.Interfaces = cloneStrings(planned.PublicInterfaces)
	module.AcceptanceCriteria = cloneStrings(planned.AcceptanceCriteria)
	module.Responsibilities = prependUnique(planned.Responsibility, module.Responsibilities)
	module.SHA256 = ""
	if err := validateModuleShape(module); err != nil {
		return contracts.ModuleSpec{}, nil, err
	}
	content, err := json.Marshal(module)
	if err != nil {
		return contracts.ModuleSpec{}, nil, err
	}
	module.SHA256, err = canonicaljson.DigestObjectWithoutFields(content, "sha256", "signature")
	if err != nil {
		return contracts.ModuleSpec{}, nil, err
	}
	if err := module.Validate(); err != nil {
		return contracts.ModuleSpec{}, nil, err
	}
	content, err = json.Marshal(module)
	if err != nil || contracts.ValidateModuleJSON(content) != nil {
		return contracts.ModuleSpec{}, nil, ErrAgentOutput
	}
	return module, content, nil
}

func decodePlanArtifact(artifact SpecArtifact, goalRef contracts.SpecRef) (contracts.PlanSpec, error) {
	var plan contracts.PlanSpec
	if err := decodeStrict(artifact.Content, &plan); err != nil || contracts.ValidatePlanJSON(artifact.Content) != nil || plan.SHA256 != artifact.ContentSHA256 || plan.GoalSpecRef != goalRef || len(plan.Modules) > maximumPlanModules || validatePlanShape(plan) != nil || validatePlanOwnership(plan) != nil {
		return contracts.PlanSpec{}, ErrAgentOutput
	}
	return plan, nil
}

func decodeModuleArtifact(artifact SpecArtifact, plan contracts.PlanSpec, planned contracts.PlanModule, requireCurrentPlan bool) (contracts.ModuleSpec, error) {
	var module contracts.ModuleSpec
	if err := decodeStrict(artifact.Content, &module); err != nil || contracts.ValidateModuleJSON(artifact.Content) != nil || module.SHA256 != artifact.ContentSHA256 || module.ProjectID != plan.ProjectID || module.PlanVersion > plan.PlanSpecVersion || requireCurrentPlan && module.PlanVersion != plan.PlanSpecVersion || module.ModuleID != planned.ModuleID || module.ExecutionPlatform != planned.ExecutionPlatform || module.SandboxLevel != planned.SandboxLevel || !slices.Equal(module.Dependencies, planned.Dependencies) || !slices.Equal(module.AllowedPaths, planned.OwnedPaths) || !slices.Equal(module.ForbiddenPaths, planned.ForbiddenPaths) || !slices.Equal(module.Interfaces, planned.PublicInterfaces) || !slices.Equal(module.AcceptanceCriteria, planned.AcceptanceCriteria) {
		return contracts.ModuleSpec{}, ErrAgentOutput
	}
	return module, nil
}

func analyzePlan(plan contracts.PlanSpec, at time.Time) (PlanAnalysis, []byte, error) {
	order, critical := graphAnalysis(plan.Modules)
	owners := make(map[string]string)
	for _, module := range plan.Modules {
		for _, ownedPath := range module.OwnedPaths {
			clean, _ := cleanOwnedPath(ownedPath)
			owners[clean] = module.ModuleID
		}
	}
	analysis := PlanAnalysis{AnalysisVersion: 1, ProjectID: plan.ProjectID, PlanSpecRef: contracts.SpecRef{Version: plan.PlanSpecVersion, SHA256: plan.SHA256}, TopologicalOrder: order, CriticalPath: critical, PathOwners: owners, CreatedAt: at.UTC().Format(time.RFC3339Nano)}
	content, err := json.Marshal(analysis)
	if err != nil {
		return PlanAnalysis{}, nil, err
	}
	analysis.SHA256, err = canonicaljson.DigestObjectWithoutFields(content, "sha256", "signature")
	if err != nil {
		return PlanAnalysis{}, nil, err
	}
	content, err = json.Marshal(analysis)
	return analysis, content, err
}

func graphAnalysis(modules []contracts.PlanModule) ([]string, []string) {
	dependencies := make(map[string][]string, len(modules))
	reverse := make(map[string][]string, len(modules))
	indegree := make(map[string]int, len(modules))
	for _, module := range modules {
		dependencies[module.ModuleID] = append([]string(nil), module.Dependencies...)
		indegree[module.ModuleID] = len(module.Dependencies)
		for _, dependency := range module.Dependencies {
			reverse[dependency] = append(reverse[dependency], module.ModuleID)
		}
	}
	var ready []string
	for id, degree := range indegree {
		if degree == 0 {
			ready = append(ready, id)
		}
	}
	sort.Strings(ready)
	var order []string
	paths := make(map[string][]string, len(modules))
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		order = append(order, id)
		best := []string{id}
		for _, dependency := range dependencies[id] {
			candidate := append(append([]string(nil), paths[dependency]...), id)
			if len(candidate) > len(best) || len(candidate) == len(best) && strings.Join(candidate, "\x00") < strings.Join(best, "\x00") {
				best = candidate
			}
		}
		paths[id] = best
		sort.Strings(reverse[id])
		for _, dependent := range reverse[id] {
			indegree[dependent]--
			if indegree[dependent] == 0 {
				ready = append(ready, dependent)
				sort.Strings(ready)
			}
		}
	}
	var critical []string
	for _, id := range order {
		candidate := paths[id]
		if len(candidate) > len(critical) || len(candidate) == len(critical) && strings.Join(candidate, "\x00") < strings.Join(critical, "\x00") {
			critical = append([]string(nil), candidate...)
		}
	}
	return order, critical
}

func prependUnique(value string, values []string) []string {
	result := []string{value}
	for _, existing := range values {
		if existing != value {
			result = append(result, existing)
		}
	}
	return result
}

func cloneStrings(values []string) []string {
	result := make([]string, len(values))
	copy(result, values)
	return result
}

func validatePlanningRequest(request PlanningRequest, projectVersion int64, projectState contracts.ProjectState, goal *state.GoalRecord, plan *contracts.SpecRef) error {
	if request.TenantID == "" || request.ProjectID == "" || request.GoalSpecID == "" || request.PlanSpecID == "" || request.PlanVersion < 1 || request.GoalRef.Validate() != nil || request.ExpectedProjectVersion < 1 || request.IdempotencyKey == "" || len(request.ModuleTaskIDs) == 0 || len(request.AttemptSeriesIDs) == 0 || len(request.ModuleSpecVersions) == 0 || goal == nil || goal.ID != request.GoalSpecID || goal.Version != request.GoalRef.Version || goal.SHA256 != request.GoalRef.SHA256 || goal.ApprovedBy == "" {
		return ErrInvalidRequest
	}
	initial := projectVersion == request.ExpectedProjectVersion && projectState == contracts.ProjectPlanning && plan == nil
	replay := projectVersion == request.ExpectedProjectVersion+1 && projectState == contracts.ProjectExecuting && plan != nil
	if !initial && !replay {
		return ErrInvalidRequest
	}
	for moduleID, retain := range request.RetainedModules {
		if !retain || request.ModuleTaskIDs[moduleID] == "" || request.ModuleSpecVersions[moduleID] < 1 {
			return ErrInvalidRequest
		}
	}
	return nil
}

func validatePlanningAssignments(plan contracts.PlanSpec, request PlanningRequest) error {
	known := make(map[string]bool, len(plan.Modules))
	taskIDs := make(map[string]bool, len(plan.Modules))
	seriesIDs := make(map[string]bool, len(plan.Modules))
	for _, module := range plan.Modules {
		known[module.ModuleID] = true
		taskID := request.ModuleTaskIDs[module.ModuleID]
		seriesID := request.AttemptSeriesIDs[module.ModuleID]
		if taskID == "" || seriesID == "" || request.ModuleSpecVersions[module.ModuleID] < 1 || taskIDs[taskID] || seriesIDs[seriesID] {
			return ErrInvalidRequest
		}
		taskIDs[taskID] = true
		seriesIDs[seriesID] = true
	}
	for moduleID, retain := range request.RetainedModules {
		if !retain || !known[moduleID] {
			return ErrInvalidRequest
		}
	}
	return nil
}
