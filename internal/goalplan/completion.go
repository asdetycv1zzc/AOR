package goalplan

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

type PlanCompletionRequest struct {
	TenantID  string
	ProjectID string
}

type PlanCompletionModuleDraft struct {
	ModuleID string `json:"moduleId"`
	Summary  string `json:"summary"`
}

type PlanCompletionDraft struct {
	Overview               string                      `json:"overview"`
	Modules                []PlanCompletionModuleDraft `json:"modules"`
	CrossModuleFindings    []string                    `json:"crossModuleFindings"`
	RecommendedNextActions []string                    `json:"recommendedNextActions"`
}

type PlanCompletionModule struct {
	TaskID          string                    `json:"taskId"`
	ModuleID        string                    `json:"moduleId"`
	State           contracts.ModuleTaskState `json:"state"`
	ModuleSpecRef   contracts.SpecRef         `json:"moduleSpecRef"`
	Attempt         int                       `json:"attempt"`
	AttemptSeriesID string                    `json:"attemptSeriesId"`
	Summary         string                    `json:"summary"`
}

type PlanCompletionSummary struct {
	SummaryVersion         int                     `json:"summaryVersion"`
	TenantID               string                  `json:"tenantId"`
	ProjectID              string                  `json:"projectId"`
	Status                 string                  `json:"status"`
	GoalSpecRef            contracts.SpecRef       `json:"goalSpecRef"`
	PlanSpecRef            contracts.SpecRef       `json:"planSpecRef"`
	CoreSummarySHA256      string                  `json:"coreSummarySha256"`
	Overview               string                  `json:"overview"`
	Modules                []PlanCompletionModule  `json:"modules"`
	CrossModuleFindings    []string                `json:"crossModuleFindings"`
	RecommendedNextActions []string                `json:"recommendedNextActions"`
	CreatedBy              contracts.AgentIdentity `json:"createdBy"`
	CreatedAt              string                  `json:"createdAt"`
	SummarySHA256          string                  `json:"summarySha256"`
}

type PlanCompletionResult struct {
	Published bool
	Duplicate bool
	Summary   PlanCompletionSummary
	Artifact  SpecArtifact
}

type planCompletionProjectReader interface {
	Project(context.Context, string, string) (state.Project, bool, error)
}

type artifactReferenceFinder interface {
	FindByRef(context.Context, string, string, ArtifactKind, contracts.SpecRef) (SpecArtifact, bool, error)
}

type PlanCompletionService struct {
	artifacts ArtifactStore
	finder    artifactReferenceFinder
	invoker   AgentInvoker
	projects  planCompletionProjectReader
}

func NewPlanCompletionService(artifacts ArtifactStore, invoker AgentInvoker, projects planCompletionProjectReader) (*PlanCompletionService, error) {
	finder, ok := artifacts.(artifactReferenceFinder)
	if artifacts == nil || invoker == nil || projects == nil || !ok {
		return nil, ErrInvalidRequest
	}
	return &PlanCompletionService{artifacts: artifacts, finder: finder, invoker: invoker, projects: projects}, nil
}

func PlanCompletionSpecID(projectID string) string {
	return projectID + ":PLAN_SUPERVISOR_SUMMARY"
}

func (service *PlanCompletionService) Publish(ctx context.Context, request PlanCompletionRequest) (PlanCompletionResult, error) {
	if service == nil || service.artifacts == nil || service.finder == nil || service.invoker == nil || service.projects == nil || ctx == nil || ctx.Err() != nil || request.TenantID == "" || request.ProjectID == "" {
		return PlanCompletionResult{}, ErrInvalidRequest
	}
	if prior, found, err := service.Get(ctx, request); err != nil {
		return PlanCompletionResult{}, err
	} else if found {
		prior.Duplicate = true
		return prior, nil
	}
	project, found, err := service.projects.Project(ctx, request.TenantID, request.ProjectID)
	if err != nil {
		return PlanCompletionResult{}, err
	}
	if !found || project.TenantID != request.TenantID || project.ID != request.ProjectID {
		return PlanCompletionResult{}, ErrInvalidRequest
	}
	if project.CoreSummary == nil {
		return PlanCompletionResult{}, nil
	}
	if !validCompletionCore(project, *project.CoreSummary) {
		return PlanCompletionResult{}, ErrInvalidRequest
	}
	goalArtifact, found, err := service.artifacts.Get(ctx, request.TenantID, request.ProjectID, ArtifactGoalApproved, project.Goal.ID, project.Goal.Version)
	if err != nil {
		return PlanCompletionResult{}, err
	}
	if !found || goalArtifact.ContentSHA256 != project.Goal.SHA256 {
		return PlanCompletionResult{}, ErrArtifactNotFound
	}
	planArtifact, found, err := service.finder.FindByRef(ctx, request.TenantID, request.ProjectID, ArtifactPlanSpec, *project.Plan)
	if err != nil {
		return PlanCompletionResult{}, err
	}
	if !found {
		return PlanCompletionResult{}, ErrArtifactNotFound
	}
	corePayload, err := json.Marshal(project.CoreSummary)
	if err != nil {
		return PlanCompletionResult{}, err
	}
	record, err := service.invoker.Invoke(ctx, AgentInvocation{
		InvocationID: stableRuntimeID("plan_summary_", request.TenantID, request.ProjectID, project.CoreSummary.SummarySHA256),
		TenantID:     request.TenantID, ProjectID: request.ProjectID,
		Role: agentruntime.RolePlanSupervisor, Stage: "PLAN_SUMMARY",
		Inputs: []ArtifactPointer{artifactPointer(goalArtifact), artifactPointer(planArtifact)}, Payload: corePayload,
	})
	if err != nil {
		return PlanCompletionResult{}, err
	}
	summary, content, err := normalizePlanCompletionRecord(record, project, *project.CoreSummary)
	if err != nil {
		return PlanCompletionResult{}, err
	}
	artifact, err := service.artifacts.Put(ctx, SpecArtifact{
		TenantID: request.TenantID, ProjectID: request.ProjectID, Kind: ArtifactPlanCompletion,
		SpecID: PlanCompletionSpecID(request.ProjectID), Version: project.Plan.Version,
		ContentSHA256: summary.SummarySHA256, Content: content,
		CreatedBy: record.AgentInstanceID, SourceRunID: record.RunID,
	})
	if err != nil {
		return PlanCompletionResult{}, err
	}
	return PlanCompletionResult{Published: true, Summary: summary, Artifact: artifact}, nil
}

func (service *PlanCompletionService) Get(ctx context.Context, request PlanCompletionRequest) (PlanCompletionResult, bool, error) {
	if service == nil || service.artifacts == nil || service.projects == nil || ctx == nil || ctx.Err() != nil || request.TenantID == "" || request.ProjectID == "" {
		return PlanCompletionResult{}, false, ErrInvalidRequest
	}
	project, found, err := service.projects.Project(ctx, request.TenantID, request.ProjectID)
	if err != nil || !found {
		return PlanCompletionResult{}, false, err
	}
	if project.Plan == nil || project.CoreSummary == nil {
		return PlanCompletionResult{}, false, nil
	}
	artifact, found, err := service.artifacts.Get(ctx, request.TenantID, request.ProjectID, ArtifactPlanCompletion, PlanCompletionSpecID(request.ProjectID), project.Plan.Version)
	if err != nil || !found {
		return PlanCompletionResult{}, false, err
	}
	summary, err := decodePlanCompletionArtifact(artifact, project, *project.CoreSummary)
	if err != nil {
		return PlanCompletionResult{}, false, err
	}
	return PlanCompletionResult{Published: true, Summary: summary, Artifact: artifact}, true, nil
}

func normalizePlanCompletionRecord(record AgentRecord, project state.Project, core state.CoreSummary) (PlanCompletionSummary, []byte, error) {
	if record.RunID == "" || record.AgentInstanceID != project.ID+":"+string(agentruntime.RolePlanSupervisor) || record.Role != agentruntime.RolePlanSupervisor || len(record.Payload) == 0 || !validCompletionCore(project, core) {
		return PlanCompletionSummary{}, nil, ErrAgentOutput
	}
	var draft PlanCompletionDraft
	if err := decodeStrict(record.Payload, &draft); err != nil || !validPlanCompletionDraft(draft, core) {
		return PlanCompletionSummary{}, nil, ErrAgentOutput
	}
	byModule := make(map[string]string, len(draft.Modules))
	for _, module := range draft.Modules {
		byModule[module.ModuleID] = module.Summary
	}
	modules := make([]PlanCompletionModule, 0, len(core.Modules))
	for _, module := range core.Modules {
		modules = append(modules, PlanCompletionModule{
			TaskID: module.TaskID, ModuleID: module.ModuleID, State: module.State,
			ModuleSpecRef: module.ModuleSpecRef, Attempt: module.Attempt,
			AttemptSeriesID: module.AttemptSeriesID, Summary: byModule[module.ModuleID],
		})
	}
	sort.Slice(modules, func(left, right int) bool { return modules[left].ModuleID < modules[right].ModuleID })
	summary := PlanCompletionSummary{
		SummaryVersion: 1, TenantID: project.TenantID, ProjectID: project.ID, Status: "COMPLETED",
		GoalSpecRef: core.GoalSpecRef, PlanSpecRef: core.PlanSpecRef, CoreSummarySHA256: core.SummarySHA256,
		Overview: draft.Overview, Modules: modules,
		CrossModuleFindings:    append([]string{}, draft.CrossModuleFindings...),
		RecommendedNextActions: append([]string{}, draft.RecommendedNextActions...),
		CreatedBy:              contracts.AgentIdentity{AgentInstanceID: record.AgentInstanceID, Role: string(record.Role)},
		CreatedAt:              core.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		return PlanCompletionSummary{}, nil, err
	}
	summary.SummarySHA256, err = canonicaljson.DigestObjectWithoutFields(encoded, "summarySha256", "createdAt")
	if err != nil {
		return PlanCompletionSummary{}, nil, err
	}
	encoded, err = json.Marshal(summary)
	return summary, encoded, err
}

func decodePlanCompletionArtifact(artifact SpecArtifact, project state.Project, core state.CoreSummary) (PlanCompletionSummary, error) {
	var summary PlanCompletionSummary
	if artifact.Kind != ArtifactPlanCompletion || artifact.SpecID != PlanCompletionSpecID(project.ID) || decodeStrict(artifact.Content, &summary) != nil || !validPlanCompletionSummary(summary, project, core) || summary.SummarySHA256 != artifact.ContentSHA256 {
		return PlanCompletionSummary{}, ErrAgentOutput
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(artifact.Content, "summarySha256", "createdAt")
	if err != nil || digest != summary.SummarySHA256 {
		return PlanCompletionSummary{}, ErrAgentOutput
	}
	return summary, nil
}

func validPlanCompletionDraft(draft PlanCompletionDraft, core state.CoreSummary) bool {
	if !validCompletionText(draft.Overview) || !validCompletionStrings(draft.CrossModuleFindings) || !validCompletionStrings(draft.RecommendedNextActions) || len(draft.Modules) != len(core.Modules) {
		return false
	}
	expected := make(map[string]struct{}, len(core.Modules))
	for _, module := range core.Modules {
		if module.ModuleID == "" {
			return false
		}
		expected[module.ModuleID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(draft.Modules))
	for _, module := range draft.Modules {
		if _, found := expected[module.ModuleID]; !found || !validCompletionText(module.Summary) {
			return false
		}
		if _, duplicate := seen[module.ModuleID]; duplicate {
			return false
		}
		seen[module.ModuleID] = struct{}{}
	}
	return len(seen) == len(expected)
}

func validPlanCompletionSummary(summary PlanCompletionSummary, project state.Project, core state.CoreSummary) bool {
	if !validCompletionCore(project, core) || summary.SummaryVersion != 1 || summary.TenantID != project.TenantID || summary.ProjectID != project.ID || summary.Status != "COMPLETED" || summary.GoalSpecRef != core.GoalSpecRef || summary.PlanSpecRef != core.PlanSpecRef || summary.CoreSummarySHA256 != core.SummarySHA256 || !validCompletionText(summary.Overview) || !validCompletionStrings(summary.CrossModuleFindings) || !validCompletionStrings(summary.RecommendedNextActions) || summary.CreatedBy.AgentInstanceID != project.ID+":"+string(agentruntime.RolePlanSupervisor) || summary.CreatedBy.Role != string(agentruntime.RolePlanSupervisor) || summary.CreatedAt != core.CreatedAt.UTC().Format(time.RFC3339Nano) || len(summary.Modules) != len(core.Modules) || (contracts.SpecRef{Version: 1, SHA256: summary.SummarySHA256}).Validate() != nil {
		return false
	}
	expected := make(map[string]state.CoreModuleOutcome, len(core.Modules))
	for _, module := range core.Modules {
		expected[module.ModuleID] = module
	}
	seen := make(map[string]struct{}, len(summary.Modules))
	for _, module := range summary.Modules {
		outcome, found := expected[module.ModuleID]
		if !found || module.TaskID != outcome.TaskID || module.State != outcome.State || module.ModuleSpecRef != outcome.ModuleSpecRef || module.Attempt != outcome.Attempt || module.AttemptSeriesID != outcome.AttemptSeriesID || !validCompletionText(module.Summary) {
			return false
		}
		if _, duplicate := seen[module.ModuleID]; duplicate {
			return false
		}
		seen[module.ModuleID] = struct{}{}
	}
	return len(seen) == len(expected)
}

func validCompletionCore(project state.Project, core state.CoreSummary) bool {
	if project.Goal == nil || project.Plan == nil || core.SummaryVersion != 1 || core.TenantID != project.TenantID || core.ProjectID != project.ID || core.Status != "COMPLETED" || core.GoalSpecRef != (contracts.SpecRef{Version: project.Goal.Version, SHA256: project.Goal.SHA256}) || core.PlanSpecRef != *project.Plan || core.CreatedAt.IsZero() || (contracts.SpecRef{Version: 1, SHA256: core.SummarySHA256}).Validate() != nil || len(core.Modules) == 0 {
		return false
	}
	seenTasks := make(map[string]struct{}, len(core.Modules))
	seenModules := make(map[string]struct{}, len(core.Modules))
	for _, module := range core.Modules {
		if module.TaskID == "" || module.ModuleID == "" || module.State != contracts.TaskPassed || module.ModuleSpecRef.Validate() != nil || module.Attempt < 1 || module.Attempt > 3 || module.AttemptSeriesID == "" {
			return false
		}
		if _, duplicate := seenTasks[module.TaskID]; duplicate {
			return false
		}
		if _, duplicate := seenModules[module.ModuleID]; duplicate {
			return false
		}
		seenTasks[module.TaskID] = struct{}{}
		seenModules[module.ModuleID] = struct{}{}
	}
	return true
}

func validCompletionStrings(values []string) bool {
	if values == nil || len(values) > 1000 {
		return false
	}
	for _, value := range values {
		if !validCompletionText(value) {
			return false
		}
	}
	return true
}

func validCompletionText(value string) bool {
	return value != "" && len(value) <= 8192 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\x00")
}
