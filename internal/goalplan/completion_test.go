package goalplan

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
)

type completionArtifactStore struct {
	values map[string]SpecArtifact
}

func (store *completionArtifactStore) Put(_ context.Context, artifact SpecArtifact) (SpecArtifact, error) {
	if store.values == nil {
		store.values = make(map[string]SpecArtifact)
	}
	store.values[completionArtifactKey(artifact.Kind, artifact.SpecID, artifact.Version)] = cloneArtifact(artifact)
	return cloneArtifact(artifact), nil
}

func (store *completionArtifactStore) Get(_ context.Context, _, _ string, kind ArtifactKind, specID string, version int) (SpecArtifact, bool, error) {
	artifact, found := store.values[completionArtifactKey(kind, specID, version)]
	return cloneArtifact(artifact), found, nil
}

func (store *completionArtifactStore) FindByRef(_ context.Context, _, _ string, kind ArtifactKind, ref contracts.SpecRef) (SpecArtifact, bool, error) {
	for _, artifact := range store.values {
		if artifact.Kind == kind && artifact.Version == ref.Version && artifact.ContentSHA256 == ref.SHA256 {
			return cloneArtifact(artifact), true, nil
		}
	}
	return SpecArtifact{}, false, nil
}

func completionArtifactKey(kind ArtifactKind, specID string, version int) string {
	return string(kind) + "\x00" + specID + "\x00" + strconv.Itoa(version)
}

type completionProjectReader struct {
	project state.Project
}

func (reader completionProjectReader) Project(_ context.Context, tenantID, projectID string) (state.Project, bool, error) {
	return reader.project, reader.project.TenantID == tenantID && reader.project.ID == projectID, nil
}

type completionInvoker struct {
	calls int
}

func (invoker *completionInvoker) Invoke(_ context.Context, request AgentInvocation) (AgentRecord, error) {
	invoker.calls++
	var core state.CoreSummary
	if json.Unmarshal(request.Payload, &core) != nil {
		return AgentRecord{}, ErrAgentOutput
	}
	modules := make([]PlanCompletionModuleDraft, 0, len(core.Modules))
	for _, module := range core.Modules {
		modules = append(modules, PlanCompletionModuleDraft{ModuleID: module.ModuleID, Summary: "completed " + module.ModuleID})
	}
	payload, _ := json.Marshal(PlanCompletionDraft{
		Overview: "all planned modules passed independent audit", Modules: modules,
		CrossModuleFindings: []string{}, RecommendedNextActions: []string{"return the result to the goal layer"},
	})
	return AgentRecord{
		RunID: request.InvocationID, AgentInstanceID: request.ProjectID + ":" + string(agentruntime.RolePlanSupervisor),
		Role: agentruntime.RolePlanSupervisor, Payload: payload,
	}, nil
}

func TestPlanCompletionServicePublishesOnePlanSupervisorSummary(t *testing.T) {
	project, goalArtifact, planArtifact := completionFixture(t)
	store := &completionArtifactStore{values: map[string]SpecArtifact{
		completionArtifactKey(goalArtifact.Kind, goalArtifact.SpecID, goalArtifact.Version): goalArtifact,
		completionArtifactKey(planArtifact.Kind, planArtifact.SpecID, planArtifact.Version): planArtifact,
	}}
	invoker := &completionInvoker{}
	service, err := NewPlanCompletionService(store, invoker, completionProjectReader{project: project})
	if err != nil {
		t.Fatal(err)
	}
	request := PlanCompletionRequest{TenantID: project.TenantID, ProjectID: project.ID}
	result, err := service.Publish(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Published || result.Duplicate || invoker.calls != 1 || result.Summary.CreatedBy.Role != string(agentruntime.RolePlanSupervisor) || len(result.Summary.Modules) != 1 || result.Summary.Modules[0].TaskID != "task_1" {
		t.Fatalf("completion result = %#v calls=%d", result, invoker.calls)
	}
	replayed, err := service.Publish(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Published || !replayed.Duplicate || replayed.Summary.SummarySHA256 != result.Summary.SummarySHA256 || invoker.calls != 1 {
		t.Fatalf("replayed completion = %#v calls=%d", replayed, invoker.calls)
	}
}

func TestPlanCompletionServiceWaitsForAllModules(t *testing.T) {
	project, goalArtifact, planArtifact := completionFixture(t)
	project.CoreSummary = nil
	store := &completionArtifactStore{values: map[string]SpecArtifact{
		completionArtifactKey(goalArtifact.Kind, goalArtifact.SpecID, goalArtifact.Version): goalArtifact,
		completionArtifactKey(planArtifact.Kind, planArtifact.SpecID, planArtifact.Version): planArtifact,
	}}
	invoker := &completionInvoker{}
	service, err := NewPlanCompletionService(store, invoker, completionProjectReader{project: project})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Publish(context.Background(), PlanCompletionRequest{TenantID: project.TenantID, ProjectID: project.ID})
	if err != nil || result.Published || invoker.calls != 0 {
		t.Fatalf("pending completion = %#v calls=%d err=%v", result, invoker.calls, err)
	}
}

func completionFixture(t *testing.T) (state.Project, SpecArtifact, SpecArtifact) {
	t.Helper()
	now := time.Date(2035, 4, 5, 6, 7, 8, 0, time.UTC)
	goalRef := contracts.SpecRef{Version: 1, SHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	planRef := contracts.SpecRef{Version: 1, SHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	moduleRef := contracts.SpecRef{Version: 1, SHA256: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
	project := state.Project{
		TenantID: "tenant_1", ID: "project_1", Version: 8, State: contracts.ProjectExecuting,
		Goal: &state.GoalRecord{ID: "goal_1", Version: goalRef.Version, SHA256: goalRef.SHA256, ApprovedBy: "user_1"}, Plan: &planRef,
	}
	project.CoreSummary = &state.CoreSummary{
		SummaryVersion: 1, TenantID: project.TenantID, ProjectID: project.ID, Status: "COMPLETED",
		GoalSpecRef: goalRef, PlanSpecRef: planRef,
		Modules: []state.CoreModuleOutcome{{
			TaskID: "task_1", ModuleID: "module_1", State: contracts.TaskPassed,
			Version: 7, ModuleSpecRef: moduleRef, Attempt: 1, AttemptSeriesID: "series_1",
		}},
		SummarySHA256: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", CreatedAt: now,
	}
	goalArtifact := SpecArtifact{
		TenantID: project.TenantID, ProjectID: project.ID, Kind: ArtifactGoalApproved, SpecID: project.Goal.ID,
		Version: goalRef.Version, ContentSHA256: goalRef.SHA256, URI: "artifact://goal", Content: []byte(`{"goal":true}`), CreatedBy: "goal",
	}
	planArtifact := SpecArtifact{
		TenantID: project.TenantID, ProjectID: project.ID, Kind: ArtifactPlanSpec, SpecID: "plan_1",
		Version: planRef.Version, ContentSHA256: planRef.SHA256, URI: "artifact://plan", Content: []byte(`{"plan":true}`), CreatedBy: "planner",
	}
	return project, goalArtifact, planArtifact
}
