package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

func TestProjectResultReportsPendingSummarizingAndCompleted(t *testing.T) {
	handler, store, authorizer := newTestHandler(t)
	project := resultProjectFixture()
	seedResultProject(t, store, project, 0)
	route := "/v1/projects/" + project.ID + "/result"

	pendingResponse := performRequest(handler, http.MethodGet, route, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	var pending projectResultResource
	if pendingResponse.Code != http.StatusOK || json.Unmarshal(pendingResponse.Body.Bytes(), &pending) != nil {
		t.Fatalf("pending status=%d body=%s", pendingResponse.Code, pendingResponse.Body.String())
	}
	if pending.Status != projectResultPending || pending.CoreSummary != nil || pending.PlanSupervisorSummary != nil || pending.ArtifactRef != "" {
		t.Fatalf("pending result = %#v", pending)
	}

	authorizer.deny = true
	denied := performRequest(handler, http.MethodGet, route, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	if denied.Code != http.StatusForbidden {
		t.Fatalf("denied status=%d body=%s", denied.Code, denied.Body.String())
	}
	authorizer.deny = false

	project.Version = 2
	project.CoreSummary = resultCoreSummary(project)
	seedResultProject(t, store, project, 1)
	summarizingResponse := performRequest(handler, http.MethodGet, route, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	var summarizing projectResultResource
	if summarizingResponse.Code != http.StatusOK || json.Unmarshal(summarizingResponse.Body.Bytes(), &summarizing) != nil {
		t.Fatalf("summarizing status=%d body=%s", summarizingResponse.Code, summarizingResponse.Body.String())
	}
	if summarizing.Status != projectResultSummarizing || summarizing.CoreSummary == nil || summarizing.CoreSummary.SummarySHA256 != project.CoreSummary.SummarySHA256 || summarizing.PlanSupervisorSummary != nil || summarizing.ArtifactRef != "" {
		t.Fatalf("summarizing result = %#v", summarizing)
	}

	summary := resultPlanCompletion(t, project)
	content, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	artifactStore, err := goalplan.NewEventArtifactStore(store, func() time.Time { return controlAPITestTime.Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	completion, err := artifactStore.Put(context.Background(), goalplan.SpecArtifact{
		TenantID: project.TenantID, ProjectID: project.ID, Kind: goalplan.ArtifactPlanCompletion,
		SpecID: goalplan.PlanCompletionSpecID(project.ID), Version: project.Plan.Version,
		ContentSHA256: summary.SummarySHA256, Content: content, CreatedBy: project.ID + ":PLAN_SUPERVISOR",
	})
	if err != nil {
		t.Fatal(err)
	}
	completedResponse := performRequest(handler, http.MethodGet, route, nil, map[string]string{"Authorization": "Bearer " + testBearer})
	var completed projectResultResource
	if completedResponse.Code != http.StatusOK || json.Unmarshal(completedResponse.Body.Bytes(), &completed) != nil {
		t.Fatalf("completed status=%d body=%s", completedResponse.Code, completedResponse.Body.String())
	}
	if completed.Status != projectResultCompleted || completed.CoreSummary == nil || completed.PlanSupervisorSummary == nil || completed.PlanSupervisorSummary.SummarySHA256 != summary.SummarySHA256 || completed.ArtifactRef != completion.URI {
		t.Fatalf("completed result = %#v", completed)
	}
	last := authorizer.inputs[len(authorizer.inputs)-1]
	if last.Action != authz.ActionProjectRead || last.Resource.Type != "project-result" || last.Resource.ID != project.ID {
		t.Fatalf("project result authorization = %#v", last)
	}
}

func resultProjectFixture() state.Project {
	goalRef := contracts.SpecRef{Version: 1, SHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	planRef := contracts.SpecRef{Version: 1, SHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	return state.Project{
		TenantID: testTenantID, ID: "33333333-3333-4333-8333-333333333333", Name: "result", CreatedBy: "user-1",
		DataClassification: "INTERNAL", RiskTolerance: "MEDIUM", State: contracts.ProjectExecuting,
		Version: 1, GoalAgentCount: 1,
		Goal: &state.GoalRecord{ID: "goal-result", Version: goalRef.Version, SHA256: goalRef.SHA256, ApprovedBy: "user-1"},
		Plan: &planRef,
	}
}

func resultCoreSummary(project state.Project) *state.CoreSummary {
	return &state.CoreSummary{
		SummaryVersion: 1, TenantID: project.TenantID, ProjectID: project.ID, Status: "COMPLETED",
		GoalSpecRef: contracts.SpecRef{Version: project.Goal.Version, SHA256: project.Goal.SHA256}, PlanSpecRef: *project.Plan,
		Modules: []state.CoreModuleOutcome{{
			TaskID: "task-result", ModuleID: "module-result", State: contracts.TaskPassed, Version: 4,
			ModuleSpecRef: contracts.SpecRef{Version: 1, SHA256: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
			Attempt:       1, AttemptSeriesID: "series-result",
		}},
		SummarySHA256: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", CreatedAt: controlAPITestTime,
	}
}

func resultPlanCompletion(t *testing.T, project state.Project) goalplan.PlanCompletionSummary {
	t.Helper()
	summary := goalplan.PlanCompletionSummary{
		SummaryVersion: 1, TenantID: project.TenantID, ProjectID: project.ID, Status: "COMPLETED",
		GoalSpecRef: project.CoreSummary.GoalSpecRef, PlanSpecRef: project.CoreSummary.PlanSpecRef,
		CoreSummarySHA256: project.CoreSummary.SummarySHA256, Overview: "all modules completed",
		Modules: []goalplan.PlanCompletionModule{{
			TaskID: "task-result", ModuleID: "module-result", State: contracts.TaskPassed,
			ModuleSpecRef: project.CoreSummary.Modules[0].ModuleSpecRef, Attempt: 1,
			AttemptSeriesID: "series-result", Summary: "module completed",
		}},
		CrossModuleFindings: []string{}, RecommendedNextActions: []string{"return result"},
		CreatedBy: contracts.AgentIdentity{AgentInstanceID: project.ID + ":" + string(agentruntime.RolePlanSupervisor), Role: string(agentruntime.RolePlanSupervisor)},
		CreatedAt: project.CoreSummary.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	summary.SummarySHA256, err = canonicaljson.DigestObjectWithoutFields(encoded, "summarySha256", "createdAt")
	if err != nil {
		t.Fatal(err)
	}
	return summary
}

func seedResultProject(t *testing.T, store *eventing.MemoryStore, project state.Project, expectedVersion int64) {
	t.Helper()
	content, err := json.Marshal(project)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonicaljson.Digest(content)
	if err != nil {
		t.Fatal(err)
	}
	version := strconv.FormatInt(project.Version, 10)
	_, err = store.Execute(context.Background(), eventing.TransactionRequest{
		TenantID: project.TenantID, PrincipalID: "test-seed", IdempotencyKey: "project-result-" + version,
		RequestSHA256: digest, Result: content, ResultSHA256: digest,
		Updates: []eventing.ProjectionUpdate{{
			TenantID: project.TenantID, ProjectID: project.ID, AggregateType: "project", AggregateID: project.ID,
			ExpectedVersion: expectedVersion, NextVersion: project.Version, State: content,
		}},
		Events: []eventing.DomainEvent{{
			EventID: "event-project-result-" + version, TenantID: project.TenantID, ProjectID: project.ID,
			AggregateType: "project", AggregateID: project.ID, AggregateVersion: project.Version,
			Type: "io.aor.test.project-result-seeded.v1", Payload: content, PayloadSHA256: digest, OccurredAt: controlAPITestTime,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
}
