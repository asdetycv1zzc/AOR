package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/projection"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
)

func TestOutOfOrderReplayMatchesOnlineProjectProjection(t *testing.T) {
	store := eventing.NewMemoryStore()
	service := orchestrator.New(store, replayClock)
	ctx := context.Background()
	create, err := service.HandleProject(ctx, orchestrator.ProjectRequest{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "usr_1", IdempotencyKey: "create", ExpectedVersion: 0, Command: state.ProjectCommand{Type: state.ProjectCommandCreate, GoalAgentCount: 2}})
	if err != nil {
		t.Fatal(err)
	}
	start, err := service.HandleProject(ctx, orchestrator.ProjectRequest{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "svc_orchestrator", IdempotencyKey: "start", ExpectedVersion: 1, Command: state.ProjectCommand{Type: state.ProjectCommandStartGoalNegotiation}})
	if err != nil {
		t.Fatal(err)
	}
	goal := state.GoalRecord{ID: "goal_1", Version: 1, SHA256: replayDigest()}
	propose, err := service.HandleProject(ctx, orchestrator.ProjectRequest{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "agt_goal", IdempotencyKey: "propose", ExpectedVersion: 2, Command: state.ProjectCommand{Type: state.ProjectCommandProposeGoal, Goal: &goal}})
	if err != nil {
		t.Fatal(err)
	}
	approve, err := service.HandleProject(ctx, orchestrator.ProjectRequest{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "usr_1", IdempotencyKey: "approve", ExpectedVersion: 3, Command: state.ProjectCommand{Type: state.ProjectCommandApproveGoal, Goal: &goal, Approval: integrationGoalApproval(goal, "approval_replay")}})
	if err != nil {
		t.Fatal(err)
	}

	projector := projection.New(map[string]projection.Reducer{"project": projection.StateReducer})
	events := []eventing.DomainEvent{create.Events[0], start.Events[0], propose.Events[0], approve.Events[0]}
	for _, index := range []int{3, 0, 2, 1, 1} {
		if _, err := projector.Apply(events[index]); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, found := projector.Snapshot("tenant_1", "project", "prj_1")
	if !found || snapshot.Version != approve.Project.Version {
		t.Fatalf("replay snapshot = %#v", snapshot)
	}
	replayedDigest, err := canonicaljson.Digest(snapshot.State)
	if err != nil {
		t.Fatal(err)
	}
	online, found, err := store.Load(ctx, "tenant_1", "project", "prj_1")
	if err != nil || !found {
		t.Fatalf("online projection missing: %v", err)
	}
	onlineDigest, err := canonicaljson.Digest(online.State)
	if err != nil {
		t.Fatal(err)
	}
	if replayedDigest != onlineDigest {
		t.Fatalf("replay %s != online %s", replayedDigest, onlineDigest)
	}
}

func replayClock() time.Time {
	return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
}

func replayDigest() string {
	return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}
