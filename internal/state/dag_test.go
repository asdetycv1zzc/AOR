package state

import (
	"testing"

	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func TestPublishPlanRejectsCyclicDAG(t *testing.T) {
	project := createProject(t)
	goal := GoalRecord{ID: "goal_1", Version: 1, SHA256: digestZero()}
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandProposeGoal, Goal: &goal, ActorID: "agt_goal", At: testTime()})
	project = applyProject(t, project, ProjectCommand{Type: ProjectCommandApproveGoal, Goal: &goal, ActorID: "usr_1", Approval: goalApproval(goal, "usr_1"), At: testTime()})
	plan := contracts.SpecRef{Version: 1, SHA256: digestZero()}
	_, err := DecideProject(project, ProjectCommand{Type: ProjectCommandPublishPlan, GoalSpecRef: &plan, Plan: &plan, DAG: map[string][]string{"a": {"b"}, "b": {"a"}}, ActorID: "agt_plan", At: testTime()})
	if err == nil || err.Code != aorerrors.CodeInvalidArgument {
		t.Fatalf("cyclic plan = %#v", err)
	}
}

func TestValidateDAGRejectsUnknownDependency(t *testing.T) {
	if ValidateDAG(map[string][]string{"a": {"missing"}}) {
		t.Fatal("DAG accepted an unknown dependency")
	}
}
