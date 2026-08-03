package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func TestServiceIsSoleIdempotentProjectStateWriter(t *testing.T) {
	store := eventing.NewMemoryStore()
	service := New(store, fixedClock)
	request := ProjectRequest{
		TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "usr_1", IdempotencyKey: "idem_create", ExpectedVersion: 0,
		Command: state.ProjectCommand{Type: state.ProjectCommandCreate, GoalAgentCount: 2},
	}
	for attempt := 0; attempt < 100; attempt++ {
		outcome, err := service.HandleProject(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if outcome.Duplicate != (attempt > 0) || outcome.Project.Version != 1 {
			t.Fatalf("attempt %d outcome = %#v", attempt, outcome)
		}
	}
	if stats := store.Stats(); stats.Events != 1 || stats.Outbox != 1 {
		t.Fatalf("store stats = %#v", stats)
	}
}

func TestServiceRejectsChangedIdempotentRequestAndStaleVersion(t *testing.T) {
	store := eventing.NewMemoryStore()
	service := New(store, fixedClock)
	request := ProjectRequest{TenantID: "tenant_1", ProjectID: "prj_1", PrincipalID: "usr_1", IdempotencyKey: "idem_create", ExpectedVersion: 0, Command: state.ProjectCommand{Type: state.ProjectCommandCreate, GoalAgentCount: 2}}
	if _, err := service.HandleProject(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.Command.GoalAgentCount = 1
	_, err := service.HandleProject(context.Background(), changed)
	var typed *aorerrors.Error
	if !errors.As(err, &typed) || typed.Code != aorerrors.CodeIdempotencyConflict {
		t.Fatalf("changed duplicate = %#v", err)
	}

	stale := request
	stale.IdempotencyKey = "idem_pause"
	stale.Command = state.ProjectCommand{Type: state.ProjectCommandPause}
	_, err = service.HandleProject(context.Background(), stale)
	if !errors.As(err, &typed) || typed.Code != aorerrors.CodeStateVersionConflict {
		t.Fatalf("stale version = %#v", err)
	}
}

func TestTaskCommandRequiresApprovedGoalAndPublishedPlan(t *testing.T) {
	store := eventing.NewMemoryStore()
	service := New(store, fixedClock)
	_, err := service.HandleTask(context.Background(), TaskRequest{
		TenantID: "tenant_1", ProjectID: "prj_1", TaskID: "task_1", PrincipalID: "svc_plan", IdempotencyKey: "define", ExpectedVersion: 0,
		Command: state.TaskCommand{Type: state.TaskCommandDefine, ModuleSpecRef: validRef(), AttemptSeriesID: "series_1"},
	})
	var typed *aorerrors.Error
	if !errors.As(err, &typed) || typed.Code != aorerrors.CodeGoalNotApproved {
		t.Fatalf("task without approved goal = %#v", err)
	}
}

func validRef() contracts.SpecRef {
	return contracts.SpecRef{Version: 1, SHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
}

func fixedClock() time.Time {
	return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
}
