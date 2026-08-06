package audit

import (
	"context"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
)

func TestFinishEvidenceQueuesReworkUntilAttemptLimit(t *testing.T) {
	for _, test := range []struct {
		name        string
		attempt     int
		wantState   contracts.ModuleTaskState
		wantCommits int
	}{
		{name: "retry", attempt: 1, wantState: contracts.TaskReadyExecution, wantCommits: 2},
		{name: "attempt limit", attempt: 3, wantState: contracts.TaskBlockedUserDecision, wantCommits: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			tasks := &reworkTaskAuthority{task: state.ModuleTask{
				TenantID: "tenant_1", ProjectID: "project_1", ID: "task_1",
				State: contracts.TaskDeterministicAudit, Version: 5, Attempt: test.attempt,
			}}
			service := &ModuleAuditService{tasks: tasks, checkpoints: completedCheckpointStore{}}
			result, err := service.finishEvidence(context.Background(), ModuleAuditRequest{
				AuditRunID: "audit_1", TenantID: "tenant_1", ProjectID: "project_1", TaskID: "task_1",
			}, tasks.task, Coordination{Facts: RuntimeFacts{PolicyDigest: digest}}, contracts.EvidenceBundle{
				ManifestSHA256: digest,
				Checks:         []contracts.EvidenceCheck{{Status: "FAIL"}},
				LLMAudit:       contracts.LLMAudit{Verdict: "NOT_RUN"},
			}, false)
			if err != nil {
				t.Fatal(err)
			}
			if result.Task.State != test.wantState || len(tasks.commits) != test.wantCommits {
				t.Fatalf("state = %s, commits = %v", result.Task.State, tasks.commits)
			}
		})
	}
}

func TestAuditFailureOutcomeRecognizesStartedRework(t *testing.T) {
	if !auditOutcomeReached(state.ModuleTask{State: contracts.TaskExecuting}, outcomeLLMFailure) {
		t.Fatal("executing rework was not recognized")
	}
}

type reworkTaskAuthority struct {
	task    state.ModuleTask
	commits []state.TaskCommandType
}

func (authority *reworkTaskAuthority) Project(context.Context, string, string) (state.Project, bool, error) {
	return state.Project{}, false, nil
}

func (authority *reworkTaskAuthority) Task(context.Context, string, string, string) (state.ModuleTask, bool, error) {
	return authority.task, true, nil
}

func (authority *reworkTaskAuthority) Commit(_ context.Context, request TaskCommitRequest) (state.ModuleTask, bool, error) {
	request.Command.At = time.Unix(1, 0).UTC()
	event, stateErr := state.DecideTask(authority.task, request.Command)
	if stateErr != nil {
		return state.ModuleTask{}, false, stateErr
	}
	updated, err := state.ApplyTask(authority.task, event)
	if err != nil {
		return state.ModuleTask{}, false, err
	}
	authority.task = updated
	authority.commits = append(authority.commits, request.Command.Type)
	return updated, false, nil
}

type completedCheckpointStore struct{}

func (completedCheckpointStore) Get(context.Context, string, string, string, int) (Coordination, bool, error) {
	return Coordination{}, false, nil
}

func (completedCheckpointStore) Claim(context.Context, Coordination) (Coordination, bool, error) {
	return Coordination{}, false, nil
}

func (completedCheckpointStore) MarkDeterministic(context.Context, Coordination, string) (Coordination, error) {
	return Coordination{}, nil
}

func (completedCheckpointStore) Complete(_ context.Context, checkpoint Coordination, evidenceSHA256, outcome string) (Coordination, error) {
	checkpoint.State = coordinationCompleted
	checkpoint.EvidenceSHA256 = evidenceSHA256
	checkpoint.Outcome = outcome
	return checkpoint, nil
}
