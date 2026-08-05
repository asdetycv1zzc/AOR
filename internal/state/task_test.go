package state

import (
	"reflect"
	"strings"
	"testing"

	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func TestThirdAuditFailureBlocksUserDecisionAndFreezesDependants(t *testing.T) {
	task := readyTask(t)
	for attempt := 1; attempt <= 3; attempt++ {
		token := int64(attempt)
		task = applyTask(t, task, TaskCommand{Type: TaskCommandLeaseExecution, FencingToken: token, At: testTime()})
		task = applyTask(t, task, TaskCommand{Type: TaskCommandSubmit, FencingToken: token, ModuleSpecRef: task.ModuleSpecRef, AttemptSeriesID: task.AttemptSeriesID, At: testTime()})
		task = applyTask(t, task, TaskCommand{Type: TaskCommandStartAudit, SubmissionValidated: true, AuditEvidenceSHA256: digestZero(), At: testTime()})
		task = applyTask(t, task, TaskCommand{Type: TaskCommandDeterministicFailure, AuditEvidenceSHA256: digestZero(), At: testTime()})
		if attempt < 3 {
			if task.State != contracts.TaskReworkRequired {
				t.Fatalf("attempt %d state = %s", attempt, task.State)
			}
			task = applyTask(t, task, TaskCommand{Type: TaskCommandQueueRework, At: testTime()})
		}
	}
	if task.State != contracts.TaskBlockedUserDecision || task.Attempt != 3 {
		t.Fatalf("third failure task = %#v", task)
	}
	if len(task.FrozenDependentIDs) != 2 {
		t.Fatalf("frozen dependants = %v", task.FrozenDependentIDs)
	}
	_, err := DecideTask(task, TaskCommand{Type: TaskCommandQueueRework, At: testTime()})
	if err == nil || err.Code != aorerrors.CodeAttemptLimitReached {
		t.Fatalf("automatic fourth attempt = %#v", err)
	}
	_, err = DecideTask(task, TaskCommand{Type: TaskCommandAuthorizeNewSeries, Decision: contracts.DecisionAuthorizeNewAttemptSeries, NewAttemptSeriesID: "series_2", ModuleSpecRef: task.ModuleSpecRef, At: testTime()})
	if err == nil || err.Code != aorerrors.CodeApprovalRequired {
		t.Fatalf("unsigned attempt reset = %#v", err)
	}
	task = applyTask(t, task, TaskCommand{Type: TaskCommandAuthorizeNewSeries, Decision: contracts.DecisionAuthorizeNewAttemptSeries, DecisionRecordID: "decision_1", DecisionReportSHA256: "sha256:" + strings.Repeat("d", 64), NewAttemptSeriesID: "series_2", Approval: attemptApproval(task, "usr_1"), ActorID: "usr_1", ModuleSpecRef: task.ModuleSpecRef, At: testTime()})
	if task.AttemptSeriesID != "series_2" || task.Attempt != 0 || task.State != contracts.TaskReadyExecution {
		t.Fatalf("authorized series = %#v", task)
	}
}

func attemptApproval(task ModuleTask, principalID string) *ApprovalBinding {
	return &ApprovalBinding{
		RecordID: "approval_reset", ApprovalType: "AUTHORIZE_NEW_ATTEMPT_SERIES", SubjectType: "MODULE_TASK", SubjectID: task.ID,
		SubjectVersion: task.ModuleSpecRef.Version, SubjectSHA256: task.ModuleSpecRef.SHA256, PrincipalID: principalID, Reason: "explicit test reset",
		IssuedAt: testTime(), Signature: "test-signature",
	}
}

func TestStaleFencingTokenAndSupersededSpecAreRejected(t *testing.T) {
	task := readyTask(t)
	task = applyTask(t, task, TaskCommand{Type: TaskCommandLeaseExecution, FencingToken: 4, At: testTime()})
	_, err := DecideTask(task, TaskCommand{Type: TaskCommandSubmit, FencingToken: 3, ModuleSpecRef: task.ModuleSpecRef, AttemptSeriesID: task.AttemptSeriesID, At: testTime()})
	if err == nil || err.Code != aorerrors.CodeLeaseExpired {
		t.Fatalf("stale token = %#v", err)
	}
	wrong := task.ModuleSpecRef
	wrong.Version++
	_, err = DecideTask(task, TaskCommand{Type: TaskCommandSubmit, FencingToken: 4, ModuleSpecRef: wrong, AttemptSeriesID: task.AttemptSeriesID, At: testTime()})
	if err == nil || err.Code != aorerrors.CodeSpecSuperseded {
		t.Fatalf("stale spec = %#v", err)
	}
}

func TestAuditAndIntegrationTransitionsRequireEvidence(t *testing.T) {
	task := readyTask(t)
	task = applyTask(t, task, TaskCommand{Type: TaskCommandLeaseExecution, FencingToken: 1, At: testTime()})
	task = applyTask(t, task, TaskCommand{Type: TaskCommandSubmit, FencingToken: 1, ModuleSpecRef: task.ModuleSpecRef, AttemptSeriesID: task.AttemptSeriesID, At: testTime()})
	if _, err := DecideTask(task, TaskCommand{Type: TaskCommandStartAudit, At: testTime()}); err == nil {
		t.Fatal("audit started without validated submission evidence")
	}
	task = applyTask(t, task, TaskCommand{Type: TaskCommandStartAudit, SubmissionValidated: true, AuditEvidenceSHA256: digestZero(), At: testTime()})
	if _, err := DecideTask(task, TaskCommand{Type: TaskCommandDeterministicSuccess, At: testTime()}); err == nil {
		t.Fatal("deterministic audit passed without evidence")
	}
	task = applyTask(t, task, TaskCommand{Type: TaskCommandDeterministicSuccess, AuditEvidenceSHA256: digestZero(), At: testTime()})
	if _, err := DecideTask(task, TaskCommand{Type: TaskCommandLLMSuccess, AuditEvidenceSHA256: digestZero(), At: testTime()}); err == nil {
		t.Fatal("LLM audit passed without fresh blind auditor facts")
	}
	task = applyTask(t, task, TaskCommand{Type: TaskCommandLLMSuccess, FreshAuditor: true, BlindAuditContext: true, NoBlockingFindings: true, AuditEvidenceSHA256: digestZero(), At: testTime()})
	if _, err := DecideTask(task, TaskCommand{Type: TaskCommandIntegrate, At: testTime()}); err == nil {
		t.Fatal("task integrated without dependency and merge evidence")
	}
}

func TestTaskDefinitionRejectsInvalidDependantsAndAttemptSeriesReuse(t *testing.T) {
	ref := contracts.SpecRef{Version: 1, SHA256: digestZero()}
	_, err := DecideTask(ModuleTask{}, TaskCommand{Type: TaskCommandDefine, TenantID: "tenant_1", ProjectID: "prj_1", TaskID: "task_1", ModuleSpecRef: ref, AttemptSeriesID: "series_1", DependentTaskIDs: []string{"task_2", "task_2"}, At: testTime()})
	if err == nil || err.Code != aorerrors.CodeInvalidArgument {
		t.Fatalf("duplicate dependants = %#v", err)
	}
	blocked := ModuleTask{TenantID: "tenant_1", ProjectID: "prj_1", ID: "task_1", State: contracts.TaskBlockedUserDecision, Version: 12, ModuleSpecRef: ref, AttemptSeriesID: "series_2", AttemptSeriesIDs: []string{"series_1", "series_2"}, Attempt: 3}
	_, err = DecideTask(blocked, TaskCommand{Type: TaskCommandAuthorizeNewSeries, Decision: contracts.DecisionAuthorizeNewAttemptSeries, DecisionRecordID: "decision_1", DecisionReportSHA256: "sha256:" + strings.Repeat("d", 64), NewAttemptSeriesID: "series_1", Approval: attemptApproval(blocked, "usr_1"), ActorID: "usr_1", ModuleSpecRef: ref, At: testTime()})
	if err == nil {
		t.Fatal("previous attempt series ID was reused")
	}
}

func TestTaskDefinitionPreservesPlanAndDependencyMetadata(t *testing.T) {
	moduleRef := contracts.SpecRef{Version: 1, SHA256: digestZero()}
	planningRef := contracts.SpecRef{Version: 2, SHA256: digestZero()}
	command := TaskCommand{
		Type: TaskCommandDefine, TenantID: "tenant_1", ProjectID: "prj_1", TaskID: "task_1", ModuleID: "module_1",
		PlanningSpecRef: planningRef, ModuleSpecRef: moduleRef, AttemptSeriesID: "series_1",
		DependentTaskIDs: []string{"task_2", "task_3"}, FrozenDependentIDs: []string{"task_3"},
		BlockingTaskIDs: []string{"task_blocker"}, BlockedFromState: contracts.TaskBlockedDependency,
		ModuleSpecSourceTaskID: "task_original", At: testTime(),
	}
	event, err := DecideTask(ModuleTask{}, command)
	if err != nil {
		t.Fatal(err)
	}
	if event.Projection.PlanningSpecRef != planningRef || event.Projection.ModuleID != command.ModuleID ||
		!reflect.DeepEqual(event.Projection.DependentTaskIDs, command.DependentTaskIDs) ||
		!reflect.DeepEqual(event.Projection.FrozenDependentIDs, command.FrozenDependentIDs) ||
		!reflect.DeepEqual(event.Projection.BlockingTaskIDs, command.BlockingTaskIDs) || event.Projection.BlockedFromState != command.BlockedFromState ||
		event.Projection.ModuleSpecSourceTaskID != command.ModuleSpecSourceTaskID {
		t.Fatalf("definition metadata was not preserved: %#v", event.Projection)
	}
}

func TestPlanningTaskBindsScopeBeforeImmutableModuleSpec(t *testing.T) {
	planRef := contracts.SpecRef{Version: 2, SHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	moduleRef := contracts.SpecRef{Version: 1, SHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	task := applyTask(t, ModuleTask{}, TaskCommand{
		Type: TaskCommandQueuePlanning, TenantID: "tenant_1", ProjectID: "prj_1", TaskID: "task_1", ModuleID: "module_api",
		PlanningSpecRef: planRef, DependentTaskIDs: []string{"task_2"}, At: testTime(),
	})
	if task.State != contracts.TaskQueuedPlanning || task.PlanningSpecRef != planRef || task.ModuleSpecRef != (contracts.SpecRef{}) || task.AttemptSeriesID != "" {
		t.Fatalf("queued planning task = %#v", task)
	}

	task = applyTask(t, task, TaskCommand{Type: TaskCommandStartPlanning, At: testTime()})
	if task.State != contracts.TaskPlanning {
		t.Fatalf("started planning task = %#v", task)
	}
	task = applyTask(t, task, TaskCommand{Type: TaskCommandAttachModuleSpec, ModuleSpecRef: moduleRef, AttemptSeriesID: "series_1", At: testTime()})
	if task.State != contracts.TaskDefined || task.ModuleSpecRef != moduleRef || task.AttemptSeriesID != "series_1" || len(task.AttemptSeriesIDs) != 1 {
		t.Fatalf("defined planning task = %#v", task)
	}

	if _, err := DecideTask(task, TaskCommand{Type: TaskCommandAttachModuleSpec, ModuleSpecRef: moduleRef, AttemptSeriesID: "series_2", At: testTime()}); err == nil {
		t.Fatal("immutable ModuleSpec binding was replaced")
	}
}

func readyTask(t *testing.T) ModuleTask {
	t.Helper()
	ref := contracts.SpecRef{Version: 1, SHA256: digestZero()}
	event, err := DecideTask(ModuleTask{}, TaskCommand{Type: TaskCommandDefine, TenantID: "tenant_1", ProjectID: "prj_1", TaskID: "task_1", ModuleSpecRef: ref, AttemptSeriesID: "series_1", DependentTaskIDs: []string{"task_2", "task_3"}, At: testTime()})
	if err != nil {
		t.Fatal(err)
	}
	task, applyErr := ApplyTask(ModuleTask{}, event)
	if applyErr != nil {
		t.Fatal(applyErr)
	}
	return applyTask(t, task, TaskCommand{Type: TaskCommandReadyExecution, At: testTime()})
}

func applyTask(t *testing.T, current ModuleTask, command TaskCommand) ModuleTask {
	t.Helper()
	event, err := DecideTask(current, command)
	if err != nil {
		t.Fatal(err)
	}
	next, applyErr := ApplyTask(current, event)
	if applyErr != nil {
		t.Fatal(applyErr)
	}
	return next
}
