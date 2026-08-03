package state

import (
	"fmt"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

// Conformance executes the deterministic state checks used by the standalone runner.
func Conformance() []error {
	var findings []error
	projectEvent, err := DecideProject(Project{}, ProjectCommand{Type: ProjectCommandCreate, TenantID: "tenant_conformance", ProjectID: "project_conformance", ActorID: "user_conformance", GoalAgentCount: 2, At: testConformanceTime()})
	if err != nil {
		return []error{err}
	}
	project, applyErr := ApplyProject(Project{}, projectEvent)
	if applyErr != nil {
		return []error{applyErr}
	}
	project, findings = conformanceProjectStep(project, ProjectCommand{Type: ProjectCommandStartGoalNegotiation, ActorID: "service_orchestrator", At: testConformanceTime()}, findings)
	goal := GoalRecord{ID: "goal_conformance", Version: 1, SHA256: conformanceDigest()}
	project, findings = conformanceProjectStep(project, ProjectCommand{Type: ProjectCommandProposeGoal, ActorID: "agent_goal", Goal: &goal, At: testConformanceTime()}, findings)
	wrongGoal := goal
	wrongGoal.SHA256 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	if _, wrongErr := DecideProject(project, ProjectCommand{Type: ProjectCommandApproveGoal, ActorID: "user_conformance", Goal: &wrongGoal, Approval: conformanceApproval(goal), At: testConformanceTime()}); wrongErr == nil || wrongErr.Code != aorerrors.CodeGoalHashMismatch {
		findings = append(findings, fmt.Errorf("wrong goal digest was not rejected: %v", wrongErr))
	}
	project, findings = conformanceProjectStep(project, ProjectCommand{Type: ProjectCommandApproveGoal, ActorID: "user_conformance", Goal: &goal, Approval: &ApprovalBinding{RecordID: "approval_conformance", ApprovalType: "GOAL_APPROVAL", SubjectType: "GOAL_SPEC", SubjectID: goal.ID, SubjectVersion: goal.Version, SubjectSHA256: goal.SHA256, PrincipalID: "user_conformance", Reason: "conformance approval", IssuedAt: testConformanceTime(), Signature: "conformance-signature"}, At: testConformanceTime()}, findings)
	if project.State != contracts.ProjectPlanning {
		findings = append(findings, fmt.Errorf("approved goal state = %s", project.State))
	}

	ref := contracts.SpecRef{Version: 1, SHA256: conformanceDigest()}
	dependentEvent, dependentErr := DecideTask(ModuleTask{}, TaskCommand{Type: TaskCommandDefine, TenantID: "tenant_conformance", ProjectID: "project_conformance", TaskID: "dependent_conformance", ModuleSpecRef: ref, AttemptSeriesID: "series_dependent", At: testConformanceTime()})
	if dependentErr != nil {
		findings = append(findings, dependentErr)
	}
	dependent, dependentApplyErr := ApplyTask(ModuleTask{}, dependentEvent)
	if dependentApplyErr != nil {
		findings = append(findings, dependentApplyErr)
	}
	taskEvent, taskErr := DecideTask(ModuleTask{}, TaskCommand{Type: TaskCommandDefine, TenantID: "tenant_conformance", ProjectID: "project_conformance", TaskID: "task_conformance", ModuleSpecRef: ref, AttemptSeriesID: "series_conformance", DependentTaskIDs: []string{"dependent_conformance"}, At: testConformanceTime()})
	if taskErr != nil {
		findings = append(findings, taskErr)
	} else {
		task, applyTaskErr := ApplyTask(ModuleTask{}, taskEvent)
		if applyTaskErr != nil {
			findings = append(findings, applyTaskErr)
		} else if task.State != contracts.TaskDefined {
			findings = append(findings, fmt.Errorf("defined task state = %s", task.State))
		} else {
			task, findings = conformanceTaskStep(task, TaskCommand{Type: TaskCommandReadyExecution, At: testConformanceTime()}, findings)
			for attempt := int64(1); attempt <= 3; attempt++ {
				task, findings = conformanceTaskStep(task, TaskCommand{Type: TaskCommandLeaseExecution, FencingToken: attempt, At: testConformanceTime()}, findings)
				task, findings = conformanceTaskStep(task, TaskCommand{Type: TaskCommandSubmit, FencingToken: attempt, ModuleSpecRef: ref, AttemptSeriesID: task.AttemptSeriesID, At: testConformanceTime()}, findings)
				task, findings = conformanceTaskStep(task, TaskCommand{Type: TaskCommandStartAudit, SubmissionValidated: true, AuditEvidenceSHA256: conformanceDigest(), At: testConformanceTime()}, findings)
				task, findings = conformanceTaskStep(task, TaskCommand{Type: TaskCommandDeterministicFailure, AuditEvidenceSHA256: conformanceDigest(), At: testConformanceTime()}, findings)
				if attempt < 3 {
					task, findings = conformanceTaskStep(task, TaskCommand{Type: TaskCommandQueueRework, At: testConformanceTime()}, findings)
				}
			}
			if task.State != contracts.TaskBlockedUserDecision || task.Attempt != 3 {
				findings = append(findings, fmt.Errorf("third failure state = %s attempt=%d", task.State, task.Attempt))
			}
			if _, blockedErr := DecideTask(task, TaskCommand{Type: TaskCommandQueueRework, At: testConformanceTime()}); blockedErr == nil {
				findings = append(findings, fmt.Errorf("blocked task accepted automatic rework"))
			}
			blockedEvent, blockErr := DecideTask(dependent, TaskCommand{Type: TaskCommandBlockDependency, BlockingTaskID: task.ID, At: testConformanceTime()})
			if blockErr != nil {
				findings = append(findings, blockErr)
			} else if blocked, applyErr := ApplyTask(dependent, blockedEvent); applyErr != nil || blocked.State != contracts.TaskBlockedDependency {
				findings = append(findings, fmt.Errorf("dependent freeze failed: %v", applyErr))
			}
		}
	}
	return findings
}

func conformanceTaskStep(current ModuleTask, command TaskCommand, findings []error) (ModuleTask, []error) {
	event, err := DecideTask(current, command)
	if err != nil {
		return current, append(findings, err)
	}
	next, applyErr := ApplyTask(current, event)
	if applyErr != nil {
		return current, append(findings, applyErr)
	}
	return next, findings
}

func conformanceApproval(goal GoalRecord) *ApprovalBinding {
	return &ApprovalBinding{RecordID: "approval_conformance", ApprovalType: "GOAL_APPROVAL", SubjectType: "GOAL_SPEC", SubjectID: goal.ID, SubjectVersion: goal.Version, SubjectSHA256: goal.SHA256, PrincipalID: "user_conformance", Reason: "conformance approval", IssuedAt: testConformanceTime(), Signature: "conformance-signature"}
}

func conformanceProjectStep(current Project, command ProjectCommand, findings []error) (Project, []error) {
	event, err := DecideProject(current, command)
	if err != nil {
		return current, append(findings, err)
	}
	next, applyErr := ApplyProject(current, event)
	if applyErr != nil {
		return current, append(findings, applyErr)
	}
	return next, findings
}

func conformanceDigest() string {
	return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

func testConformanceTime() time.Time {
	return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
}
