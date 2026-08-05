package controlapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type taskDecisionBody struct {
	Decision        contracts.Decision `json:"decision"`
	ExpectedVersion int64              `json:"expectedVersion"`
}

type commandAccepted struct {
	CommandID string `json:"commandId"`
}

func (handler *Handler) getTaskDecisionReport(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID, taskID string) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "decision report query"}))
		return
	}
	project, task, err := handler.loadDecisionTask(request.Context(), principal, projectID, taskID)
	if err != nil {
		writeError(response, request, err)
		return
	}
	if err := authorizeRead(request.Context(), handler.authorizer, principal, projectID, authz.ActionTaskRead, "task-decision-report", taskID, string(project.State), project.Version, project.DataClassification); err != nil {
		writeError(response, request, err)
		return
	}
	if handler.decisionReports == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "decision report"}))
		return
	}
	report, err := handler.decisionReports.DecisionReport(request.Context(), principal.TenantID, projectID, taskID)
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	if err := validateTaskDecisionReport(report, projectID, taskID); err != nil || !verifyTaskDecisionReport(request.Context(), handler.decisionVerifier, report) || report.State != task.State || project.Goal == nil || report.GoalSpec.Version != project.Goal.Version || report.GoalSpec.SHA256 != project.Goal.SHA256 {
		writeError(response, request, aorerrors.New(aorerrors.CodeAuditEvidenceInvalid, "", map[string]any{"scope": "decision report binding"}))
		return
	}
	digest, err := decisionReportDigest(report)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "decision report digest"}))
		return
	}
	response.Header().Set("ETag", `"`+digest+`"`)
	writeJSON(response, http.StatusOK, report)
}

func (handler *Handler) decideTask(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID, taskID string) {
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	var body taskDecisionBody
	if err := decodeJSON(request, &body); err != nil || !canonicalTaskDecision(body.Decision) || body.ExpectedVersion < 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "task decision"}))
		return
	}
	if err := validateIfMatch(request.Header.Get("If-Match"), body.ExpectedVersion); err != nil {
		writeError(response, request, err)
		return
	}
	replayed, err := handler.replayTaskDecision(request.Context(), response, request, principal, projectID, taskID, idempotencyKey, body)
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	if replayed {
		return
	}
	project, task, err := handler.loadDecisionTask(request.Context(), principal, projectID, taskID)
	if err != nil {
		writeError(response, request, err)
		return
	}
	if task.Version != body.ExpectedVersion {
		writeError(response, request, aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"expectedVersion": body.ExpectedVersion, "actualVersion": task.Version}))
		return
	}
	if handler.decisionReports == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "decision report"}))
		return
	}
	report, err := handler.decisionReports.DecisionReport(request.Context(), principal.TenantID, projectID, taskID)
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	if err := validateTaskDecisionReport(report, projectID, taskID); err != nil || !verifyTaskDecisionReport(request.Context(), handler.decisionVerifier, report) || report.State != task.State || project.Goal == nil || report.GoalSpec.Version != project.Goal.Version || report.GoalSpec.SHA256 != project.Goal.SHA256 {
		writeError(response, request, aorerrors.New(aorerrors.CodeAuditEvidenceInvalid, "", map[string]any{"scope": "decision report binding"}))
		return
	}
	if !containsTaskDecision(report.AllowedDecisions, body.Decision) {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidStateTransition, "", map[string]any{"scope": "unsupported task decision"}))
		return
	}
	if body.Decision != contracts.DecisionAuthorizeNewAttemptSeries {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidStateTransition, "", map[string]any{"scope": "unsupported task decision"}))
		return
	}
	reportDigest, err := decisionReportDigest(report)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "decision report digest"}))
		return
	}
	approvalID, err := newRecordUUIDv7()
	if err != nil {
		writeError(response, request, aorerrors.Wrap(aorerrors.CodeInternalError, "", err, nil))
		return
	}
	decisionID, err := newRecordUUIDv7()
	if err != nil {
		writeError(response, request, aorerrors.Wrap(aorerrors.CodeInternalError, "", err, nil))
		return
	}
	newSeriesID, err := newRecordUUIDv7()
	if err != nil {
		writeError(response, request, aorerrors.Wrap(aorerrors.CodeInternalError, "", err, nil))
		return
	}
	issuedAt := handler.clock().UTC()
	reason := "explicit task decision " + string(body.Decision) + " report " + reportDigest
	command := state.TaskCommand{
		Type: state.TaskCommandAuthorizeNewSeries, Decision: body.Decision,
		DecisionRecordID: decisionID, DecisionReportSHA256: reportDigest,
		NewAttemptSeriesID: newSeriesID, ModuleSpecRef: task.ModuleSpecRef,
		ActorID: principal.ID,
		Approval: &state.ApprovalBinding{
			RecordID: approvalID, ApprovalType: "AUTHORIZE_NEW_ATTEMPT_SERIES", SubjectType: "MODULE_TASK",
			SubjectID: task.ID, SubjectVersion: task.ModuleSpecRef.Version, SubjectSHA256: task.ModuleSpecRef.SHA256,
			PrincipalID: principal.ID, Reason: reason, IssuedAt: issuedAt,
			Signature: taskDecisionApprovalSignature(principal.TenantID, projectID, task.ID, task.Version, task.ModuleSpecRef.SHA256, reportDigest, principal.ID, idempotencyKey),
		},
	}
	outcome, err := handler.orchestrator.HandleTask(request.Context(), orchestrator.TaskRequest{
		TenantID: principal.TenantID, ProjectID: projectID, TaskID: taskID, PrincipalID: principal.ID,
		IdempotencyKey: idempotencyKey, ExpectedVersion: body.ExpectedVersion, Command: command,
	})
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	if !writeTaskDecisionAccepted(response, outcome.Task, outcome.Events) {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "task decision command"}))
	}
}

func (handler *Handler) replayTaskDecision(ctx context.Context, response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID, taskID, idempotencyKey string, body taskDecisionBody) (bool, error) {
	digest, err := orchestrator.TaskParameterDigest(orchestrator.TaskRequest{
		TenantID: principal.TenantID, ProjectID: projectID, TaskID: taskID, PrincipalID: principal.ID,
		IdempotencyKey: idempotencyKey, ExpectedVersion: body.ExpectedVersion,
		Command: state.TaskCommand{Type: state.TaskCommandAuthorizeNewSeries, Decision: body.Decision},
	})
	if err != nil {
		return false, err
	}
	prior, found, err := handler.store.Lookup(ctx, principal.TenantID, principal.ID, idempotencyKey, digest)
	if err != nil || !found {
		return false, err
	}
	var task state.ModuleTask
	if json.Unmarshal(prior.Result, &task) != nil || task.TenantID != principal.TenantID || task.ProjectID != projectID || task.ID != taskID || task.Version != body.ExpectedVersion+1 || !writeTaskDecisionAccepted(response, task, prior.Events) {
		return false, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "task decision replay"})
	}
	return true, nil
}

func writeTaskDecisionAccepted(response http.ResponseWriter, task state.ModuleTask, events []eventing.DomainEvent) bool {
	for _, event := range events {
		if event.Type != "io.aor.module.attempt-series-authorized.v1" || event.AggregateID != task.ID {
			continue
		}
		response.Header().Set("ETag", entityTag(task.Version))
		writeJSON(response, http.StatusAccepted, commandAccepted{CommandID: event.EventID})
		return true
	}
	return false
}

func (handler *Handler) loadDecisionTask(ctx context.Context, principal authn.Principal, projectID, taskID string) (state.Project, state.ModuleTask, error) {
	project, found, err := handler.orchestrator.Project(ctx, principal.TenantID, projectID)
	if err != nil {
		return state.Project{}, state.ModuleTask{}, normalizeError(err)
	}
	if !found {
		return state.Project{}, state.ModuleTask{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	task, found, err := handler.orchestrator.Task(ctx, principal.TenantID, projectID, taskID)
	if err != nil {
		return state.Project{}, state.ModuleTask{}, normalizeError(err)
	}
	if !found {
		return state.Project{}, state.ModuleTask{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	if err := authorizeTaskRead(ctx, handler.authorizer, principal, project, task); err != nil {
		return state.Project{}, state.ModuleTask{}, err
	}
	return project, task, nil
}

func containsTaskDecision(values []contracts.Decision, expected contracts.Decision) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func taskDecisionApprovalSignature(tenantID, projectID, taskID string, version int64, specSHA256, reportSHA256, principalID, idempotencyKey string) string {
	value := sha256.Sum256([]byte(strings.Join([]string{tenantID, projectID, taskID, strconv.FormatInt(version, 10), specSHA256, reportSHA256, principalID, "explicit task decision", idempotencyKey}, "\x00")))
	return "oidc-sha256:" + hex.EncodeToString(value[:])
}
