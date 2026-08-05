package controlapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

type staticDecisionReportReader struct {
	report contracts.UserDecisionReport
	calls  int
}

func TestTaskDecisionReportHMACUsesDetachedJWS(t *testing.T) {
	signer, err := NewHMACTaskDecisionReportSigner([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"reportVersion":"1.0"}`)
	signature, err := signer.Sign(context.Background(), payload)
	if err != nil || !signer.Verify(context.Background(), payload, signature) || signer.Verify(context.Background(), []byte(`{}`), signature) {
		t.Fatalf("signature=%#v err=%v", signature, err)
	}
	parts := strings.Split(signature.JWS, ".")
	protected, decodeErr := base64.RawURLEncoding.DecodeString(parts[0])
	if len(parts) != 3 || parts[1] != "" || decodeErr != nil || !json.Valid(protected) {
		t.Fatalf("invalid detached JWS %q", signature.JWS)
	}
}

func (reader *staticDecisionReportReader) DecisionReport(context.Context, string, string, string) (contracts.UserDecisionReport, error) {
	reader.calls++
	return reader.report, nil
}

func TestTaskDecisionReportRoutesAuthorizeAndReplay(t *testing.T) {
	handler, store, _ := newTestHandler(t)
	projectID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	taskID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	digest := "sha256:" + strings.Repeat("1", 64)
	goal := &state.GoalRecord{ID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Version: 1, SHA256: digest, Status: contracts.GoalApproved, ApprovedBy: "user-1"}
	plan := contracts.SpecRef{Version: 1, SHA256: digest}
	project := state.Project{TenantID: testTenantID, ID: projectID, State: contracts.ProjectExecuting, Version: 1, DataClassification: "INTERNAL", GoalAgentCount: 1, Goal: goal, Plan: &plan}
	task := state.ModuleTask{TenantID: testTenantID, ProjectID: projectID, ID: taskID, State: contracts.TaskBlockedUserDecision, Version: 1, ModuleSpecRef: contracts.SpecRef{Version: 1, SHA256: digest}, AttemptSeriesID: "series-1", AttemptSeriesIDs: []string{"series-1"}, Attempt: 3}
	seedDecisionProjection(t, store, "project", projectID, project, projectID)
	seedDecisionProjection(t, store, "task", taskID, task, projectID)
	reader := &staticDecisionReportReader{report: testDecisionReport(projectID, taskID, digest)}
	signer, err := NewHMACTaskDecisionReportSigner([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := canonicalDecisionReport(reader.report)
	if err != nil {
		t.Fatal(err)
	}
	reader.report.Signature, err = signer.Sign(context.Background(), unsigned)
	if err != nil {
		t.Fatal(err)
	}
	handler.decisionReports = reader
	handler.decisionVerifier = signer
	headers := map[string]string{"Authorization": "Bearer " + testBearer, "Content-Type": "application/json"}
	reportResponse := performRequest(handler, http.MethodGet, "/v1/projects/"+projectID+"/tasks/"+taskID+"/decision-report", nil, headers)
	if reportResponse.Code != http.StatusOK || !strings.Contains(reportResponse.Body.String(), `"dependencyImpact"`) || reportResponse.Header().Get("ETag") == "" {
		t.Fatalf("report response status=%d body=%s etag=%q", reportResponse.Code, reportResponse.Body.String(), reportResponse.Header().Get("ETag"))
	}
	decisionHeaders := map[string]string{}
	for key, value := range headers {
		decisionHeaders[key] = value
	}
	decisionHeaders["Idempotency-Key"] = "decision-1"
	decisionHeaders["If-Match"] = `"v1"`
	body := []byte(`{"decision":"AUTHORIZE_NEW_ATTEMPT_SERIES","expectedVersion":1}`)
	accepted := performRequest(handler, http.MethodPost, "/v1/projects/"+projectID+"/tasks/"+taskID+"/decisions", body, decisionHeaders)
	if accepted.Code != http.StatusAccepted || accepted.Header().Get("ETag") != `"v2"` || !strings.Contains(accepted.Body.String(), `"commandId"`) {
		t.Fatalf("decision response status=%d body=%s etag=%q", accepted.Code, accepted.Body.String(), accepted.Header().Get("ETag"))
	}
	replayed := performRequest(handler, http.MethodPost, "/v1/projects/"+projectID+"/tasks/"+taskID+"/decisions", body, decisionHeaders)
	if replayed.Code != http.StatusAccepted || replayed.Body.String() != accepted.Body.String() || reader.calls != 2 {
		t.Fatalf("replay status=%d body=%s calls=%d", replayed.Code, replayed.Body.String(), reader.calls)
	}
	if stats := store.Stats(); stats.UserDecisions != 1 || stats.Approvals != 1 {
		t.Fatalf("decision persistence stats=%#v", stats)
	}
}

func testDecisionReport(projectID, taskID, digest string) contracts.UserDecisionReport {
	findings := []string{"FND-1"}
	attempts := []contracts.AttemptSummary{
		{Attempt: 1, SubmissionCommit: strings.Repeat("a", 40), FailureStage: "DETERMINISTIC_AUDIT", FindingIDs: findings, EvidenceURI: "artifact://sha256/" + strings.Repeat("2", 64)},
		{Attempt: 2, SubmissionCommit: strings.Repeat("b", 40), FailureStage: "DETERMINISTIC_AUDIT", FindingIDs: findings, EvidenceURI: "artifact://sha256/" + strings.Repeat("3", 64)},
		{Attempt: 3, SubmissionCommit: strings.Repeat("c", 40), FailureStage: "LLM_AUDIT", FindingIDs: findings, EvidenceURI: "artifact://sha256/" + strings.Repeat("4", 64)},
	}
	return contracts.UserDecisionReport{
		ReportVersion: "1.0", ProjectID: projectID, GoalSpec: contracts.SpecRef{Version: 1, SHA256: digest}, ModuleTaskID: taskID,
		ModuleName: "API", State: contracts.TaskBlockedUserDecision, AttemptLimit: 3, Attempts: attempts,
		BlockingFindings: []contracts.BlockingFinding{{ID: "FND-1", Severity: "HIGH", Category: "CORRECTNESS", Summary: "the result is wrong", Location: "internal/api.go:12", ReproductionURI: attempts[2].EvidenceURI, FirstObservedAttempt: 1, LastObservedAttempt: 3}},
		DependencyImpact: contracts.DecisionDependencyImpact{FrozenTaskIDs: []string{}, CriticalPathImpact: false},
		CostSummary:      contracts.DecisionCostSummary{InputTokens: 1, OutputTokens: 2, EstimatedCost: "0.01", Currency: "USD"},
		AllowedDecisions: []contracts.Decision{contracts.DecisionAuthorizeNewAttemptSeries}, GeneratedAt: "2026-08-04T04:00:00Z",
		Signature: &contracts.Signature{Type: "detached-jws", KID: "test", JWS: strings.Repeat("x", 16)},
	}
}

func seedDecisionProjection(t *testing.T, store *eventing.MemoryStore, aggregateType, aggregateID string, value any, projectID string) {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonicaljson.Digest(content)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Execute(context.Background(), eventing.TransactionRequest{
		TenantID: testTenantID, PrincipalID: "seed", IdempotencyKey: aggregateType + aggregateID, RequestSHA256: digest,
		Result: content, ResultSHA256: digest,
		Updates: []eventing.ProjectionUpdate{{TenantID: testTenantID, ProjectID: projectID, AggregateType: aggregateType, AggregateID: aggregateID, ExpectedVersion: 0, NextVersion: 1, State: content}},
		Events:  []eventing.DomainEvent{{EventID: aggregateType + "-event-" + aggregateID, TenantID: testTenantID, ProjectID: projectID, AggregateType: aggregateType, AggregateID: aggregateID, AggregateVersion: 1, Type: "seed", Payload: content, PayloadSHA256: digest, OccurredAt: time.Date(2026, 8, 4, 3, 0, 0, 0, time.UTC)}},
	})
	if err != nil {
		t.Fatal(err)
	}
}
