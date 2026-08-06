package execution

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/pkg/contracts"
)

type testPriorEvidence struct {
	bundle contracts.EvidenceBundle
	found  bool
	calls  int
}

func (source *testPriorEvidence) Get(_ context.Context, tenantID, projectID, taskID, seriesID string, attempt int) (contracts.EvidenceBundle, bool, error) {
	source.calls++
	if tenantID != "tenant-1" || projectID != "project-1" || taskID != "task-1" || seriesID != "series-1" || attempt != 1 {
		return contracts.EvidenceBundle{}, false, ErrPreparationInvalid
	}
	return source.bundle, source.found, nil
}

type emptyExecutionKnowledge struct{}

func (emptyExecutionKnowledge) Context(context.Context, authn.Principal, string, string, []string) ([]agentruntime.ContextItem, error) {
	return nil, nil
}

func TestExecutorRetryReceivesStructuredPriorAuditFeedback(t *testing.T) {
	bundle := executionFailureEvidence(t, "test returned the wrong value")
	source := &testPriorEvidence{bundle: bundle, found: true}
	preparer := &ExecutorRuntimePreparer{knowledge: emptyExecutionKnowledge{}, priorEvidence: source}
	request, goalRef, planRef := executionRetryPreparationRequest()

	items, _, err := preparer.contextItems(context.Background(), request, goalRef, planRef)
	if err != nil {
		t.Fatal(err)
	}
	manifest := agentruntime.ContextManifest{ManifestID: "ctx_retry", Version: "1", Role: agentruntime.RoleExecutor, Items: items}
	manifest.SHA256 = agentruntime.DigestContextManifest(manifest)
	if err := agentruntime.ValidateContextManifest(manifest); err != nil {
		t.Fatal(err)
	}
	var prior *agentruntime.ContextItem
	for index := range items {
		if items[index].Kind == agentruntime.ContextPriorFinding {
			prior = &items[index]
			break
		}
	}
	if prior == nil || prior.SourceSHA256 != bundle.ManifestSHA256 || prior.Trust != agentruntime.TrustCurated {
		t.Fatalf("prior feedback context is not evidence-bound: %#v", prior)
	}
	var feedback ReworkFeedback
	if err := json.Unmarshal([]byte(prior.Content), &feedback); err != nil {
		t.Fatal(err)
	}
	if feedback.PreviousAttempt != 1 || feedback.EvidenceBundleSHA256 != bundle.ManifestSHA256 ||
		feedback.SubmissionCommit != bundle.SubmissionCommit || feedback.AuditorVerdict != "FAIL" ||
		len(feedback.FailedChecks) != 0 || len(feedback.OpenFindings) != 1 ||
		feedback.OpenFindings[0].FindingID != bundle.Findings[0].FindingID ||
		len(feedback.FailedCriteria) != 1 || feedback.FailedCriteria[0].CriterionID != "criterion-1" || source.calls != 1 {
		t.Fatalf("unexpected retry feedback: %#v calls=%d", feedback, source.calls)
	}
}

func TestExecutorRetryRejectsOversizedPriorAuditFeedback(t *testing.T) {
	bundle := executionFailureEvidence(t, strings.Repeat("x", agentruntime.MaximumContextItemBytes))
	preparer := &ExecutorRuntimePreparer{
		knowledge:     emptyExecutionKnowledge{},
		priorEvidence: &testPriorEvidence{bundle: bundle, found: true},
	}
	request, goalRef, planRef := executionRetryPreparationRequest()

	_, _, err := preparer.contextItems(context.Background(), request, goalRef, planRef)
	if !errors.Is(err, ErrPreparationInvalid) {
		t.Fatalf("oversized audit feedback was accepted: %v", err)
	}
}

func executionRetryPreparationRequest() (PreparationRequest, contracts.SpecRef, contracts.SpecRef) {
	project, task, module := executionTestScope(contracts.TaskExecuting)
	task.Attempt = 1
	task.FencingToken = 7
	goalRef := contracts.SpecRef{Version: project.Goal.Version, SHA256: project.Goal.SHA256}
	planRef := *project.Plan
	return PreparationRequest{
		ExecutionID: "execution-2", Project: project, Task: task, ModuleSpec: module,
		Assignment: Assignment{AgentInstanceID: "agent-2", FencingToken: 7},
		Attempt:    2, BaseCommit: executionHeadCommit,
	}, goalRef, planRef
}

func executionFailureEvidence(t *testing.T, observed string) contracts.EvidenceBundle {
	t.Helper()
	finding, err := contracts.CanonicalAuditFinding(contracts.AuditFinding{
		Severity: contracts.FindingHigh, Category: "correctness", RuleID: "rule.retry",
		File: "internal/module/file.go", LineStart: 12, LineEnd: 12, Status: contracts.FindingOpen,
		SemanticLocation: "Run", EvidencePattern: "wrong return value",
		EvidenceRefs: []string{"artifact://audit/result"}, ExpectedBehavior: "return the expected value",
		ObservedBehavior: observed, RemediationConstraint: "preserve the public interface",
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle := contracts.EvidenceBundle{
		EvidenceBundleVersion: 1, ProjectID: "project-1", TaskID: "task-1", AttemptSeriesID: "series-1",
		Attempt: 1, SpecVersion: 1, BaseCommit: executionBaseCommit, SubmissionCommit: executionHeadCommit,
		PipelineVersion: "1.0.0", PolicyBundleDigest: executionPlanDigest,
		ExecutionPlatform: contracts.PlatformLinux, IsolationLevel: contracts.IsolationContainer,
		SandboxAttestation: "oci:" + executionTestDigest,
		Checks: []contracts.EvidenceCheck{{
			CheckID: "module-tests", Ordinal: 1, Type: "DETERMINISTIC", Status: "PASS",
			Tool:      contracts.CheckTool{Name: "go-test", Version: "1", Digest: executionTestDigest},
			StartedAt: "2025-01-02T03:04:05Z", CompletedAt: "2025-01-02T03:04:06Z",
			StdoutURI: "artifact://audit/stdout", StderrURI: "artifact://audit/stderr",
			ResultURI: "artifact://audit/result", ResultSHA256: executionTestDigest,
		}},
		Findings: []contracts.AuditFinding{finding},
		CriteriaResults: []contracts.CriterionResult{{
			CriterionID: "criterion-1", Status: contracts.CriterionFail,
			EvidenceRefs: []string{"artifact://audit/result"},
		}},
		ResidualRisks: []string{}, Confidence: 0.9, Artifacts: []string{},
		LLMAudit: contracts.LLMAudit{
			AuditorRunID: "audit-run-1", ModelIdentity: "provider/auditor",
			PromptDigest: executionGoalDigest, ContextManifestDigest: executionPlanDigest, Verdict: "FAIL",
		},
		ManifestSHA256: executionGoalDigest,
		Signature:      &contracts.Signature{Type: "HMAC-SHA256", KID: "audit-test", JWS: "signed"},
	}
	if err := bundle.Validate(); err != nil {
		t.Fatal(err)
	}
	return bundle
}
