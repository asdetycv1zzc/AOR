package execution

import (
	"context"
	"encoding/json"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/pkg/contracts"
)

// PriorAuditEvidenceSource resolves the immutable evidence for a completed
// module attempt. Retry execution fails closed when that evidence is absent.
type PriorAuditEvidenceSource interface {
	Get(context.Context, string, string, string, string, int) (contracts.EvidenceBundle, bool, error)
}

type ReworkFeedback struct {
	PreviousAttempt      int                         `json:"previousAttempt"`
	EvidenceBundleSHA256 string                      `json:"evidenceBundleSha256"`
	SubmissionCommit     string                      `json:"submissionCommit"`
	AuditorVerdict       string                      `json:"auditorVerdict"`
	FailedChecks         []contracts.EvidenceCheck   `json:"failedChecks"`
	OpenFindings         []contracts.AuditFinding    `json:"openFindings"`
	FailedCriteria       []contracts.CriterionResult `json:"failedCriteria"`
}

func loadReworkFeedback(ctx context.Context, source PriorAuditEvidenceSource, request PreparationRequest) (agentruntime.ContextItem, error) {
	previousAttempt := request.Attempt - 1
	if source == nil || previousAttempt < 1 {
		return agentruntime.ContextItem{}, ErrPreparationInvalid
	}
	bundle, found, err := source.Get(ctx, request.Project.TenantID, request.Project.ID, request.Task.ID, request.Task.AttemptSeriesID, previousAttempt)
	if err != nil {
		return agentruntime.ContextItem{}, err
	}
	if !found || bundle.Validate() != nil || bundle.PassesAuditGate() ||
		bundle.ProjectID != request.Project.ID || bundle.TaskID != request.Task.ID ||
		bundle.AttemptSeriesID != request.Task.AttemptSeriesID || bundle.Attempt != previousAttempt ||
		bundle.SpecVersion != request.Task.ModuleSpecRef.Version {
		return agentruntime.ContextItem{}, ErrPreparationInvalid
	}

	feedback := ReworkFeedback{
		PreviousAttempt: previousAttempt, EvidenceBundleSHA256: bundle.ManifestSHA256,
		SubmissionCommit: bundle.SubmissionCommit, AuditorVerdict: bundle.LLMAudit.Verdict,
		FailedChecks: []contracts.EvidenceCheck{}, OpenFindings: []contracts.AuditFinding{},
		FailedCriteria: []contracts.CriterionResult{},
	}
	for _, check := range bundle.Checks {
		if check.Status != "PASS" {
			feedback.FailedChecks = append(feedback.FailedChecks, check)
		}
	}
	for _, finding := range bundle.Findings {
		if finding.Status == contracts.FindingOpen {
			feedback.OpenFindings = append(feedback.OpenFindings, finding)
		}
	}
	for _, criterion := range bundle.CriteriaResults {
		if criterion.Status != contracts.CriterionPass {
			feedback.FailedCriteria = append(feedback.FailedCriteria, criterion)
		}
	}
	content, err := json.Marshal(feedback)
	if err != nil || len(content) > agentruntime.MaximumContextItemBytes {
		return agentruntime.ContextItem{}, ErrPreparationInvalid
	}
	reference := "audit://evidence/" + bundle.ManifestSHA256
	return executionContextItem("rework", agentruntime.ContextPriorFinding, reference, bundle.ManifestSHA256, string(content), agentruntime.TrustCurated), nil
}
