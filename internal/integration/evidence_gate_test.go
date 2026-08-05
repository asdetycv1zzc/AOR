package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/akimisaka/aor/internal/audit"
	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

func TestSignedEvidenceSourceUsesStructuredAuditGate(t *testing.T) {
	tests := []struct {
		name            string
		severity        contracts.FindingSeverity
		criterionStatus contracts.CriterionStatus
		wantPassed      bool
	}{
		{name: "open-low", severity: contracts.FindingLow, criterionStatus: contracts.CriterionPass, wantPassed: true},
		{name: "open-high", severity: contracts.FindingHigh, criterionStatus: contracts.CriterionPass, wantPassed: false},
		{name: "criterion-not-tested", severity: contracts.FindingLow, criterionStatus: contracts.CriterionNotTested, wantPassed: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signer, err := audit.NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
			if err != nil {
				t.Fatal(err)
			}
			finding, err := contracts.CanonicalAuditFinding(contracts.AuditFinding{
				Severity: test.severity, Category: "QUALITY", RuleID: "quality.advisory", File: "owned/file.go",
				Status: contracts.FindingOpen, SemanticLocation: "file", EvidencePattern: "advisory-pattern",
				EvidenceRefs: []string{}, ExpectedBehavior: "quality target is met", ObservedBehavior: "quality target is not met",
				RemediationConstraint: "preserve required behavior",
			})
			if err != nil {
				t.Fatal(err)
			}
			bundle := contracts.EvidenceBundle{
				EvidenceBundleVersion: 1, ProjectID: "project-1", TaskID: "task-1", AttemptSeriesID: "series-1", Attempt: 1, SpecVersion: 1,
				BaseCommit: strings.Repeat("1", 40), SubmissionCommit: strings.Repeat("2", 40), PipelineVersion: "1.0.0",
				PolicyBundleDigest: integrationEvidenceDigest("policy"), ExecutionPlatform: contracts.PlatformLinux, IsolationLevel: contracts.IsolationContainer, SandboxAttestation: "oci:test",
				Checks: []contracts.EvidenceCheck{{
					CheckID: "required", Ordinal: 1, Type: "DETERMINISTIC", Status: "PASS",
					Tool:      contracts.CheckTool{Name: "audit", Version: "1", Digest: integrationEvidenceDigest("tool")},
					StartedAt: "2030-01-01T00:00:00Z", CompletedAt: "2030-01-01T00:00:01Z",
					StdoutURI: "artifact://empty", StderrURI: "artifact://empty", ResultURI: "artifact://empty", ResultSHA256: integrationEvidenceDigest("result"),
				}},
				Findings:        []contracts.AuditFinding{finding},
				CriteriaResults: []contracts.CriterionResult{{CriterionID: "criterion-1", Status: test.criterionStatus, EvidenceRefs: []string{}}},
				ResidualRisks:   []string{}, Confidence: 0.8, Artifacts: []string{},
				LLMAudit: contracts.LLMAudit{AuditorRunID: "auditor-run", ModelIdentity: "model", PromptDigest: integrationEvidenceDigest("prompt"), ContextManifestDigest: integrationEvidenceDigest("context"), Verdict: "PASS"},
			}
			encoded, err := json.Marshal(bundle)
			if err != nil {
				t.Fatal(err)
			}
			bundle.ManifestSHA256, err = canonicaljson.DigestObjectWithoutFields(encoded, "manifestSha256", "signature")
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(bundle)
			if err != nil {
				t.Fatal(err)
			}
			bundle.Signature, err = signer.Sign(context.Background(), payload)
			if err != nil || bundle.Validate() != nil {
				t.Fatalf("sign evidence: error=%v validation=%v", err, bundle.Validate())
			}

			store := audit.NewMemoryEvidenceStore()
			if err := store.Put(context.Background(), "tenant-1", bundle); err != nil {
				t.Fatal(err)
			}
			task := state.ModuleTask{TenantID: "tenant-1", ProjectID: bundle.ProjectID, ID: bundle.TaskID, AttemptSeriesID: bundle.AttemptSeriesID, Attempt: bundle.Attempt}
			submission := submissionForEvidence(bundle)
			record, err := (SignedEvidenceSource{Store: store, Signer: signer}).Verified(context.Background(), task, submission, bundle.ManifestSHA256)
			if err != nil || record.Passed != test.wantPassed {
				t.Fatalf("verified record=%#v error=%v", record, err)
			}
		})
	}
}

func submissionForEvidence(bundle contracts.EvidenceBundle) repository.Submission {
	return repository.Submission{Manifest: contracts.SubmissionManifest{
		SubmissionVersion: 1, ProjectID: bundle.ProjectID, ModuleTaskID: bundle.TaskID,
		AttemptSeriesID: bundle.AttemptSeriesID, Attempt: bundle.Attempt,
		ModuleSpecRef: contracts.SpecRef{Version: bundle.SpecVersion, SHA256: integrationEvidenceDigest("module")},
		BaseCommit:    bundle.BaseCommit, HeadCommit: bundle.SubmissionCommit,
	}}
}

func integrationEvidenceDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
