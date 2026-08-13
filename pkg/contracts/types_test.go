package contracts

import (
	"strings"
	"testing"
)

func TestModuleTaskDoneIsComputedFromIntegratedEvidence(t *testing.T) {
	evidence := CompletionEvidence{SubmissionImmutable: true, AuditPassed: true, MergeQueued: true, NoBlockingFindings: true, RequiredEvidence: true}
	if evidence.Done(TaskPassed) {
		t.Fatal("passed task is not complete before integration")
	}
	if !evidence.Done(TaskIntegrated) {
		t.Fatal("integrated task with complete evidence should be done")
	}
}

func TestModuleSpecRejectsWindowsIsolationClaims(t *testing.T) {
	spec := ModuleSpec{
		ModuleSpecVersion: 1,
		ModuleID:          "mod_1",
		ProjectID:         "prj_1",
		PlanVersion:       1,
		ExecutionPlatform: PlatformWindows,
		SandboxLevel:      IsolationNone,
		NetworkPolicy:     NetworkPolicy{Mode: NetworkAllowlist, Destinations: []string{"example.test"}},
	}
	if err := spec.Validate(); err == nil {
		t.Fatal("windows NONE must reject claimed network isolation")
	}
}

func TestSubmissionRequiresAttemptSeriesAndBoundedAttempt(t *testing.T) {
	manifest := SubmissionManifest{SubmissionVersion: 1, ProjectID: "prj_1", ModuleTaskID: "task_1", Attempt: 4, BaseCommit: "0000000000000000000000000000000000000001", HeadCommit: "0000000000000000000000000000000000000002", SHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
	if err := manifest.Validate(); err == nil {
		t.Fatal("attempt four must be rejected")
	}
}

func TestApprovedGoalRequiresUserApprovalAndNoUnresolvedItems(t *testing.T) {
	goal := GoalSpec{Content: GoalContent{GoalSpecVersion: 1, ProjectID: "prj_1", Version: 1, UnresolvedItems: []string{"open"}}, Status: GoalApproved, ContentSHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
	if err := goal.Validate(); err == nil {
		t.Fatal("unresolved approved goal must be rejected")
	}
}

func TestGoalRejectsUnknownStatus(t *testing.T) {
	goal := GoalSpec{Content: GoalContent{GoalSpecVersion: 1, ProjectID: "prj_1", Version: 1, Title: "Goal", Summary: "Summary", ProblemStatement: "Problem", BusinessOutcomes: []Outcome{{ID: "outcome_1", Statement: "Outcome"}}, AcceptanceCriteria: []AcceptanceCriterion{{ID: "criterion_1", Statement: "Pass", EvidenceType: "AUTOMATED"}}, CreatedAt: "2030-01-01T00:00:00Z", CreatedBy: AgentIdentity{AgentInstanceID: "agt_1", Role: "GOAL_PROPOSER"}}, Status: GoalStatus("UNKNOWN"), ContentSHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
	if err := goal.Validate(); err == nil {
		t.Fatal("unknown GoalStatus must be rejected")
	}
}

func TestLinuxModuleRejectsUnrestrictedNetwork(t *testing.T) {
	spec := ModuleSpec{ModuleSpecVersion: 1, ModuleID: "mod_1", ProjectID: "prj_1", PlanVersion: 1, Name: "module", Purpose: "purpose", ExecutionPlatform: PlatformLinux, SandboxLevel: IsolationContainer, NetworkPolicy: NetworkPolicy{Mode: NetworkUnrestricted}, SHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
	if err := spec.Validate(); err == nil {
		t.Fatal("Linux module accepted unrestricted network")
	}
}

func TestAuditFindingFingerprintSurvivesLineMovement(t *testing.T) {
	base := AuditFinding{
		Severity: FindingHigh, Category: "CORRECTNESS", RuleID: "rule.concurrent-write",
		File: "internal\\worker\\run.go", Status: FindingOpen,
		SemanticLocation: "worker.Run/commit", EvidencePattern: "lost-update",
		EvidenceRefs:     []string{"artifact://sha256/evidence"},
		ExpectedBehavior: "each accepted write is committed", ObservedBehavior: "one accepted write is lost",
		RemediationConstraint: "preserve optimistic concurrency",
	}
	first := base
	first.LineStart, first.LineEnd = 12, 14
	second := base
	second.LineStart, second.LineEnd = 91, 93

	first, err := CanonicalAuditFinding(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err = CanonicalAuditFinding(second)
	if err != nil {
		t.Fatal(err)
	}
	if first.File != "internal/worker/run.go" || first.StableFingerprint != second.StableFingerprint || first.FindingID != second.FindingID {
		t.Fatalf("line movement changed stable identity: first=%#v second=%#v", first, second)
	}

	second.StableFingerprint = "sha256:" + strings.Repeat("0", 64)
	if second.Validate() == nil {
		t.Fatal("tampered stable fingerprint was accepted")
	}
}

func TestEvidenceAuditGateUsesBlockingFindingsAndCriteria(t *testing.T) {
	finding, err := CanonicalAuditFinding(AuditFinding{
		Severity: FindingLow, Category: "STYLE", RuleID: "style.naming", File: "pkg/name.go",
		Status: FindingOpen, SemanticLocation: "Name", EvidencePattern: "non-idiomatic-name",
		EvidenceRefs: []string{}, ExpectedBehavior: "name follows conventions", ObservedBehavior: "name is unconventional",
		RemediationConstraint: "preserve the public API",
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle := EvidenceBundle{
		Checks: []EvidenceCheck{{
			CheckID: "required", Ordinal: 1, Type: "DETERMINISTIC", Status: "PASS",
			Tool:      CheckTool{Name: "audit", Version: "1", Digest: "sha256:" + strings.Repeat("1", 64)},
			StartedAt: "2030-01-01T00:00:00Z", CompletedAt: "2030-01-01T00:00:01Z",
			StdoutURI: "artifact://empty", StderrURI: "artifact://empty", ResultURI: "artifact://empty", ResultSHA256: "sha256:" + strings.Repeat("2", 64),
		}},
		Findings:        []AuditFinding{finding},
		CriteriaResults: []CriterionResult{{CriterionID: "criterion-1", Status: CriterionPass, EvidenceRefs: []string{}}},
		ResidualRisks:   []string{},
		Confidence:      0.8,
		Artifacts:       []string{},
		LLMAudit: LLMAudit{
			AuditorRunID: "auditor-run", ModelIdentity: "model", PromptDigest: "sha256:" + strings.Repeat("3", 64),
			ContextManifestDigest: "sha256:" + strings.Repeat("4", 64), Verdict: "PASS",
		},
	}
	if !bundle.PassesAuditGate() {
		t.Fatal("an OPEN LOW finding incorrectly blocked the audit")
	}

	bundle.Findings[0].Severity = FindingHigh
	bundle.Findings[0], err = CanonicalAuditFinding(AuditFinding{
		Severity: FindingHigh, Category: "STYLE", RuleID: "style.naming", File: "pkg/name.go",
		Status: FindingOpen, SemanticLocation: "Name", EvidencePattern: "non-idiomatic-name",
		EvidenceRefs: []string{}, ExpectedBehavior: "name follows conventions", ObservedBehavior: "name is unconventional",
		RemediationConstraint: "preserve the public API",
	})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.PassesAuditGate() {
		t.Fatal("an OPEN HIGH finding did not block the audit")
	}
	bundle.Findings[0].Status = FindingFixed
	if !bundle.PassesAuditGate() {
		t.Fatal("a resolved HIGH finding incorrectly blocked the audit")
	}
	bundle.CriteriaResults[0].Status = CriterionNotTested
	if bundle.PassesAuditGate() {
		t.Fatal("a required NOT_TESTED criterion did not block the audit")
	}
}

func TestCrosstoolNGArchiveRequiresMatchingUploadedArtifact(t *testing.T) {
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tool := VersionedTool{
		Kind: ToolchainCompiler, Name: "GNU g++", Version: "15.2.0", Platform: PlatformLinux, Architecture: "amd64", Source: ToolchainInstallRequired,
		Install: &ToolchainInstall{
			Method: ToolchainInstallCrosstoolNGArchive, Authorized: true,
			EvidenceRef: "artifact://sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ArtifactID:  "019feeec-e315-7763-818e-8c31192809c0", ArtifactRef: "artifact://sha256/" + digest,
			SourceSHA256: "sha256:" + digest,
		},
	}
	selection := GoalToolchain{Languages: []LanguageRequirement{{Name: "C++", Version: "C++23"}}, Tools: []VersionedTool{tool}}
	if err := selection.Validate(); err != nil || !tool.ReadyToProvision() {
		t.Fatalf("authorized crosstool-ng archive rejected: %v", err)
	}
	tool.Install.ArtifactRef = "artifact://sha256/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if (GoalToolchain{Languages: selection.Languages, Tools: []VersionedTool{tool}}).Validate() == nil || tool.ReadyToProvision() {
		t.Fatal("mismatched crosstool-ng artifact digest accepted")
	}
}

func TestCrosstoolNGArchiveCanAwaitUpload(t *testing.T) {
	tool := VersionedTool{
		Kind: ToolchainCompiler, Name: "GCC", Version: "15.2.0", Platform: PlatformLinux, Architecture: "amd64", Source: ToolchainInstallRequired,
		Install: &ToolchainInstall{Method: ToolchainInstallCrosstoolNGArchive, Authorized: false},
	}
	selection := GoalToolchain{Languages: []LanguageRequirement{{Name: "C", Version: "C23"}}, Tools: []VersionedTool{tool}}
	if err := selection.Validate(); err != nil || tool.ReadyToProvision() || !tool.NeedsInstallationInput() {
		t.Fatalf("pending crosstool-ng upload state invalid: %v", err)
	}
}

func TestCrosstoolNGSuiteUsesOneCompilerEntry(t *testing.T) {
	gcc := VersionedTool{
		Kind: ToolchainCompiler, Name: "GCC", Version: "15.2.0", Platform: PlatformLinux, Architecture: "amd64", Source: ToolchainInstallRequired,
		Install: &ToolchainInstall{Method: ToolchainInstallCrosstoolNGArchive, Authorized: false},
	}
	gxx := gcc
	gxx.Name = "G++"
	selection := GoalToolchain{
		Languages: []LanguageRequirement{{Name: "C", Version: "C23"}, {Name: "C++", Version: "C++23"}},
		Tools:     []VersionedTool{gcc, gxx},
	}
	if selection.Validate() == nil {
		t.Fatal("separate GCC and G++ entries accepted for one crosstool-ng suite")
	}
}
