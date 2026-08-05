package audit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type testAuditorFactory struct {
	calls int
}

func (f *testAuditorFactory) New(context.Context) (Auditor, error) {
	f.calls++
	return testAuditor{run: "auditor-run-" + string(rune('0'+f.calls))}, nil
}

type testAuditor struct{ run string }

func (a testAuditor) Audit(_ context.Context, input BlindAuditInput) (LLMAuditResult, error) {
	if input.ProjectID == "" || len(input.ChangedFiles) != 1 || len(input.RequiredCriteria) != 1 {
		return LLMAuditResult{}, ErrBlindContext
	}
	return LLMAuditResult{AuditorRunID: a.run, ModelIdentity: "model/auditor", PromptDigest: digestBytes([]byte("prompt")), ContextDigest: digestBytes([]byte("context")), Verdict: "PASS", Findings: []contracts.AuditFinding{}, CriteriaResults: []contracts.CriterionResult{{CriterionID: input.RequiredCriteria[0], Status: contracts.CriterionPass, EvidenceRefs: []string{}}}, ResidualRisks: []string{}, Confidence: 0.9}, nil
}

type fixedAuditorFactory struct{ result LLMAuditResult }

func (factory fixedAuditorFactory) New(context.Context) (Auditor, error) {
	return fixedAuditor{result: factory.result}, nil
}

type fixedAuditor struct{ result LLMAuditResult }

func (auditor fixedAuditor) Audit(context.Context, BlindAuditInput) (LLMAuditResult, error) {
	return auditor.result, nil
}

type recordingAuditRunStore struct {
	runs []AuditRun
	err  error
}

func (store *recordingAuditRunStore) Put(_ context.Context, run AuditRun) error {
	run.Findings = cloneFindings(run.Findings)
	store.runs = append(store.runs, run)
	return store.err
}

func TestPipelineRunsFixedOrderAndCreatesSignedEvidence(t *testing.T) {
	factory := &testAuditorFactory{}
	signer, err := NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryEvidenceStore()
	pipeline, err := NewPipeline(nil, factory, signer, store, "1.0.0", func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifest()
	input := DeterministicInput{TenantID: "tenant-1", Manifest: manifest, ModuleSpecRef: manifest.ModuleSpecRef, AllowedPaths: []string{"owned/..."}, RequiredCriteria: []string{"criterion-1"}, PolicyDigest: digestBytes([]byte("policy")), Platform: contracts.PlatformLinux, Isolation: contracts.IsolationContainer, SandboxAttestation: "oci:sha256:container"}
	result, err := pipeline.Run(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != "PASS" || factory.calls != 1 || len(result.Bundle.Checks) != 4 || result.Bundle.Signature == nil {
		t.Fatalf("unexpected audit result: %#v calls=%d", result, factory.calls)
	}
	if CheckOrder(pipeline.checks)[0] != "submission-schema" || result.Bundle.Checks[0].Ordinal != 1 {
		t.Fatalf("fixed order not preserved: %#v", result.Bundle.Checks)
	}
	assertEvidenceSchema(t, result.Bundle)
	stored, found, err := store.Get(context.Background(), input.TenantID, manifest.ProjectID, manifest.ModuleTaskID, manifest.AttemptSeriesID, manifest.Attempt)
	if err != nil || !found || stored.ManifestSHA256 != result.Bundle.ManifestSHA256 {
		t.Fatalf("evidence storage failed: %v %#v", err, stored)
	}
}

func TestPipelineFailsBeforeAuditorOnUnownedPath(t *testing.T) {
	factory := &testAuditorFactory{}
	signer, _ := NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	pipeline, _ := NewPipeline(nil, factory, signer, NewMemoryEvidenceStore(), "1.0.0", nil)
	manifest := testManifest()
	manifest.ChangedFiles = []string{"secret.txt"}
	result, err := pipeline.Run(context.Background(), DeterministicInput{TenantID: "tenant-1", Manifest: manifest, ModuleSpecRef: manifest.ModuleSpecRef, AllowedPaths: []string{"owned/..."}, RequiredCriteria: []string{"criterion-1"}, PolicyDigest: digestBytes([]byte("policy")), Platform: contracts.PlatformLinux, Isolation: contracts.IsolationContainer, SandboxAttestation: "oci:sha256:container"})
	if !errors.Is(err, ErrDeterministicGate) || result.Verdict != "FAIL" || factory.calls != 0 {
		t.Fatalf("deterministic gate bypassed: %v %#v calls=%d", err, result, factory.calls)
	}
}

func TestPipelineFailsClosedWhenCheckOmitsFindings(t *testing.T) {
	factory := &testAuditorFactory{}
	signer, _ := NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	pipeline, _ := NewPipeline([]Check{emptyFindingFailureCheck{}}, factory, signer, NewMemoryEvidenceStore(), "1.0.0", nil)
	manifest := testManifest()
	result, err := pipeline.Run(context.Background(), DeterministicInput{TenantID: "tenant-1", Manifest: manifest, ModuleSpecRef: manifest.ModuleSpecRef, AllowedPaths: []string{"owned/..."}, RequiredCriteria: []string{"criterion-1"}, PolicyDigest: digestBytes([]byte("policy")), Platform: contracts.PlatformLinux, Isolation: contracts.IsolationContainer, SandboxAttestation: "oci:sha256:container"})
	if !errors.Is(err, ErrDeterministicGate) || result.Verdict != "FAIL" || factory.calls != 0 || len(result.Bundle.Findings) != 1 || result.Bundle.Checks[0].Status != "FAIL" {
		t.Fatalf("empty finding bypassed deterministic gate: %v %#v calls=%d", err, result, factory.calls)
	}
}

func TestPipelineEnforcesBlockingFindingAndCriterionGate(t *testing.T) {
	base := LLMAuditResult{
		AuditorRunID: "auditor-run", ModelIdentity: "model/auditor",
		PromptDigest: digestBytes([]byte("prompt")), ContextDigest: digestBytes([]byte("context")), Verdict: "PASS",
		Findings:        []contracts.AuditFinding{},
		CriteriaResults: []contracts.CriterionResult{{CriterionID: "criterion-1", Status: contracts.CriterionPass, EvidenceRefs: []string{}}},
		ResidualRisks:   []string{}, Confidence: 0.9,
	}
	blocking := base
	blocking.Findings = []contracts.AuditFinding{deterministicFinding(contracts.FindingCritical, "SECURITY", "security.boundary", "owned/file.go", "handler/authorize", "missing-authorization", "authorization is checked", "authorization can be bypassed", "restore authorization without broadening access")}
	notTested := base
	notTested.CriteriaResults = []contracts.CriterionResult{{CriterionID: "criterion-1", Status: contracts.CriterionNotTested, EvidenceRefs: []string{}}}

	for name, llm := range map[string]LLMAuditResult{"open-critical": blocking, "criterion-not-tested": notTested} {
		t.Run(name, func(t *testing.T) {
			signer, _ := NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
			pipeline, err := NewPipeline(nil, fixedAuditorFactory{result: llm}, signer, NewMemoryEvidenceStore(), "1.0.0", nil)
			if err != nil {
				t.Fatal(err)
			}
			manifest := testManifest()
			result, err := pipeline.Run(context.Background(), DeterministicInput{TenantID: "tenant-1", Manifest: manifest, ModuleSpecRef: manifest.ModuleSpecRef, AllowedPaths: []string{"owned/..."}, RequiredCriteria: []string{"criterion-1"}, PolicyDigest: digestBytes([]byte("policy")), Platform: contracts.PlatformLinux, Isolation: contracts.IsolationContainer, SandboxAttestation: "oci:sha256:container"})
			if !errors.Is(err, ErrDeterministicGate) || result.Verdict != "FAIL" || result.Bundle.PassesAuditGate() {
				t.Fatalf("structured pass gate was bypassed: result=%#v error=%v", result, err)
			}
		})
	}
}

func TestPersistentPipelineStoresStructuredLLMRun(t *testing.T) {
	signer, _ := NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	finding := deterministicFinding(contracts.FindingMedium, "CORRECTNESS", "criterion.behavior", "owned/file.go", "handler/result", "wrong-result", "the handler returns the accepted result", "the handler returns a stale result", "preserve the approved interface while correcting the result")
	auditor := fixedAuditorFactory{result: LLMAuditResult{
		AuditorRunID: "auditor-run", ModelIdentity: "model/auditor",
		PromptDigest: digestBytes([]byte("prompt")), ContextDigest: digestBytes([]byte("context")), Verdict: "PASS",
		Findings:        []contracts.AuditFinding{finding},
		CriteriaResults: []contracts.CriterionResult{{CriterionID: "criterion-1", Status: contracts.CriterionPass, EvidenceRefs: []string{}}},
		ResidualRisks:   []string{}, Confidence: 0.9,
	}}
	runs := &recordingAuditRunStore{}
	instant := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	pipeline, err := NewPersistentPipeline(nil, auditor, signer, NewMemoryEvidenceStore(), nil, runs, "1.0.0", func() time.Time { return instant })
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifest()
	input := DeterministicInput{TenantID: "tenant-1", AuditRunID: "01936f3e-0000-7000-8000-000000000002", SubmissionID: "11111111-1111-4111-8111-111111111111", Manifest: manifest, ModuleSpecRef: manifest.ModuleSpecRef, AllowedPaths: []string{"owned/..."}, RequiredCriteria: []string{"criterion-1"}, PolicyDigest: digestBytes([]byte("policy")), Platform: contracts.PlatformLinux, Isolation: contracts.IsolationContainer, SandboxAttestation: "oci:sha256:container"}
	result, err := pipeline.Run(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs.runs) != 1 {
		t.Fatalf("stored runs = %d", len(runs.runs))
	}
	run := runs.runs[0]
	if run.ID != input.AuditRunID || run.TenantID != input.TenantID || run.ProjectID != manifest.ProjectID || run.SubmissionID != input.SubmissionID || run.Phase != auditPhaseLLM || run.Verdict != "PASS" || run.EvidenceBundleRef != result.Bundle.ManifestSHA256 || !run.StartedAt.Equal(instant) || !run.CompletedAt.Equal(instant) {
		t.Fatalf("unexpected persisted run: %#v", run)
	}
	if len(run.Findings) != 1 || run.Findings[0].StableFingerprint == "" || run.Findings[0].ObservedBehavior != finding.ObservedBehavior {
		t.Fatalf("structured finding was not persisted: %#v", run.Findings)
	}
}

func TestPersistentPipelineStoresDeterministicFailure(t *testing.T) {
	signer, _ := NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	auditors := &testAuditorFactory{}
	runs := &recordingAuditRunStore{}
	pipeline, err := NewPersistentPipeline(nil, auditors, signer, NewMemoryEvidenceStore(), nil, runs, "1.0.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifest()
	manifest.ChangedFiles = []string{"forbidden/file.go"}
	input := DeterministicInput{TenantID: "tenant-1", AuditRunID: "01936f3e-0000-7000-8000-000000000003", SubmissionID: "11111111-1111-4111-8111-111111111111", Manifest: manifest, ModuleSpecRef: manifest.ModuleSpecRef, AllowedPaths: []string{"owned/..."}, RequiredCriteria: []string{"criterion-1"}, PolicyDigest: digestBytes([]byte("policy")), Platform: contracts.PlatformLinux, Isolation: contracts.IsolationContainer, SandboxAttestation: "oci:sha256:container"}
	if _, err := pipeline.Run(context.Background(), input); !errors.Is(err, ErrDeterministicGate) {
		t.Fatalf("deterministic failure error = %v", err)
	}
	if len(runs.runs) != 1 || runs.runs[0].Phase != auditPhaseDeterministic || runs.runs[0].Verdict != "FAIL" || len(runs.runs[0].Findings) == 0 || auditors.calls != 0 {
		t.Fatalf("unexpected deterministic run: runs=%#v auditorCalls=%d", runs.runs, auditors.calls)
	}
}

func TestPersistentPipelineFailsClosedAfterEvidenceWhenRunStoreFails(t *testing.T) {
	signer, _ := NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	evidence := NewMemoryEvidenceStore()
	persistenceErr := errors.New("audit database unavailable")
	runs := &recordingAuditRunStore{err: persistenceErr}
	pipeline, err := NewPersistentPipeline(nil, &testAuditorFactory{}, signer, evidence, nil, runs, "1.0.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifest()
	input := DeterministicInput{TenantID: "tenant-1", AuditRunID: "01936f3e-0000-7000-8000-000000000004", SubmissionID: "11111111-1111-4111-8111-111111111111", Manifest: manifest, ModuleSpecRef: manifest.ModuleSpecRef, AllowedPaths: []string{"owned/..."}, RequiredCriteria: []string{"criterion-1"}, PolicyDigest: digestBytes([]byte("policy")), Platform: contracts.PlatformLinux, Isolation: contracts.IsolationContainer, SandboxAttestation: "oci:sha256:container"}
	if _, err := pipeline.Run(context.Background(), input); !errors.Is(err, persistenceErr) {
		t.Fatalf("persistence error = %v", err)
	}
	stored, found, err := evidence.Get(context.Background(), input.TenantID, manifest.ProjectID, manifest.ModuleTaskID, manifest.AttemptSeriesID, manifest.Attempt)
	if err != nil || !found || stored.ManifestSHA256 == "" || len(runs.runs) != 1 {
		t.Fatalf("fail-closed ordering was not preserved: found=%t stored=%#v runs=%d err=%v", found, stored, len(runs.runs), err)
	}
}

type emptyFindingFailureCheck struct{}

func (emptyFindingFailureCheck) ID() string { return "empty-finding-failure" }

func (emptyFindingFailureCheck) Run(context.Context, DeterministicInput) CheckResult {
	return CheckResult{Status: StatusFail}
}

func TestBlindInputRejectsExecutorContent(t *testing.T) {
	manifest := testManifest()
	input := BlindAuditInput{ProjectID: manifest.ProjectID, TaskID: manifest.ModuleTaskID, Attempt: 1, ModuleSpecRef: manifest.ModuleSpecRef, BaseCommit: manifest.BaseCommit, SubmissionCommit: manifest.HeadCommit, ChangedFiles: []string{"../executor-statement"}, RequiredCriteria: []string{"criterion-1"}}
	if validateBlindInput(input) == nil {
		t.Fatal("untrusted path accepted as blind context")
	}
}

func TestPipelineStreamsOneGiBArtifactWithoutWholeOutputBuffer(t *testing.T) {
	factory := &testAuditorFactory{}
	signer, err := NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	publisher := &boundedArtifactPublisher{}
	pipeline, err := NewPipelineWithArtifactStore([]Check{largeStreamCheck{}}, factory, signer, NewMemoryEvidenceStore(), publisher, "1.0.0", func() time.Time {
		return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifest()
	result, err := pipeline.Run(context.Background(), DeterministicInput{TenantID: "tenant-1", Manifest: manifest, ModuleSpecRef: manifest.ModuleSpecRef, AllowedPaths: []string{"owned/..."}, RequiredCriteria: []string{"criterion-1"}, PolicyDigest: digestBytes([]byte("policy")), Platform: contracts.PlatformLinux, Isolation: contracts.IsolationContainer, SandboxAttestation: "oci:sha256:container"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != "PASS" || publisher.puts != 3 || publisher.maximumSize != 1<<30 || publisher.maximumWrite > 1<<20 {
		t.Fatalf("streaming bounds were not preserved: verdict=%s puts=%d size=%d write=%d", result.Verdict, publisher.puts, publisher.maximumSize, publisher.maximumWrite)
	}
}

type largeStreamCheck struct{}

func (largeStreamCheck) ID() string { return "large-stream" }

func (largeStreamCheck) Run(context.Context, DeterministicInput) CheckResult {
	return CheckResult{Status: StatusPass, ResultStream: &StreamOutput{MediaType: "application/octet-stream", Write: func(ctx context.Context, destination io.Writer) error {
		chunk := make([]byte, 1<<20)
		var written int64
		for written < 1<<30 {
			if err := ctx.Err(); err != nil {
				return err
			}
			amount, err := destination.Write(chunk)
			if err != nil {
				return err
			}
			if amount != len(chunk) {
				return io.ErrShortWrite
			}
			written += int64(amount)
		}
		return nil
	}}}
}

type boundedArtifactPublisher struct {
	puts         int
	maximumSize  int64
	maximumWrite int
}

func (publisher *boundedArtifactPublisher) Put(ctx context.Context, request artifact.PutRequest, produce func(io.Writer) error) (artifact.Manifest, error) {
	writer := &boundedWriter{}
	if err := produce(writer); err != nil {
		return artifact.Manifest{}, err
	}
	publisher.puts++
	if writer.size > publisher.maximumSize {
		publisher.maximumSize = writer.size
	}
	if writer.maximumWrite > publisher.maximumWrite {
		publisher.maximumWrite = writer.maximumWrite
	}
	digest := digestBytes([]byte(request.ArtifactID))
	return artifact.Manifest{URI: "artifact://sha256/" + digest[len("sha256:"):], SHA256: digest, Size: writer.size}, ctx.Err()
}

type boundedWriter struct {
	size         int64
	maximumWrite int
}

func (writer *boundedWriter) Write(value []byte) (int, error) {
	if len(value) > writer.maximumWrite {
		writer.maximumWrite = len(value)
	}
	writer.size += int64(len(value))
	return len(value), nil
}

func testManifest() contracts.SubmissionManifest {
	return contracts.SubmissionManifest{SubmissionVersion: 1, ProjectID: "project-1", ModuleTaskID: "task-1", AttemptSeriesID: "series-1", Attempt: 1, ModuleSpecRef: contracts.SpecRef{Version: 1, SHA256: digestBytes([]byte("module"))}, BaseCommit: "0000000000000000000000000000000000000001", HeadCommit: "0000000000000000000000000000000000000002", ChangedFiles: []string{"owned/file.go"}, AgentIdentity: contracts.AgentIdentity{AgentInstanceID: "agent-1", Role: "EXECUTOR", LeaseID: "lease-1"}, CreatedAt: "2030-01-01T00:00:00Z", SHA256: digestBytes([]byte("manifest"))}
}

func assertEvidenceSchema(t *testing.T, bundle contracts.EvidenceBundle) {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	for _, name := range []string{"common.v1.schema.json", "evidence-bundle.v1.schema.json"} {
		encoded, err := os.ReadFile("../../api/json-schema/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var document any
		if err := json.Unmarshal(encoded, &document); err != nil {
			t.Fatal(err)
		}
		if err := compiler.AddResource("https://schemas.aor.local/"+name, document); err != nil {
			t.Fatal(err)
		}
	}
	schema, err := compiler.Compile("https://schemas.aor.local/evidence-bundle.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.ValidateEvidenceJSON(encoded); err != nil {
		t.Fatalf("signed evidence failed raw validation: %v", err)
	}
	var instance any
	if err := json.Unmarshal(encoded, &instance); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("signed evidence does not match schema: %v", err)
	}
}
