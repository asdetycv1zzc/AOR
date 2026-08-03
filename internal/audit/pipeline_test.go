package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
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
	if input.ProjectID == "" || len(input.ChangedFiles) != 1 {
		return LLMAuditResult{}, ErrBlindContext
	}
	return LLMAuditResult{AuditorRunID: a.run, ModelIdentity: "model/auditor", PromptDigest: digestBytes([]byte("prompt")), ContextDigest: digestBytes([]byte("context")), Verdict: "PASS"}, nil
}

func TestPipelineRunsFixedOrderAndCreatesSignedEvidence(t *testing.T) {
	factory := &testAuditorFactory{}
	signer, err := NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryEvidenceStore()
	pipeline, err := NewPipeline(nil, factory, signer, store, "pipeline-1", func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifest()
	result, err := pipeline.Run(context.Background(), DeterministicInput{Manifest: manifest, ModuleSpecRef: manifest.ModuleSpecRef, AllowedPaths: []string{"owned/..."}, PolicyDigest: digestBytes([]byte("policy")), Platform: contracts.PlatformLinux, Isolation: contracts.IsolationContainer, SandboxAttestation: "oci:sha256:container"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != "PASS" || factory.calls != 1 || len(result.Bundle.Checks) != 4 || result.Bundle.Signature == nil {
		t.Fatalf("unexpected audit result: %#v calls=%d", result, factory.calls)
	}
	if CheckOrder(pipeline.checks)[0] != "submission-schema" || result.Bundle.Checks[0].Ordinal != 1 {
		t.Fatalf("fixed order not preserved: %#v", result.Bundle.Checks)
	}
	stored, found, err := store.Get(context.Background(), manifest.ProjectID, manifest.ModuleTaskID, manifest.Attempt)
	if err != nil || !found || stored.ManifestSHA256 != result.Bundle.ManifestSHA256 {
		t.Fatalf("evidence storage failed: %v %#v", err, stored)
	}
}

func TestPipelineFailsBeforeAuditorOnUnownedPath(t *testing.T) {
	factory := &testAuditorFactory{}
	signer, _ := NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	pipeline, _ := NewPipeline(nil, factory, signer, NewMemoryEvidenceStore(), "pipeline-1", nil)
	manifest := testManifest()
	manifest.ChangedFiles = []string{"secret.txt"}
	result, err := pipeline.Run(context.Background(), DeterministicInput{Manifest: manifest, ModuleSpecRef: manifest.ModuleSpecRef, AllowedPaths: []string{"owned/..."}, PolicyDigest: digestBytes([]byte("policy")), Platform: contracts.PlatformLinux, Isolation: contracts.IsolationContainer, SandboxAttestation: "oci:sha256:container"})
	if !errors.Is(err, ErrDeterministicGate) || result.Verdict != "FAIL" || factory.calls != 0 {
		t.Fatalf("deterministic gate bypassed: %v %#v calls=%d", err, result, factory.calls)
	}
}

func TestBlindInputRejectsExecutorContent(t *testing.T) {
	manifest := testManifest()
	input := BlindAuditInput{ProjectID: manifest.ProjectID, TaskID: manifest.ModuleTaskID, Attempt: 1, ModuleSpecRef: manifest.ModuleSpecRef, BaseCommit: manifest.BaseCommit, SubmissionCommit: manifest.HeadCommit, ChangedFiles: []string{"../executor-statement"}}
	if validateBlindInput(input) == nil {
		t.Fatal("untrusted path accepted as blind context")
	}
}

func testManifest() contracts.SubmissionManifest {
	return contracts.SubmissionManifest{SubmissionVersion: 1, ProjectID: "project-1", ModuleTaskID: "task-1", AttemptSeriesID: "series-1", Attempt: 1, ModuleSpecRef: contracts.SpecRef{Version: 1, SHA256: digestBytes([]byte("module"))}, BaseCommit: "0000000000000000000000000000000000000001", HeadCommit: "0000000000000000000000000000000000000002", ChangedFiles: []string{"owned/file.go"}, AgentIdentity: contracts.AgentIdentity{AgentInstanceID: "agent-1", Role: "EXECUTOR", LeaseID: "lease-1"}, CreatedAt: "2030-01-01T00:00:00Z", SHA256: digestBytes([]byte("manifest"))}
}
