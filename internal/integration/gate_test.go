package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
)

type gateProjectSource struct{ facts ProjectFacts }

func (s gateProjectSource) Current(context.Context, string, string, string) (ProjectFacts, error) {
	return s.facts, nil
}

type gateTaskSource struct{ task state.ModuleTask }

func (s gateTaskSource) Current(context.Context, string, string, string) (state.ModuleTask, error) {
	return s.task, nil
}

type gateSubmissionSource struct{ submission repository.Submission }

func (s gateSubmissionSource) Current(context.Context, state.ModuleTask) (repository.Submission, error) {
	return s.submission, nil
}

type gateEvidenceSource struct{ evidence EvidenceRecord }

func (s gateEvidenceSource) Verified(context.Context, state.ModuleTask, repository.Submission, string) (EvidenceRecord, error) {
	return s.evidence, nil
}

type gateModuleSource struct{ module ModuleRecord }

func (s gateModuleSource) Current(context.Context, string, string, string, contracts.SpecRef) (ModuleRecord, error) {
	return s.module, nil
}

type gateAuthorizer struct{}

func (gateAuthorizer) Authorize(context.Context, AuthorizationRequest) (string, error) {
	return digest("authorization"), nil
}

type gateRepositorySigner struct{ reject bool }

func (signer gateRepositorySigner) Sign(context.Context, []byte) (*contracts.Signature, error) {
	return nil, errors.New("not implemented")
}

func (signer gateRepositorySigner) Verify(context.Context, []byte, *contracts.Signature) error {
	if signer.reject {
		return errors.New("invalid signature")
	}
	return nil
}

func TestAuthoritativeGateRejectsCallerSuppliedAuditFacts(t *testing.T) {
	ref := contracts.SpecRef{Version: 1, SHA256: digest("module")}
	task := state.ModuleTask{TenantID: "tenant-1", ProjectID: "project-1", ID: "task-1", State: contracts.TaskPassed, Version: 4, ModuleSpecRef: ref, AttemptSeriesID: "series-1", Attempt: 1}
	manifest := contracts.SubmissionManifest{SubmissionVersion: 1, ProjectID: "project-1", ModuleTaskID: "task-1", AttemptSeriesID: "series-1", Attempt: 1, ModuleSpecRef: ref, BaseCommit: commit(1), HeadCommit: commit(3), AgentIdentity: contracts.AgentIdentity{AgentInstanceID: "agent-1", Role: "EXECUTOR", LeaseID: "lease-1"}, CreatedAt: time.Now().UTC().Format(time.RFC3339), SHA256: digest("manifest")}
	gate, err := NewAuthoritativeGate(gateProjectSource{facts: ProjectFacts{TenantID: "tenant-1", ProjectID: "project-1", IntegrationID: "integration-1", BaseCommit: commit(1), PolicyDigest: digest("policy"), StateVersion: 7}}, gateTaskSource{task: task}, gateSubmissionSource{submission: repository.Submission{Manifest: manifest}}, gateEvidenceSource{evidence: EvidenceRecord{SHA256: digest("evidence"), ProjectID: "project-1", TaskID: "task-1", AttemptSeriesID: "series-1", Attempt: 1, ModuleSpecRef: ref, BaseCommit: commit(1), SubmissionCommit: commit(3), PolicyDigest: digest("policy"), Passed: true}}, gateModuleSource{module: ModuleRecord{ModuleID: "module-1", Ref: ref, OwnedPaths: []string{"owned/..."}, PublicInterfaces: []string{"HTTP /v1"}}}, gateAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	request := Request{TenantID: "tenant-1", ProjectID: "project-1", IntegrationID: "integration-1", IdempotencyKey: "merge-1", BaseCommit: commit(1), PolicyDigest: digest("policy"), ExpectedVersion: 7, CreatedAt: time.Now().UTC(), PrincipalID: "service-1", LeaseID: "lease-1", FencingToken: 1, Candidates: []Candidate{{TaskID: "task-1", ModuleID: "module-1", SubmissionCommit: commit(3), ModuleSpecRef: ref, OwnedPaths: []string{"owned/..."}, PublicInterfaces: []string{"HTTP /v1"}, EvidenceSHA256: digest("evidence"), AuditPassed: true}}}
	verified, err := gate.Validate(context.Background(), request)
	if err != nil || len(verified.Candidates) != 1 {
		t.Fatalf("verified request = %#v error=%v", verified, err)
	}
	request.Candidates[0].AuditPassed = false
	if _, err := gate.Validate(context.Background(), request); err == nil {
		t.Fatal("caller-supplied failed audit fact was accepted")
	}
}

func TestAuthoritativeGateRejectsNonPassedTask(t *testing.T) {
	ref := contracts.SpecRef{Version: 1, SHA256: digest("module")}
	gate, err := NewAuthoritativeGate(gateProjectSource{facts: ProjectFacts{TenantID: "tenant-1", ProjectID: "project-1", IntegrationID: "integration-1", BaseCommit: commit(1), PolicyDigest: digest("policy"), StateVersion: 7}}, gateTaskSource{task: state.ModuleTask{TenantID: "tenant-1", ProjectID: "project-1", ID: "task-1", State: contracts.TaskSubmitted, Version: 4, ModuleSpecRef: ref, AttemptSeriesID: "series-1", Attempt: 1}}, gateSubmissionSource{}, gateEvidenceSource{}, gateModuleSource{}, gateAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	request := Request{TenantID: "tenant-1", ProjectID: "project-1", IntegrationID: "integration-1", IdempotencyKey: "merge-1", BaseCommit: commit(1), PolicyDigest: digest("policy"), ExpectedVersion: 7, CreatedAt: time.Now().UTC(), PrincipalID: "service-1", LeaseID: "lease-1", FencingToken: 1, Candidates: []Candidate{{TaskID: "task-1", ModuleID: "module-1", SubmissionCommit: commit(3), ModuleSpecRef: ref, OwnedPaths: []string{"owned/..."}, EvidenceSHA256: digest("evidence"), AuditPassed: true}}}
	if _, err := gate.Validate(context.Background(), request); err == nil {
		t.Fatal("non-passed task was accepted for merge")
	}
}

func TestRepositorySubmissionSourceVerifiesServiceSignature(t *testing.T) {
	ref := contracts.SpecRef{Version: 1, SHA256: digest("module")}
	identity := contracts.AgentIdentity{AgentInstanceID: "agent-1", Role: "EXECUTOR", LeaseID: "lease-1"}
	manifest := contracts.SubmissionManifest{SubmissionVersion: 1, ProjectID: "project-1", ModuleTaskID: "task-1", AttemptSeriesID: "series-1", Attempt: 1, ModuleSpecRef: ref, BaseCommit: commit(1), HeadCommit: commit(2), AgentIdentity: identity, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	manifest.SHA256, _ = repository.DigestManifest(manifest)
	manifest.Signature = &contracts.Signature{Type: "TEST", KID: "repository-test", JWS: "signed"}
	submission := repository.Submission{
		Manifest:       manifest,
		Workspace:      repository.Workspace{TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", Attempt: 1, AttemptSeriesID: "series-1", BaseCommit: commit(1), ModuleSpecRef: ref, AgentIdentity: identity},
		IdempotencyKey: "submission-1",
		RequestSHA256:  digest("request"),
	}
	store := repository.NewMemorySubmissionStore()
	if err := store.Put(context.Background(), submission); err != nil {
		t.Fatal(err)
	}
	task := state.ModuleTask{TenantID: "tenant-1", ProjectID: "project-1", ID: "task-1", AttemptSeriesID: "series-1", Attempt: 1}
	if _, err := (RepositorySubmissionSource{Store: store, Signer: gateRepositorySigner{}}).Current(context.Background(), task); err != nil {
		t.Fatalf("valid signed submission rejected: %v", err)
	}
	if _, err := (RepositorySubmissionSource{Store: store, Signer: gateRepositorySigner{reject: true}}).Current(context.Background(), task); !errors.Is(err, ErrNotAudited) {
		t.Fatalf("invalid signature error = %v", err)
	}
}
