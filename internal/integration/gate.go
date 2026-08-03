package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"sort"

	"github.com/akimisaka/aor/internal/audit"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

type ProjectFacts struct {
	TenantID      string
	ProjectID     string
	IntegrationID string
	BaseCommit    string
	PolicyDigest  string
	StateVersion  int64
}

type ProjectFactsSource interface {
	Current(context.Context, string, string, string) (ProjectFacts, error)
}

type TaskSource interface {
	Current(context.Context, string, string, string) (state.ModuleTask, error)
}

type SubmissionSource interface {
	Current(context.Context, state.ModuleTask) (repository.Submission, error)
}

type EvidenceRecord struct {
	SHA256           string
	ProjectID        string
	TaskID           string
	AttemptSeriesID  string
	Attempt          int
	ModuleSpecRef    contracts.SpecRef
	BaseCommit       string
	SubmissionCommit string
	PolicyDigest     string
	Passed           bool
}

type EvidenceSource interface {
	Verified(context.Context, state.ModuleTask, repository.Submission, string) (EvidenceRecord, error)
}

type ModuleRecord struct {
	ModuleID         string
	Ref              contracts.SpecRef
	OwnedPaths       []string
	PublicInterfaces []string
}

type ModuleSource interface {
	Current(context.Context, string, string, string, contracts.SpecRef) (ModuleRecord, error)
}

type AuthorizationRequest struct {
	TenantID        string
	ProjectID       string
	IntegrationID   string
	PrincipalID     string
	LeaseID         string
	FencingToken    int64
	PolicyDigest    string
	ExpectedVersion int64
	BaseCommit      string
	Candidates      []Candidate
}

type IntegrationAuthorizer interface {
	Authorize(context.Context, AuthorizationRequest) (string, error)
}

type AuthoritativeGate struct {
	projects    ProjectFactsSource
	tasks       TaskSource
	submissions SubmissionSource
	evidence    EvidenceSource
	modules     ModuleSource
	authorizer  IntegrationAuthorizer
}

func NewAuthoritativeGate(projects ProjectFactsSource, tasks TaskSource, submissions SubmissionSource, evidence EvidenceSource, modules ModuleSource, authorizer IntegrationAuthorizer) (*AuthoritativeGate, error) {
	if projects == nil || tasks == nil || submissions == nil || evidence == nil || modules == nil || authorizer == nil {
		return nil, ErrInvalidRequest
	}
	return &AuthoritativeGate{projects: projects, tasks: tasks, submissions: submissions, evidence: evidence, modules: modules, authorizer: authorizer}, nil
}

func (g *AuthoritativeGate) Validate(ctx context.Context, request Request) (VerifiedRequest, error) {
	if g == nil || ctx == nil {
		return VerifiedRequest{}, ErrNotAudited
	}
	facts, err := g.projects.Current(ctx, request.TenantID, request.ProjectID, request.IntegrationID)
	if err != nil || facts.TenantID != request.TenantID || facts.ProjectID != request.ProjectID || facts.IntegrationID != request.IntegrationID || facts.BaseCommit != request.BaseCommit || facts.PolicyDigest != request.PolicyDigest || facts.StateVersion != request.ExpectedVersion {
		return VerifiedRequest{}, ErrNotAudited
	}
	candidates := make([]Candidate, 0, len(request.Candidates))
	for _, untrusted := range canonicalCandidates(request.Candidates) {
		if !untrusted.AuditPassed {
			return VerifiedRequest{}, ErrNotAudited
		}
		task, err := g.tasks.Current(ctx, request.TenantID, request.ProjectID, untrusted.TaskID)
		if err != nil || task.TenantID != request.TenantID || task.ProjectID != request.ProjectID || task.ID != untrusted.TaskID || task.State != contracts.TaskPassed || task.ModuleSpecRef != untrusted.ModuleSpecRef || task.Attempt < 1 || task.Attempt > 3 || task.AttemptSeriesID == "" {
			return VerifiedRequest{}, ErrNotAudited
		}
		submission, err := g.submissions.Current(ctx, task)
		if err != nil || submission.Manifest.ProjectID != request.ProjectID || submission.Manifest.ModuleTaskID != task.ID || submission.Manifest.AttemptSeriesID != task.AttemptSeriesID || submission.Manifest.Attempt != task.Attempt || submission.Manifest.ModuleSpecRef != task.ModuleSpecRef || submission.Manifest.HeadCommit != untrusted.SubmissionCommit || submission.Manifest.BaseCommit != request.BaseCommit || submission.Manifest.Validate() != nil {
			return VerifiedRequest{}, ErrNotAudited
		}
		record, err := g.evidence.Verified(ctx, task, submission, untrusted.EvidenceSHA256)
		if err != nil || !record.Passed || record.SHA256 != untrusted.EvidenceSHA256 || record.ProjectID != request.ProjectID || record.TaskID != task.ID || record.AttemptSeriesID != task.AttemptSeriesID || record.Attempt != task.Attempt || record.ModuleSpecRef != task.ModuleSpecRef || record.BaseCommit != request.BaseCommit || record.SubmissionCommit != submission.Manifest.HeadCommit || record.PolicyDigest != request.PolicyDigest {
			return VerifiedRequest{}, ErrNotAudited
		}
		module, err := g.modules.Current(ctx, request.TenantID, request.ProjectID, untrusted.ModuleID, task.ModuleSpecRef)
		if err != nil || module.ModuleID != untrusted.ModuleID || module.Ref != task.ModuleSpecRef || !slices.Equal(module.OwnedPaths, untrusted.OwnedPaths) || !slices.Equal(module.PublicInterfaces, untrusted.PublicInterfaces) {
			return VerifiedRequest{}, ErrNotAudited
		}
		candidates = append(candidates, Candidate{TaskID: task.ID, ModuleID: module.ModuleID, SubmissionCommit: submission.Manifest.HeadCommit, ModuleSpecRef: task.ModuleSpecRef, OwnedPaths: append([]string(nil), module.OwnedPaths...), PublicInterfaces: append([]string(nil), module.PublicInterfaces...), EvidenceSHA256: record.SHA256, AuditPassed: true})
	}
	candidates = canonicalCandidates(candidates)
	authorization, err := g.authorizer.Authorize(ctx, AuthorizationRequest{TenantID: request.TenantID, ProjectID: request.ProjectID, IntegrationID: request.IntegrationID, PrincipalID: request.PrincipalID, LeaseID: request.LeaseID, FencingToken: request.FencingToken, PolicyDigest: facts.PolicyDigest, ExpectedVersion: facts.StateVersion, BaseCommit: facts.BaseCommit, Candidates: cloneCandidates(candidates)})
	if err != nil || !digestPattern(authorization) {
		return VerifiedRequest{}, ErrNotAudited
	}
	return VerifiedRequest{TenantID: facts.TenantID, ProjectID: facts.ProjectID, IntegrationID: facts.IntegrationID, BaseCommit: facts.BaseCommit, Candidates: candidates, PolicyDigest: facts.PolicyDigest, ExpectedVersion: facts.StateVersion, PrincipalID: request.PrincipalID, LeaseID: request.LeaseID, FencingToken: request.FencingToken, Authorization: authorization}, nil
}

type EventTaskSource struct {
	Store eventing.Store
}

func (s EventTaskSource) Current(ctx context.Context, tenantID, projectID, taskID string) (state.ModuleTask, error) {
	if s.Store == nil {
		return state.ModuleTask{}, ErrNotAudited
	}
	projection, found, err := s.Store.Load(ctx, tenantID, "task", taskID)
	if err != nil || !found {
		return state.ModuleTask{}, ErrNotAudited
	}
	var task state.ModuleTask
	if err := json.Unmarshal(projection.State, &task); err != nil || task.TenantID != tenantID || task.ProjectID != projectID || task.ID != taskID || task.Version != projection.Version {
		return state.ModuleTask{}, ErrNotAudited
	}
	return task, nil
}

type RepositorySubmissionSource struct {
	Store repository.SubmissionStore
}

func (s RepositorySubmissionSource) Current(ctx context.Context, task state.ModuleTask) (repository.Submission, error) {
	if s.Store == nil {
		return repository.Submission{}, ErrNotAudited
	}
	submission, found, err := s.Store.Get(ctx, task.TenantID, task.ID, task.AttemptSeriesID, task.Attempt)
	if err != nil || !found {
		return repository.Submission{}, ErrNotAudited
	}
	return submission, nil
}

type SignedEvidenceSource struct {
	Store  audit.EvidenceStore
	Signer audit.Signer
}

func (s SignedEvidenceSource) Verified(ctx context.Context, task state.ModuleTask, submission repository.Submission, expectedSHA string) (EvidenceRecord, error) {
	if s.Store == nil || s.Signer == nil || !digestPattern(expectedSHA) {
		return EvidenceRecord{}, ErrNotAudited
	}
	bundle, found, err := s.Store.Get(ctx, task.ProjectID, task.ID, task.AttemptSeriesID, task.Attempt)
	if err != nil || !found || bundle.Validate() != nil || bundle.ManifestSHA256 != expectedSHA || bundle.Signature == nil {
		return EvidenceRecord{}, ErrNotAudited
	}
	signature := bundle.Signature
	bundle.Signature = nil
	payload, err := json.Marshal(bundle)
	if err != nil || s.Signer.Verify(ctx, payload, signature) != nil {
		return EvidenceRecord{}, ErrNotAudited
	}
	digest := bundle.ManifestSHA256
	bundle.ManifestSHA256 = ""
	encoded, err := json.Marshal(bundle)
	computed, digestErr := canonicaljson.DigestObjectWithoutFields(encoded, "manifestSha256", "signature")
	if err != nil || digestErr != nil || computed != digest {
		return EvidenceRecord{}, ErrNotAudited
	}
	passed := bundle.LLMAudit.Verdict == "PASS" && len(bundle.Findings) == 0 && len(bundle.Checks) > 0
	for _, check := range bundle.Checks {
		if check.Status != "PASS" {
			passed = false
		}
	}
	return EvidenceRecord{SHA256: digest, ProjectID: bundle.ProjectID, TaskID: bundle.TaskID, AttemptSeriesID: bundle.AttemptSeriesID, Attempt: bundle.Attempt, ModuleSpecRef: submission.Manifest.ModuleSpecRef, BaseCommit: bundle.BaseCommit, SubmissionCommit: bundle.SubmissionCommit, PolicyDigest: bundle.PolicyBundleDigest, Passed: passed}, nil
}

type ArtifactModuleSource struct {
	Store goalplan.ArtifactStore
}

func (s ArtifactModuleSource) Current(ctx context.Context, tenantID, projectID, moduleID string, ref contracts.SpecRef) (ModuleRecord, error) {
	if s.Store == nil || ref.Validate() != nil {
		return ModuleRecord{}, ErrNotAudited
	}
	artifact, found, err := s.Store.Get(ctx, tenantID, projectID, goalplan.ArtifactModuleSpec, moduleID, ref.Version)
	if err != nil || !found || artifact.ContentSHA256 != ref.SHA256 {
		return ModuleRecord{}, ErrNotAudited
	}
	var module contracts.ModuleSpec
	decoder := json.NewDecoder(bytes.NewReader(artifact.Content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&module); err != nil || !decodeAtEOF(decoder) || module.Validate() != nil || module.ModuleID != moduleID || module.ProjectID != projectID || module.ModuleSpecVersion != ref.Version || module.SHA256 != ref.SHA256 {
		return ModuleRecord{}, ErrNotAudited
	}
	owned := append([]string(nil), module.AllowedPaths...)
	interfaces := append([]string(nil), module.Interfaces...)
	sort.Strings(owned)
	sort.Strings(interfaces)
	return ModuleRecord{ModuleID: module.ModuleID, Ref: ref, OwnedPaths: owned, PublicInterfaces: interfaces}, nil
}

func decodeAtEOF(decoder *json.Decoder) bool {
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}
