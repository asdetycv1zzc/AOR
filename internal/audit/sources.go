package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/sandbox"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/google/uuid"
)

type RuntimeFacts struct {
	PolicyDigest       string
	Platform           contracts.ExecutionPlatform
	Isolation          contracts.IsolationLevel
	SandboxAttestation string
}

type InputRequest struct {
	AuditRunID string
	SandboxID  string
	Project    state.Project
	Task       state.ModuleTask
	Pinned     *RuntimeFacts
}

type PreparedInput struct {
	Input       DeterministicInput
	Facts       RuntimeFacts
	InputSHA256 string
}

type InputSource interface {
	Load(context.Context, InputRequest) (PreparedInput, error)
}

type SandboxFactsRequest struct {
	SandboxID string
	Project   state.Project
	Task      state.ModuleTask
	Module    contracts.ModuleSpec
}

type SandboxFactsSource interface {
	Facts(context.Context, SandboxFactsRequest) (RuntimeFacts, error)
}

// SnapshotSandboxFacts obtains the attestation from the clean Auditor sandbox
// rather than accepting a caller-supplied platform or isolation claim.
type SnapshotSandboxFacts struct {
	provider sandbox.SandboxProvider
}

func NewSnapshotSandboxFacts(provider sandbox.SandboxProvider) (*SnapshotSandboxFacts, error) {
	if provider == nil {
		return nil, ErrAuditServiceUnavailable
	}
	return &SnapshotSandboxFacts{provider: provider}, nil
}

func (source *SnapshotSandboxFacts) Facts(ctx context.Context, request SandboxFactsRequest) (RuntimeFacts, error) {
	if source == nil || source.provider == nil || ctx == nil || ctx.Err() != nil ||
		!validCoordinatorID(request.SandboxID) || request.Module.Validate() != nil ||
		request.Module.ProjectID != request.Project.ID || request.Module.ModuleID != request.Task.ModuleID {
		return RuntimeFacts{}, ErrInvalidAuditRequest
	}
	snapshot, err := source.provider.Snapshot(ctx, request.SandboxID)
	if err != nil {
		return RuntimeFacts{}, err
	}
	if string(snapshot.IsolationLevel) != string(request.Module.SandboxLevel) {
		return RuntimeFacts{}, ErrAuditFactsInvalid
	}
	facts := RuntimeFacts{Platform: request.Module.ExecutionPlatform, Isolation: request.Module.SandboxLevel}
	switch request.Module.ExecutionPlatform {
	case contracts.PlatformLinux:
		if !validLinuxAttestation(snapshot.Attestation) {
			return RuntimeFacts{}, ErrAuditFactsInvalid
		}
		encoded, err := json.Marshal(struct {
			SandboxID   string                 `json:"sandboxId"`
			Snapshot    string                 `json:"snapshotSha256"`
			Isolation   sandbox.IsolationLevel `json:"isolation"`
			Attestation sandbox.Attestation    `json:"attestation"`
		}{request.SandboxID, snapshot.SHA256, snapshot.IsolationLevel, snapshot.Attestation})
		if err != nil {
			return RuntimeFacts{}, err
		}
		digest, err := canonicaljson.Digest(encoded)
		if err != nil {
			return RuntimeFacts{}, err
		}
		facts.SandboxAttestation = "oci:" + digest
	case contracts.PlatformWindows:
		if snapshot.Attestation.Runtime != "native-process" || strings.TrimSpace(snapshot.Attestation.RiskDisclosure) == "" {
			return RuntimeFacts{}, ErrAuditFactsInvalid
		}
		facts.SandboxAttestation = "windows:none"
	default:
		return RuntimeFacts{}, ErrAuditFactsInvalid
	}
	return facts, nil
}

// AuthoritativeInputSource verifies the immutable repository Submission and
// ModuleSpec, resolves the active policy digest, and obtains sandbox facts from
// a trusted provider before constructing DeterministicInput.
type AuthoritativeInputSource struct {
	submissions repository.SubmissionStore
	signer      repository.Signer
	artifacts   goalplan.ArtifactStore
	policy      authz.PolicyEvaluator
	principal   authn.Principal
	sandboxes   SandboxFactsSource
}

func NewAuthoritativeInputSource(submissions repository.SubmissionStore, signer repository.Signer, artifacts goalplan.ArtifactStore, policy authz.PolicyEvaluator, principal authn.Principal, sandboxes SandboxFactsSource) (*AuthoritativeInputSource, error) {
	if submissions == nil || signer == nil || artifacts == nil || policy == nil || sandboxes == nil || !validAuditServicePrincipal(principal) {
		return nil, ErrAuditServiceUnavailable
	}
	return &AuthoritativeInputSource{
		submissions: submissions, signer: signer, artifacts: artifacts,
		policy: policy, principal: cloneAuditPrincipal(principal), sandboxes: sandboxes,
	}, nil
}

func NewSnapshotAuthoritativeInputSource(submissions repository.SubmissionStore, signer repository.Signer, artifacts goalplan.ArtifactStore, policy authz.PolicyEvaluator, principal authn.Principal, provider sandbox.SandboxProvider) (*AuthoritativeInputSource, error) {
	sandboxes, err := NewSnapshotSandboxFacts(provider)
	if err != nil {
		return nil, err
	}
	return NewAuthoritativeInputSource(submissions, signer, artifacts, policy, principal, sandboxes)
}

func (source *AuthoritativeInputSource) Load(ctx context.Context, request InputRequest) (PreparedInput, error) {
	if source == nil || source.submissions == nil || source.signer == nil || source.artifacts == nil ||
		source.policy == nil || source.sandboxes == nil || ctx == nil || ctx.Err() != nil ||
		!validAuditRunID(request.AuditRunID) || request.Project.TenantID == "" || request.Project.ID == "" ||
		request.Task.TenantID != request.Project.TenantID || request.Task.ProjectID != request.Project.ID ||
		request.Task.ID == "" || request.Task.ModuleID == "" || request.Task.Attempt < 1 || request.Task.Attempt > 3 ||
		request.Task.AttemptSeriesID == "" || request.Task.ModuleSpecRef.Validate() != nil || request.Project.Plan == nil {
		return PreparedInput{}, ErrInvalidAuditRequest
	}
	submission, found, err := source.submissions.Get(ctx, request.Task.TenantID, request.Task.ID, request.Task.AttemptSeriesID, request.Task.Attempt)
	if err != nil {
		return PreparedInput{}, err
	}
	if !found || repository.VerifySubmission(ctx, submission, source.signer) != nil || !submissionMatchesTask(submission, request.Task) {
		return PreparedInput{}, ErrSubmissionNotAuditable
	}
	module, err := source.moduleSpec(ctx, request.Project, request.Task)
	if err != nil {
		return PreparedInput{}, err
	}
	policyDigest, err := source.policyDigest(ctx, request.Project, request.Task)
	if err != nil {
		return PreparedInput{}, err
	}
	var facts RuntimeFacts
	if request.Pinned == nil {
		facts, err = source.sandboxes.Facts(ctx, SandboxFactsRequest{
			SandboxID: request.SandboxID, Project: request.Project, Task: request.Task, Module: module,
		})
		if err != nil {
			return PreparedInput{}, err
		}
		facts.PolicyDigest = policyDigest
	} else {
		facts = *request.Pinned
		if facts.PolicyDigest != policyDigest {
			return PreparedInput{}, ErrAuditPolicyChanged
		}
	}
	if !validRuntimeFacts(facts, module) {
		return PreparedInput{}, ErrAuditFactsInvalid
	}
	input := DeterministicInput{
		TenantID: request.Task.TenantID, AuditRunID: request.AuditRunID,
		SubmissionID: submission.ID, Manifest: submission.Manifest,
		ModuleSpecRef:    request.Task.ModuleSpecRef,
		AllowedPaths:     append([]string(nil), module.AllowedPaths...),
		ForbiddenPaths:   append([]string(nil), module.ForbiddenPaths...),
		RequiredCriteria: append([]string(nil), module.AcceptanceCriteria...),
		PolicyDigest:     facts.PolicyDigest, Platform: facts.Platform, Isolation: facts.Isolation,
		SandboxAttestation: facts.SandboxAttestation,
	}
	if validateInput(input) != nil {
		return PreparedInput{}, ErrAuditFactsInvalid
	}
	digest, err := deterministicInputDigest(input)
	if err != nil {
		return PreparedInput{}, err
	}
	return PreparedInput{Input: input, Facts: facts, InputSHA256: digest}, nil
}

func (source *AuthoritativeInputSource) moduleSpec(ctx context.Context, project state.Project, task state.ModuleTask) (contracts.ModuleSpec, error) {
	artifact, found, err := source.artifacts.Get(ctx, task.TenantID, task.ProjectID, goalplan.ArtifactModuleSpec, task.ModuleID, task.ModuleSpecRef.Version)
	if err != nil {
		return contracts.ModuleSpec{}, err
	}
	if !found || artifact.TenantID != task.TenantID || artifact.ProjectID != task.ProjectID ||
		artifact.Kind != goalplan.ArtifactModuleSpec || artifact.SpecID != task.ModuleID ||
		artifact.Version != task.ModuleSpecRef.Version || artifact.ContentSHA256 != task.ModuleSpecRef.SHA256 ||
		contracts.ValidateModuleJSON(artifact.Content) != nil {
		return contracts.ModuleSpec{}, ErrModuleSpecNotAuditable
	}
	var module contracts.ModuleSpec
	decoder := json.NewDecoder(bytes.NewReader(artifact.Content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&module) != nil {
		return contracts.ModuleSpec{}, ErrModuleSpecNotAuditable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return contracts.ModuleSpec{}, ErrModuleSpecNotAuditable
	}
	encoded, err := json.Marshal(module)
	if err != nil {
		return contracts.ModuleSpec{}, ErrModuleSpecNotAuditable
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(encoded, "sha256", "signature")
	if err != nil || module.Validate() != nil || module.ProjectID != project.ID || module.ModuleID != task.ModuleID ||
		module.ModuleSpecVersion != task.ModuleSpecRef.Version || module.PlanVersion != project.Plan.Version ||
		module.SHA256 != task.ModuleSpecRef.SHA256 || digest != task.ModuleSpecRef.SHA256 {
		return contracts.ModuleSpec{}, ErrModuleSpecNotAuditable
	}
	return module, nil
}

func (source *AuthoritativeInputSource) policyDigest(ctx context.Context, project state.Project, task state.ModuleTask) (string, error) {
	principal := cloneAuditPrincipal(source.principal)
	if principal.TenantID != "" && principal.TenantID != project.TenantID || principal.ProjectID != "" && principal.ProjectID != project.ID {
		return "", ErrAuditAuthorization
	}
	principal.TenantID = project.TenantID
	principal.ProjectID = project.ID
	decision, err := source.policy.Evaluate(ctx, authz.PolicyInput{
		Principal: principal,
		Project: authz.ProjectScope{
			TenantID: project.TenantID, ID: project.ID, State: string(project.State),
			StateVersion: project.Version, Classification: auditClassification(project.DataClassification),
		},
		Task: authz.TaskScope{
			TenantID: task.TenantID, ProjectID: task.ProjectID, ID: task.ID,
			State: string(task.State), StateVersion: task.Version, SpecDigest: task.ModuleSpecRef.SHA256,
		},
		Action: authz.ActionTaskRead, Resource: authz.Resource{Type: "task", ID: task.ID},
		Budget: authz.BudgetScope{AccountID: "audit-control-plane", Available: true},
	})
	if err != nil || !decision.Decision.Allowed() || !digestPattern.MatchString(decision.PolicyVersion) {
		return "", ErrAuditAuthorization
	}
	return decision.PolicyVersion, nil
}

func submissionMatchesTask(submission repository.Submission, task state.ModuleTask) bool {
	manifest := submission.Manifest
	workspace := submission.Workspace
	parsedID, err := uuid.Parse(submission.ID)
	return err == nil && parsedID != uuid.Nil && parsedID.Version() == uuid.Version(7) && parsedID.String() == submission.ID &&
		manifest.ProjectID == task.ProjectID && manifest.ModuleTaskID == task.ID &&
		manifest.AttemptSeriesID == task.AttemptSeriesID && manifest.Attempt == task.Attempt &&
		manifest.ModuleSpecRef == task.ModuleSpecRef && workspace.TenantID == task.TenantID &&
		workspace.ProjectID == task.ProjectID && workspace.TaskID == task.ID &&
		workspace.AttemptSeriesID == task.AttemptSeriesID && workspace.Attempt == task.Attempt &&
		workspace.ModuleSpecRef == task.ModuleSpecRef
}

func validRuntimeFacts(facts RuntimeFacts, module contracts.ModuleSpec) bool {
	if !digestPattern.MatchString(facts.PolicyDigest) || facts.Platform != module.ExecutionPlatform || facts.Isolation != module.SandboxLevel {
		return false
	}
	return facts.Platform == contracts.PlatformLinux && strings.HasPrefix(facts.SandboxAttestation, "oci:sha256:") ||
		facts.Platform == contracts.PlatformWindows && facts.SandboxAttestation == "windows:none"
}

func validLinuxAttestation(attestation sandbox.Attestation) bool {
	return digestPattern.MatchString(attestation.SecurityProfileSHA256) && digestPattern.MatchString(attestation.ImageDigest) &&
		attestation.Runtime != "" && attestation.NonRoot && (attestation.Rootless || attestation.UserNamespace) &&
		attestation.ReadOnlyRootFS && attestation.CapabilitiesDropped && attestation.SeccompEnabled &&
		attestation.MandatoryPolicy && attestation.CgroupsV2 && attestation.Tmpfs && attestation.WorkdirReadWrite &&
		!attestation.HostDevices && !attestation.HostPID && !attestation.HostNetwork && !attestation.Privileged && !attestation.RuntimeSocket
}

func deterministicInputDigest(input DeterministicInput) (string, error) {
	encoded, err := json.Marshal(struct {
		TenantID           string                       `json:"tenantId"`
		AuditRunID         string                       `json:"auditRunId"`
		SubmissionID       string                       `json:"submissionId"`
		Manifest           contracts.SubmissionManifest `json:"manifest"`
		ModuleSpecRef      contracts.SpecRef            `json:"moduleSpecRef"`
		AllowedPaths       []string                     `json:"allowedPaths"`
		ForbiddenPaths     []string                     `json:"forbiddenPaths"`
		RequiredCriteria   []string                     `json:"requiredCriteria"`
		PolicyDigest       string                       `json:"policyDigest"`
		Platform           contracts.ExecutionPlatform  `json:"platform"`
		Isolation          contracts.IsolationLevel     `json:"isolation"`
		SandboxAttestation string                       `json:"sandboxAttestation"`
	}{
		input.TenantID, input.AuditRunID, input.SubmissionID, input.Manifest, input.ModuleSpecRef,
		input.AllowedPaths, input.ForbiddenPaths, input.RequiredCriteria, input.PolicyDigest,
		input.Platform, input.Isolation, input.SandboxAttestation,
	})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

var _ InputSource = (*AuthoritativeInputSource)(nil)
var _ SandboxFactsSource = (*SnapshotSandboxFacts)(nil)
