package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

type ArtifactModuleSpecs struct {
	store goalplan.ArtifactStore
}

func NewArtifactModuleSpecs(store goalplan.ArtifactStore) (*ArtifactModuleSpecs, error) {
	if store == nil {
		return nil, ErrExecutionUnavailable
	}
	return &ArtifactModuleSpecs{store: store}, nil
}

func (source *ArtifactModuleSpecs) ModuleSpec(ctx context.Context, tenantID, projectID, moduleID string, ref contracts.SpecRef) (contracts.ModuleSpec, error) {
	if source == nil || source.store == nil || ctx == nil || ctx.Err() != nil || !validID(tenantID) || !validID(projectID) || !validID(moduleID) || ref.Validate() != nil {
		return contracts.ModuleSpec{}, ErrInvalidRequest
	}
	artifact, found, err := source.store.Get(ctx, tenantID, projectID, goalplan.ArtifactModuleSpec, moduleID, ref.Version)
	if err != nil {
		return contracts.ModuleSpec{}, err
	}
	if !found || artifact.TenantID != tenantID || artifact.ProjectID != projectID || artifact.Kind != goalplan.ArtifactModuleSpec || artifact.SpecID != moduleID || artifact.Version != ref.Version || artifact.ContentSHA256 != ref.SHA256 || contracts.ValidateModuleJSON(artifact.Content) != nil {
		return contracts.ModuleSpec{}, ErrTaskNotReady
	}
	var module contracts.ModuleSpec
	decoder := json.NewDecoder(bytes.NewReader(artifact.Content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&module) != nil {
		return contracts.ModuleSpec{}, ErrTaskNotReady
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return contracts.ModuleSpec{}, ErrTaskNotReady
	}
	encoded, err := json.Marshal(module)
	if err != nil {
		return contracts.ModuleSpec{}, ErrTaskNotReady
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(encoded, "sha256", "signature")
	if err != nil || module.Validate() != nil || module.ProjectID != projectID || module.ModuleID != moduleID || module.ModuleSpecVersion != ref.Version || module.SHA256 != ref.SHA256 || digest != ref.SHA256 {
		return contracts.ModuleSpec{}, ErrTaskNotReady
	}
	return module, nil
}

type VerifiedSubmissions struct {
	store  repository.SubmissionStore
	signer repository.Signer
}

func NewVerifiedSubmissions(store repository.SubmissionStore, signer repository.Signer) (*VerifiedSubmissions, error) {
	if store == nil || signer == nil {
		return nil, ErrExecutionUnavailable
	}
	return &VerifiedSubmissions{store: store, signer: signer}, nil
}

func (source *VerifiedSubmissions) Submission(ctx context.Context, tenantID, taskID, attemptSeriesID string, attempt int) (repository.Submission, bool, error) {
	if source == nil || source.store == nil || source.signer == nil || ctx == nil || ctx.Err() != nil || !validID(tenantID) || !validID(taskID) || !validID(attemptSeriesID) || attempt < 1 || attempt > 3 {
		return repository.Submission{}, false, ErrInvalidRequest
	}
	submission, found, err := source.store.Get(ctx, tenantID, taskID, attemptSeriesID, attempt)
	if err != nil || !found {
		return repository.Submission{}, found, err
	}
	if repository.VerifySubmission(ctx, submission, source.signer) != nil {
		return repository.Submission{}, false, ErrSubmissionInvalid
	}
	return submission, true, nil
}

var _ ModuleSpecSource = (*ArtifactModuleSpecs)(nil)
var _ SubmissionSource = (*VerifiedSubmissions)(nil)
