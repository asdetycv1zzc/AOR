package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

const (
	evidenceContentType = "application/vnd.aor.evidence-bundle.v1+json"
	evidencePrincipal   = "aor-audit-service"
	maxEvidenceBytes    = 4 << 20
)

type evidenceCatalog interface {
	OpenByIdempotencyKey(context.Context, string, string, string) (artifact.Record, io.ReadCloser, error)
}

type ArtifactEvidenceStore struct {
	publisher artifact.Publisher
	catalog   evidenceCatalog
}

func NewArtifactEvidenceStore(publisher artifact.Publisher, catalog evidenceCatalog) (*ArtifactEvidenceStore, error) {
	if publisher == nil || catalog == nil {
		return nil, ErrInvalidInput
	}
	return &ArtifactEvidenceStore{publisher: publisher, catalog: catalog}, nil
}

func (s *ArtifactEvidenceStore) Put(ctx context.Context, tenantID string, bundle contracts.EvidenceBundle) error {
	if ctx == nil || ctx.Err() != nil || tenantID == "" || bundle.AttemptSeriesID == "" {
		return ErrInvalidInput
	}
	encoded, err := json.Marshal(bundle)
	if err != nil || validateEvidenceBytes(encoded, bundle) != nil {
		return ErrInvalidInput
	}

	existing, found, err := s.Get(ctx, tenantID, bundle.ProjectID, bundle.TaskID, bundle.AttemptSeriesID, bundle.Attempt)
	if err != nil {
		return err
	}
	if found {
		if existing.ManifestSHA256 == bundle.ManifestSHA256 {
			return nil
		}
		return ErrEvidenceConflict
	}

	record, err := s.publisher.Publish(ctx, artifact.Publication{
		TenantID:           tenantID,
		ProjectID:          bundle.ProjectID,
		IdempotencyKey:     evidencePublicationKey(bundle.TaskID, bundle.AttemptSeriesID, bundle.Attempt),
		TaskID:             bundle.TaskID,
		CreatedByPrincipal: evidencePrincipal,
		ContentType:        evidenceContentType,
		Metadata: map[string]any{
			"kind":            "evidence-bundle",
			"attemptSeriesId": bundle.AttemptSeriesID,
			"attempt":         bundle.Attempt,
			"manifestSha256":  bundle.ManifestSHA256,
		},
		Data: encoded,
	})
	if err != nil {
		current, found, lookupErr := s.Get(ctx, tenantID, bundle.ProjectID, bundle.TaskID, bundle.AttemptSeriesID, bundle.Attempt)
		if lookupErr == nil && found {
			if current.ManifestSHA256 == bundle.ManifestSHA256 {
				return nil
			}
			return ErrEvidenceConflict
		}
		if errors.Is(err, artifact.ErrConflict) {
			return ErrEvidenceConflict
		}
		return err
	}
	if err := validateEvidenceRecord(record, tenantID, bundle, encoded); err != nil {
		return err
	}
	return nil
}

func (s *ArtifactEvidenceStore) Get(ctx context.Context, tenantID, projectID, taskID, attemptSeriesID string, attempt int) (contracts.EvidenceBundle, bool, error) {
	if ctx == nil || ctx.Err() != nil || tenantID == "" || projectID == "" || taskID == "" || attemptSeriesID == "" || attempt < 1 || attempt > 3 {
		return contracts.EvidenceBundle{}, false, ErrInvalidInput
	}
	record, reader, err := s.catalog.OpenByIdempotencyKey(ctx, tenantID, projectID, evidencePublicationKey(taskID, attemptSeriesID, attempt))
	if errors.Is(err, artifact.ErrNotFound) {
		return contracts.EvidenceBundle{}, false, nil
	}
	if err != nil {
		return contracts.EvidenceBundle{}, false, err
	}
	if reader == nil {
		return contracts.EvidenceBundle{}, false, artifact.ErrIntegrity
	}
	encoded, readErr := io.ReadAll(io.LimitReader(reader, maxEvidenceBytes+1))
	closeErr := reader.Close()
	if readErr != nil {
		return contracts.EvidenceBundle{}, false, readErr
	}
	if len(encoded) > maxEvidenceBytes {
		return contracts.EvidenceBundle{}, false, artifact.ErrIntegrity
	}
	if closeErr != nil {
		return contracts.EvidenceBundle{}, false, closeErr
	}

	var bundle contracts.EvidenceBundle
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return contracts.EvidenceBundle{}, false, artifact.ErrIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return contracts.EvidenceBundle{}, false, artifact.ErrIntegrity
	}
	if bundle.ProjectID != projectID || bundle.TaskID != taskID || bundle.AttemptSeriesID != attemptSeriesID || bundle.Attempt != attempt {
		return contracts.EvidenceBundle{}, false, artifact.ErrIntegrity
	}
	if err := validateEvidenceBytes(encoded, bundle); err != nil {
		return contracts.EvidenceBundle{}, false, artifact.ErrIntegrity
	}
	if err := validateEvidenceRecord(record, tenantID, bundle, encoded); err != nil {
		return contracts.EvidenceBundle{}, false, err
	}
	return bundle, true, nil
}

func evidencePublicationKey(taskID, attemptSeriesID string, attempt int) string {
	return auditPublicationKey("evidence-bundle", taskID, attemptSeriesID, strconv.Itoa(attempt))
}

func validateEvidenceBytes(encoded []byte, bundle contracts.EvidenceBundle) error {
	if len(encoded) > maxEvidenceBytes || !json.Valid(encoded) {
		return artifact.ErrIntegrity
	}
	if err := bundle.Validate(); err != nil {
		return err
	}
	if bundle.Signature == nil || strings.TrimSpace(bundle.Signature.Type) == "" || strings.TrimSpace(bundle.Signature.KID) == "" || strings.TrimSpace(bundle.Signature.JWS) == "" {
		return ErrInvalidInput
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(encoded, "manifestSha256", "signature")
	if err != nil || digest != bundle.ManifestSHA256 {
		return artifact.ErrIntegrity
	}
	return nil
}

func validateEvidenceRecord(record artifact.Record, tenantID string, bundle contracts.EvidenceBundle, encoded []byte) error {
	digest := evidenceBytesDigest(encoded)
	uri, err := artifact.URIFromDigest(digest)
	if err != nil || record.ID == "" || record.TenantID != tenantID || record.ProjectID != bundle.ProjectID || record.URI != uri || record.SHA256 != digest || record.SizeBytes != int64(len(encoded)) || record.ContentType != evidenceContentType || record.CreatedByPrincipal != evidencePrincipal {
		return artifact.ErrIntegrity
	}
	if record.Metadata["kind"] != "evidence-bundle" || record.Metadata["taskId"] != bundle.TaskID || record.Metadata["attemptSeriesId"] != bundle.AttemptSeriesID || record.Metadata["manifestSha256"] != bundle.ManifestSHA256 || !metadataAttemptEquals(record.Metadata["attempt"], bundle.Attempt) {
		return artifact.ErrIntegrity
	}
	return nil
}

func evidenceBytesDigest(encoded []byte) string {
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func metadataAttemptEquals(value any, attempt int) bool {
	switch number := value.(type) {
	case int:
		return number == attempt
	case float64:
		return number == float64(attempt)
	case json.Number:
		parsed, err := number.Int64()
		return err == nil && parsed == int64(attempt)
	default:
		return false
	}
}

var _ EvidenceStore = (*ArtifactEvidenceStore)(nil)
