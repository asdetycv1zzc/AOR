package artifact

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
)

const MaxUserUploadBytes = int64(4 << 30)

type UserUpload struct {
	TenantID           string
	ProjectID          string
	IdempotencyKey     string
	CreatedByPrincipal string
	ContentType        string
	Metadata           map[string]any
	Body               io.Reader
	SizeBytes          int64
}

type UserUploadPublisher interface {
	PublishUserUpload(context.Context, UserUpload) (Record, error)
}

// PublishUserUpload streams an authenticated human upload into immutable,
// project-scoped artifact storage. Authorization is performed by the control
// API before this storage commit; this method rechecks the current project row
// and binds the catalog write and idempotency key under tenant RLS.
func (catalog *PostgresS3Catalog) PublishUserUpload(ctx context.Context, upload UserUpload) (Record, error) {
	if catalog == nil || catalog.database == nil || catalog.objects == nil || upload.Body == nil ||
		!trustedTenant(ctx, upload.TenantID) || !validUserUpload(upload) {
		return Record{}, ErrInvalidRequest
	}
	stageName := "staging/" + upload.TenantID + "/" + upload.ProjectID + "/" + uuid.NewString()
	hasher := sha256.New()
	reader := io.TeeReader(io.LimitReader(upload.Body, MaxUserUploadBytes+1), hasher)
	info, err := catalog.objects.PutObject(ctx, catalog.bucket, stageName, reader, upload.SizeBytes, minio.PutObjectOptions{
		ContentType: upload.ContentType,
		PartSize:    64 << 20,
	})
	if err != nil {
		return Record{}, err
	}
	defer catalog.removeStaged(stageName)
	if info.Size <= 0 || info.Size > MaxUserUploadBytes || upload.SizeBytes >= 0 && info.Size != upload.SizeBytes {
		return Record{}, ErrInvalidRequest
	}
	digest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	uri, err := URIFromDigest(digest)
	if err != nil {
		return Record{}, err
	}
	stageInfo, err := catalog.objects.StatObject(ctx, catalog.bucket, stageName, minio.StatObjectOptions{})
	if err != nil || stageInfo.Size != info.Size {
		if err != nil {
			return Record{}, err
		}
		return Record{}, ErrIntegrity
	}
	if err := catalog.verifyUploadedStage(ctx, stageName, digest, info.Size); err != nil {
		return Record{}, err
	}

	metadata := cloneMetadataMap(upload.Metadata)
	metadataBytes, err := json.Marshal(metadata)
	if err != nil || metadata == nil || len(metadataBytes) > maxMetadataBytes || validateContent(metadataBytes) != nil {
		return Record{}, ErrInvalidRequest
	}
	artifactID, err := newArtifactID()
	if err != nil {
		return Record{}, err
	}
	publicationKeyID, err := newArtifactID()
	if err != nil {
		return Record{}, err
	}

	tx, err := beginCatalogTx(ctx, catalog.database, upload.TenantID, false)
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var projectState, classification, deletionStatus string
	var projectVersion int64
	if err := tx.QueryRowContext(ctx, `
SELECT state, state_version, data_classification, COALESCE(deletion_status, '')
FROM projects
WHERE tenant_id = $1::uuid AND id = $2::uuid
FOR UPDATE`, upload.TenantID, upload.ProjectID).Scan(&projectState, &projectVersion, &classification, &deletionStatus); errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	} else if err != nil {
		return Record{}, err
	}
	if projectState != "GOAL_NEGOTIATING" && projectState != "GOAL_SUSPENDED" || deletionStatus != "" {
		return Record{}, ErrConflict
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return Record{}, err
	}
	now = now.UTC()
	retentionUntil := now.AddDate(1, 0, 0)
	record := Record{
		ID: artifactID, TenantID: upload.TenantID, ProjectID: upload.ProjectID,
		URI: uri, SHA256: digest, SizeBytes: info.Size, ContentType: upload.ContentType,
		Classification: classification, CreatedByPrincipal: upload.CreatedByPrincipal,
		Metadata: metadata, CreatedAt: now, RetentionUntil: &retentionUntil,
	}
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}

	objectName := projectObjectName(upload.TenantID, upload.ProjectID, digest)
	finalInfo, statErr := catalog.objects.StatObject(ctx, catalog.bucket, objectName, minio.StatObjectOptions{})
	createdFinal := false
	if statErr == nil {
		if finalInfo.Size != info.Size || finalInfo.Metadata.Get("X-Amz-Meta-Aor-Sha256") != digest {
			return Record{}, ErrIntegrity
		}
	} else if !minioObjectMissing(statErr) {
		return Record{}, statErr
	} else {
		_, err = catalog.objects.CopyObject(ctx, minio.CopyDestOptions{
			Bucket: catalog.bucket, Object: objectName, ContentType: upload.ContentType,
			ReplaceMetadata: true, UserMetadata: map[string]string{"Aor-Sha256": digest},
		}, minio.CopySrcOptions{Bucket: catalog.bucket, Object: stageName})
		if err != nil {
			return Record{}, err
		}
		createdFinal = true
	}
	if createdFinal {
		defer func() {
			if createdFinal {
				_ = catalog.objects.RemoveObject(context.Background(), catalog.bucket, objectName, minio.RemoveObjectOptions{})
			}
		}()
	}
	if err := catalog.verifyObject(ctx, objectName, digest, info.Size); err != nil {
		return Record{}, err
	}

	var insertedID string
	err = tx.QueryRowContext(ctx, `
INSERT INTO artifacts
  (id, tenant_id, project_id, uri, sha256, size_bytes, content_type,
   classification, created_by_principal, metadata_jsonb, created_at, retention_until)
VALUES
  ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12)
ON CONFLICT (tenant_id, project_id, uri) DO NOTHING
RETURNING id::text`, record.ID, record.TenantID, record.ProjectID, record.URI, record.SHA256,
		record.SizeBytes, record.ContentType, record.Classification, record.CreatedByPrincipal,
		metadataBytes, record.CreatedAt, record.RetentionUntil).Scan(&insertedID)
	if errors.Is(err, sql.ErrNoRows) {
		existing, lookupErr := scanRecord(tx.QueryRowContext(ctx, `
SELECT id::text, tenant_id::text, project_id::text, uri, sha256, size_bytes,
       content_type, classification, created_by_principal, metadata_jsonb,
       created_at, retention_until
FROM artifacts
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND uri = $3`, upload.TenantID, upload.ProjectID, uri))
		if lookupErr != nil || !samePublication(existing, record) || !userUploadMatches(existing, upload) {
			return Record{}, ErrConflict
		}
		record = existing
	} else if err != nil {
		return Record{}, err
	}

	var boundArtifactID string
	err = tx.QueryRowContext(ctx, `
INSERT INTO artifact_publication_keys
  (id, tenant_id, project_id, idempotency_key, artifact_id, created_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::uuid, $6)
ON CONFLICT (tenant_id, project_id, idempotency_key) DO NOTHING
RETURNING artifact_id::text`, publicationKeyID, upload.TenantID, upload.ProjectID, upload.IdempotencyKey, record.ID, record.CreatedAt).Scan(&boundArtifactID)
	if errors.Is(err, sql.ErrNoRows) {
		mapped, lookupErr := scanRecord(tx.QueryRowContext(ctx, `
SELECT a.id::text, a.tenant_id::text, a.project_id::text, a.uri, a.sha256, a.size_bytes,
       a.content_type, a.classification, a.created_by_principal, a.metadata_jsonb,
       a.created_at, a.retention_until
FROM artifact_publication_keys k
JOIN artifacts a ON a.tenant_id = k.tenant_id AND a.project_id = k.project_id AND a.id = k.artifact_id
WHERE k.tenant_id = $1::uuid AND k.project_id = $2::uuid AND k.idempotency_key = $3`, upload.TenantID, upload.ProjectID, upload.IdempotencyKey))
		if lookupErr != nil || mapped.URI != record.URI || mapped.SHA256 != record.SHA256 || !userUploadMatches(mapped, upload) {
			return Record{}, ErrConflict
		}
		record = mapped
	} else if err != nil || boundArtifactID != record.ID {
		return Record{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	createdFinal = false
	return record, nil
}

func validUserUpload(upload UserUpload) bool {
	if !uuidValuePattern.MatchString(upload.TenantID) || !uuidValuePattern.MatchString(upload.ProjectID) ||
		!safeText(upload.IdempotencyKey, 256) || !safeText(upload.CreatedByPrincipal, 256) ||
		!safeText(upload.ContentType, 256) || upload.SizeBytes == 0 || upload.SizeBytes > MaxUserUploadBytes ||
		upload.SizeBytes < -1 || upload.Metadata == nil {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(upload.ContentType)
	if err != nil {
		return false
	}
	switch mediaType {
	case "application/gzip", "application/x-gzip", "application/x-tar", "application/x-xz", "application/zip", "application/x-7z-compressed":
		return true
	default:
		return false
	}
}

func userUploadMatches(record Record, upload UserUpload) bool {
	return record.ProjectID == upload.ProjectID && record.ContentType == upload.ContentType &&
		record.CreatedByPrincipal == upload.CreatedByPrincipal && metadataString(record.Metadata, "kind") == metadataString(upload.Metadata, "kind") &&
		metadataString(record.Metadata, "toolName") == metadataString(upload.Metadata, "toolName") &&
		metadataString(record.Metadata, "toolVersion") == metadataString(upload.Metadata, "toolVersion") &&
		metadataString(record.Metadata, "architecture") == metadataString(upload.Metadata, "architecture") &&
		(upload.SizeBytes < 0 || record.SizeBytes == upload.SizeBytes) && strings.HasPrefix(record.URI, artifactURIPrefix)
}

func (catalog *PostgresS3Catalog) verifyUploadedStage(ctx context.Context, objectName, digest string, size int64) error {
	object, err := catalog.objects.GetObject(ctx, catalog.bucket, objectName, minio.GetObjectOptions{})
	if err != nil {
		return err
	}
	hasher := sha256.New()
	written, copyErr := io.CopyBuffer(hasher, io.LimitReader(object, size+1), make([]byte, verificationBufferBytes))
	closeErr := object.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	actual := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if written != size || actual != digest {
		return ErrIntegrity
	}
	return nil
}

var _ UserUploadPublisher = (*PostgresS3Catalog)(nil)
