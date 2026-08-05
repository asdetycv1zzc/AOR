package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"regexp"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
)

const (
	artifactURIPrefix  = "artifact://sha256/"
	defaultCatalogPage = 100
	maxCatalogPage     = 100
	maxMetadataBytes   = 64 << 10
	defaultPurgeLimit  = 100
	maxPurgeLimit      = 1000
)

var uuidValuePattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Record struct {
	ID                 string         `json:"id"`
	TenantID           string         `json:"-"`
	ProjectID          string         `json:"projectId"`
	URI                string         `json:"uri"`
	SHA256             string         `json:"sha256"`
	SizeBytes          int64          `json:"sizeBytes"`
	ContentType        string         `json:"contentType"`
	Classification     string         `json:"classification"`
	CreatedByPrincipal string         `json:"createdByPrincipal"`
	Metadata           map[string]any `json:"metadata"`
	CreatedAt          time.Time      `json:"createdAt"`
	RetentionUntil     *time.Time     `json:"retentionUntil,omitempty"`
}

type Page struct {
	Items      []Record `json:"items"`
	NextCursor string   `json:"nextCursor,omitempty"`
}

type Publication struct {
	TenantID   string
	ProjectID  string
	ArtifactID string
	// IdempotencyKey binds a logical publication to its generated artifact.
	// It is deliberately separate from the artifact primary key so retries do
	// not require a predictable identifier.
	IdempotencyKey     string
	TaskID             string
	CreatedByPrincipal string
	ContentType        string
	Metadata           map[string]any
	RetentionUntil     *time.Time
	Data               []byte
}

type Catalog interface {
	List(context.Context, string, string, string, int) (Page, error)
	Get(context.Context, string, string, string) (Record, error)
	Open(context.Context, string, string, string) (Record, io.ReadCloser, error)
}

type Publisher interface {
	Publish(context.Context, Publication) (Record, error)
}

// ErasureReport is the content-free accounting returned after an idempotent
// project purge. It is intentionally independent of the control API package so
// the storage implementation can be wired without an import cycle.
type ErasureReport struct {
	Scopes       []string
	Records      int64
	Objects      int64
	CacheEntries int64
}

type RetentionReport struct {
	Records int64
	Objects int64
}

type PostgresS3Catalog struct {
	database *sql.DB
	objects  *minio.Client
	bucket   string
	clock    func() time.Time
}

func NewPostgresS3Catalog(database *sql.DB, objects *minio.Client, bucket string, clock func() time.Time) (*PostgresS3Catalog, error) {
	if database == nil || objects == nil || !safeText(bucket, 255) {
		return nil, ErrInvalidRequest
	}
	if clock == nil {
		clock = time.Now
	}
	return &PostgresS3Catalog{database: database, objects: objects, bucket: bucket, clock: clock}, nil
}

func ParseURI(value string) (string, string, error) {
	if len(value) != len(artifactURIPrefix)+64 || !strings.HasPrefix(value, artifactURIPrefix) {
		return "", "", ErrInvalidRequest
	}
	hexDigest := strings.TrimPrefix(value, artifactURIPrefix)
	if strings.Trim(hexDigest, "0123456789abcdef") != "" {
		return "", "", ErrInvalidRequest
	}
	return "sha256:" + hexDigest, "sha256/" + hexDigest, nil
}

func URIFromDigest(digest string) (string, error) {
	if !digestPattern.MatchString(digest) {
		return "", ErrInvalidRequest
	}
	return artifactURIPrefix + strings.TrimPrefix(digest, "sha256:"), nil
}

func projectObjectName(tenantID, projectID, digest string) string {
	return "tenants/" + tenantID + "/projects/" + projectID + "/sha256/" + strings.TrimPrefix(digest, "sha256:")
}

func metadataString(metadata map[string]any, key string) string {
	value, ok := metadata[key].(string)
	if !ok {
		return ""
	}
	return value
}

func (catalog *PostgresS3Catalog) List(ctx context.Context, tenantID, projectID, cursor string, limit int) (Page, error) {
	if catalog == nil || catalog.database == nil || !trustedTenant(ctx, tenantID) || !uuidValuePattern.MatchString(projectID) {
		return Page{}, ErrInvalidRequest
	}
	if limit == 0 {
		limit = defaultCatalogPage
	}
	if limit < 1 || limit > maxCatalogPage {
		return Page{}, ErrInvalidRequest
	}
	after, err := decodeCatalogCursor(projectID, cursor)
	if err != nil {
		return Page{}, err
	}
	tx, err := beginCatalogTx(ctx, catalog.database, tenantID, true)
	if err != nil {
		return Page{}, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
SELECT id::text, tenant_id::text, project_id::text, uri, sha256, size_bytes,
       content_type, classification, created_by_principal, metadata_jsonb,
       created_at, retention_until
FROM artifacts
WHERE tenant_id = $1::uuid AND project_id = $2::uuid
  AND ($3::timestamptz IS NULL OR (created_at, id) > ($3::timestamptz, $4::uuid))
ORDER BY created_at, id
LIMIT $5`, tenantID, projectID, nullableCursorTime(after), nullableCursorID(after), limit+1)
	if err != nil {
		return Page{}, err
	}
	defer rows.Close()
	items := make([]Record, 0, limit+1)
	for rows.Next() {
		record, scanErr := scanRecord(rows)
		if scanErr != nil {
			return Page{}, scanErr
		}
		items = append(items, record)
	}
	if err := rows.Err(); err != nil {
		return Page{}, err
	}
	if err := tx.Commit(); err != nil {
		return Page{}, err
	}
	page := Page{Items: items}
	if len(page.Items) > limit {
		last := page.Items[limit-1]
		page.Items = page.Items[:limit]
		page.NextCursor, err = encodeCatalogCursor(projectID, last.CreatedAt, last.ID)
		if err != nil {
			return Page{}, err
		}
	}
	return page, nil
}

func (catalog *PostgresS3Catalog) Get(ctx context.Context, tenantID, projectID, artifactID string) (Record, error) {
	if catalog == nil || catalog.database == nil || !trustedTenant(ctx, tenantID) || !uuidValuePattern.MatchString(projectID) || !uuidValuePattern.MatchString(artifactID) {
		return Record{}, ErrInvalidRequest
	}
	tx, err := beginCatalogTx(ctx, catalog.database, tenantID, true)
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = tx.Rollback() }()
	record, err := scanRecord(tx.QueryRowContext(ctx, `
SELECT id::text, tenant_id::text, project_id::text, uri, sha256, size_bytes,
       content_type, classification, created_by_principal, metadata_jsonb,
       created_at, retention_until
FROM artifacts
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3::uuid`, tenantID, projectID, artifactID))
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (catalog *PostgresS3Catalog) Open(ctx context.Context, tenantID, projectID, artifactID string) (Record, io.ReadCloser, error) {
	if catalog == nil || catalog.objects == nil {
		return Record{}, nil, ErrInvalidRequest
	}
	record, err := catalog.Get(ctx, tenantID, projectID, artifactID)
	if err != nil {
		return Record{}, nil, err
	}
	return catalog.openRecord(ctx, record)
}

// GetByIdempotencyKey resolves the durable logical publication binding. The
// lookup is tenant and project scoped by both the query and the RLS context.
func (catalog *PostgresS3Catalog) GetByIdempotencyKey(ctx context.Context, tenantID, projectID, key string) (Record, error) {
	if catalog == nil || catalog.database == nil || !trustedTenant(ctx, tenantID) || !uuidValuePattern.MatchString(projectID) || !safeText(key, 256) {
		return Record{}, ErrInvalidRequest
	}
	tx, err := beginCatalogTx(ctx, catalog.database, tenantID, true)
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = tx.Rollback() }()
	record, err := scanRecord(tx.QueryRowContext(ctx, `
SELECT a.id::text, a.tenant_id::text, a.project_id::text, a.uri, a.sha256, a.size_bytes,
       a.content_type, a.classification, a.created_by_principal, a.metadata_jsonb,
       a.created_at, a.retention_until
FROM artifact_publication_keys k
JOIN artifacts a ON a.tenant_id = k.tenant_id AND a.project_id = k.project_id AND a.id = k.artifact_id
WHERE k.tenant_id = $1::uuid AND k.project_id = $2::uuid AND k.idempotency_key = $3`, tenantID, projectID, key))
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return record, nil
}

// OpenByIdempotencyKey resolves and verifies a logically identified artifact.
// This method is intentionally outside Catalog: only workflows that need
// durable idempotency should depend on the additional lookup contract.
func (catalog *PostgresS3Catalog) OpenByIdempotencyKey(ctx context.Context, tenantID, projectID, key string) (Record, io.ReadCloser, error) {
	if catalog == nil || catalog.objects == nil {
		return Record{}, nil, ErrInvalidRequest
	}
	record, err := catalog.GetByIdempotencyKey(ctx, tenantID, projectID, key)
	if err != nil {
		return Record{}, nil, err
	}
	return catalog.openRecord(ctx, record)
}

func (catalog *PostgresS3Catalog) openRecord(ctx context.Context, record Record) (Record, io.ReadCloser, error) {
	digest, _, err := ParseURI(record.URI)
	if err != nil || digest != record.SHA256 {
		return Record{}, nil, ErrIntegrity
	}
	objectName := projectObjectName(record.TenantID, record.ProjectID, digest)
	info, err := catalog.objects.StatObject(ctx, catalog.bucket, objectName, minio.StatObjectOptions{})
	if err != nil {
		if minioObjectMissing(err) {
			// Artifacts created before project-scoped object names are still
			// readable during the expand/migrate window. They are only removed
			// by the eraser when no other catalog row references the digest.
			_, legacyName, parseErr := ParseURI(record.URI)
			if parseErr != nil {
				return Record{}, nil, ErrNotFound
			}
			objectName = legacyName
			info, err = catalog.objects.StatObject(ctx, catalog.bucket, objectName, minio.StatObjectOptions{})
		}
		if err != nil {
			if minioObjectMissing(err) {
				return Record{}, nil, ErrNotFound
			}
			return Record{}, nil, err
		}
	}
	if err := validateObjectInfo(info, record.SHA256, record.SizeBytes); err != nil {
		return Record{}, nil, err
	}
	// Verify before callers commit response headers; the returned stream verifies again against replacement races.
	if err := catalog.verifyObject(ctx, objectName, record.SHA256, record.SizeBytes); err != nil {
		return Record{}, nil, err
	}
	object, err := catalog.objects.GetObject(ctx, catalog.bucket, objectName, minio.GetObjectOptions{})
	if err != nil {
		return Record{}, nil, err
	}
	return record, newVerifyingReader(ctx, object, PublishedObject{URI: record.URI, SHA256: record.SHA256, Size: record.SizeBytes}), nil
}

func (catalog *PostgresS3Catalog) Publish(ctx context.Context, publication Publication) (Record, error) {
	if catalog == nil || catalog.database == nil || catalog.objects == nil || !trustedTenant(ctx, publication.TenantID) || !validPublication(publication) {
		return Record{}, ErrInvalidRequest
	}
	if err := validateContent(publication.Data); err != nil {
		return Record{}, err
	}
	sum := sha256.Sum256(publication.Data)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	uri, _ := URIFromDigest(digest)
	artifactID := publication.ArtifactID
	if artifactID == "" {
		generatedID, generationErr := newArtifactID()
		if generationErr != nil {
			return Record{}, generationErr
		}
		artifactID = generatedID
	}
	if !uuidValuePattern.MatchString(artifactID) {
		return Record{}, ErrInvalidRequest
	}
	publicationKeyID := ""
	if publication.IdempotencyKey != "" {
		generatedKeyID, generationErr := newArtifactID()
		if generationErr != nil {
			return Record{}, generationErr
		}
		publicationKeyID = generatedKeyID
	}
	metadata := cloneMetadataMap(publication.Metadata)
	if metadata == nil {
		return Record{}, ErrInvalidRequest
	}
	if publication.TaskID != "" {
		metadata["taskId"] = publication.TaskID
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil || len(metadataBytes) > maxMetadataBytes {
		return Record{}, ErrInvalidRequest
	}
	now := catalog.clock().UTC()
	retentionUntil := publication.RetentionUntil
	if retentionUntil == nil {
		value := now.AddDate(1, 0, 0)
		retentionUntil = &value
	} else {
		value := retentionUntil.UTC()
		retentionUntil = &value
	}
	if retentionUntil.Before(now) {
		return Record{}, ErrInvalidRequest
	}
	objectName := projectObjectName(publication.TenantID, publication.ProjectID, digest)
	stageName := "staging/" + publication.TenantID + "/" + publication.ProjectID + "/" + uuid.NewString()
	if _, err := catalog.objects.PutObject(ctx, catalog.bucket, stageName, bytes.NewReader(publication.Data), int64(len(publication.Data)), minio.PutObjectOptions{ContentType: publication.ContentType, UserMetadata: map[string]string{"Aor-Sha256": digest}}); err != nil {
		return Record{}, err
	}
	defer catalog.removeStaged(stageName)
	stageInfo, err := catalog.objects.StatObject(ctx, catalog.bucket, stageName, minio.StatObjectOptions{})
	if err != nil {
		return Record{}, err
	}
	if validateObjectInfo(stageInfo, digest, int64(len(publication.Data))) != nil {
		return Record{}, ErrIntegrity
	}
	if err := catalog.verifyObject(ctx, stageName, digest, int64(len(publication.Data))); err != nil {
		return Record{}, err
	}
	tx, err := beginCatalogTx(ctx, catalog.database, publication.TenantID, false)
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var classification string
	var deletionStatus sql.NullString
	var deletionID sql.NullString
	if err := tx.QueryRowContext(ctx, `
SELECT data_classification, deletion_status, deletion_id
FROM projects
WHERE tenant_id = $1::uuid AND id = $2::uuid
FOR UPDATE`, publication.TenantID, publication.ProjectID).Scan(&classification, &deletionStatus, &deletionID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrNotFound
		}
		return Record{}, err
	}
	if deletionStatus.Valid && (deletionStatus.String == "ERASING" || deletionStatus.String == "COMPLETED") {
		proofAllowed := deletionStatus.String == "ERASING" && deletionID.Valid && metadataString(metadata, "kind") == "deletion-proof" && metadataString(metadata, "deletionId") == deletionID.String
		if !proofAllowed {
			return Record{}, ErrConflict
		}
	}
	record := Record{ID: artifactID, TenantID: publication.TenantID, ProjectID: publication.ProjectID, URI: uri, SHA256: digest, SizeBytes: int64(len(publication.Data)), ContentType: publication.ContentType, Classification: classification, CreatedByPrincipal: publication.CreatedByPrincipal, Metadata: metadata, CreatedAt: now, RetentionUntil: retentionUntil}
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	finalInfo, statErr := catalog.objects.StatObject(ctx, catalog.bucket, objectName, minio.StatObjectOptions{})
	createdFinal := false
	if statErr == nil {
		if err := validateObjectInfo(finalInfo, digest, int64(len(publication.Data))); err != nil {
			return Record{}, err
		}
	} else if !minioObjectMissing(statErr) {
		return Record{}, statErr
	} else {
		if _, err := catalog.objects.CopyObject(ctx, minio.CopyDestOptions{Bucket: catalog.bucket, Object: objectName}, minio.CopySrcOptions{Bucket: catalog.bucket, Object: stageName}); err != nil {
			return Record{}, err
		}
		createdFinal = true
		finalInfo, err = catalog.objects.StatObject(ctx, catalog.bucket, objectName, minio.StatObjectOptions{})
		if err != nil {
			return Record{}, err
		}
		if validateObjectInfo(finalInfo, digest, int64(len(publication.Data))) != nil {
			return Record{}, ErrIntegrity
		}
	}
	if createdFinal {
		defer func() {
			// The catalog row is the commit point. If the relational transaction
			// below fails, remove the newly-created object so retries cannot leave
			// an unreferenced scoped blob behind.
			_ = catalog.objects.RemoveObject(context.Background(), catalog.bucket, objectName, minio.RemoveObjectOptions{})
		}()
	}
	if err := catalog.verifyObject(ctx, objectName, digest, int64(len(publication.Data))); err != nil {
		return Record{}, err
	}
	var inserted string
	err = tx.QueryRowContext(ctx, `
INSERT INTO artifacts
  (id, tenant_id, project_id, uri, sha256, size_bytes, content_type,
   classification, created_by_principal, metadata_jsonb, created_at, retention_until)
VALUES
  ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12)
ON CONFLICT (tenant_id, project_id, uri) DO NOTHING
RETURNING id::text`, record.ID, record.TenantID, record.ProjectID, record.URI, record.SHA256,
		record.SizeBytes, record.ContentType, record.Classification, record.CreatedByPrincipal,
		metadataBytes, record.CreatedAt, record.RetentionUntil).Scan(&inserted)
	if errors.Is(err, sql.ErrNoRows) {
		existing, lookupErr := scanRecord(tx.QueryRowContext(ctx, `
SELECT id::text, tenant_id::text, project_id::text, uri, sha256, size_bytes,
       content_type, classification, created_by_principal, metadata_jsonb,
       created_at, retention_until
FROM artifacts
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND uri = $3`, publication.TenantID, publication.ProjectID, uri))
		if lookupErr != nil || !samePublication(existing, record) {
			return Record{}, ErrConflict
		}
		if existing.RetentionUntil != nil && !existing.RetentionUntil.After(now) {
			return Record{}, ErrConflict
		}
		record = existing
	} else if err != nil {
		return Record{}, err
	}
	if publication.IdempotencyKey != "" {
		var boundArtifactID string
		bindErr := tx.QueryRowContext(ctx, `
INSERT INTO artifact_publication_keys
  (id, tenant_id, project_id, idempotency_key, artifact_id, created_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::uuid, $6)
ON CONFLICT (tenant_id, project_id, idempotency_key) DO NOTHING
RETURNING artifact_id::text`, publicationKeyID, publication.TenantID, publication.ProjectID, publication.IdempotencyKey, record.ID, record.CreatedAt).Scan(&boundArtifactID)
		if errors.Is(bindErr, sql.ErrNoRows) {
			mapped, lookupErr := scanRecord(tx.QueryRowContext(ctx, `
SELECT a.id::text, a.tenant_id::text, a.project_id::text, a.uri, a.sha256, a.size_bytes,
       a.content_type, a.classification, a.created_by_principal, a.metadata_jsonb,
       a.created_at, a.retention_until
FROM artifact_publication_keys k
JOIN artifacts a ON a.tenant_id = k.tenant_id AND a.project_id = k.project_id AND a.id = k.artifact_id
WHERE k.tenant_id = $1::uuid AND k.project_id = $2::uuid AND k.idempotency_key = $3`, publication.TenantID, publication.ProjectID, publication.IdempotencyKey))
			if lookupErr != nil || !samePublication(mapped, record) {
				return Record{}, ErrConflict
			}
			record = mapped
		} else if bindErr != nil {
			return Record{}, bindErr
		} else if boundArtifactID != record.ID {
			return Record{}, ErrConflict
		}
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	createdFinal = false
	return record, nil
}

// PurgeExpired removes expired artifacts only after their project is terminal
// and its authoritative projection has no active legal hold. Each object is
// removed while the artifact and project rows are locked; a retry safely
// completes the row deletion when an object was already removed.
func (catalog *PostgresS3Catalog) PurgeExpired(ctx context.Context, limit int) (RetentionReport, error) {
	if catalog == nil || catalog.database == nil || catalog.objects == nil || ctx == nil {
		return RetentionReport{}, ErrInvalidRequest
	}
	if limit == 0 {
		limit = defaultPurgeLimit
	}
	if limit < 1 || limit > maxPurgeLimit {
		return RetentionReport{}, ErrInvalidRequest
	}
	now := catalog.clock().UTC()
	rows, err := catalog.database.QueryContext(ctx, `
SELECT tenant_id::text
FROM aor_expired_artifact_tenants($1, $2)`, now, limit)
	if err != nil {
		return RetentionReport{}, err
	}
	tenants := make([]string, 0, limit)
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			_ = rows.Close()
			return RetentionReport{}, err
		}
		if !uuidValuePattern.MatchString(tenantID) {
			_ = rows.Close()
			return RetentionReport{}, ErrIntegrity
		}
		tenants = append(tenants, tenantID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return RetentionReport{}, err
	}
	_ = rows.Close()

	var report RetentionReport
	for _, tenantID := range tenants {
		remaining := limit - int(report.Records)
		if remaining <= 0 {
			break
		}
		tenantCtx, err := retentionTenantContext(ctx, tenantID)
		if err != nil {
			return report, err
		}
		artifactIDs, err := catalog.expiredArtifactIDs(tenantCtx, tenantID, now, remaining)
		if err != nil {
			return report, err
		}
		for _, artifactID := range artifactIDs {
			objects, removed, err := catalog.purgeExpiredArtifact(tenantCtx, tenantID, artifactID, now)
			if err != nil {
				return report, err
			}
			if removed {
				report.Records++
				report.Objects += objects
			}
		}
	}
	return report, nil
}

func retentionTenantContext(ctx context.Context, tenantID string) (context.Context, error) {
	principal := authn.Principal{
		ID: "service:artifact-retention", Type: authn.PrincipalService,
		Role: authn.RoleService, TenantID: tenantID,
	}
	return authn.ContextWithPrincipal(ctx, principal)
}

func (catalog *PostgresS3Catalog) expiredArtifactIDs(ctx context.Context, tenantID string, now time.Time, limit int) ([]string, error) {
	tx, err := beginCatalogTx(ctx, catalog.database, tenantID, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
SELECT artifacts.id::text
FROM artifacts
JOIN projects
  ON projects.tenant_id = artifacts.tenant_id
 AND projects.id = artifacts.project_id
JOIN aggregate_projections AS projection
  ON projection.tenant_id = projects.tenant_id
 AND projection.project_id = projects.id
 AND projection.aggregate_type = 'project'
 AND projection.aggregate_id = projects.id::text
WHERE artifacts.tenant_id = $1::uuid
  AND artifacts.retention_until IS NOT NULL
  AND artifacts.retention_until <= $2
  AND projects.state IN ('COMPLETED', 'ABORTED', 'ARCHIVED')
  AND projects.deletion_status IS NULL
  AND NOT EXISTS (
    SELECT 1
    FROM jsonb_array_elements(
      CASE
        WHEN jsonb_typeof(projection.state_jsonb -> 'legalHolds') = 'array'
          THEN projection.state_jsonb -> 'legalHolds'
        ELSE '[]'::jsonb
      END
    ) AS legal_hold
    WHERE COALESCE(legal_hold ->> 'releasedAt', '') = ''
  )
ORDER BY artifacts.retention_until, artifacts.id
LIMIT $3`, tenantID, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	artifactIDs := make([]string, 0, limit)
	for rows.Next() {
		var artifactID string
		if err := rows.Scan(&artifactID); err != nil {
			return nil, err
		}
		if !uuidValuePattern.MatchString(artifactID) {
			return nil, ErrIntegrity
		}
		artifactIDs = append(artifactIDs, artifactID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return artifactIDs, nil
}

func (catalog *PostgresS3Catalog) purgeExpiredArtifact(ctx context.Context, tenantID, artifactID string, now time.Time) (int64, bool, error) {
	tx, err := beginCatalogTx(ctx, catalog.database, tenantID, false)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var projectState, deletionStatus string
	var projectVersion int64
	var projectionState []byte
	err = tx.QueryRowContext(ctx, `
SELECT projects.state, projects.state_version, COALESCE(projects.deletion_status, ''),
       projection.state_jsonb
FROM artifacts
JOIN projects
  ON projects.tenant_id = artifacts.tenant_id
 AND projects.id = artifacts.project_id
JOIN aggregate_projections AS projection
  ON projection.tenant_id = projects.tenant_id
 AND projection.project_id = projects.id
 AND projection.aggregate_type = 'project'
 AND projection.aggregate_id = projects.id::text
WHERE artifacts.tenant_id = $1::uuid AND artifacts.id = $2::uuid
FOR UPDATE OF projects, projection`, tenantID, artifactID).Scan(&projectState, &projectVersion, &deletionStatus, &projectionState)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	record, err := scanRecord(tx.QueryRowContext(ctx, `
SELECT id::text, tenant_id::text, project_id::text, uri, sha256, size_bytes,
       content_type, classification, created_by_principal, metadata_jsonb,
       created_at, retention_until
FROM artifacts
WHERE tenant_id = $1::uuid AND id = $2::uuid
FOR UPDATE`, tenantID, artifactID))
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if record.RetentionUntil == nil || record.RetentionUntil.After(now) || !retentionProjectEligible(projectionState, tenantID, record.ProjectID, projectState, projectVersion, deletionStatus) {
		if err := tx.Commit(); err != nil {
			return 0, false, err
		}
		return 0, false, nil
	}

	objects, err := catalog.removeObject(ctx, projectObjectName(tenantID, record.ProjectID, record.SHA256))
	if err != nil {
		return 0, false, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM artifact_publication_keys WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND artifact_id = $3::uuid`, tenantID, record.ProjectID, record.ID); err != nil {
		return 0, false, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM artifacts WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3::uuid`, tenantID, record.ProjectID, record.ID)
	if err != nil {
		return 0, false, err
	}
	removed, err := result.RowsAffected()
	if err != nil || removed != 1 {
		return 0, false, ErrIntegrity
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return objects, true, nil
}

type retentionProjectProjection struct {
	TenantID   string `json:"tenantId"`
	ID         string `json:"id"`
	State      string `json:"state"`
	Version    int64  `json:"version"`
	LegalHolds []struct {
		ReleasedAt *time.Time `json:"releasedAt,omitempty"`
	} `json:"legalHolds,omitempty"`
}

func retentionProjectEligible(content []byte, tenantID, projectID, state string, version int64, deletionStatus string) bool {
	if deletionStatus != "" || state != "COMPLETED" && state != "ABORTED" && state != "ARCHIVED" {
		return false
	}
	var projection retentionProjectProjection
	if json.Unmarshal(content, &projection) != nil || projection.TenantID != tenantID || projection.ID != projectID || projection.State != state || projection.Version != version {
		return false
	}
	for _, hold := range projection.LegalHolds {
		if hold.ReleasedAt == nil {
			return false
		}
	}
	return true
}

// EraseProject performs the durable, resumable portion of project deletion.
// The relational journal is committed before any object is removed, so a
// process or object-store failure can safely retry the same deletion ID.
func (catalog *PostgresS3Catalog) EraseProject(ctx context.Context, tenantID, projectID, deletionID string) (ErasureReport, error) {
	if ctx == nil || catalog == nil || catalog.database == nil || catalog.objects == nil || !trustedTenant(ctx, tenantID) || !uuidValuePattern.MatchString(projectID) || !safeText(deletionID, 256) {
		return ErasureReport{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return ErasureReport{}, err
	}
	if err := catalog.prepareErasure(ctx, tenantID, projectID, deletionID); err != nil {
		return ErasureReport{}, err
	}
	_, err := catalog.removeErasureObjects(ctx, tenantID, projectID, deletionID)
	if err != nil {
		return ErasureReport{}, err
	}
	report, err := catalog.finalizeErasure(ctx, tenantID, projectID, deletionID)
	if err != nil {
		return ErasureReport{}, err
	}
	return report, nil
}

type erasureItem struct {
	ArtifactID       string
	ObjectName       string
	LegacyObjectName sql.NullString
}

func (catalog *PostgresS3Catalog) prepareErasure(ctx context.Context, tenantID, projectID, deletionID string) error {
	tx, err := beginCatalogTx(ctx, catalog.database, tenantID, false)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var status, currentID string
	err = tx.QueryRowContext(ctx, `
SELECT deletion_status, deletion_id
FROM projects
WHERE tenant_id = $1::uuid AND id = $2::uuid
FOR UPDATE`, tenantID, projectID).Scan(&status, &currentID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if status != "ERASING" || currentID != deletionID {
		return ErrConflict
	}
	now := catalog.clock().UTC()
	_, err = tx.ExecContext(ctx, `
INSERT INTO project_erasure_jobs
  (tenant_id, project_id, deletion_id, status, prepared_at)
VALUES ($1::uuid, $2::uuid, $3, 'PREPARED', $4)
ON CONFLICT (tenant_id, project_id) DO NOTHING`, tenantID, projectID, deletionID, now)
	if err != nil {
		return err
	}
	var jobDeletionID, jobStatus string
	if err := tx.QueryRowContext(ctx, `SELECT deletion_id, status FROM project_erasure_jobs WHERE tenant_id = $1::uuid AND project_id = $2::uuid`, tenantID, projectID).Scan(&jobDeletionID, &jobStatus); err != nil {
		return err
	}
	if jobDeletionID != deletionID {
		return ErrConflict
	}
	if jobStatus == "COMPLETE" {
		return tx.Commit()
	}
	rows, err := tx.QueryContext(ctx, `
SELECT id::text, uri, sha256
FROM artifacts
WHERE tenant_id = $1::uuid AND project_id = $2::uuid
ORDER BY id`, tenantID, projectID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var artifactID, uri, digest string
		if err := rows.Scan(&artifactID, &uri, &digest); err != nil {
			return err
		}
		parsedDigest, legacyName, parseErr := ParseURI(uri)
		if parseErr != nil || parsedDigest != digest {
			return ErrIntegrity
		}
		objectName := projectObjectName(tenantID, projectID, digest)
		if _, err := tx.ExecContext(ctx, `
INSERT INTO project_erasure_items
  (tenant_id, project_id, deletion_id, artifact_id, object_name, legacy_object_name)
VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, $6)
ON CONFLICT (tenant_id, project_id, deletion_id, artifact_id) DO NOTHING`, tenantID, projectID, deletionID, artifactID, objectName, legacyName); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO project_key_revocations (tenant_id, project_id, deletion_id, revoked_at, reason)
VALUES ($1::uuid, $2::uuid, $3, $4, 'project deletion')
ON CONFLICT (tenant_id, project_id, deletion_id) DO NOTHING`, tenantID, projectID, deletionID, now)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (catalog *PostgresS3Catalog) removeErasureObjects(ctx context.Context, tenantID, projectID, deletionID string) (int64, error) {
	tx, err := beginCatalogTx(ctx, catalog.database, tenantID, true)
	if err != nil {
		return 0, err
	}
	rows, err := tx.QueryContext(ctx, `
SELECT artifact_id::text, object_name, legacy_object_name
FROM project_erasure_items
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND deletion_id = $3 AND removed_at IS NULL
ORDER BY artifact_id`, tenantID, projectID, deletionID)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	items := make([]erasureItem, 0)
	for rows.Next() {
		var item erasureItem
		if err := rows.Scan(&item.ArtifactID, &item.ObjectName, &item.LegacyObjectName); err != nil {
			_ = rows.Close()
			_ = tx.Rollback()
			return 0, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		_ = tx.Rollback()
		return 0, err
	}
	_ = rows.Close()
	if err := tx.Commit(); err != nil {
		return 0, err
	}

	var removed int64
	for _, item := range items {
		count, err := catalog.removeObject(ctx, item.ObjectName)
		if err != nil {
			return removed, err
		}
		removed += count
		// Legacy keys are global across tenants. Tenant-scoped erasure leaves
		// them intact because removing one can delete another tenant's content.
		markTx, markErr := beginCatalogTx(ctx, catalog.database, tenantID, false)
		if markErr != nil {
			return removed, markErr
		}
		markResult, markErr := markTx.ExecContext(ctx, `
UPDATE project_erasure_items
SET removed_at = transaction_timestamp()
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND deletion_id = $3 AND artifact_id = $4::uuid AND removed_at IS NULL`, tenantID, projectID, deletionID, item.ArtifactID)
		marked := int64(0)
		if markErr == nil {
			marked, markErr = markResult.RowsAffected()
		}
		if markErr == nil && marked == 1 && count > 0 {
			_, markErr = markTx.ExecContext(ctx, `
UPDATE project_erasure_jobs
SET objects_deleted = objects_deleted + $4
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND deletion_id = $3 AND status = 'PREPARED'`, tenantID, projectID, deletionID, count)
		}
		if markErr == nil {
			markErr = markTx.Commit()
		}
		_ = markTx.Rollback()
		if markErr != nil {
			return removed, markErr
		}
	}
	return removed, nil
}

func (catalog *PostgresS3Catalog) removeObject(ctx context.Context, objectName string) (int64, error) {
	info, err := catalog.objects.StatObject(ctx, catalog.bucket, objectName, minio.StatObjectOptions{})
	if err != nil {
		if minioObjectMissing(err) {
			return 0, nil
		}
		return 0, err
	}
	if err := catalog.objects.RemoveObject(ctx, catalog.bucket, objectName, minio.RemoveObjectOptions{}); err != nil && !minioObjectMissing(err) {
		return 0, err
	}
	if info.Size < 0 {
		return 0, ErrIntegrity
	}
	return 1, nil
}

func (catalog *PostgresS3Catalog) finalizeErasure(ctx context.Context, tenantID, projectID, deletionID string) (ErasureReport, error) {
	tx, err := beginCatalogTx(ctx, catalog.database, tenantID, false)
	if err != nil {
		return ErasureReport{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var pending int
	if err := tx.QueryRowContext(ctx, `
SELECT count(*) FROM project_erasure_items
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND deletion_id = $3 AND removed_at IS NULL`, tenantID, projectID, deletionID).Scan(&pending); err != nil {
		return ErasureReport{}, err
	}
	if pending != 0 {
		return ErasureReport{}, ErrConflict
	}
	var jobStatus string
	var persistedRecords, persistedObjects, persistedCache int64
	if err := tx.QueryRowContext(ctx, `SELECT status, records_deleted, objects_deleted, cache_entries_deleted FROM project_erasure_jobs WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND deletion_id = $3 FOR UPDATE`, tenantID, projectID, deletionID).Scan(&jobStatus, &persistedRecords, &persistedObjects, &persistedCache); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErasureReport{}, ErrConflict
		}
		return ErasureReport{}, err
	}
	if jobStatus == "COMPLETE" {
		if err := tx.Commit(); err != nil {
			return ErasureReport{}, err
		}
		return ErasureReport{Scopes: erasureScopes(), Records: persistedRecords, Objects: persistedObjects, CacheEntries: persistedCache}, nil
	}
	var report ErasureReport
	report.Scopes = erasureScopes()
	report.Objects = persistedObjects
	report.CacheEntries = persistedCache
	for _, statement := range []string{
		`DELETE FROM model_call_replays WHERE tenant_id = $1::uuid AND request_id IN (SELECT request_id FROM model_calls WHERE tenant_id = $1::uuid AND project_id = $2::uuid)`,
		`DELETE FROM tool_invocations WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
		`DELETE FROM model_calls WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
		`DELETE FROM agent_leases WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
		`DELETE FROM agent_instances WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
		`DELETE FROM budget_reservations WHERE tenant_id = $1::uuid AND account_id IN (SELECT id FROM budget_accounts WHERE tenant_id = $1::uuid AND scope_type = 'PROJECT' AND scope_id = $2)`,
		`DELETE FROM budget_accounts WHERE tenant_id = $1::uuid AND scope_type = 'PROJECT' AND scope_id = $2`,
		`DELETE FROM artifact_publication_keys WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
		`DELETE FROM artifacts WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
		`DELETE FROM aggregate_projections WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND aggregate_type <> 'project'`,
	} {
		result, execErr := tx.ExecContext(ctx, statement, tenantID, projectID)
		if execErr != nil {
			return ErasureReport{}, fmt.Errorf("erase project records: %w", execErr)
		}
		if affected, rowsErr := result.RowsAffected(); rowsErr == nil {
			report.Records += affected
		}
	}
	_, err = tx.ExecContext(ctx, `
UPDATE project_erasure_jobs
SET status = 'COMPLETE', completed_at = transaction_timestamp(), records_deleted = $4
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND deletion_id = $3`, tenantID, projectID, deletionID, report.Records)
	if err != nil {
		return ErasureReport{}, err
	}
	if err := tx.Commit(); err != nil {
		return ErasureReport{}, err
	}
	return report, nil
}

func erasureScopes() []string {
	return []string{"artifacts", "model-call-replays", "model-calls", "tool-invocations", "agent-leases", "agent-instances", "budget", "projections", "indexes", "cache", "keys"}
}

type rowScanner interface {
	Scan(...any) error
}

func scanRecord(scanner rowScanner) (Record, error) {
	var record Record
	var metadataBytes []byte
	var retention sql.NullTime
	if err := scanner.Scan(&record.ID, &record.TenantID, &record.ProjectID, &record.URI, &record.SHA256, &record.SizeBytes, &record.ContentType, &record.Classification, &record.CreatedByPrincipal, &metadataBytes, &record.CreatedAt, &retention); err != nil {
		return Record{}, err
	}
	if len(metadataBytes) > maxMetadataBytes || json.Unmarshal(metadataBytes, &record.Metadata) != nil || record.Metadata == nil {
		return Record{}, ErrIntegrity
	}
	record.CreatedAt = record.CreatedAt.UTC()
	if retention.Valid {
		value := retention.Time.UTC()
		record.RetentionUntil = &value
	}
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func validateRecord(record Record) error {
	digest, _, err := ParseURI(record.URI)
	if err != nil || digest != record.SHA256 || !uuidValuePattern.MatchString(record.ID) || !uuidValuePattern.MatchString(record.TenantID) || !uuidValuePattern.MatchString(record.ProjectID) || record.SizeBytes < 0 || !safeText(record.CreatedByPrincipal, 256) || record.Metadata == nil || record.CreatedAt.IsZero() {
		return ErrIntegrity
	}
	if !safeText(record.ContentType, 256) {
		return ErrIntegrity
	}
	if _, _, err := mime.ParseMediaType(record.ContentType); err != nil {
		return ErrIntegrity
	}
	if record.Classification != "PUBLIC" && record.Classification != "INTERNAL" && record.Classification != "CONFIDENTIAL" && record.Classification != "RESTRICTED" {
		return ErrIntegrity
	}
	if record.RetentionUntil != nil && record.RetentionUntil.Before(record.CreatedAt) {
		return ErrIntegrity
	}
	return nil
}

func validPublication(publication Publication) bool {
	if !uuidValuePattern.MatchString(publication.TenantID) || !uuidValuePattern.MatchString(publication.ProjectID) || publication.TaskID != "" && !uuidValuePattern.MatchString(publication.TaskID) || publication.IdempotencyKey != "" && !safeText(publication.IdempotencyKey, 256) || !safeText(publication.CreatedByPrincipal, 256) || !safeText(publication.ContentType, 256) || len(publication.Data) > 1<<30 {
		return false
	}
	_, _, err := mime.ParseMediaType(publication.ContentType)
	return err == nil
}

func safeText(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func trustedTenant(ctx context.Context, tenantID string) bool {
	principal, ok := authn.PrincipalFromContext(ctx)
	return ok && principal.TenantID == tenantID && uuidValuePattern.MatchString(tenantID)
}

func beginCatalogTx(ctx context.Context, database *sql.DB, tenantID string, readOnly bool) (*sql.Tx, error) {
	if ctx == nil || database == nil || !trustedTenant(ctx, tenantID) {
		return nil, ErrInvalidRequest
	}
	tx, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: readOnly})
	if err != nil {
		return nil, err
	}
	var superuser, bypassRLS bool
	if err := tx.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS); err != nil || superuser || bypassRLS {
		_ = tx.Rollback()
		return nil, ErrInvalidRequest
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

type catalogCursor struct {
	ProjectID string `json:"p"`
	CreatedAt string `json:"t"`
	ID        string `json:"i"`
}

func encodeCatalogCursor(projectID string, createdAt time.Time, id string) (string, error) {
	if !uuidValuePattern.MatchString(projectID) || !uuidValuePattern.MatchString(id) || createdAt.IsZero() {
		return "", ErrInvalidRequest
	}
	content, err := json.Marshal(catalogCursor{ProjectID: projectID, CreatedAt: createdAt.UTC().Format(time.RFC3339Nano), ID: id})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(content), nil
}

func decodeCatalogCursor(projectID, cursor string) (catalogCursor, error) {
	if cursor == "" {
		return catalogCursor{}, nil
	}
	if len(cursor) > 512 || strings.ContainsAny(cursor, "\r\n\x00") {
		return catalogCursor{}, ErrInvalidRequest
	}
	content, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || len(content) > 512 || base64.RawURLEncoding.EncodeToString(content) != cursor {
		return catalogCursor{}, ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var value catalogCursor
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF || value.ProjectID != projectID || !uuidValuePattern.MatchString(value.ID) {
		return catalogCursor{}, ErrInvalidRequest
	}
	createdAt, err := time.Parse(time.RFC3339Nano, value.CreatedAt)
	if err != nil || createdAt.Location() != time.UTC {
		return catalogCursor{}, ErrInvalidRequest
	}
	value.CreatedAt = createdAt.UTC().Format(time.RFC3339Nano)
	return value, nil
}

func nullableCursorTime(cursor catalogCursor) any {
	if cursor.CreatedAt == "" {
		return nil
	}
	value, _ := time.Parse(time.RFC3339Nano, cursor.CreatedAt)
	return value
}

func nullableCursorID(cursor catalogCursor) any {
	if cursor.ID == "" {
		return nil
	}
	return cursor.ID
}

func validateObjectInfo(info minio.ObjectInfo, digest string, size int64) error {
	if info.Size != size || info.Metadata.Get("X-Amz-Meta-Aor-Sha256") != digest {
		return ErrIntegrity
	}
	return nil
}

func (catalog *PostgresS3Catalog) verifyObject(ctx context.Context, objectName, digest string, size int64) error {
	object, err := catalog.objects.GetObject(ctx, catalog.bucket, objectName, minio.GetObjectOptions{})
	if err != nil {
		if minioObjectMissing(err) {
			return ErrNotFound
		}
		return err
	}
	verified := newVerifyingReader(ctx, object, PublishedObject{URI: artifactURIPrefix + strings.TrimPrefix(digest, "sha256:"), SHA256: digest, Size: size})
	_, copyErr := io.CopyBuffer(io.Discard, verified, make([]byte, verificationBufferBytes))
	closeErr := verified.Close()
	if copyErr != nil {
		if minioObjectMissing(copyErr) {
			return ErrNotFound
		}
		return copyErr
	}
	if closeErr != nil && minioObjectMissing(closeErr) {
		return ErrNotFound
	}
	return closeErr
}

func minioObjectMissing(err error) bool {
	response := minio.ToErrorResponse(err)
	return response.Code == "NoSuchKey" || response.Code == "NoSuchObject" || response.StatusCode == 404
}

func (catalog *PostgresS3Catalog) removeStaged(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = catalog.objects.RemoveObject(ctx, catalog.bucket, name, minio.RemoveObjectOptions{})
}

func newArtifactID() (string, error) {
	value, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return value.String(), nil
}

func cloneMetadataMap(input map[string]any) map[string]any {
	if input == nil {
		return make(map[string]any)
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil
	}
	var output map[string]any
	if json.Unmarshal(encoded, &output) != nil || output == nil {
		return nil
	}
	return output
}

func samePublication(existing, candidate Record) bool {
	return existing.ProjectID == candidate.ProjectID && existing.URI == candidate.URI && existing.SHA256 == candidate.SHA256 && existing.SizeBytes == candidate.SizeBytes && existing.ContentType == candidate.ContentType && existing.Classification == candidate.Classification
}

var _ Catalog = (*PostgresS3Catalog)(nil)
var _ Publisher = (*PostgresS3Catalog)(nil)
