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
	TenantID           string
	ProjectID          string
	ArtifactID         string
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
	digest, objectName, err := ParseURI(record.URI)
	if err != nil || digest != record.SHA256 {
		return Record{}, nil, ErrIntegrity
	}
	info, err := catalog.objects.StatObject(ctx, catalog.bucket, objectName, minio.StatObjectOptions{})
	if err != nil {
		if minioObjectMissing(err) {
			return Record{}, nil, ErrNotFound
		}
		return Record{}, nil, err
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
	sum := sha256.Sum256(publication.Data)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	uri, _ := URIFromDigest(digest)
	artifactID := publication.ArtifactID
	if artifactID == "" {
		artifactID = deterministicArtifactID(publication.TenantID, publication.ProjectID, uri)
	}
	if !uuidValuePattern.MatchString(artifactID) {
		return Record{}, ErrInvalidRequest
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
	objectName := "sha256/" + strings.TrimPrefix(digest, "sha256:")
	stageName := "staging/" + uuid.NewString()
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
	finalInfo, statErr := catalog.objects.StatObject(ctx, catalog.bucket, objectName, minio.StatObjectOptions{})
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
		finalInfo, err = catalog.objects.StatObject(ctx, catalog.bucket, objectName, minio.StatObjectOptions{})
		if err != nil {
			return Record{}, err
		}
		if validateObjectInfo(finalInfo, digest, int64(len(publication.Data))) != nil {
			return Record{}, ErrIntegrity
		}
	}
	if err := catalog.verifyObject(ctx, objectName, digest, int64(len(publication.Data))); err != nil {
		return Record{}, err
	}
	tx, err := beginCatalogTx(ctx, catalog.database, publication.TenantID, false)
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var classification string
	if err := tx.QueryRowContext(ctx, `SELECT data_classification FROM projects WHERE tenant_id = $1::uuid AND id = $2::uuid`, publication.TenantID, publication.ProjectID).Scan(&classification); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrNotFound
		}
		return Record{}, err
	}
	record := Record{ID: artifactID, TenantID: publication.TenantID, ProjectID: publication.ProjectID, URI: uri, SHA256: digest, SizeBytes: int64(len(publication.Data)), ContentType: publication.ContentType, Classification: classification, CreatedByPrincipal: publication.CreatedByPrincipal, Metadata: metadata, CreatedAt: now, RetentionUntil: retentionUntil}
	if err := validateRecord(record); err != nil {
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
		record = existing
	} else if err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return record, nil
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
	if !uuidValuePattern.MatchString(publication.TenantID) || !uuidValuePattern.MatchString(publication.ProjectID) || publication.TaskID != "" && !uuidValuePattern.MatchString(publication.TaskID) || !safeText(publication.CreatedByPrincipal, 256) || !safeText(publication.ContentType, 256) || len(publication.Data) > 1<<30 {
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

func deterministicArtifactID(tenantID, projectID, uri string) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + projectID + "\x00" + uri))
	bytes := append([]byte(nil), sum[:16]...)
	bytes[6] = bytes[6]&0x0f | 0x50
	bytes[8] = bytes[8]&0x3f | 0x80
	value, _ := uuid.FromBytes(bytes)
	return value.String()
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
