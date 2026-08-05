package globalaudit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/google/uuid"
)

const (
	globalAuditContentType = "application/vnd.aor.global-audit-report+json"
	maximumReportBytes     = 8 << 20
)

type ArtifactCatalog interface {
	Publish(context.Context, artifact.Publication) (artifact.Record, error)
	Open(context.Context, string, string, string) (artifact.Record, io.ReadCloser, error)
}

type Store interface {
	Put(context.Context, Report) (string, error)
	Get(context.Context, string, string) (Report, bool, error)
}

type PostgresStore struct {
	database  *sql.DB
	artifacts ArtifactCatalog
	signer    Signer
}

func NewPostgresStore(database *sql.DB, artifacts ArtifactCatalog, signer Signer) (*PostgresStore, error) {
	if database == nil || artifacts == nil || signer == nil {
		return nil, ErrStore
	}
	return &PostgresStore{database: database, artifacts: artifacts, signer: signer}, nil
}

func (store *PostgresStore) Put(ctx context.Context, report Report) (string, error) {
	if store == nil || store.database == nil || store.artifacts == nil || store.signer == nil || !tenantBound(ctx, report.TenantID) {
		return "", ErrStore
	}
	if err := Verify(ctx, report, store.signer); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) > maximumReportBytes {
		return "", ErrInvalidReport
	}
	retentionUntil := report.CompletedAt.AddDate(2, 0, 0)
	record, err := store.artifacts.Publish(ctx, artifact.Publication{
		TenantID: report.TenantID, ProjectID: report.ProjectID, ArtifactID: report.RunID,
		CreatedByPrincipal: "aor-global-audit-service", ContentType: globalAuditContentType,
		Metadata: map[string]any{
			"kind": "global-audit-report", "runId": report.RunID,
			"goalSpecSha256": report.GoalSpecRef.SHA256, "planSpecSha256": report.PlanSpecRef.SHA256,
			"releaseCommit": report.ReleaseCommit, "reportSha256": report.ManifestSHA256,
		},
		RetentionUntil: &retentionUntil, Data: encoded,
	})
	if err != nil {
		return "", err
	}
	if !validArtifactRecord(record, report, encoded) {
		return "", ErrStore
	}
	tx, err := store.begin(ctx, report.TenantID, false)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_runs
  (id, tenant_id, project_id, subject_type, subject_id, submission_id,
   phase, state, pipeline_version, execution_platform, isolation_level,
   sandbox_image_digest, auditor_agent_id, started_at, completed_at, verdict,
   evidence_bundle_ref)
VALUES
  ($1::uuid, $2::uuid, $3::uuid, 'PROJECT', $3, NULL,
   'GLOBAL', 'COMPLETED', $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (id) DO NOTHING`, report.RunID, report.TenantID, report.ProjectID,
		report.PipelineVersion, string(report.ExecutionPlatform), string(report.IsolationLevel), report.SandboxImageDigest,
		report.AuditorAgentID, report.StartedAt, report.CompletedAt, report.Verdict, record.SHA256); err != nil {
		return "", err
	}
	if err := verifyRunRow(ctx, tx, report, record.SHA256); err != nil {
		return "", err
	}
	for _, finding := range report.Findings {
		findingID, idErr := uuid.NewV7()
		if idErr != nil {
			return "", ErrStore
		}
		content, encodeErr := json.Marshal(finding)
		if encodeErr != nil {
			return "", ErrInvalidReport
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_findings
  (id, tenant_id, audit_run_id, stable_fingerprint, severity, category,
   rule_id, file_path, line_start, line_end, status, content_jsonb,
   evidence_refs_jsonb, created_at)
VALUES
  ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9, $10, $11,
   $12::jsonb, $13::jsonb, transaction_timestamp())
ON CONFLICT (tenant_id, audit_run_id, stable_fingerprint) DO NOTHING`,
			findingID.String(), report.TenantID, report.RunID, finding.StableFingerprint,
			string(finding.Severity), finding.Category, finding.RuleID, nullableString(finding.File),
			nullableLine(finding.LineStart), nullableLine(finding.LineEnd), string(finding.Status), content, mustJSON(finding.EvidenceRefs)); err != nil {
			return "", err
		}
	}
	storedFindings, err := loadFindings(ctx, tx, report.TenantID, report.RunID)
	if err != nil || !reflect.DeepEqual(storedFindings, report.Findings) {
		return "", ErrStore
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return record.SHA256, nil
}

func (store *PostgresStore) Get(ctx context.Context, tenantID, runID string) (Report, bool, error) {
	if store == nil || store.database == nil || store.artifacts == nil || store.signer == nil || !tenantBound(ctx, tenantID) || !uuidV7(runID) {
		return Report{}, false, ErrStore
	}
	tx, err := store.begin(ctx, tenantID, true)
	if err != nil {
		return Report{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	row, found, err := loadRunRow(ctx, tx, tenantID, runID)
	if err != nil || !found {
		return Report{}, found, err
	}
	findings, err := loadFindings(ctx, tx, tenantID, runID)
	if err != nil {
		return Report{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Report{}, false, err
	}
	record, reader, err := store.artifacts.Open(ctx, tenantID, row.ProjectID, runID)
	if err != nil {
		return Report{}, false, err
	}
	encoded, readErr := io.ReadAll(io.LimitReader(reader, maximumReportBytes+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || len(encoded) > maximumReportBytes {
		return Report{}, false, ErrStore
	}
	report, err := decodeReport(encoded)
	if err != nil || Verify(ctx, report, store.signer) != nil || !validArtifactRecord(record, report, encoded) ||
		!runRowMatchesReport(row, report, record.SHA256) || !reflect.DeepEqual(findings, report.Findings) {
		return Report{}, false, ErrStore
	}
	return report, true, nil
}

type auditRunRow struct {
	ProjectID          string
	PipelineVersion    string
	ExecutionPlatform  string
	IsolationLevel     string
	SandboxImageDigest string
	AuditorAgentID     string
	StartedAt          time.Time
	CompletedAt        time.Time
	Verdict            string
	EvidenceSHA256     string
}

func loadRunRow(ctx context.Context, tx *sql.Tx, tenantID, runID string) (auditRunRow, bool, error) {
	var row auditRunRow
	err := tx.QueryRowContext(ctx, `
SELECT project_id::text, pipeline_version, execution_platform, isolation_level,
       sandbox_image_digest, auditor_agent_id, started_at, completed_at, verdict,
       evidence_bundle_ref
FROM audit_runs
WHERE tenant_id = $1::uuid AND id = $2::uuid
  AND subject_type = 'PROJECT' AND phase = 'GLOBAL' AND state = 'COMPLETED'
  AND submission_id IS NULL`, tenantID, runID).Scan(
		&row.ProjectID, &row.PipelineVersion, &row.ExecutionPlatform, &row.IsolationLevel,
		&row.SandboxImageDigest, &row.AuditorAgentID, &row.StartedAt, &row.CompletedAt,
		&row.Verdict, &row.EvidenceSHA256,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return auditRunRow{}, false, nil
	}
	return row, err == nil, err
}

func verifyRunRow(ctx context.Context, tx *sql.Tx, report Report, evidenceSHA256 string) error {
	row, found, err := loadRunRow(ctx, tx, report.TenantID, report.RunID)
	if err != nil || !found || !runRowMatchesReport(row, report, evidenceSHA256) {
		return ErrStore
	}
	return nil
}

func runRowMatchesReport(row auditRunRow, report Report, evidenceSHA256 string) bool {
	return row.ProjectID == report.ProjectID && row.PipelineVersion == report.PipelineVersion &&
		row.ExecutionPlatform == string(report.ExecutionPlatform) && row.IsolationLevel == string(report.IsolationLevel) &&
		row.SandboxImageDigest == report.SandboxImageDigest && row.AuditorAgentID == report.AuditorAgentID &&
		row.StartedAt.Equal(report.StartedAt) && row.CompletedAt.Equal(report.CompletedAt) &&
		row.Verdict == report.Verdict && row.EvidenceSHA256 == evidenceSHA256
}

func loadFindings(ctx context.Context, tx *sql.Tx, tenantID, runID string) ([]contracts.AuditFinding, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT content_jsonb
FROM audit_findings
WHERE tenant_id = $1::uuid AND audit_run_id = $2::uuid
ORDER BY stable_fingerprint`, tenantID, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	findings := []contracts.AuditFinding{}
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return nil, err
		}
		var finding contracts.AuditFinding
		if err := decodeStrict(encoded, &finding); err != nil || finding.Validate() != nil {
			return nil, ErrStore
		}
		findings = append(findings, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

func (store *PostgresStore) begin(ctx context.Context, tenantID string, readOnly bool) (*sql.Tx, error) {
	if !tenantBound(ctx, tenantID) {
		return nil, ErrStore
	}
	tx, err := store.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: readOnly})
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func decodeReport(encoded []byte) (Report, error) {
	var report Report
	if err := decodeStrict(encoded, &report); err != nil {
		return Report{}, err
	}
	return report, nil
}

func decodeStrict(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidReport
	}
	return nil
}

func validArtifactRecord(record artifact.Record, report Report, encoded []byte) bool {
	return record.ID == report.RunID && record.TenantID == report.TenantID && record.ProjectID == report.ProjectID &&
		record.ContentType == globalAuditContentType && record.SizeBytes == int64(len(encoded)) && digestBytes(encoded) == record.SHA256 &&
		record.URI == "artifact://sha256/"+record.SHA256[len("sha256:"):] &&
		metadataValue(record.Metadata, "kind") == "global-audit-report" && metadataValue(record.Metadata, "runId") == report.RunID &&
		metadataValue(record.Metadata, "goalSpecSha256") == report.GoalSpecRef.SHA256 && metadataValue(record.Metadata, "planSpecSha256") == report.PlanSpecRef.SHA256 &&
		metadataValue(record.Metadata, "releaseCommit") == report.ReleaseCommit && metadataValue(record.Metadata, "reportSha256") == report.ManifestSHA256
}

func metadataValue(metadata map[string]any, key string) string {
	value, _ := metadata[key].(string)
	return value
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableLine(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

func tenantBound(ctx context.Context, tenantID string) bool {
	principal, found := authn.PrincipalFromContext(ctx)
	return found && principal.Type == authn.PrincipalService && principal.Role == authn.RoleService &&
		principal.TenantID == tenantID && canonicalUUID(tenantID)
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

var _ Store = (*PostgresStore)(nil)
