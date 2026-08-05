package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/google/uuid"
)

const (
	auditPhaseDeterministic = "DETERMINISTIC"
	auditPhaseLLM           = "LLM"
	auditRunRunning         = "RUNNING"
	auditRunCompleted       = "COMPLETED"
)

type PostgresAuditRunStore struct {
	database *sql.DB
}

func NewPostgresAuditRunStore(database *sql.DB) (*PostgresAuditRunStore, error) {
	if database == nil {
		return nil, ErrInvalidInput
	}
	return &PostgresAuditRunStore{database: database}, nil
}

func (store *PostgresAuditRunStore) Put(ctx context.Context, run AuditRun) error {
	if store == nil || store.database == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	run, err := canonicalAuditRun(run)
	if err != nil {
		return err
	}
	runID := auditRunID(run)
	tx, err := store.begin(ctx, run.TenantID)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx, `
INSERT INTO audit_runs
  (id, tenant_id, project_id, subject_type, subject_id, submission_id, phase,
   state, pipeline_version, execution_platform, isolation_level, started_at)
VALUES
  ($1::uuid, $2::uuid, $3::uuid, 'SUBMISSION', $4, $4::uuid, $5, $6, $7, $8, $9, $10)
ON CONFLICT (id) DO NOTHING`, runID, run.TenantID, run.ProjectID, run.SubmissionID,
		run.Phase, auditRunRunning, run.PipelineVersion, run.Platform, run.Isolation, run.StartedAt)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		if err := verifyStoredAuditRun(ctx, tx, runID, run); err != nil {
			return err
		}
		return tx.Commit()
	}

	for _, finding := range run.Findings {
		if err := insertAuditFinding(ctx, tx, runID, run.TenantID, finding); err != nil {
			return err
		}
	}
	result, err = tx.ExecContext(ctx, `
UPDATE audit_runs
SET state = $3, completed_at = $4, verdict = $5, evidence_bundle_ref = $6
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state = $7`, run.TenantID, runID,
		auditRunCompleted, run.CompletedAt, run.Verdict, run.EvidenceBundleRef, auditRunRunning)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrAuditRunConflict
	}
	return tx.Commit()
}

func (store *PostgresAuditRunStore) begin(ctx context.Context, tenantID string) (*sql.Tx, error) {
	tx, err := store.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	var superuser, bypassRLS bool
	if err := tx.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS); err != nil || superuser || bypassRLS {
		_ = tx.Rollback()
		if err != nil {
			return nil, err
		}
		return nil, ErrInvalidInput
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func canonicalAuditRun(run AuditRun) (AuditRun, error) {
	if !canonicalAuditUUID(run.TenantID) || !canonicalAuditUUID(run.ProjectID) || !canonicalAuditUUID(run.SubmissionID) ||
		(run.Phase != auditPhaseDeterministic && run.Phase != auditPhaseLLM) ||
		!pipelineVersionPattern.MatchString(run.PipelineVersion) ||
		!contractsPlatformIsolation(run.Platform, run.Isolation) ||
		(run.Verdict != "PASS" && run.Verdict != "FAIL" && run.Verdict != "INCONCLUSIVE") ||
		!digestPattern.MatchString(run.EvidenceBundleRef) || run.StartedAt.IsZero() || run.CompletedAt.IsZero() || run.CompletedAt.Before(run.StartedAt) {
		return AuditRun{}, ErrInvalidInput
	}
	findings, err := canonicalFindings(run.Findings)
	if err != nil {
		return AuditRun{}, ErrInvalidInput
	}
	run.Findings = findings
	run.StartedAt = run.StartedAt.UTC()
	run.CompletedAt = run.CompletedAt.UTC()
	return run, nil
}

func canonicalAuditUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func auditRunID(run AuditRun) string {
	seed := run.TenantID + "\x00" + run.SubmissionID + "\x00" + run.Phase + "\x00" + run.PipelineVersion
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(seed)).String()
}

func auditFindingID(runID, fingerprint string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(runID+"\x00"+fingerprint)).String()
}

func insertAuditFinding(ctx context.Context, tx *sql.Tx, runID, tenantID string, finding contracts.AuditFinding) error {
	content, err := json.Marshal(finding)
	if err != nil {
		return ErrInvalidInput
	}
	evidenceRefs, err := json.Marshal(finding.EvidenceRefs)
	if err != nil {
		return ErrInvalidInput
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO audit_findings
  (id, tenant_id, audit_run_id, stable_fingerprint, severity, category, rule_id,
   file_path, line_start, line_end, status, content_jsonb, evidence_refs_jsonb)
VALUES
  ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13::jsonb)`,
		auditFindingID(runID, finding.StableFingerprint), tenantID, runID, finding.StableFingerprint,
		finding.Severity, finding.Category, finding.RuleID, nullableFindingFile(finding.File),
		nullableFindingLine(finding.LineStart), nullableFindingLine(finding.LineEnd), finding.Status,
		content, evidenceRefs)
	return err
}

func verifyStoredAuditRun(ctx context.Context, tx *sql.Tx, runID string, expected AuditRun) error {
	var projectID, subjectType, subjectID, submissionID, phase, state, version, platform, isolation string
	var startedAt time.Time
	var completedAt sql.NullTime
	var verdict, evidenceRef, imageDigest, auditorAgentID sql.NullString
	err := tx.QueryRowContext(ctx, `
SELECT project_id::text, subject_type, subject_id, submission_id::text, phase, state,
       pipeline_version, execution_platform, isolation_level, sandbox_image_digest,
       auditor_agent_id, started_at, completed_at, verdict, evidence_bundle_ref
FROM audit_runs
WHERE tenant_id = $1::uuid AND id = $2::uuid
FOR UPDATE`, expected.TenantID, runID).Scan(&projectID, &subjectType, &subjectID, &submissionID,
		&phase, &state, &version, &platform, &isolation, &imageDigest, &auditorAgentID,
		&startedAt, &completedAt, &verdict, &evidenceRef)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAuditRunConflict
	}
	if err != nil {
		return err
	}
	if projectID != expected.ProjectID || subjectType != "SUBMISSION" || subjectID != expected.SubmissionID ||
		submissionID != expected.SubmissionID || phase != expected.Phase || state != auditRunCompleted ||
		version != expected.PipelineVersion || platform != string(expected.Platform) || isolation != string(expected.Isolation) ||
		imageDigest.Valid || auditorAgentID.Valid || startedAt.IsZero() || !completedAt.Valid || completedAt.Time.Before(startedAt) ||
		!verdict.Valid || verdict.String != expected.Verdict || !evidenceRef.Valid || evidenceRef.String != expected.EvidenceBundleRef {
		return ErrAuditRunConflict
	}
	return verifyStoredAuditFindings(ctx, tx, runID, expected)
}

func verifyStoredAuditFindings(ctx context.Context, tx *sql.Tx, runID string, expected AuditRun) error {
	rows, err := tx.QueryContext(ctx, `
SELECT stable_fingerprint, severity, category, rule_id, file_path, line_start,
       line_end, status, content_jsonb, evidence_refs_jsonb
FROM audit_findings
WHERE tenant_id = $1::uuid AND audit_run_id = $2::uuid
ORDER BY stable_fingerprint`, expected.TenantID, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	wanted := make(map[string]contracts.AuditFinding, len(expected.Findings))
	for _, finding := range expected.Findings {
		wanted[finding.StableFingerprint] = finding
	}
	seen := 0
	for rows.Next() {
		var fingerprint, severity, category, ruleID, status string
		var file sql.NullString
		var lineStart, lineEnd sql.NullInt64
		var content, evidenceRefs []byte
		if err := rows.Scan(&fingerprint, &severity, &category, &ruleID, &file, &lineStart,
			&lineEnd, &status, &content, &evidenceRefs); err != nil {
			return err
		}
		finding, exists := wanted[fingerprint]
		if !exists {
			return ErrAuditRunConflict
		}
		var stored contracts.AuditFinding
		var storedRefs []string
		if json.Unmarshal(content, &stored) != nil || json.Unmarshal(evidenceRefs, &storedRefs) != nil ||
			!sameAuditFinding(stored, finding) || !slices.Equal(storedRefs, finding.EvidenceRefs) ||
			severity != string(finding.Severity) || category != finding.Category || ruleID != finding.RuleID ||
			status != string(finding.Status) || !sameNullableString(file, finding.File) ||
			!sameNullableLine(lineStart, finding.LineStart) || !sameNullableLine(lineEnd, finding.LineEnd) {
			return ErrAuditRunConflict
		}
		delete(wanted, fingerprint)
		seen++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if seen != len(expected.Findings) || len(wanted) != 0 {
		return ErrAuditRunConflict
	}
	return nil
}

func sameAuditFinding(left, right contracts.AuditFinding) bool {
	return left.FindingID == right.FindingID && left.StableFingerprint == right.StableFingerprint &&
		left.Severity == right.Severity && left.Category == right.Category && left.RuleID == right.RuleID &&
		left.File == right.File && left.LineStart == right.LineStart && left.LineEnd == right.LineEnd &&
		left.Status == right.Status && left.SemanticLocation == right.SemanticLocation &&
		left.EvidencePattern == right.EvidencePattern && slices.Equal(left.EvidenceRefs, right.EvidenceRefs) &&
		left.ExpectedBehavior == right.ExpectedBehavior && left.ObservedBehavior == right.ObservedBehavior &&
		left.RemediationConstraint == right.RemediationConstraint
}

func nullableFindingFile(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableFindingLine(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

func sameNullableString(value sql.NullString, expected string) bool {
	return value.Valid == (expected != "") && (!value.Valid || value.String == expected)
}

func sameNullableLine(value sql.NullInt64, expected int) bool {
	return value.Valid == (expected != 0) && (!value.Valid || value.Int64 == int64(expected))
}

var _ AuditRunStore = (*PostgresAuditRunStore)(nil)
