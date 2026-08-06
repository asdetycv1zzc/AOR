package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

// PostgresSnapshotLoader reads the tenant-scoped metadata needed to verify a
// restore. It intentionally uses a read-only serializable transaction and the
// same RLS tenant binding as the application stores.
type PostgresSnapshotLoader struct {
	db  *sql.DB
	now func() time.Time
}

func NewPostgresSnapshotLoader(db *sql.DB) (*PostgresSnapshotLoader, error) {
	if db == nil {
		return nil, ErrInvalidSnapshot
	}
	return &PostgresSnapshotLoader{db: db, now: time.Now}, nil
}

// Load returns a point-in-time metadata graph for one tenant. Artifact bytes
// are deliberately not read here; callers pass an ArtifactVerifier to Verify
// so object-store hash checks remain mandatory during restore validation.
func (l *PostgresSnapshotLoader) Load(ctx context.Context, tenantID string) (Snapshot, error) {
	if l == nil || l.db == nil || ctx == nil || tenantID == "" {
		return Snapshot{}, ErrInvalidSnapshot
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	now := time.Now
	if l.now != nil {
		now = l.now
	}
	createdAt := now().UTC()
	if createdAt.IsZero() {
		return Snapshot{}, ErrInvalidSnapshot
	}
	tx, err := l.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return Snapshot{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setSnapshotTenant(ctx, tx, tenantID); err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{Version: 1, CreatedAt: createdAt}
	if err := loadProjects(ctx, tx, tenantID, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if err := loadGoals(ctx, tx, tenantID, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if err := loadPlans(ctx, tx, tenantID, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if err := loadTasks(ctx, tx, tenantID, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if err := loadAudits(ctx, tx, tenantID, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if err := loadArtifacts(ctx, tx, tenantID, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return Snapshot{}, err
	}
	if err := validateSnapshot(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

// VerifyPostgres loads and verifies a tenant's metadata graph in one call.
func VerifyPostgres(ctx context.Context, db *sql.DB, tenantID string, artifacts ArtifactVerifier) (Report, error) {
	loader, err := NewPostgresSnapshotLoader(db)
	if err != nil {
		return Report{}, err
	}
	snapshot, err := loader.Load(ctx, tenantID)
	if err != nil {
		return Report{}, err
	}
	return Verify(ctx, snapshot, artifacts)
}

func setSnapshotTenant(ctx context.Context, tx *sql.Tx, tenantID string) error {
	var superuser bool
	var bypassRLS bool
	if err := tx.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS); err != nil {
		return err
	}
	if superuser || bypassRLS {
		return aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "database role bypasses tenant isolation"})
	}
	_, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID)
	return err
}

func loadProjects(ctx context.Context, tx *sql.Tx, tenantID string, snapshot *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `
SELECT id::text, COALESCE(active_goal_spec_id::text, ''), COALESCE(active_plan_spec_id::text, '')
FROM projects
WHERE tenant_id = $1::uuid
ORDER BY id`, tenantID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var record ProjectRecord
		if err := rows.Scan(&record.ID, &record.ActiveGoalID, &record.ActivePlanID); err != nil {
			return err
		}
		record.TenantID = tenantID
		snapshot.Projects = append(snapshot.Projects, record)
	}
	return rows.Err()
}

func loadGoals(ctx context.Context, tx *sql.Tx, tenantID string, snapshot *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `
SELECT project_id::text, id::text, version
FROM goal_specs
WHERE tenant_id = $1::uuid
ORDER BY project_id, id`, tenantID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var record GoalRecord
		if err := rows.Scan(&record.ProjectID, &record.ID, &record.Version); err != nil {
			return err
		}
		record.TenantID = tenantID
		snapshot.Goals = append(snapshot.Goals, record)
	}
	return rows.Err()
}

func loadPlans(ctx context.Context, tx *sql.Tx, tenantID string, snapshot *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `
SELECT project_id::text, id::text, COALESCE(goal_spec_id::text, '')
FROM plan_specs
WHERE tenant_id = $1::uuid
ORDER BY project_id, id`, tenantID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var record PlanRecord
		if err := rows.Scan(&record.ProjectID, &record.ID, &record.GoalID); err != nil {
			return err
		}
		record.TenantID = tenantID
		snapshot.Plans = append(snapshot.Plans, record)
	}
	return rows.Err()
}

func loadTasks(ctx context.Context, tx *sql.Tx, tenantID string, snapshot *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `
SELECT task.project_id::text, task.id::text, COALESCE(plan.id::text, '')
FROM module_tasks AS task
LEFT JOIN module_specs AS spec ON spec.tenant_id = task.tenant_id AND spec.id = task.module_spec_id
LEFT JOIN plan_specs AS plan ON plan.tenant_id = task.tenant_id AND plan.id = COALESCE(task.planning_spec_id, spec.plan_spec_id)
WHERE task.tenant_id = $1::uuid
ORDER BY task.project_id, task.id`, tenantID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var record TaskRecord
		if err := rows.Scan(&record.ProjectID, &record.ID, &record.PlanID); err != nil {
			return err
		}
		record.TenantID = tenantID
		snapshot.Tasks = append(snapshot.Tasks, record)
	}
	return rows.Err()
}

func loadAudits(ctx context.Context, tx *sql.Tx, tenantID string, snapshot *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `
SELECT audit.id::text, audit.project_id::text,
       CASE WHEN audit.subject_type = 'SUBMISSION' THEN COALESCE(submission.module_task_id::text, '') ELSE '' END,
       audit.evidence_bundle_ref, evidence.id::text
FROM audit_runs AS audit
LEFT JOIN submissions AS submission
  ON submission.tenant_id = audit.tenant_id AND submission.id = audit.submission_id
LEFT JOIN artifacts AS evidence
  ON evidence.tenant_id = audit.tenant_id AND evidence.project_id = audit.project_id
 AND (
   (audit.subject_type = 'SUBMISSION'
    AND evidence.metadata_jsonb->>'kind' = 'evidence-bundle'
    AND evidence.metadata_jsonb->>'taskId' = submission.module_task_id::text
    AND evidence.metadata_jsonb->>'manifestSha256' = audit.evidence_bundle_ref)
   OR
   (audit.subject_type <> 'SUBMISSION' AND evidence.sha256 = audit.evidence_bundle_ref)
 )
WHERE audit.tenant_id = $1::uuid
ORDER BY audit.project_id, audit.id, evidence.id`, tenantID)
	if err != nil {
		return err
	}
	defer rows.Close()
	auditIndexes := make(map[string]int)
	for rows.Next() {
		var record AuditRecord
		var evidenceRef sql.NullString
		var artifactID sql.NullString
		if err := rows.Scan(&record.ID, &record.ProjectID, &record.TaskID, &evidenceRef, &artifactID); err != nil {
			return err
		}
		index, found := auditIndexes[record.ID]
		if !found {
			record.TenantID = tenantID
			snapshot.Audits = append(snapshot.Audits, record)
			index = len(snapshot.Audits) - 1
			auditIndexes[record.ID] = index
		}
		if !evidenceRef.Valid {
			continue
		}
		if !artifactID.Valid || artifactID.String == "" {
			return ErrDanglingReference
		}
		snapshot.Audits[index].ArtifactIDs = append(snapshot.Audits[index].ArtifactIDs, artifactID.String)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	refs, err := tx.QueryContext(ctx, `
SELECT audit.id::text, finding.evidence_refs_jsonb
FROM audit_runs AS audit
JOIN audit_findings AS finding
  ON finding.tenant_id = audit.tenant_id AND finding.audit_run_id = audit.id
WHERE audit.tenant_id = $1::uuid
ORDER BY audit.id, finding.stable_fingerprint`, tenantID)
	if err != nil {
		return err
	}
	for index := range snapshot.Audits {
		auditIndexes[snapshot.Audits[index].ID] = index
	}
	for refs.Next() {
		var auditID string
		var encoded []byte
		if err := refs.Scan(&auditID, &encoded); err != nil {
			_ = refs.Close()
			return err
		}
		index, found := auditIndexes[auditID]
		if !found {
			_ = refs.Close()
			return ErrDanglingReference
		}
		var values []string
		if err := json.Unmarshal(encoded, &values); err != nil || values == nil && string(encoded) != "[]" {
			_ = refs.Close()
			return ErrInvalidSnapshot
		}
		snapshot.Audits[index].EvidenceRefs = append(snapshot.Audits[index].EvidenceRefs, values...)
	}
	if err := refs.Err(); err != nil {
		_ = refs.Close()
		return err
	}
	return refs.Close()
}

func loadArtifacts(ctx context.Context, tx *sql.Tx, tenantID string, snapshot *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `
SELECT id::text, project_id::text, COALESCE(metadata_jsonb->>'taskId', ''), uri, sha256, size_bytes
FROM artifacts
WHERE tenant_id = $1::uuid
ORDER BY project_id, id`, tenantID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var record ArtifactRecord
		if err := rows.Scan(&record.ID, &record.ProjectID, &record.TaskID, &record.URI, &record.SHA256, &record.Size); err != nil {
			return err
		}
		record.TenantID = tenantID
		snapshot.Artifacts = append(snapshot.Artifacts, record)
	}
	return rows.Err()
}
