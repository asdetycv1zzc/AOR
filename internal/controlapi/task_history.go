package controlapi

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

const taskHistoryPageSize = 100

type TaskHistoryReader interface {
	ListSubmissions(context.Context, string, string, string, string) (TaskSubmissionPage, error)
	ListAudits(context.Context, string, string, string, string) (TaskAuditPage, error)
}

type TaskSubmissionPage struct {
	Items      []json.RawMessage `json:"items"`
	NextCursor string            `json:"nextCursor,omitempty"`
}

type TaskAuditPage struct {
	Items      []TaskAuditRun `json:"items"`
	NextCursor string         `json:"nextCursor,omitempty"`
}

type TaskAuditRun struct {
	ID                 string             `json:"id"`
	ProjectID          string             `json:"projectId"`
	TaskID             string             `json:"taskId"`
	SubmissionID       string             `json:"submissionId"`
	Phase              string             `json:"phase"`
	State              string             `json:"state"`
	PipelineVersion    string             `json:"pipelineVersion"`
	ExecutionPlatform  string             `json:"executionPlatform"`
	IsolationLevel     string             `json:"isolationLevel"`
	SandboxImageDigest string             `json:"sandboxImageDigest,omitempty"`
	AuditorAgentID     string             `json:"auditorAgentId,omitempty"`
	StartedAt          time.Time          `json:"startedAt"`
	CompletedAt        *time.Time         `json:"completedAt,omitempty"`
	Verdict            string             `json:"verdict,omitempty"`
	EvidenceBundleRef  string             `json:"evidenceBundleRef,omitempty"`
	Findings           []TaskAuditFinding `json:"findings"`
}

type TaskAuditFinding struct {
	ID                string          `json:"id"`
	StableFingerprint string          `json:"stableFingerprint"`
	Severity          string          `json:"severity"`
	Category          string          `json:"category"`
	RuleID            string          `json:"ruleId"`
	FilePath          string          `json:"filePath,omitempty"`
	LineStart         *int            `json:"lineStart,omitempty"`
	LineEnd           *int            `json:"lineEnd,omitempty"`
	Status            string          `json:"status"`
	Content           json.RawMessage `json:"content"`
	EvidenceRefs      []string        `json:"evidenceRefs"`
	CreatedAt         time.Time       `json:"createdAt"`
}

type taskHistoryCursor struct {
	Kind      string    `json:"kind"`
	ProjectID string    `json:"projectId"`
	TaskID    string    `json:"taskId"`
	CreatedAt time.Time `json:"createdAt"`
	ID        string    `json:"id"`
}

type PostgresTaskHistoryReader struct {
	database *sql.DB
}

func NewPostgresTaskHistoryReader(database *sql.DB) (*PostgresTaskHistoryReader, error) {
	if database == nil {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "task history database"})
	}
	return &PostgresTaskHistoryReader{database: database}, nil
}

func (reader *PostgresTaskHistoryReader) ListSubmissions(ctx context.Context, tenantID, projectID, taskID, cursor string) (TaskSubmissionPage, error) {
	position, err := decodeTaskHistoryCursor(cursor, "submission", projectID, taskID)
	if err != nil {
		return TaskSubmissionPage{}, err
	}
	tx, err := reader.begin(ctx, tenantID)
	if err != nil {
		return TaskSubmissionPage{}, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
SELECT id::text, manifest_jsonb, created_at
FROM submissions
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND module_task_id::text = $3
  AND (created_at, id) > ($4::timestamptz, $5::uuid)
ORDER BY created_at, id
LIMIT $6`, tenantID, projectID, taskID, position.CreatedAt, cursorUUID(position.ID), taskHistoryPageSize+1)
	if err != nil {
		return TaskSubmissionPage{}, err
	}
	defer rows.Close()
	type item struct {
		id        string
		manifest  json.RawMessage
		createdAt time.Time
	}
	items := make([]item, 0, taskHistoryPageSize+1)
	for rows.Next() {
		var value item
		if err := rows.Scan(&value.id, &value.manifest, &value.createdAt); err != nil {
			return TaskSubmissionPage{}, err
		}
		if err := contracts.ValidateSubmissionJSON(value.manifest); err != nil {
			return TaskSubmissionPage{}, aorerrors.Wrap(aorerrors.CodeInternalError, "", err, map[string]any{"scope": "submission manifest integrity"})
		}
		items = append(items, value)
	}
	if err := rows.Err(); err != nil {
		return TaskSubmissionPage{}, err
	}
	result := TaskSubmissionPage{Items: make([]json.RawMessage, 0, min(len(items), taskHistoryPageSize))}
	for _, value := range items[:min(len(items), taskHistoryPageSize)] {
		result.Items = append(result.Items, append(json.RawMessage(nil), value.manifest...))
	}
	if len(items) > taskHistoryPageSize {
		last := items[taskHistoryPageSize-1]
		result.NextCursor = encodeTaskHistoryCursor(taskHistoryCursor{Kind: "submission", ProjectID: projectID, TaskID: taskID, CreatedAt: last.createdAt, ID: last.id})
	}
	if err := tx.Commit(); err != nil {
		return TaskSubmissionPage{}, err
	}
	return result, nil
}

func (reader *PostgresTaskHistoryReader) ListAudits(ctx context.Context, tenantID, projectID, taskID, cursor string) (TaskAuditPage, error) {
	position, err := decodeTaskHistoryCursor(cursor, "audit", projectID, taskID)
	if err != nil {
		return TaskAuditPage{}, err
	}
	tx, err := reader.begin(ctx, tenantID)
	if err != nil {
		return TaskAuditPage{}, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
SELECT ar.id::text, ar.project_id::text, s.module_task_id::text, ar.submission_id::text,
       ar.phase, ar.state, ar.pipeline_version, ar.execution_platform, ar.isolation_level,
       ar.sandbox_image_digest, ar.auditor_agent_id, ar.started_at, ar.completed_at,
       ar.verdict, ar.evidence_bundle_ref
FROM audit_runs ar
JOIN submissions s ON s.tenant_id = ar.tenant_id AND s.id = ar.submission_id
WHERE ar.tenant_id = $1::uuid AND ar.project_id = $2::uuid AND s.module_task_id::text = $3
  AND (ar.started_at, ar.id) > ($4::timestamptz, $5::uuid)
ORDER BY ar.started_at, ar.id
LIMIT $6`, tenantID, projectID, taskID, position.CreatedAt, cursorUUID(position.ID), taskHistoryPageSize+1)
	if err != nil {
		return TaskAuditPage{}, err
	}
	defer rows.Close()
	items := make([]TaskAuditRun, 0, taskHistoryPageSize+1)
	for rows.Next() {
		var run TaskAuditRun
		var sandboxDigest, auditorID, verdict, evidenceRef sql.NullString
		var completedAt sql.NullTime
		if err := rows.Scan(&run.ID, &run.ProjectID, &run.TaskID, &run.SubmissionID, &run.Phase, &run.State, &run.PipelineVersion, &run.ExecutionPlatform, &run.IsolationLevel, &sandboxDigest, &auditorID, &run.StartedAt, &completedAt, &verdict, &evidenceRef); err != nil {
			return TaskAuditPage{}, err
		}
		run.SandboxImageDigest = sandboxDigest.String
		run.AuditorAgentID = auditorID.String
		run.Verdict = verdict.String
		run.EvidenceBundleRef = evidenceRef.String
		if completedAt.Valid {
			value := completedAt.Time
			run.CompletedAt = &value
		}
		items = append(items, run)
	}
	if err := rows.Err(); err != nil {
		return TaskAuditPage{}, err
	}
	if err := rows.Close(); err != nil {
		return TaskAuditPage{}, err
	}
	for index := range items {
		items[index].Findings, err = listTaskAuditFindings(ctx, tx, tenantID, items[index].ID)
		if err != nil {
			return TaskAuditPage{}, err
		}
	}
	result := TaskAuditPage{Items: append([]TaskAuditRun(nil), items[:min(len(items), taskHistoryPageSize)]...)}
	if len(items) > taskHistoryPageSize {
		last := items[taskHistoryPageSize-1]
		result.NextCursor = encodeTaskHistoryCursor(taskHistoryCursor{Kind: "audit", ProjectID: projectID, TaskID: taskID, CreatedAt: last.StartedAt, ID: last.ID})
	}
	if err := tx.Commit(); err != nil {
		return TaskAuditPage{}, err
	}
	return result, nil
}

func listTaskAuditFindings(ctx context.Context, tx *sql.Tx, tenantID, auditID string) ([]TaskAuditFinding, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT id::text, stable_fingerprint, severity, category, rule_id, file_path, line_start,
       line_end, status, content_jsonb, evidence_refs_jsonb, created_at
FROM audit_findings
WHERE tenant_id = $1::uuid AND audit_run_id = $2::uuid
ORDER BY created_at, id`, tenantID, auditID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]TaskAuditFinding, 0)
	for rows.Next() {
		var finding TaskAuditFinding
		var filePath sql.NullString
		var lineStart, lineEnd sql.NullInt64
		var evidenceJSON []byte
		if err := rows.Scan(&finding.ID, &finding.StableFingerprint, &finding.Severity, &finding.Category, &finding.RuleID, &filePath, &lineStart, &lineEnd, &finding.Status, &finding.Content, &evidenceJSON, &finding.CreatedAt); err != nil {
			return nil, err
		}
		finding.FilePath = filePath.String
		if lineStart.Valid {
			value := int(lineStart.Int64)
			finding.LineStart = &value
		}
		if lineEnd.Valid {
			value := int(lineEnd.Int64)
			finding.LineEnd = &value
		}
		if !json.Valid(finding.Content) || json.Unmarshal(evidenceJSON, &finding.EvidenceRefs) != nil {
			return nil, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "audit finding integrity"})
		}
		if finding.EvidenceRefs == nil {
			finding.EvidenceRefs = []string{}
		}
		items = append(items, finding)
	}
	return items, rows.Err()
}

func (reader *PostgresTaskHistoryReader) begin(ctx context.Context, tenantID string) (*sql.Tx, error) {
	if reader == nil || reader.database == nil || tenantID == "" {
		return nil, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "task history database"})
	}
	tx, err := reader.database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func encodeTaskHistoryCursor(cursor taskHistoryCursor) string {
	encoded, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func decodeTaskHistoryCursor(value, kind, projectID, taskID string) (taskHistoryCursor, error) {
	if value == "" {
		return taskHistoryCursor{Kind: kind, ProjectID: projectID, TaskID: taskID, CreatedAt: time.Unix(0, 0).UTC()}, nil
	}
	if len(value) > 512 {
		return taskHistoryCursor{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": kind + " cursor"})
	}
	encoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return taskHistoryCursor{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": kind + " cursor"})
	}
	var cursor taskHistoryCursor
	if json.Unmarshal(encoded, &cursor) != nil || cursor.Kind != kind || cursor.ProjectID != projectID || cursor.TaskID != taskID || cursor.CreatedAt.IsZero() || cursor.ID == "" {
		return taskHistoryCursor{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": kind + " cursor"})
	}
	return cursor, nil
}

func cursorUUID(value string) string {
	if value == "" {
		return "00000000-0000-0000-0000-000000000000"
	}
	return value
}

var _ TaskHistoryReader = (*PostgresTaskHistoryReader)(nil)
