package toolbroker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/akimisaka/aor/internal/authn"
)

type PostgresInvocationRecorder struct {
	database *sql.DB
}

func NewPostgresInvocationRecorder(database *sql.DB) (*PostgresInvocationRecorder, error) {
	if database == nil {
		return nil, ErrInvocationRecord
	}
	return &PostgresInvocationRecorder{database: database}, nil
}

func (recorder *PostgresInvocationRecorder) Record(ctx context.Context, invocation Invocation) error {
	if recorder == nil || recorder.database == nil || ctx == nil || invocation.Status != "SUCCEEDED" || invocation.Decision != "ALLOW" || !validRisk(invocation.Risk) || !validDigest(invocation.InputSHA256) || !validDigest(invocation.OutputSHA256) || invocation.RequestID == "" || invocation.TenantID == "" || invocation.ProjectID == "" || invocation.TaskID == "" || invocation.PrincipalID == "" || invocation.ToolID == "" || invocation.ToolVersion == "" || invocation.PolicyVersion == "" || invocation.StartedAt.IsZero() || invocation.OccurredAt.IsZero() || invocation.OccurredAt.Before(invocation.StartedAt) {
		return ErrInvocationRecord
	}
	if principal, ok := authn.PrincipalFromContext(ctx); !ok || principal.TenantID != invocation.TenantID {
		return ErrInvocationRecord
	}
	tx, err := beginInvocationTx(ctx, recorder.database, invocation.TenantID, false)
	if err != nil {
		return ErrInvocationRecord
	}
	defer func() { _ = tx.Rollback() }()
	id := invocationUUID(invocation)
	var inserted string
	err = tx.QueryRowContext(ctx, `
INSERT INTO tool_invocations
  (id, tenant_id, request_id, project_id, task_id, agent_instance_id,
   tool_id, tool_version, risk_level, policy_version, decision,
   input_sha256, output_sha256, sandbox_id, status, started_at, completed_at)
VALUES
  ($1::uuid, $2::uuid, $3, $4::uuid, $5::uuid, $6, $7, $8, $9, $10, $11,
   $12, $13, NULL, $14, $15, $16)
ON CONFLICT (tenant_id, request_id) DO NOTHING
RETURNING id::text`, id, invocation.TenantID, invocation.RequestID,
		invocation.ProjectID, invocation.TaskID, invocation.PrincipalID,
		invocation.ToolID, invocation.ToolVersion, string(invocation.Risk),
		invocation.PolicyVersion, invocation.Decision, invocation.InputSHA256,
		invocation.OutputSHA256, invocation.Status, invocation.StartedAt.UTC(),
		invocation.OccurredAt.UTC()).Scan(&inserted)
	if err == nil {
		if err := tx.Commit(); err != nil {
			return ErrInvocationRecord
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ErrInvocationRecord
	}
	var existingInput, existingOutput, existingPolicy, existingStatus string
	if err := tx.QueryRowContext(ctx, `
SELECT input_sha256, output_sha256, policy_version, status
FROM tool_invocations
WHERE tenant_id = $1::uuid AND request_id = $2`, invocation.TenantID, invocation.RequestID).Scan(&existingInput, &existingOutput, &existingPolicy, &existingStatus); err != nil {
		return ErrInvocationRecord
	}
	if existingInput != invocation.InputSHA256 || existingOutput != invocation.OutputSHA256 || existingPolicy != invocation.PolicyVersion || existingStatus != invocation.Status {
		return ErrIdempotencyConflict
	}
	if err := tx.Commit(); err != nil {
		return ErrInvocationRecord
	}
	return nil
}

func (recorder *PostgresInvocationRecorder) RecordAttempt(context.Context, InvocationAttempt) error {
	// The durable schema has no mutable failure-attempt table. Failed attempts
	// are emitted by the JetStream recorder, while successful effects are
	// committed to tool_invocations above.
	return nil
}

type CompositeInvocationRecorder struct {
	durable  *PostgresInvocationRecorder
	stream   InvocationRecorder
	attempts InvocationAttemptRecorder
}

func NewCompositeInvocationRecorder(durable *PostgresInvocationRecorder, stream InvocationRecorder) (*CompositeInvocationRecorder, error) {
	if durable == nil || stream == nil {
		return nil, ErrInvocationRecord
	}
	attempts, _ := stream.(InvocationAttemptRecorder)
	return &CompositeInvocationRecorder{durable: durable, stream: stream, attempts: attempts}, nil
}

func (recorder *CompositeInvocationRecorder) Record(ctx context.Context, invocation Invocation) error {
	if recorder == nil || recorder.durable == nil || recorder.stream == nil {
		return ErrInvocationRecord
	}
	if err := recorder.durable.Record(ctx, invocation); err != nil {
		return err
	}
	return recorder.stream.Record(ctx, invocation)
}

func (recorder *CompositeInvocationRecorder) RecordAttempt(ctx context.Context, attempt InvocationAttempt) error {
	if recorder == nil || recorder.attempts == nil {
		return nil
	}
	return recorder.attempts.RecordAttempt(ctx, attempt)
}

func beginInvocationTx(ctx context.Context, database *sql.DB, tenantID string, readOnly bool) (*sql.Tx, error) {
	if ctx == nil || database == nil || tenantID == "" {
		return nil, ErrInvocationRecord
	}
	tx, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: readOnly})
	if err != nil {
		return nil, err
	}
	var superuser, bypassRLS bool
	if err := tx.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS); err != nil || superuser || bypassRLS {
		_ = tx.Rollback()
		return nil, ErrInvocationRecord
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func invocationUUID(invocation Invocation) string {
	sum := sha256.Sum256([]byte(invocation.TenantID + "\x00" + invocation.RequestID))
	b := sum[:16]
	b[6] = b[6]&0x0f | 0x50
	b[8] = b[8]&0x3f | 0x80
	encoded := hex.EncodeToString(b)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func validRisk(value Risk) bool {
	return value == RiskLow || value == RiskMedium || value == RiskHigh || value == RiskCritical
}

func validDigest(value string) bool {
	return len(value) == len("sha256:")+64 && strings.HasPrefix(value, "sha256:") && strings.Trim(value[len("sha256:"):], "0123456789abcdef") == ""
}

var _ InvocationRecorder = (*PostgresInvocationRecorder)(nil)
var _ InvocationAttemptRecorder = (*PostgresInvocationRecorder)(nil)
var _ InvocationRecorder = (*CompositeInvocationRecorder)(nil)
var _ InvocationAttemptRecorder = (*CompositeInvocationRecorder)(nil)
