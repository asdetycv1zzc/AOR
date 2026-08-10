package projectactivity

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

type Flow string

const (
	FlowGoal      Flow = "GOAL"
	FlowPlan      Flow = "PLAN"
	FlowExecution Flow = "EXECUTION"
	FlowAudit     Flow = "AUDIT"
	FlowKnowledge Flow = "KNOWLEDGE"
)

type Sender string

const (
	SenderUser   Sender = "USER"
	SenderAgent  Sender = "AGENT"
	SenderSystem Sender = "SYSTEM"
)

type State string

const (
	StateQueued    State = "QUEUED"
	StateStreaming State = "STREAMING"
	StateCompleted State = "COMPLETED"
	StateFailed    State = "FAILED"
)

type Message struct {
	TenantID        string
	ProjectID       string
	ID              string
	TaskID          string
	RequestID       string
	Flow            Flow
	AgentInstanceID string
	Role            string
	Sender          Sender
	State           State
	Content         string
	ErrorCode       string
	Provider        string
	Model           string
	InputTokens     int64
	OutputTokens    int64
	LatencyMS       int64
	OutputSHA256    string
	PrincipalID     string
	IdempotencyKey  string
	RequestSHA256   string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("project activity database is required")
	}
	return &Store{db: db}, nil
}

func (store *Store) Upsert(ctx context.Context, message Message) error {
	if err := validateMessage(message); err != nil {
		return err
	}
	return store.withTenantTx(ctx, message.TenantID, false, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
INSERT INTO project_activity_messages (
  tenant_id, project_id, id, task_id, request_id, flow, agent_instance_id,
  role, sender, state, content, error_code, provider, model, input_tokens,
  output_tokens, latency_ms, output_sha256, principal_id, idempotency_key,
  request_sha256, created_at, updated_at
) VALUES (
  $1::uuid, $2::uuid, $3, NULLIF($4, '')::uuid, $5, $6, $7,
  $8, $9, $10, $11, $12, $13, $14, $15,
  $16, $17, $18, $19, $20, $21, $22, $23
)
ON CONFLICT (tenant_id, id) DO UPDATE SET
  task_id = EXCLUDED.task_id,
  request_id = EXCLUDED.request_id,
  flow = EXCLUDED.flow,
  agent_instance_id = EXCLUDED.agent_instance_id,
  role = EXCLUDED.role,
  sender = EXCLUDED.sender,
  state = EXCLUDED.state,
  content = EXCLUDED.content,
  error_code = EXCLUDED.error_code,
  provider = EXCLUDED.provider,
  model = EXCLUDED.model,
  input_tokens = EXCLUDED.input_tokens,
  output_tokens = EXCLUDED.output_tokens,
  latency_ms = EXCLUDED.latency_ms,
  output_sha256 = EXCLUDED.output_sha256,
  updated_at = EXCLUDED.updated_at
WHERE EXCLUDED.updated_at >= project_activity_messages.updated_at
  AND (
    project_activity_messages.state IN ('COMPLETED', 'FAILED')
      AND EXCLUDED.state = project_activity_messages.state
    OR project_activity_messages.state NOT IN ('COMPLETED', 'FAILED')
      AND CASE EXCLUDED.state
        WHEN 'QUEUED' THEN 0
        WHEN 'STREAMING' THEN 1
        WHEN 'COMPLETED' THEN 2
        WHEN 'FAILED' THEN 2
        ELSE -1
      END >= CASE project_activity_messages.state
        WHEN 'QUEUED' THEN 0
        WHEN 'STREAMING' THEN 1
        WHEN 'COMPLETED' THEN 2
        WHEN 'FAILED' THEN 2
        ELSE -1
      END
  )`,
			message.TenantID, message.ProjectID, message.ID, message.TaskID, message.RequestID,
			message.Flow, message.AgentInstanceID, message.Role, message.Sender, message.State,
			message.Content, message.ErrorCode, message.Provider, message.Model, message.InputTokens,
			message.OutputTokens, message.LatencyMS, message.OutputSHA256, message.PrincipalID,
			message.IdempotencyKey, message.RequestSHA256, message.CreatedAt.UTC(), message.UpdatedAt.UTC())
		return err
	})
}

func (store *Store) AppendDelta(ctx context.Context, tenantID, id, delta string, updatedAt time.Time) error {
	if tenantID == "" || id == "" || delta == "" || updatedAt.IsZero() {
		return errors.New("invalid project activity delta")
	}
	return store.withTenantTx(ctx, tenantID, false, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `
UPDATE project_activity_messages
SET content = left(content || $3, 4194304), state = 'STREAMING', updated_at = GREATEST(updated_at, $4)
WHERE tenant_id = $1::uuid AND id = $2
  AND state NOT IN ('COMPLETED', 'FAILED')
  AND updated_at <= $4`, tenantID, id, delta, updatedAt.UTC())
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 1 {
			return sql.ErrNoRows
		}
		return nil
	})
}

func (store *Store) List(ctx context.Context, tenantID, projectID string) ([]Message, error) {
	if tenantID == "" || projectID == "" {
		return nil, errors.New("invalid project activity scope")
	}
	var messages []Message
	err := store.withTenantTx(ctx, tenantID, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
	SELECT tenant_id::text, project_id::text, id, COALESCE(task_id::text, ''), COALESCE(request_id, ''),
       flow, agent_instance_id, role, sender, state, content, error_code, provider,
       model, input_tokens, output_tokens, latency_ms, output_sha256, principal_id,
       idempotency_key, request_sha256, created_at, updated_at
FROM project_activity_messages
WHERE tenant_id = $1::uuid AND project_id = $2::uuid
ORDER BY created_at, id`, tenantID, projectID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var message Message
			if err := rows.Scan(
				&message.TenantID, &message.ProjectID, &message.ID, &message.TaskID,
				&message.RequestID, &message.Flow, &message.AgentInstanceID, &message.Role,
				&message.Sender, &message.State, &message.Content, &message.ErrorCode,
				&message.Provider, &message.Model, &message.InputTokens, &message.OutputTokens,
				&message.LatencyMS, &message.OutputSHA256, &message.PrincipalID,
				&message.IdempotencyKey, &message.RequestSHA256, &message.CreatedAt,
				&message.UpdatedAt,
			); err != nil {
				return err
			}
			messages = append(messages, message)
		}
		return rows.Err()
	})
	return messages, err
}

func (store *Store) FindByIdempotency(ctx context.Context, tenantID, principalID, idempotencyKey string) (Message, bool, error) {
	if tenantID == "" || principalID == "" || idempotencyKey == "" {
		return Message{}, false, errors.New("invalid project activity idempotency scope")
	}
	var message Message
	err := store.withTenantTx(ctx, tenantID, true, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
SELECT tenant_id::text, project_id::text, id, COALESCE(task_id::text, ''), COALESCE(request_id, ''),
       flow, agent_instance_id, role, sender, state, content, error_code, provider,
       model, input_tokens, output_tokens, latency_ms, output_sha256, principal_id,
       idempotency_key, request_sha256, created_at, updated_at
FROM project_activity_messages
WHERE tenant_id = $1::uuid AND principal_id = $2 AND idempotency_key = $3
LIMIT 1`, tenantID, principalID, idempotencyKey)
		return row.Scan(
			&message.TenantID, &message.ProjectID, &message.ID, &message.TaskID,
			&message.RequestID, &message.Flow, &message.AgentInstanceID, &message.Role,
			&message.Sender, &message.State, &message.Content, &message.ErrorCode,
			&message.Provider, &message.Model, &message.InputTokens, &message.OutputTokens,
			&message.LatencyMS, &message.OutputSHA256, &message.PrincipalID,
			&message.IdempotencyKey, &message.RequestSHA256, &message.CreatedAt,
			&message.UpdatedAt,
		)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Message{}, false, nil
	}
	if err != nil {
		return Message{}, false, err
	}
	return message, true, nil
}

func (store *Store) ClaimQueued(ctx context.Context, tenantID, projectID string, flow Flow, agentID, requestID string, now time.Time) ([]Message, error) {
	if tenantID == "" || projectID == "" || !validFlow(flow) || requestID == "" || now.IsZero() {
		return nil, errors.New("invalid project activity claim scope")
	}
	var messages []Message
	err := store.withTenantTx(ctx, tenantID, false, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
SELECT tenant_id::text, project_id::text, id, COALESCE(task_id::text, ''), COALESCE(request_id, ''),
       flow, agent_instance_id, role, sender, state, content, error_code, provider,
       model, input_tokens, output_tokens, latency_ms, output_sha256, principal_id,
       idempotency_key, request_sha256, created_at, updated_at
FROM project_activity_messages
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND flow = $3
  AND sender = 'USER' AND claim_request_id = $4
ORDER BY created_at, id
FOR UPDATE`, tenantID, projectID, flow, requestID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var message Message
			if err := scanMessage(rows, &message); err != nil {
				_ = rows.Close()
				return err
			}
			messages = append(messages, message)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(messages) != 0 {
			return nil
		}

		rows, err = tx.QueryContext(ctx, `
WITH claimed AS (
  SELECT tenant_id, id
  FROM project_activity_messages
  WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND flow = $3
    AND sender = 'USER' AND state = 'QUEUED'
    AND ($4 = '' OR agent_instance_id = '' OR agent_instance_id = $4)
  ORDER BY created_at, id
  LIMIT 1
  FOR UPDATE SKIP LOCKED
)
UPDATE project_activity_messages AS activity
SET state = 'STREAMING', claim_request_id = $5, updated_at = $6
FROM claimed
WHERE activity.tenant_id = claimed.tenant_id AND activity.id = claimed.id
RETURNING activity.tenant_id::text, activity.project_id::text, activity.id,
       COALESCE(activity.task_id::text, ''), COALESCE(activity.request_id, ''),
       activity.flow, activity.agent_instance_id, activity.role, activity.sender,
       activity.state, activity.content, activity.error_code, activity.provider,
       activity.model, activity.input_tokens, activity.output_tokens, activity.latency_ms,
       activity.output_sha256, activity.principal_id, activity.idempotency_key,
       activity.request_sha256, activity.created_at, activity.updated_at`, tenantID, projectID, flow, agentID, requestID, now.UTC())
		if err != nil {
			return err
		}
		for rows.Next() {
			var message Message
			if err := scanMessage(rows, &message); err != nil {
				_ = rows.Close()
				return err
			}
			messages = append(messages, message)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(messages) != 0 {
			return nil
		}

		// Another request may have claimed the row while this transaction was
		// waiting on SKIP LOCKED. Read its binding before returning an empty
		// prompt, otherwise concurrent retries could produce different digests.
		rows, err = tx.QueryContext(ctx, `
SELECT tenant_id::text, project_id::text, id, COALESCE(task_id::text, ''), COALESCE(request_id, ''),
       flow, agent_instance_id, role, sender, state, content, error_code, provider,
       model, input_tokens, output_tokens, latency_ms, output_sha256, principal_id,
       idempotency_key, request_sha256, created_at, updated_at
FROM project_activity_messages
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND flow = $3
  AND sender = 'USER' AND claim_request_id = $4
ORDER BY created_at, id
FOR UPDATE`, tenantID, projectID, flow, requestID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var message Message
			if err := scanMessage(rows, &message); err != nil {
				_ = rows.Close()
				return err
			}
			messages = append(messages, message)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		return rows.Close()
	})
	return messages, err
}

func (store *Store) CompleteClaimed(ctx context.Context, tenantID, projectID, requestID string, ids []string, failed, requeue bool, now time.Time) error {
	if tenantID == "" || projectID == "" || requestID == "" || len(ids) == 0 || now.IsZero() {
		return nil
	}
	stateValue := StateCompleted
	if failed {
		stateValue = StateFailed
	}
	if requeue {
		stateValue = StateQueued
	}
	return store.withTenantTx(ctx, tenantID, false, func(tx *sql.Tx) error {
		for _, id := range ids {
			if id == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, `
UPDATE project_activity_messages
SET state = $5, claim_request_id = CASE WHEN $7 THEN '' ELSE claim_request_id END,
    updated_at = GREATEST(updated_at, $6::timestamptz)
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND id = $3
  AND state = 'STREAMING' AND claim_request_id = $4`, tenantID, projectID, id, requestID, stateValue, now.UTC(), requeue); err != nil {
				return err
			}
		}
		return nil
	})
}

func (store *Store) HasQueuedOrClaimed(ctx context.Context, tenantID, projectID string, flow Flow, agentID, requestID string) (bool, error) {
	if tenantID == "" || projectID == "" || !validFlow(flow) || requestID == "" {
		return false, errors.New("invalid project activity pending scope")
	}
	var pending bool
	err := store.withTenantTx(ctx, tenantID, true, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1
  FROM project_activity_messages
  WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND flow = $3
    AND sender = 'USER'
    AND (
      claim_request_id = $5
      OR state = 'QUEUED' AND ($4 = '' OR agent_instance_id = '' OR agent_instance_id = $4)
    )
)`, tenantID, projectID, flow, agentID, requestID).Scan(&pending)
	})
	return pending, err
}

type scanner interface {
	Scan(...any) error
}

func scanMessage(row scanner, message *Message) error {
	return row.Scan(
		&message.TenantID, &message.ProjectID, &message.ID, &message.TaskID,
		&message.RequestID, &message.Flow, &message.AgentInstanceID, &message.Role,
		&message.Sender, &message.State, &message.Content, &message.ErrorCode,
		&message.Provider, &message.Model, &message.InputTokens, &message.OutputTokens,
		&message.LatencyMS, &message.OutputSHA256, &message.PrincipalID,
		&message.IdempotencyKey, &message.RequestSHA256, &message.CreatedAt,
		&message.UpdatedAt,
	)
}

func (store *Store) withTenantTx(ctx context.Context, tenantID string, readOnly bool, operation func(*sql.Tx) error) error {
	if ctx == nil || tenantID == "" || operation == nil {
		return errors.New("invalid project activity transaction")
	}
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted, ReadOnly: readOnly})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		return err
	}
	if err := operation(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func validateMessage(message Message) error {
	if message.TenantID == "" || message.ProjectID == "" || message.ID == "" || len(message.ID) > 512 || !validFlow(message.Flow) || !validSender(message.Sender) || !validState(message.State) || message.CreatedAt.IsZero() || message.UpdatedAt.Before(message.CreatedAt) || message.InputTokens < 0 || message.OutputTokens < 0 || message.LatencyMS < 0 || len(message.Content) > 4<<20 {
		return errors.New("invalid project activity message")
	}
	for _, value := range []string{message.ID, message.TaskID, message.RequestID, message.AgentInstanceID, message.Role, message.ErrorCode, message.Provider, message.Model, message.PrincipalID, message.IdempotencyKey, message.RequestSHA256} {
		if len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("invalid project activity message")
		}
	}
	return nil
}

func validFlow(flow Flow) bool {
	switch flow {
	case FlowGoal, FlowPlan, FlowExecution, FlowAudit, FlowKnowledge:
		return true
	default:
		return false
	}
}

func validSender(sender Sender) bool {
	switch sender {
	case SenderUser, SenderAgent, SenderSystem:
		return true
	default:
		return false
	}
}

func validState(state State) bool {
	switch state {
	case StateQueued, StateStreaming, StateCompleted, StateFailed:
		return true
	default:
		return false
	}
}
