package eventing

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) Load(ctx context.Context, tenantID, aggregateType, aggregateID string) (Projection, bool, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Projection{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenant(ctx, tx, tenantID); err != nil {
		return Projection{}, false, err
	}
	var projection Projection
	var state []byte
	err = tx.QueryRowContext(ctx, `
SELECT tenant_id::text, project_id::text, aggregate_type, aggregate_id, aggregate_version, state_jsonb
FROM aggregate_projections
WHERE tenant_id = $1::uuid AND aggregate_type = $2 AND aggregate_id = $3`, tenantID, aggregateType, aggregateID).
		Scan(&projection.TenantID, &projection.ProjectID, &projection.AggregateType, &projection.AggregateID, &projection.Version, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return Projection{}, false, nil
	}
	if err != nil {
		return Projection{}, false, err
	}
	projection.State = cloneJSON(state)
	if err := tx.Commit(); err != nil {
		return Projection{}, false, err
	}
	return projection, true, nil
}

func (s *PostgresStore) ListProjections(ctx context.Context, tenantID, projectID, aggregateType string) ([]Projection, error) {
	if tenantID == "" || projectID == "" || aggregateType == "" {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "projection list"})
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenant(ctx, tx, tenantID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `
SELECT tenant_id::text, project_id::text, aggregate_type, aggregate_id, aggregate_version, state_jsonb
FROM aggregate_projections
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND aggregate_type = $3
ORDER BY aggregate_id`, tenantID, projectID, aggregateType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	projections := make([]Projection, 0)
	for rows.Next() {
		var projection Projection
		var state []byte
		if err := rows.Scan(&projection.TenantID, &projection.ProjectID, &projection.AggregateType, &projection.AggregateID, &projection.Version, &state); err != nil {
			return nil, err
		}
		projection.State = cloneJSON(state)
		projections = append(projections, projection)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return projections, nil
}

func (s *PostgresStore) ListTenantProjections(ctx context.Context, tenantID string) ([]Projection, error) {
	if s == nil || s.db == nil || ctx == nil || tenantID == "" {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "tenant projection catalog"})
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenant(ctx, tx, tenantID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `
SELECT tenant_id::text, project_id::text, aggregate_type, aggregate_id, aggregate_version, state_jsonb
FROM aggregate_projections
WHERE tenant_id = $1::uuid
ORDER BY aggregate_type, aggregate_id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	projections := make([]Projection, 0)
	for rows.Next() {
		var projection Projection
		var state []byte
		if err := rows.Scan(&projection.TenantID, &projection.ProjectID, &projection.AggregateType, &projection.AggregateID, &projection.Version, &state); err != nil {
			return nil, err
		}
		projection.State = cloneJSON(state)
		projections = append(projections, projection)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return projections, nil
}

func (s *PostgresStore) Lookup(ctx context.Context, tenantID, principalID, idempotencyKey, requestSHA256 string) (TransactionResult, bool, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return TransactionResult{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenant(ctx, tx, tenantID); err != nil {
		return TransactionResult{}, false, err
	}
	result, found, err := lookupCommand(ctx, tx, tenantID, principalID, idempotencyKey, requestSHA256)
	if err != nil || !found {
		return result, found, err
	}
	if err := tx.Commit(); err != nil {
		return TransactionResult{}, false, err
	}
	return result, true, nil
}

func (s *PostgresStore) ListEvents(ctx context.Context, tenantID string) ([]DomainEvent, error) {
	if s == nil || s.db == nil || ctx == nil || tenantID == "" {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "event log tenant"})
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenant(ctx, tx, tenantID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `
SELECT event_id::text, tenant_id::text, project_id::text, aggregate_type, aggregate_id,
       aggregate_version, event_type, payload_jsonb, payload_sha256, metadata_jsonb, created_at
FROM domain_events
WHERE tenant_id = $1::uuid
ORDER BY aggregate_type, aggregate_id, aggregate_version, event_id`, tenantID)
	if err != nil {
		return nil, err
	}
	events := make([]DomainEvent, 0)
	for rows.Next() {
		event, scanErr := scanEvent(rows)
		if scanErr != nil {
			_ = rows.Close()
			return nil, scanErr
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

func (s *PostgresStore) LoadReconciliationSnapshot(ctx context.Context, tenantID string) (ReconciliationSnapshot, error) {
	if s == nil || s.db == nil || ctx == nil || tenantID == "" {
		return ReconciliationSnapshot{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "reconciliation snapshot"})
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return ReconciliationSnapshot{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenant(ctx, tx, tenantID); err != nil {
		return ReconciliationSnapshot{}, err
	}
	events, err := loadReplayEvents(ctx, tx, tenantID)
	if err != nil {
		return ReconciliationSnapshot{}, err
	}
	rows, err := tx.QueryContext(ctx, `
SELECT tenant_id::text, project_id::text, aggregate_type, aggregate_id, aggregate_version, state_jsonb
FROM aggregate_projections
WHERE tenant_id = $1::uuid
ORDER BY aggregate_type, aggregate_id`, tenantID)
	if err != nil {
		return ReconciliationSnapshot{}, err
	}
	projections := make([]Projection, 0)
	for rows.Next() {
		var projection Projection
		var state []byte
		if err := rows.Scan(&projection.TenantID, &projection.ProjectID, &projection.AggregateType, &projection.AggregateID, &projection.Version, &state); err != nil {
			_ = rows.Close()
			return ReconciliationSnapshot{}, err
		}
		projection.State = cloneJSON(state)
		projections = append(projections, projection)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return ReconciliationSnapshot{}, err
	}
	if err := rows.Close(); err != nil {
		return ReconciliationSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return ReconciliationSnapshot{}, err
	}
	return ReconciliationSnapshot{Events: events, Projections: projections}, nil
}

func (s *PostgresStore) PendingOutboxTenants(ctx context.Context, now time.Time, limit int) ([]string, error) {
	if s == nil || s.db == nil || ctx == nil || now.IsZero() || limit < 1 || limit > 1000 {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "pending outbox tenants"})
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT tenant_id::text
FROM aor_pending_outbox_tenants($1, $2)`, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tenants := make([]string, 0, limit)
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		tenants = append(tenants, tenantID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tenants, nil
}

func (s *PostgresStore) Execute(ctx context.Context, request TransactionRequest) (TransactionResult, error) {
	if err := validateTransaction(request); err != nil {
		return TransactionResult{}, err
	}
	boundEvents, err := bindReplayStates(request.Events, request.Updates)
	if err != nil {
		return TransactionResult{}, err
	}
	request.Events = boundEvents
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return TransactionResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenant(ctx, tx, request.TenantID); err != nil {
		return TransactionResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, postgresAdvisoryLockKey(request.TenantID, request.PrincipalID, request.IdempotencyKey)); err != nil {
		return TransactionResult{}, err
	}
	if prior, found, err := lookupCommand(ctx, tx, request.TenantID, request.PrincipalID, request.IdempotencyKey, request.RequestSHA256); err != nil {
		return TransactionResult{}, err
	} else if found {
		if err := tx.Commit(); err != nil {
			return TransactionResult{}, err
		}
		return prior, nil
	}

	for _, update := range request.Updates {
		var version int64
		err := tx.QueryRowContext(ctx, `
SELECT aggregate_version
FROM aggregate_projections
WHERE tenant_id = $1::uuid AND aggregate_type = $2 AND aggregate_id = $3
FOR UPDATE`, request.TenantID, update.AggregateType, update.AggregateID).Scan(&version)
		if errors.Is(err, sql.ErrNoRows) {
			version = 0
		} else if err != nil {
			return TransactionResult{}, err
		}
		if version != update.ExpectedVersion {
			return TransactionResult{}, aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"expectedVersion": update.ExpectedVersion, "actualVersion": version})
		}
	}

	for _, update := range request.Updates {
		if update.AggregateType == "project" {
			if err := syncProjectRow(ctx, tx, request, update); err != nil {
				return TransactionResult{}, err
			}
		}
		if update.AggregateType == "goal_spec" {
			if err := syncGoalSpecRow(ctx, tx, request, update); err != nil {
				return TransactionResult{}, err
			}
		}
	}

	// Persist the event-sourced projections before reconciling their relational
	// counterparts. This lets a publication transaction include artifacts that
	// were supplied in the same command while every failure still rolls back.
	for _, update := range request.Updates {
		if update.ExpectedVersion == 0 {
			_, err = tx.ExecContext(ctx, `
INSERT INTO aggregate_projections
  (tenant_id, project_id, aggregate_type, aggregate_id, aggregate_version, schema_version, state_jsonb, updated_at)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, 1, $6::jsonb, transaction_timestamp())`,
				request.TenantID, update.ProjectID, update.AggregateType, update.AggregateID, update.NextVersion, []byte(update.State))
		} else {
			var result sql.Result
			result, err = tx.ExecContext(ctx, `
UPDATE aggregate_projections
SET aggregate_version = $5, state_jsonb = $6::jsonb, updated_at = transaction_timestamp()
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND aggregate_type = $3 AND aggregate_id = $4 AND aggregate_version = $7`,
				request.TenantID, update.ProjectID, update.AggregateType, update.AggregateID, update.NextVersion, []byte(update.State), update.ExpectedVersion)
			if err == nil {
				rows, rowsErr := result.RowsAffected()
				if rowsErr != nil {
					err = rowsErr
				} else if rows != 1 {
					err = aorerrors.New(aorerrors.CodeStateVersionConflict, "", nil)
				}
			}
		}
		if err != nil {
			return TransactionResult{}, err
		}
	}

	publication, err := syncPublishedPlan(ctx, tx, request)
	if err != nil {
		return TransactionResult{}, err
	}
	taskUpdates := make([]relationalTaskProjection, 0)
	for _, update := range request.Updates {
		if update.AggregateType != "task" {
			continue
		}
		task, syncErr := syncTaskRow(ctx, tx, request, update)
		if syncErr != nil {
			return TransactionResult{}, syncErr
		}
		taskUpdates = append(taskUpdates, task)
	}

	for _, approval := range request.Approvals {
		_, err = tx.ExecContext(ctx, `
INSERT INTO approvals
  (id, tenant_id, project_id, approval_type, subject_type, subject_id, subject_version, subject_sha256, principal_id, reason, constraints_jsonb, issued_at, expires_at, revoked_at, signature)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9, $10, '{}'::jsonb, $11, $12, $13, $14)`,
			approval.ID, approval.TenantID, approval.ProjectID, approval.ApprovalType, approval.SubjectType, approval.SubjectID, approval.SubjectVersion, approval.SubjectSHA256,
			approval.PrincipalID, approval.Reason, approval.IssuedAt, approval.ExpiresAt, approval.RevokedAt, approval.Signature)
		if err != nil {
			return TransactionResult{}, err
		}
	}
	for _, task := range taskUpdates {
		if err := syncTaskAttemptSeries(ctx, tx, request, task); err != nil {
			return TransactionResult{}, err
		}
	}
	if publication != nil {
		if err := validatePublishedPlanTasks(ctx, tx, request, *publication); err != nil {
			return TransactionResult{}, err
		}
	} else {
		for _, task := range taskUpdates {
			if err := syncTaskDependencies(ctx, tx, request.TenantID, task); err != nil {
				return TransactionResult{}, err
			}
			if err := validateRelationalTaskRow(ctx, tx, request.TenantID, task); err != nil {
				return TransactionResult{}, err
			}
		}
	}
	for _, update := range request.Updates {
		if update.AggregateType == "project" {
			if err := syncProjectSpecBindings(ctx, tx, request, update); err != nil {
				return TransactionResult{}, err
			}
		}
	}

	eventIDs := make([]string, 0, len(request.Events))
	for _, event := range request.Events {
		metadata, marshalErr := json.Marshal(map[string]string{"correlationId": event.CorrelationID, "causationId": event.CausationID, "traceparent": event.Traceparent, "tracestate": event.Tracestate, "taskId": event.TaskID, "taskIdReason": event.TaskIDReason, "agentRunId": event.AgentRunID, "agentRunReason": event.AgentRunReason})
		if marshalErr != nil {
			return TransactionResult{}, marshalErr
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO domain_events
  (event_id, tenant_id, project_id, aggregate_type, aggregate_id, aggregate_version, event_type, schema_version,
   payload_jsonb, payload_sha256, replay_state_jsonb, replay_state_sha256, metadata_jsonb, created_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, 1, $8::jsonb, $9, $10::jsonb, $11, $12::jsonb, $13)`,
			event.EventID, request.TenantID, event.ProjectID, event.AggregateType, event.AggregateID, event.AggregateVersion, event.Type,
			[]byte(event.Payload), event.PayloadSHA256, []byte(event.ReplayState), event.ReplayStateSHA256, metadata, event.OccurredAt)
		if err != nil {
			return TransactionResult{}, err
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO outbox (id, tenant_id, event_id, payload_jsonb, attempt_count, next_attempt_at)
VALUES ($1::uuid, $2::uuid, $1::uuid, $3::jsonb, 0, $4)`, event.EventID, request.TenantID, []byte(event.Payload), event.OccurredAt)
		if err != nil {
			return TransactionResult{}, err
		}
		eventIDs = append(eventIDs, event.EventID)
	}
	eventIDsJSON, err := json.Marshal(eventIDs)
	if err != nil {
		return TransactionResult{}, err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO command_results
  (tenant_id, principal_id, idempotency_key, request_sha256, result_jsonb, result_sha256, event_ids_jsonb)
VALUES ($1::uuid, $2, $3, $4, $5::jsonb, $6, $7::jsonb)`,
		request.TenantID, request.PrincipalID, request.IdempotencyKey, request.RequestSHA256, []byte(request.Result), request.ResultSHA256, eventIDsJSON)
	if err != nil {
		return TransactionResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return TransactionResult{}, err
	}
	return TransactionResult{Result: cloneJSON(request.Result), Events: cloneEvents(request.Events)}, nil
}

func (s *PostgresStore) ClaimOutbox(ctx context.Context, tenantID string, now time.Time, limit int, lease time.Duration) ([]OutboxClaim, error) {
	if tenantID == "" || now.IsZero() || limit <= 0 || lease <= 0 {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "outbox claim"})
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenant(ctx, tx, tenantID); err != nil {
		return nil, err
	}
	claimUntil := now.Add(lease)
	rows, err := tx.QueryContext(ctx, `
WITH ready AS (
  SELECT id
  FROM outbox
  WHERE tenant_id = $1::uuid AND published_at IS NULL AND next_attempt_at <= $2
  ORDER BY next_attempt_at, id
  LIMIT $3
  FOR UPDATE SKIP LOCKED
), claimed AS (
  UPDATE outbox AS item
  SET attempt_count = item.attempt_count + 1, next_attempt_at = $4
  FROM ready
  WHERE item.id = ready.id
  RETURNING item.id, item.tenant_id, item.event_id, item.attempt_count, item.next_attempt_at
)
SELECT claimed.id::text, event.event_id::text, event.tenant_id::text, event.project_id::text,
       event.aggregate_type, event.aggregate_id, event.aggregate_version, event.event_type,
       event.payload_jsonb, event.payload_sha256, event.metadata_jsonb, event.created_at,
       claimed.attempt_count, claimed.next_attempt_at
FROM claimed
JOIN domain_events AS event
  ON event.tenant_id = claimed.tenant_id AND event.event_id = claimed.event_id
ORDER BY claimed.next_attempt_at, claimed.id`, tenantID, now, limit, claimUntil)
	if err != nil {
		return nil, err
	}
	claims := make([]OutboxClaim, 0, limit)
	for rows.Next() {
		var record OutboxRecord
		var event DomainEvent
		var payload []byte
		var metadata []byte
		if err := rows.Scan(
			&record.ID, &event.EventID, &event.TenantID, &event.ProjectID,
			&event.AggregateType, &event.AggregateID, &event.AggregateVersion, &event.Type,
			&payload, &event.PayloadSHA256, &metadata, &event.OccurredAt,
			&record.Attempts, &record.NextAttempt,
		); err != nil {
			_ = rows.Close()
			return nil, err
		}
		var values map[string]string
		if err := json.Unmarshal(metadata, &values); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("decode outbox event metadata: %w", err)
		}
		event.Payload = cloneJSON(payload)
		event.CorrelationID = values["correlationId"]
		event.CausationID = values["causationId"]
		event.Traceparent = values["traceparent"]
		event.Tracestate = values["tracestate"]
		event.TaskID = values["taskId"]
		event.TaskIDReason = values["taskIdReason"]
		event.AgentRunID = values["agentRunId"]
		event.AgentRunReason = values["agentRunReason"]
		record.Event = event
		claims = append(claims, OutboxClaim{Record: record, Attempt: record.Attempts})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return claims, nil
}

func (s *PostgresStore) MarkOutboxPublished(ctx context.Context, tenantID, outboxID string, attempt int, publishedAt time.Time) error {
	if tenantID == "" || outboxID == "" || attempt <= 0 || publishedAt.IsZero() {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "outbox publish"})
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenant(ctx, tx, tenantID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE outbox
SET published_at = $4, next_attempt_at = $4
WHERE tenant_id = $1::uuid AND id = $2::uuid AND attempt_count = $3 AND published_at IS NULL`, tenantID, outboxID, attempt, publishedAt)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrOutboxClaimLost
	}
	return tx.Commit()
}

func (s *PostgresStore) RetryOutbox(ctx context.Context, tenantID, outboxID string, attempt int, nextAttempt time.Time) error {
	if tenantID == "" || outboxID == "" || attempt <= 0 || nextAttempt.IsZero() {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "outbox retry"})
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenant(ctx, tx, tenantID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE outbox
SET next_attempt_at = $4
WHERE tenant_id = $1::uuid AND id = $2::uuid AND attempt_count = $3 AND published_at IS NULL`, tenantID, outboxID, attempt, nextAttempt)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrOutboxClaimLost
	}
	return tx.Commit()
}

func syncProjectRow(ctx context.Context, tx *sql.Tx, request TransactionRequest, update ProjectionUpdate) error {
	var projection struct {
		TenantID             string   `json:"tenantId"`
		ID                   string   `json:"id"`
		State                string   `json:"state"`
		Name                 string   `json:"name"`
		GoalAgentCount       int      `json:"goalAgentCount"`
		DataClassification   string   `json:"dataClassification"`
		DeploymentTargets    []string `json:"deploymentTargets"`
		BudgetCurrency       string   `json:"budgetCurrency"`
		BudgetHardLimitMinor int64    `json:"budgetHardLimitMinor"`
		BudgetSoftLimitMinor int64    `json:"budgetSoftLimitMinor"`
		PromptBundleVersion  string   `json:"promptBundleVersion"`
		RiskTolerance        string   `json:"riskTolerance"`
		CreatedBy            string   `json:"createdBy"`
		Deletion             *struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"deletion"`
	}
	if err := json.Unmarshal(update.State, &projection); err != nil {
		return fmt.Errorf("decode project projection for relational sync: %w", err)
	}
	if projection.TenantID != request.TenantID || projection.ID == "" || projection.ID != update.AggregateID || projection.State == "" {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "project relational projection"})
	}
	var deletionStatus any
	var deletionID any
	if projection.Deletion != nil {
		if projection.Deletion.ID == "" || projection.Deletion.Status == "" {
			return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "project deletion relational projection"})
		}
		deletionStatus = projection.Deletion.Status
		deletionID = projection.Deletion.ID
	}
	if update.ExpectedVersion == 0 {
		if projection.Name == "" {
			projection.Name = projection.ID
		}
		if projection.DataClassification == "" {
			projection.DataClassification = "INTERNAL"
		}
		if projection.RiskTolerance == "" {
			projection.RiskTolerance = "MEDIUM"
		}
		if projection.CreatedBy == "" {
			projection.CreatedBy = request.PrincipalID
		}
		if projection.BudgetCurrency == "" {
			projection.BudgetCurrency = "USD"
		}
		deploymentTargets, err := json.Marshal(projection.DeploymentTargets)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO projects
	  (id, tenant_id, name, state, state_version, data_classification, deployment_targets_jsonb,
	   risk_tolerance, goal_agent_count, created_by, deletion_status, deletion_id, created_at, updated_at)
	VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11, $12, transaction_timestamp(), transaction_timestamp())`,
			projection.ID, request.TenantID, projection.Name, projection.State, update.NextVersion, projection.DataClassification, deploymentTargets, projection.RiskTolerance, projection.GoalAgentCount, projection.CreatedBy, deletionStatus, deletionID)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO budget_accounts
  (tenant_id, id, scope_type, scope_id, currency, hard_limit_micros, soft_limit_micros,
   spent_micros, reserved_micros, period_start, version)
VALUES ($1::uuid, $2, 'PROJECT', $2, $3, $4, $5, 0, 0, transaction_timestamp(), 1)`,
			request.TenantID, projection.ID, projection.BudgetCurrency, projection.BudgetHardLimitMinor, projection.BudgetSoftLimitMinor)
		if err != nil {
			return err
		}
		if projection.PromptBundleVersion == "" {
			return nil
		}
		roles := []string{"GOAL_PROPOSER"}
		if projection.GoalAgentCount == 2 {
			roles = append(roles, "GOAL_CHALLENGER")
		}
		for _, role := range roles {
			agentID := projection.ID + ":" + role
			_, err = tx.ExecContext(ctx, `
INSERT INTO agent_instances
  (id, tenant_id, project_id, role, provider, logical_model, actual_model_version,
   prompt_bundle_version, state, created_at)
VALUES ($1, $2::uuid, $3::uuid, $4, 'UNASSIGNED', 'UNASSIGNED', 'UNASSIGNED', $5, 'DECLARED', transaction_timestamp())`,
				agentID, request.TenantID, projection.ID, role, projection.PromptBundleVersion)
			if err != nil {
				return err
			}
		}
		return nil
	}
	result, err := tx.ExecContext(ctx, `
UPDATE projects
SET state = $3, state_version = $4,
	deletion_status = $6, deletion_id = $7,
	    archived_at = CASE WHEN $3 = 'ARCHIVED' THEN transaction_timestamp() ELSE archived_at END,
	    updated_at = transaction_timestamp()
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state_version = $5`,
		request.TenantID, projection.ID, projection.State, update.NextVersion, update.ExpectedVersion, deletionStatus, deletionID)
	if err == nil {
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return rowsErr
		}
		if rows != 1 {
			return aorerrors.New(aorerrors.CodeStateVersionConflict, "", nil)
		}
	}
	return err
}

func syncGoalSpecRow(ctx context.Context, tx *sql.Tx, request TransactionRequest, update ProjectionUpdate) error {
	var projection struct {
		TenantID   string `json:"tenantId"`
		ProjectID  string `json:"projectId"`
		GoalSpecID string `json:"goalSpecId"`
		RecordID   string `json:"recordId"`
		Spec       struct {
			Content    json.RawMessage `json:"content"`
			Status     string          `json:"status"`
			ApprovedBy *struct {
				ActorID    string `json:"actorId"`
				ApprovedAt string `json:"approvedAt"`
			} `json:"approvedBy"`
			ContentSHA256 string `json:"contentSha256"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(update.State, &projection); err != nil {
		return fmt.Errorf("decode GoalSpec projection for relational sync: %w", err)
	}
	var content struct {
		GoalSpecVersion int    `json:"goalSpecVersion"`
		Version         int    `json:"version"`
		ProjectID       string `json:"projectId"`
		CreatedBy       struct {
			AgentInstanceID string `json:"agentInstanceId"`
		} `json:"createdBy"`
	}
	if err := json.Unmarshal(projection.Spec.Content, &content); err != nil {
		return fmt.Errorf("decode GoalSpec content for relational sync: %w", err)
	}
	if projection.TenantID != request.TenantID || projection.ProjectID != update.ProjectID || projection.ProjectID != content.ProjectID || projection.GoalSpecID == "" || projection.RecordID == "" || projection.Spec.ContentSHA256 == "" || content.GoalSpecVersion < 1 || content.Version < 1 || content.CreatedBy.AgentInstanceID == "" {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "GoalSpec relational projection"})
	}
	var approvedBy any
	var approvedAt any
	if projection.Spec.ApprovedBy != nil {
		approvedBy = projection.Spec.ApprovedBy.ActorID
		approvedAt = projection.Spec.ApprovedBy.ApprovedAt
	}
	if projection.Spec.Status == "APPROVED" && (approvedBy == nil || approvedAt == nil) || projection.Spec.Status != "APPROVED" && (approvedBy != nil || approvedAt != nil) {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "GoalSpec approval projection"})
	}
	if update.ExpectedVersion == 0 {
		_, err := tx.ExecContext(ctx, `
INSERT INTO goal_specs
  (id, tenant_id, project_id, version, status, schema_version, content_jsonb, content_sha256, proposer_agent_id, approved_by, approved_at, created_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7::jsonb, $8, $9, $10, $11, transaction_timestamp())`,
			projection.RecordID, request.TenantID, projection.ProjectID, content.Version, projection.Spec.Status, content.GoalSpecVersion,
			[]byte(projection.Spec.Content), projection.Spec.ContentSHA256, content.CreatedBy.AgentInstanceID, approvedBy, approvedAt)
		if err != nil {
			return err
		}
	} else {
		result, err := tx.ExecContext(ctx, `
UPDATE goal_specs
SET status = $6, approved_by = $7, approved_at = $8
WHERE tenant_id = $1::uuid AND id = $2::uuid AND project_id = $3::uuid
  AND version = $4 AND content_sha256 = $5`,
			request.TenantID, projection.RecordID, projection.ProjectID, content.Version, projection.Spec.ContentSHA256, projection.Spec.Status, approvedBy, approvedAt)
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 1 {
			return aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"scope": "GoalSpec relational projection"})
		}
	}
	if projection.Spec.Status == "APPROVED" {
		_, err := tx.ExecContext(ctx, `
UPDATE projects
SET active_goal_spec_id = $3::uuid
WHERE tenant_id = $1::uuid AND id = $2::uuid`, request.TenantID, projection.ProjectID, projection.RecordID)
		return err
	}
	if projection.Spec.Status == "SUPERSEDED" || projection.Spec.Status == "REJECTED" {
		_, err := tx.ExecContext(ctx, `
UPDATE projects
SET active_goal_spec_id = NULL
WHERE tenant_id = $1::uuid AND id = $2::uuid AND active_goal_spec_id = $3::uuid`, request.TenantID, projection.ProjectID, projection.RecordID)
		return err
	}
	return nil
}

func lookupCommand(ctx context.Context, tx *sql.Tx, tenantID, principalID, idempotencyKey, requestSHA256 string) (TransactionResult, bool, error) {
	var storedRequestSHA string
	var resultJSON []byte
	var eventIDsJSON []byte
	err := tx.QueryRowContext(ctx, `
SELECT request_sha256, result_jsonb, event_ids_jsonb
FROM command_results
WHERE tenant_id = $1::uuid AND principal_id = $2 AND idempotency_key = $3`, tenantID, principalID, idempotencyKey).
		Scan(&storedRequestSHA, &resultJSON, &eventIDsJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return TransactionResult{}, false, nil
	}
	if err != nil {
		return TransactionResult{}, false, err
	}
	if storedRequestSHA != requestSHA256 {
		return TransactionResult{}, false, aorerrors.New(aorerrors.CodeIdempotencyConflict, "", nil)
	}
	var eventIDs []string
	if err := json.Unmarshal(eventIDsJSON, &eventIDs); err != nil {
		return TransactionResult{}, false, fmt.Errorf("decode command event IDs: %w", err)
	}
	events := make([]DomainEvent, 0, len(eventIDs))
	for _, eventID := range eventIDs {
		event, err := loadEvent(ctx, tx, tenantID, eventID)
		if err != nil {
			return TransactionResult{}, false, err
		}
		events = append(events, event)
	}
	return TransactionResult{Result: cloneJSON(resultJSON), Events: events, Duplicate: true}, true, nil
}

func loadEvent(ctx context.Context, tx *sql.Tx, tenantID, eventID string) (DomainEvent, error) {
	row := tx.QueryRowContext(ctx, `
SELECT event_id::text, tenant_id::text, project_id::text, aggregate_type, aggregate_id, aggregate_version, event_type, payload_jsonb, payload_sha256, metadata_jsonb, created_at
FROM domain_events
WHERE tenant_id = $1::uuid AND event_id = $2::uuid`, tenantID, eventID)
	return scanEvent(row)
}

type eventScanner interface {
	Scan(dest ...any) error
}

func scanEvent(scanner eventScanner) (DomainEvent, error) {
	var event DomainEvent
	var payload []byte
	var metadata []byte
	err := scanner.Scan(&event.EventID, &event.TenantID, &event.ProjectID, &event.AggregateType, &event.AggregateID, &event.AggregateVersion, &event.Type, &payload, &event.PayloadSHA256, &metadata, &event.OccurredAt)
	if err != nil {
		return DomainEvent{}, err
	}
	event.Payload = cloneJSON(payload)
	var values map[string]string
	if err := json.Unmarshal(metadata, &values); err != nil {
		return DomainEvent{}, err
	}
	event.CorrelationID = values["correlationId"]
	event.CausationID = values["causationId"]
	event.Traceparent = values["traceparent"]
	event.Tracestate = values["tracestate"]
	event.TaskID = values["taskId"]
	event.TaskIDReason = values["taskIdReason"]
	event.AgentRunID = values["agentRunId"]
	event.AgentRunReason = values["agentRunReason"]
	return event, nil
}

func loadReplayEvents(ctx context.Context, tx *sql.Tx, tenantID string) ([]DomainEvent, error) {
	events, err := loadStoredEvents(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	legacy := false
	for _, event := range events {
		if len(event.ReplayState) == 0 {
			legacy = true
			break
		}
	}
	if !legacy {
		return events, nil
	}
	candidates, err := loadReplayResultCandidates(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	for index, event := range events {
		if len(event.ReplayState) != 0 {
			continue
		}
		events[index], err = deriveReplayState(event, candidates[event.EventID])
		if err != nil {
			return nil, err
		}
	}
	return events, nil
}

func loadStoredEvents(ctx context.Context, tx *sql.Tx, tenantID string) ([]DomainEvent, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT event_id::text, tenant_id::text, project_id::text, aggregate_type, aggregate_id,
       aggregate_version, event_type, payload_jsonb, payload_sha256,
       replay_state_jsonb, replay_state_sha256, metadata_jsonb, created_at
FROM domain_events
WHERE tenant_id = $1::uuid
ORDER BY aggregate_type, aggregate_id, aggregate_version, event_id`, tenantID)
	if err != nil {
		return nil, err
	}
	events := make([]DomainEvent, 0)
	for rows.Next() {
		event, scanErr := scanReplayEvent(rows)
		if scanErr != nil {
			_ = rows.Close()
			return nil, scanErr
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return events, nil
}

func scanReplayEvent(scanner eventScanner) (DomainEvent, error) {
	var event DomainEvent
	var payload, replayState, metadata []byte
	var replayStateSHA256 sql.NullString
	err := scanner.Scan(
		&event.EventID, &event.TenantID, &event.ProjectID, &event.AggregateType, &event.AggregateID,
		&event.AggregateVersion, &event.Type, &payload, &event.PayloadSHA256,
		&replayState, &replayStateSHA256, &metadata, &event.OccurredAt,
	)
	if err != nil {
		return DomainEvent{}, err
	}
	if (len(replayState) == 0) != !replayStateSHA256.Valid {
		return DomainEvent{}, ErrReplayStateUnavailable
	}
	event.Payload = cloneJSON(payload)
	if len(replayState) != 0 {
		bound, err := bindReplayState(event, replayState)
		if err != nil || bound.ReplayStateSHA256 != replayStateSHA256.String {
			return DomainEvent{}, ErrReplayStateUnavailable
		}
		event.ReplayState = bound.ReplayState
		event.ReplayStateSHA256 = bound.ReplayStateSHA256
	}
	if err := applyEventMetadata(&event, metadata); err != nil {
		return DomainEvent{}, err
	}
	return event, nil
}

func loadReplayResultCandidates(ctx context.Context, tx *sql.Tx, tenantID string) (map[string][]replayResultCandidate, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT result_jsonb, result_sha256, event_ids_jsonb
FROM command_results
WHERE tenant_id = $1::uuid
ORDER BY principal_id, idempotency_key`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string][]replayResultCandidate)
	for rows.Next() {
		var rawResult, rawEventIDs []byte
		var resultSHA256 string
		if err := rows.Scan(&rawResult, &resultSHA256, &rawEventIDs); err != nil {
			return nil, err
		}
		var eventIDs []string
		if json.Unmarshal(rawEventIDs, &eventIDs) != nil || len(eventIDs) == 0 {
			return nil, ErrReplayStateUnavailable
		}
		candidate := replayResultCandidate{EventIDs: append([]string(nil), eventIDs...), Result: cloneJSON(rawResult), ResultSHA256: resultSHA256}
		for _, eventID := range eventIDs {
			if eventID == "" {
				return nil, ErrReplayStateUnavailable
			}
			result[eventID] = append(result[eventID], candidate)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func applyEventMetadata(event *DomainEvent, metadata []byte) error {
	var values map[string]string
	if err := json.Unmarshal(metadata, &values); err != nil {
		return err
	}
	event.CorrelationID = values["correlationId"]
	event.CausationID = values["causationId"]
	event.Traceparent = values["traceparent"]
	event.Tracestate = values["tracestate"]
	event.TaskID = values["taskId"]
	event.TaskIDReason = values["taskIdReason"]
	event.AgentRunID = values["agentRunId"]
	event.AgentRunReason = values["agentRunReason"]
	return nil
}

func setTenant(ctx context.Context, tx *sql.Tx, tenantID string) error {
	if tenantID == "" {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "tenant"})
	}
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

func postgresAdvisoryLockKey(tenantID, principalID, idempotencyKey string) string {
	digest := sha256.Sum256([]byte(tenantID + "\x00" + principalID + "\x00" + idempotencyKey))
	return hex.EncodeToString(digest[:])
}

func cloneEvents(events []DomainEvent) []DomainEvent {
	cloned := append([]DomainEvent(nil), events...)
	for index := range cloned {
		cloned[index] = cloneEvent(cloned[index])
	}
	return cloned
}

var _ Store = (*PostgresStore)(nil)
var _ OutboxStore = (*PostgresStore)(nil)
var _ EventLog = (*PostgresStore)(nil)
var _ OutboxTenantSource = (*PostgresStore)(nil)
var _ ReconciliationSource = (*PostgresStore)(nil)
