package eventing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

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

func (s *PostgresStore) Execute(ctx context.Context, request TransactionRequest) (TransactionResult, error) {
	if err := validateTransaction(request); err != nil {
		return TransactionResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return TransactionResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenant(ctx, tx, request.TenantID); err != nil {
		return TransactionResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, request.TenantID+"\x00"+request.PrincipalID+"\x00"+request.IdempotencyKey); err != nil {
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

	eventIDs := make([]string, 0, len(request.Events))
	for _, event := range request.Events {
		metadata, marshalErr := json.Marshal(map[string]string{"correlationId": event.CorrelationID, "causationId": event.CausationID})
		if marshalErr != nil {
			return TransactionResult{}, marshalErr
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO domain_events
  (event_id, tenant_id, project_id, aggregate_type, aggregate_id, aggregate_version, event_type, schema_version, payload_jsonb, payload_sha256, metadata_jsonb, created_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, 1, $8::jsonb, $9, $10::jsonb, $11)`,
			event.EventID, request.TenantID, event.ProjectID, event.AggregateType, event.AggregateID, event.AggregateVersion, event.Type, []byte(event.Payload), event.PayloadSHA256, metadata, event.OccurredAt)
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

func syncProjectRow(ctx context.Context, tx *sql.Tx, request TransactionRequest, update ProjectionUpdate) error {
	var projection struct {
		ID                 string `json:"id"`
		State              string `json:"state"`
		Name               string `json:"name"`
		GoalAgentCount     int    `json:"goalAgentCount"`
		DataClassification string `json:"dataClassification"`
		RiskTolerance      string `json:"riskTolerance"`
		CreatedBy          string `json:"createdBy"`
	}
	if err := json.Unmarshal(update.State, &projection); err != nil {
		return fmt.Errorf("decode project projection for relational sync: %w", err)
	}
	if projection.ID == "" || projection.ID != update.AggregateID || projection.State == "" {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "project relational projection"})
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
		_, err := tx.ExecContext(ctx, `
INSERT INTO projects
  (id, tenant_id, name, state, state_version, data_classification, risk_tolerance, goal_agent_count, created_by, created_at, updated_at)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, transaction_timestamp(), transaction_timestamp())`,
			projection.ID, request.TenantID, projection.Name, projection.State, update.NextVersion, projection.DataClassification, projection.RiskTolerance, projection.GoalAgentCount, projection.CreatedBy)
		return err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE projects
SET state = $3, state_version = $4, updated_at = transaction_timestamp()
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state_version = $5`,
		request.TenantID, projection.ID, projection.State, update.NextVersion, update.ExpectedVersion)
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
	var event DomainEvent
	var payload []byte
	var metadata []byte
	err := tx.QueryRowContext(ctx, `
SELECT event_id::text, tenant_id::text, project_id::text, aggregate_type, aggregate_id, aggregate_version, event_type, payload_jsonb, payload_sha256, metadata_jsonb, created_at
FROM domain_events
WHERE tenant_id = $1::uuid AND event_id = $2::uuid`, tenantID, eventID).
		Scan(&event.EventID, &event.TenantID, &event.ProjectID, &event.AggregateType, &event.AggregateID, &event.AggregateVersion, &event.Type, &payload, &event.PayloadSHA256, &metadata, &event.OccurredAt)
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
	return event, nil
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

func cloneEvents(events []DomainEvent) []DomainEvent {
	cloned := append([]DomainEvent(nil), events...)
	for index := range cloned {
		cloned[index] = cloneEvent(cloned[index])
	}
	return cloned
}

var _ Store = (*PostgresStore)(nil)
