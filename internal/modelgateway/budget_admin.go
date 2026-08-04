package modelgateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/google/uuid"
)

const budgetAdjustedEventType = "io.aor.budget.adjusted.v1"

func (ledger *PostgresBudgetLedger) ListAccounts(ctx context.Context, tenantID, projectID string) ([]BudgetAccount, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if tenantID == "" || projectID == "" {
		return nil, ErrInvalidRequest
	}
	tx, err := ledger.beginReadOnly(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
SELECT id, tenant_id::text, scope_type, scope_id, currency, hard_limit_micros,
       soft_limit_micros, reserved_micros, spent_micros, period_start, period_end, version
FROM budget_accounts
WHERE tenant_id = $1::uuid AND scope_type = 'PROJECT' AND scope_id = $2
ORDER BY id`, tenantID, projectID)
	if err != nil {
		return nil, err
	}
	accounts := make([]BudgetAccount, 0, 1)
	for rows.Next() {
		var account BudgetAccount
		if err := rows.Scan(
			&account.ID, &account.TenantID, &account.ScopeType, &account.ScopeID, &account.Currency,
			&account.LimitMicros, &account.SoftLimitMicros, &account.ReservedMicros, &account.SpentMicros,
			&account.PeriodStart, &account.PeriodEnd, &account.Version,
		); err != nil {
			_ = rows.Close()
			return nil, err
		}
		accounts = append(accounts, account)
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
	return accounts, nil
}

func (ledger *PostgresBudgetLedger) Usage(ctx context.Context, tenantID, projectID string) (BudgetUsage, error) {
	if err := contextError(ctx); err != nil {
		return BudgetUsage{}, err
	}
	if tenantID == "" || projectID == "" {
		return BudgetUsage{}, ErrInvalidRequest
	}
	tx, err := ledger.beginReadOnly(ctx, tenantID)
	if err != nil {
		return BudgetUsage{}, err
	}
	defer func() { _ = tx.Rollback() }()
	account, found, err := loadProjectBudgetAccount(ctx, tx, tenantID, projectID, false)
	if err != nil {
		return BudgetUsage{}, err
	}
	if !found {
		return BudgetUsage{}, ErrBudgetAccountNotFound
	}
	usage, err := loadBudgetUsage(ctx, tx, tenantID, projectID, account)
	if err != nil {
		return BudgetUsage{}, err
	}
	if err := tx.Commit(); err != nil {
		return BudgetUsage{}, err
	}
	return usage, nil
}

func (ledger *PostgresBudgetLedger) Adjust(ctx context.Context, adjustment BudgetAdjustment) (BudgetAdjustmentResult, error) {
	if err := contextError(ctx); err != nil {
		return BudgetAdjustmentResult{}, err
	}
	if err := prepareBudgetAdjustment(&adjustment); err != nil {
		return BudgetAdjustmentResult{}, ErrInvalidRequest
	}
	requestDigest, err := budgetAdjustmentDigest(adjustment)
	if err != nil {
		return BudgetAdjustmentResult{}, err
	}
	tx, err := ledger.begin(ctx, adjustment.TenantID)
	if err != nil {
		return BudgetAdjustmentResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	lockKey, err := json.Marshal([]string{adjustment.TenantID, adjustment.PrincipalID, adjustment.IdempotencyKey})
	if err != nil {
		return BudgetAdjustmentResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, string(lockKey)); err != nil {
		return BudgetAdjustmentResult{}, err
	}
	prior, found, err := loadBudgetAdjustmentResult(ctx, tx, adjustment, requestDigest)
	if err != nil {
		return BudgetAdjustmentResult{}, err
	}
	if found {
		if err := tx.Commit(); err != nil {
			return BudgetAdjustmentResult{}, err
		}
		prior.Duplicate = true
		return prior, nil
	}
	if adjustment.ProjectVersion > 0 {
		var projectState string
		var projectVersion int64
		err := tx.QueryRowContext(ctx, `
SELECT state, state_version
FROM projects
WHERE tenant_id = $1::uuid AND id = $2::uuid
FOR SHARE`, adjustment.TenantID, adjustment.ProjectID).Scan(&projectState, &projectVersion)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && (projectVersion != adjustment.ProjectVersion || projectState != adjustment.ProjectState)) {
			return BudgetAdjustmentResult{}, ErrBudgetProjectConflict
		}
		if err != nil {
			return BudgetAdjustmentResult{}, err
		}
	}

	account, found, err := loadProjectBudgetAccount(ctx, tx, adjustment.TenantID, adjustment.ProjectID, true)
	if err != nil {
		return BudgetAdjustmentResult{}, err
	}
	if !found {
		return BudgetAdjustmentResult{}, ErrBudgetAccountNotFound
	}
	if account.Version != adjustment.ExpectedVersion {
		return BudgetAdjustmentResult{}, ErrBudgetVersionConflict
	}
	if account.Currency != adjustment.Currency {
		return BudgetAdjustmentResult{}, ErrBudgetCurrencyConflict
	}
	if !budgetPeriodOpen(ledger.clock().UTC(), account) {
		return BudgetAdjustmentResult{}, ErrBudgetPeriodClosed
	}
	if adjustment.SoftLimitMicros > adjustment.HardLimitMicros || adjustment.HardLimitMicros < account.SpentMicros+account.ReservedMicros {
		return BudgetAdjustmentResult{}, ErrBudgetLimitConflict
	}
	result, err := tx.ExecContext(ctx, `
UPDATE budget_accounts
SET hard_limit_micros = $4, soft_limit_micros = $5, version = version + 1
WHERE tenant_id = $1::uuid AND id = $2 AND version = $3`,
		adjustment.TenantID, account.ID, adjustment.ExpectedVersion, adjustment.HardLimitMicros, adjustment.SoftLimitMicros)
	if err != nil {
		return BudgetAdjustmentResult{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return BudgetAdjustmentResult{}, err
	}
	if rows != 1 {
		return BudgetAdjustmentResult{}, ErrBudgetVersionConflict
	}
	account.LimitMicros = adjustment.HardLimitMicros
	account.SoftLimitMicros = adjustment.SoftLimitMicros
	account.Version++
	usage, err := loadBudgetUsage(ctx, tx, adjustment.TenantID, adjustment.ProjectID, account)
	if err != nil {
		return BudgetAdjustmentResult{}, err
	}
	adjusted := BudgetAdjustmentResult{Account: account, Usage: usage}
	if err := persistBudgetAdjustment(ctx, tx, ledger.clock().UTC(), adjustment, adjusted, requestDigest); err != nil {
		return BudgetAdjustmentResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return BudgetAdjustmentResult{}, err
	}
	return adjusted, nil
}

func loadBudgetUsage(ctx context.Context, tx *sql.Tx, tenantID, projectID string, account BudgetAccount) (BudgetUsage, error) {
	usage := usageFromAccount(account)
	if err := tx.QueryRowContext(ctx, `
SELECT count(*)
FROM budget_reservations
	WHERE tenant_id = $1::uuid AND account_id = $2
	  AND created_at >= $3
	  AND ($4::timestamptz IS NULL OR created_at < $4::timestamptz)`, tenantID, account.ID, account.PeriodStart, account.PeriodEnd).Scan(&usage.ReservationCount); err != nil {
		return BudgetUsage{}, err
	}
	if err := tx.QueryRowContext(ctx, `
SELECT count(*), coalesce(sum(input_tokens), 0), coalesce(sum(output_tokens), 0), coalesce(sum(cost_micros), 0)
FROM model_calls
	WHERE tenant_id = $1::uuid AND project_id = $2::uuid
	  AND created_at >= $3
	  AND ($4::timestamptz IS NULL OR created_at < $4::timestamptz)`, tenantID, projectID, account.PeriodStart, account.PeriodEnd).
		Scan(&usage.CallCount, &usage.InputTokens, &usage.OutputTokens, &usage.CostMicros); err != nil {
		return BudgetUsage{}, err
	}
	return usage, nil
}

func loadBudgetAdjustmentResult(ctx context.Context, tx *sql.Tx, adjustment BudgetAdjustment, requestDigest string) (BudgetAdjustmentResult, bool, error) {
	var storedDigest string
	var resultJSON []byte
	var storedResultDigest string
	err := tx.QueryRowContext(ctx, `
SELECT request_sha256, result_jsonb, result_sha256
FROM command_results
WHERE tenant_id = $1::uuid AND principal_id = $2 AND idempotency_key = $3`,
		adjustment.TenantID, adjustment.PrincipalID, adjustment.IdempotencyKey).Scan(&storedDigest, &resultJSON, &storedResultDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return BudgetAdjustmentResult{}, false, nil
	}
	if err != nil {
		return BudgetAdjustmentResult{}, false, err
	}
	if storedDigest != requestDigest {
		return BudgetAdjustmentResult{}, false, ErrBudgetIdempotencyConflict
	}
	resultDigest, err := canonicaljson.Digest(resultJSON)
	if err != nil || resultDigest != storedResultDigest {
		return BudgetAdjustmentResult{}, false, ErrBudgetIdempotencyConflict
	}
	var result BudgetAdjustmentResult
	if err := json.Unmarshal(resultJSON, &result); err != nil || result.Account.ID == "" || result.Account.TenantID != adjustment.TenantID || result.Account.ScopeID != adjustment.ProjectID || result.Account.Version < 1 {
		return BudgetAdjustmentResult{}, false, ErrBudgetIdempotencyConflict
	}
	return result, true, nil
}

func persistBudgetAdjustment(ctx context.Context, tx *sql.Tx, occurredAt time.Time, adjustment BudgetAdjustment, result BudgetAdjustmentResult, requestDigest string) error {
	eventID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		TenantID         string   `json:"tenantId"`
		ProjectID        string   `json:"projectId"`
		AccountID        string   `json:"accountId"`
		PrincipalID      string   `json:"principalId"`
		ProjectState     string   `json:"projectState,omitempty"`
		ProjectVersion   int64    `json:"projectVersion,omitempty"`
		PreviousVersion  int64    `json:"previousVersion"`
		AggregateVersion int64    `json:"aggregateVersion"`
		Version          int64    `json:"version"`
		HardLimitMicros  int64    `json:"hardLimitMinor"`
		SoftLimitMicros  int64    `json:"softLimitMinor"`
		Currency         string   `json:"currency"`
		Reason           string   `json:"reason"`
		ParameterDigest  string   `json:"parameterDigest,omitempty"`
		PolicyVersion    string   `json:"policyVersion,omitempty"`
		PolicyRuleID     string   `json:"ruleId,omitempty"`
		PolicyDecision   string   `json:"policyDecision,omitempty"`
		PolicyReasons    []string `json:"policyReasons,omitempty"`
	}{
		TenantID: adjustment.TenantID, ProjectID: adjustment.ProjectID, AccountID: result.Account.ID,
		PrincipalID: adjustment.PrincipalID, ProjectState: adjustment.ProjectState, ProjectVersion: adjustment.ProjectVersion,
		PreviousVersion:  adjustment.ExpectedVersion,
		AggregateVersion: result.Account.Version, Version: result.Account.Version,
		HardLimitMicros: result.Account.LimitMicros, SoftLimitMicros: result.Account.SoftLimitMicros,
		Currency: result.Account.Currency, Reason: adjustment.Reason, ParameterDigest: adjustment.ParameterDigest,
		PolicyVersion: adjustment.PolicyVersion, PolicyRuleID: adjustment.PolicyRuleID,
		PolicyDecision: adjustment.PolicyDecision, PolicyReasons: append([]string(nil), adjustment.PolicyReasons...),
	})
	if err != nil {
		return err
	}
	payloadDigest, err := canonicaljson.Digest(payload)
	if err != nil {
		return err
	}
	metadata, err := json.Marshal(map[string]string{
		"correlationId": "corr_" + strings.TrimPrefix(requestDigest, "sha256:"),
		"traceparent":   adjustment.Traceparent, "tracestate": adjustment.Tracestate,
		"taskIdReason": "NOT_CREATED", "agentRunReason": "NOT_CREATED",
	})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO domain_events
  (event_id, tenant_id, project_id, aggregate_type, aggregate_id, aggregate_version,
   event_type, schema_version, payload_jsonb, payload_sha256, metadata_jsonb, created_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, 'budget', $4, $5, $6, 1, $7::jsonb, $8, $9::jsonb, $10)`,
		eventID.String(), adjustment.TenantID, adjustment.ProjectID, result.Account.ID, result.Account.Version,
		budgetAdjustedEventType, payload, payloadDigest, metadata, occurredAt); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO outbox (id, tenant_id, event_id, payload_jsonb, attempt_count, next_attempt_at)
VALUES ($1::uuid, $2::uuid, $1::uuid, $3::jsonb, 0, $4)`, eventID.String(), adjustment.TenantID, payload, occurredAt); err != nil {
		return err
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return err
	}
	resultDigest, err := canonicaljson.Digest(resultJSON)
	if err != nil {
		return err
	}
	eventIDs, err := json.Marshal([]string{eventID.String()})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO command_results
  (tenant_id, principal_id, idempotency_key, request_sha256, result_jsonb, result_sha256, event_ids_jsonb)
VALUES ($1::uuid, $2, $3, $4, $5::jsonb, $6, $7::jsonb)`, adjustment.TenantID,
		adjustment.PrincipalID, adjustment.IdempotencyKey, requestDigest, resultJSON, resultDigest, eventIDs)
	return err
}

func budgetAdjustmentDigest(adjustment BudgetAdjustment) (string, error) {
	payload, err := json.Marshal(struct {
		TenantID        string `json:"tenantId"`
		ProjectID       string `json:"projectId"`
		PrincipalID     string `json:"principalId"`
		ExpectedVersion int64  `json:"expectedVersion"`
		HardLimitMicros int64  `json:"hardLimitMinor"`
		SoftLimitMicros int64  `json:"softLimitMinor"`
		Currency        string `json:"currency"`
		Reason          string `json:"reason"`
	}{
		TenantID: adjustment.TenantID, ProjectID: adjustment.ProjectID, PrincipalID: adjustment.PrincipalID,
		ExpectedVersion: adjustment.ExpectedVersion, HardLimitMicros: adjustment.HardLimitMicros,
		SoftLimitMicros: adjustment.SoftLimitMicros, Currency: adjustment.Currency, Reason: adjustment.Reason,
	})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(payload)
}

func safeBudgetText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func validCurrency(value string) bool {
	return len(value) == 3 && value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z' && value[2] >= 'A' && value[2] <= 'Z'
}

var _ BudgetAdministration = (*PostgresBudgetLedger)(nil)
var _ BudgetAdministration = (*BudgetLedger)(nil)
