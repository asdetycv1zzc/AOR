package eventing

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

var ErrInboxClaimLost = errors.New("inbox claim is no longer current")

type PostgresInboxConfig struct {
	ClaimTTL     time.Duration
	PollInterval time.Duration
	Clock        func() time.Time
}

type PostgresInbox struct {
	db           *sql.DB
	claimTTL     time.Duration
	pollInterval time.Duration
	clock        func() time.Time
}

type inboxClaim struct {
	result json.RawMessage
	token  string
	owner  bool
}

func NewPostgresInbox(db *sql.DB, config PostgresInboxConfig) (*PostgresInbox, error) {
	if db == nil || config.ClaimTTL < 0 || config.PollInterval < 0 {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "postgres inbox"})
	}
	if config.ClaimTTL == 0 {
		config.ClaimTTL = 30 * time.Second
	}
	if config.PollInterval == 0 {
		config.PollInterval = 20 * time.Millisecond
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &PostgresInbox{db: db, claimTTL: config.ClaimTTL, pollInterval: config.PollInterval, clock: config.Clock}, nil
}

// Process claims an inbox message durably before invoking handler and records a
// successful JSON result afterwards. The claim is not an external side-effect
// transaction: a crash after handler returns but before complete can invoke the
// handler again after its lease expires.
func (i *PostgresInbox) Process(ctx context.Context, tenantID, consumerID, messageID, requestSHA256 string, handler func(context.Context) ([]byte, error)) (InboxResult, error) {
	if err := validateInboxInput(ctx, tenantID, consumerID, messageID, requestSHA256, handler); err != nil {
		return InboxResult{}, err
	}
	for {
		claim, err := i.claim(ctx, tenantID, consumerID, messageID, requestSHA256)
		if err != nil {
			return InboxResult{}, err
		}
		if claim.result != nil {
			return InboxResult{Result: cloneJSON(claim.result), Duplicate: true}, nil
		}
		if !claim.owner {
			if err := waitForInbox(ctx, i.pollInterval); err != nil {
				return InboxResult{}, err
			}
			continue
		}

		result, handlerErr := handler(ctx)
		if handlerErr == nil {
			handlerErr = validateInboxResult(result)
		}
		if handlerErr != nil {
			if releaseErr := i.release(ctx, tenantID, consumerID, messageID, requestSHA256, claim.token); releaseErr != nil && !errors.Is(releaseErr, ErrInboxClaimLost) {
				return InboxResult{}, errors.Join(handlerErr, releaseErr)
			}
			return InboxResult{}, handlerErr
		}
		if err := i.complete(ctx, tenantID, consumerID, messageID, requestSHA256, claim.token, result); err != nil {
			return InboxResult{}, err
		}
		return InboxResult{Result: cloneJSON(result)}, nil
	}
}

func (i *PostgresInbox) claim(ctx context.Context, tenantID, consumerID, messageID, requestSHA256 string) (inboxClaim, error) {
	tx, err := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return inboxClaim{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenant(ctx, tx, tenantID); err != nil {
		return inboxClaim{}, err
	}
	now := i.clock().UTC()
	token, err := inboxClaimToken()
	if err != nil {
		return inboxClaim{}, err
	}
	result, err := tx.ExecContext(ctx, `
INSERT INTO inbox
  (tenant_id, consumer_id, message_id, request_sha256, processed_at, result_sha256, result_jsonb, status, claim_token, claim_attempt, claimed_at, lease_expires_at)
VALUES ($1::uuid, $2, $3, $4, $5, NULL, NULL, 'PROCESSING', $6, 1, $5, $7)
ON CONFLICT (tenant_id, consumer_id, message_id) DO NOTHING`, tenantID, consumerID, messageID, requestSHA256, now, token, now.Add(i.claimTTL))
	if err != nil {
		return inboxClaim{}, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return inboxClaim{}, err
	}
	if inserted == 1 {
		if err := tx.Commit(); err != nil {
			return inboxClaim{}, err
		}
		return inboxClaim{owner: true, token: token}, nil
	}

	var storedDigest string
	var status string
	var storedResult []byte
	var storedResultDigest sql.NullString
	var leaseExpiresAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
SELECT request_sha256, status, result_jsonb, result_sha256, lease_expires_at
FROM inbox
WHERE tenant_id = $1::uuid AND consumer_id = $2 AND message_id = $3
FOR UPDATE`, tenantID, consumerID, messageID).Scan(&storedDigest, &status, &storedResult, &storedResultDigest, &leaseExpiresAt)
	if err != nil {
		return inboxClaim{}, err
	}
	if storedDigest != requestSHA256 {
		return inboxClaim{}, aorerrors.New(aorerrors.CodeIdempotencyConflict, "", nil)
	}
	if status == "COMPLETED" {
		if !storedResultDigest.Valid || validateInboxResult(storedResult) != nil {
			return inboxClaim{}, fmt.Errorf("completed inbox record is invalid")
		}
		digest, digestErr := canonicaljson.Digest(storedResult)
		if digestErr != nil || digest != storedResultDigest.String {
			return inboxClaim{}, fmt.Errorf("completed inbox result digest is invalid")
		}
		if err := tx.Commit(); err != nil {
			return inboxClaim{}, err
		}
		return inboxClaim{result: cloneJSON(storedResult)}, nil
	}
	if status == "PROCESSING" && leaseExpiresAt.Valid && leaseExpiresAt.Time.After(now) {
		if err := tx.Commit(); err != nil {
			return inboxClaim{}, err
		}
		return inboxClaim{}, nil
	}
	result, err = tx.ExecContext(ctx, `
UPDATE inbox
SET status = 'PROCESSING', claim_token = $5, claim_attempt = claim_attempt + 1,
    claimed_at = $6, lease_expires_at = $7, processed_at = $6,
    result_jsonb = NULL, result_sha256 = NULL
WHERE tenant_id = $1::uuid AND consumer_id = $2 AND message_id = $3 AND request_sha256 = $4`, tenantID, consumerID, messageID, requestSHA256, token, now, now.Add(i.claimTTL))
	if err != nil {
		return inboxClaim{}, err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return inboxClaim{}, err
	}
	if updated != 1 {
		return inboxClaim{}, ErrInboxClaimLost
	}
	if err := tx.Commit(); err != nil {
		return inboxClaim{}, err
	}
	return inboxClaim{owner: true, token: token}, nil
}

func (i *PostgresInbox) complete(ctx context.Context, tenantID, consumerID, messageID, requestSHA256, token string, value []byte) error {
	digest, err := canonicaljson.Digest(value)
	if err != nil {
		return err
	}
	return i.updateClaim(ctx, tenantID, consumerID, messageID, requestSHA256, token, `
UPDATE inbox
SET status = 'COMPLETED', result_jsonb = $6::jsonb, result_sha256 = $7,
    processed_at = $8, lease_expires_at = NULL
WHERE tenant_id = $1::uuid AND consumer_id = $2 AND message_id = $3
  AND request_sha256 = $4 AND status = 'PROCESSING' AND claim_token = $5`, value, digest, i.clock().UTC())
}

func (i *PostgresInbox) release(ctx context.Context, tenantID, consumerID, messageID, requestSHA256, token string) error {
	return i.updateClaim(ctx, tenantID, consumerID, messageID, requestSHA256, token, `
UPDATE inbox
SET status = 'RETRYABLE', claim_token = NULL, claimed_at = NULL,
    lease_expires_at = NULL, processed_at = $6
WHERE tenant_id = $1::uuid AND consumer_id = $2 AND message_id = $3
  AND request_sha256 = $4 AND status = 'PROCESSING' AND claim_token = $5`, i.clock().UTC())
}

func (i *PostgresInbox) updateClaim(ctx context.Context, tenantID, consumerID, messageID, requestSHA256, token, statement string, values ...any) error {
	tx, err := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTenant(ctx, tx, tenantID); err != nil {
		return err
	}
	arguments := append([]any{tenantID, consumerID, messageID, requestSHA256, token}, values...)
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrInboxClaimLost
	}
	return tx.Commit()
}

func waitForInbox(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func inboxClaimToken() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

var _ Inbox = (*PostgresInbox)(nil)
