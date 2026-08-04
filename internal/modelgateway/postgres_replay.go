package modelgateway

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	defaultModelReplayTTL = 24 * time.Hour
	maximumModelReplayTTL = 30 * 24 * time.Hour
	maximumReplayPayload  = MaximumResponseBytes + 64<<10
)

type ReplayStoreConfig struct {
	KeyID         string
	EncryptionKey []byte
	TTL           time.Duration
}

type postgresReplayCodec struct {
	aead  cipher.AEAD
	keyID string
	ttl   time.Duration
}

func newPostgresReplayCodec(config ReplayStoreConfig) (*postgresReplayCodec, error) {
	if config.TTL == 0 {
		config.TTL = defaultModelReplayTTL
	}
	if len(config.EncryptionKey) != 32 || config.KeyID == "" || len(config.KeyID) > 128 || strings.ContainsAny(config.KeyID, "\r\n\x00") || config.TTL <= 0 || config.TTL > maximumModelReplayTTL {
		return nil, ErrInvalidRequest
	}
	block, err := aes.NewCipher(config.EncryptionKey)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	return &postgresReplayCodec{aead: aead, keyID: config.KeyID, ttl: config.TTL}, nil
}

func (ledger *PostgresBudgetLedger) ReplayEnabled() bool {
	return ledger != nil && ledger.replay != nil
}

func (ledger *PostgresBudgetLedger) LookupModelCall(ctx context.Context, tenantID, requestID string) (ModelCall, bool, error) {
	if err := contextError(ctx); err != nil {
		return ModelCall{}, false, err
	}
	if ledger == nil || tenantID == "" || requestID == "" {
		return ModelCall{}, false, ErrInvalidRequest
	}
	tx, err := ledger.beginReadOnly(ctx, tenantID)
	if err != nil {
		return ModelCall{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	call, found, err := loadModelCall(ctx, tx, tenantID, requestID)
	if err != nil || !found {
		return call, found, err
	}
	if err := tx.Commit(); err != nil {
		return ModelCall{}, false, err
	}
	return call, true, nil
}

func (ledger *PostgresBudgetLedger) LoadModelReplay(ctx context.Context, tenantID, requestID string) (ModelReplay, bool, error) {
	if err := contextError(ctx); err != nil {
		return ModelReplay{}, false, err
	}
	if !ledger.ReplayEnabled() || tenantID == "" || requestID == "" {
		return ModelReplay{}, false, ErrReplayUnavailable
	}
	tx, err := ledger.beginReadOnly(ctx, tenantID)
	if err != nil {
		return ModelReplay{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	replay, expiresAt, found, err := ledger.loadModelReplayTx(ctx, tx, tenantID, requestID)
	if err != nil || !found {
		return replay, found, err
	}
	if !ledger.clock().UTC().Before(expiresAt) {
		return ModelReplay{}, false, nil
	}
	if err := tx.Commit(); err != nil {
		return ModelReplay{}, false, err
	}
	return replay, true, nil
}

func (ledger *PostgresBudgetLedger) StoreModelReplay(ctx context.Context, tenantID, requestID string, replay ModelReplay) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !ledger.ReplayEnabled() || validateReplayPayload(tenantID, requestID, replay) != nil {
		return ErrInvalidRequest
	}
	tx, err := ledger.begin(ctx, tenantID)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	call, found, err := loadModelCall(ctx, tx, tenantID, requestID)
	if err != nil {
		return err
	}
	if !found || call.Status != ModelCallSucceeded || call.InputSHA256 != replay.InputSHA256 || call.OutputSHA256 != responseOutputDigest(replay.Response) {
		return ErrRequestConflict
	}
	if err := ledger.insertModelReplayTx(ctx, tx, tenantID, requestID, replay); err != nil {
		return err
	}
	return tx.Commit()
}

func validateReplayPayload(tenantID, requestID string, replay ModelReplay) error {
	if tenantID == "" || requestID == "" || !validModelDigest(replay.InputSHA256) || replay.Response.RequestID != requestID || validateNormalizedResponseOutput(replay.Response) != nil {
		return ErrInvalidRequest
	}
	return nil
}

func (ledger *PostgresBudgetLedger) insertModelReplayTx(ctx context.Context, tx *sql.Tx, tenantID, requestID string, replay ModelReplay) error {
	if !ledger.ReplayEnabled() || validateReplayPayload(tenantID, requestID, replay) != nil {
		return ErrInvalidRequest
	}
	nonce, ciphertext, err := ledger.encryptModelReplay(tenantID, requestID, replay)
	if err != nil {
		return err
	}
	createdAt := ledger.clock().UTC()
	result, err := tx.ExecContext(ctx, `
INSERT INTO model_call_replays
  (tenant_id, request_id, input_sha256, key_id, nonce, response_ciphertext, created_at, expires_at)
VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (tenant_id, request_id) DO NOTHING`, tenantID, requestID, replay.InputSHA256, ledger.replay.keyID, nonce, ciphertext, createdAt, createdAt.Add(ledger.replay.ttl))
	if err != nil {
		return mapBudgetSQLError(err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 1 {
		return nil
	}
	existing, _, found, err := ledger.loadModelReplayTx(ctx, tx, tenantID, requestID)
	if err != nil {
		return err
	}
	if !found || existing.InputSHA256 != replay.InputSHA256 || !sameNormalizedResponse(existing.Response, replay.Response) {
		return ErrRequestConflict
	}
	return nil
}

func (ledger *PostgresBudgetLedger) loadModelReplayTx(ctx context.Context, tx *sql.Tx, tenantID, requestID string) (ModelReplay, time.Time, bool, error) {
	var inputSHA256, keyID string
	var nonce, ciphertext []byte
	var expiresAt time.Time
	err := tx.QueryRowContext(ctx, `
SELECT input_sha256, key_id, nonce, response_ciphertext, expires_at
FROM model_call_replays
WHERE tenant_id = $1::uuid AND request_id = $2`, tenantID, requestID).Scan(&inputSHA256, &keyID, &nonce, &ciphertext, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ModelReplay{}, time.Time{}, false, nil
	}
	if err != nil {
		return ModelReplay{}, time.Time{}, false, err
	}
	if keyID != ledger.replay.keyID || len(nonce) != ledger.replay.aead.NonceSize() || len(ciphertext) == 0 || len(ciphertext) > maximumReplayPayload+ledger.replay.aead.Overhead() {
		return ModelReplay{}, time.Time{}, false, ErrReplayUnavailable
	}
	plaintext, err := ledger.replay.aead.Open(nil, nonce, ciphertext, replayAdditionalData(tenantID, requestID, inputSHA256, keyID))
	if err != nil || len(plaintext) == 0 || len(plaintext) > maximumReplayPayload {
		return ModelReplay{}, time.Time{}, false, ErrReplayUnavailable
	}
	var response NormalizedResponse
	if json.Unmarshal(plaintext, &response) != nil {
		return ModelReplay{}, time.Time{}, false, ErrReplayUnavailable
	}
	replay := ModelReplay{InputSHA256: inputSHA256, Response: response}
	if validateReplayPayload(tenantID, requestID, replay) != nil {
		return ModelReplay{}, time.Time{}, false, ErrReplayUnavailable
	}
	return replay, expiresAt.UTC(), true, nil
}

func (ledger *PostgresBudgetLedger) encryptModelReplay(tenantID, requestID string, replay ModelReplay) ([]byte, []byte, error) {
	plaintext, err := json.Marshal(replay.Response)
	if err != nil || len(plaintext) == 0 || len(plaintext) > maximumReplayPayload {
		return nil, nil, ErrInvalidRequest
	}
	nonce := make([]byte, ledger.replay.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext := ledger.replay.aead.Seal(nil, nonce, plaintext, replayAdditionalData(tenantID, requestID, replay.InputSHA256, ledger.replay.keyID))
	return nonce, ciphertext, nil
}

func replayAdditionalData(tenantID, requestID, inputSHA256, keyID string) []byte {
	return []byte(tenantID + "\x00" + requestID + "\x00" + inputSHA256 + "\x00" + keyID)
}

var _ EnabledModelReplayStore = (*PostgresBudgetLedger)(nil)
var _ ModelCallLookup = (*PostgresBudgetLedger)(nil)
