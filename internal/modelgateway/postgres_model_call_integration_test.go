//go:build postgres_integration

package modelgateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresModelCallSettlementAndUsage(t *testing.T) {
	dsn := os.Getenv("AOR_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Fatal("AOR_TEST_DATABASE_DSN is required with the postgres_integration build tag")
	}
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := database.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 8, 4, 5, 0, 0, 0, time.UTC)
	ledger, err := NewPostgresBudgetLedger(database, func() time.Time { return now }, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	const (
		tenantID      = "d1000000-0000-4000-8000-000000000001"
		projectID     = "d2000000-0000-4000-8000-000000000001"
		agentID       = "model-call-integration-agent"
		accountID     = "model-call-integration-budget"
		reservationID = "model-call-integration-reservation"
		requestID     = "model-call-integration-request"
	)
	if _, err := ledger.Reserve(ctx, tenantID, accountID, reservationID, requestID, 100); err != nil {
		t.Fatal(err)
	}
	finalization := ModelCallFinalization{
		ReservationID: reservationID, Disposition: ReservationDispositionSettle, ActualMicros: 37,
		Call: ModelCall{
			TenantID: tenantID, RequestID: requestID, ProjectID: projectID, AgentInstanceID: agentID,
			Provider: "integration", LogicalModel: "model", ActualModelVersion: "model-2030-08-04",
			PromptBundleVersion: "prompt-v1", InputSHA256: digestBytes([]byte("input")),
			OutputSHA256: digestBytes([]byte("output")), InputTokens: 21, OutputTokens: 8,
			CostMicros: 37, LatencyMilliseconds: 125, Status: ModelCallSucceeded,
			ProviderRequestID: "provider-request", CreatedAt: now,
		},
	}
	if _, err := ledger.FinalizeModelCall(ctx, finalization); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.FinalizeModelCall(ctx, finalization); err != nil {
		t.Fatalf("idempotent finalization: %v", err)
	}
	usage, err := ledger.Usage(ctx, tenantID, projectID)
	if err != nil {
		t.Fatal(err)
	}
	if usage.CallCount != 1 || usage.InputTokens != 21 || usage.OutputTokens != 8 || usage.CostMicros != 37 || usage.SpentMicros != 37 || usage.ReservedMicros != 0 {
		t.Fatalf("usage = %#v", usage)
	}
}

func TestPostgresModelReplaySurvivesRestartAndRejectsConflict(t *testing.T) {
	dsn := os.Getenv("AOR_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Fatal("AOR_TEST_DATABASE_DSN is required with the postgres_integration build tag")
	}
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := database.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 8, 4, 6, 0, 0, 0, time.UTC)
	config := ReplayStoreConfig{KeyID: "integration-key-v1", EncryptionKey: bytes.Repeat([]byte{0x31}, 32), TTL: time.Hour}
	ledger, err := NewPostgresBudgetLedgerWithReplay(database, func() time.Time { return now }, time.Hour, config)
	if err != nil {
		t.Fatal(err)
	}
	const (
		tenantID      = "d1000000-0000-4000-8000-000000000001"
		projectID     = "d2000000-0000-4000-8000-000000000001"
		agentID       = "model-call-integration-agent"
		accountID     = "model-call-integration-budget"
		reservationID = "model-replay-integration-reservation"
		requestID     = "model-replay-integration-request"
	)
	if _, err := ledger.Reserve(ctx, tenantID, accountID, reservationID, requestID, 100); err != nil {
		t.Fatal(err)
	}
	response := NormalizedResponse{
		RequestID: requestID, ProviderRequestID: "provider-replay-request", ModelVersion: "model-v1",
		Content: json.RawMessage(`{"result":"durable"}`), Usage: Usage{InputTokens: 13, OutputTokens: 5, CostMicros: 29},
	}
	inputDigest := digestBytes([]byte("replay-input"))
	finalization := ModelCallFinalization{
		ReservationID: reservationID, Disposition: ReservationDispositionSettle, ActualMicros: 29,
		Call: ModelCall{
			TenantID: tenantID, RequestID: requestID, ProjectID: projectID, AgentInstanceID: agentID,
			Provider: "integration", LogicalModel: "model", ActualModelVersion: "model-v1",
			PromptBundleVersion: "prompt-v1", InputSHA256: inputDigest, OutputSHA256: responseOutputDigest(response),
			InputTokens: 13, OutputTokens: 5, CostMicros: 29, Status: ModelCallSucceeded,
			ProviderRequestID: response.ProviderRequestID, CreatedAt: now,
		},
	}
	replay := ModelReplay{InputSHA256: inputDigest, Response: response}
	if _, err := ledger.FinalizeModelCallWithReplay(ctx, finalization, replay); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewPostgresBudgetLedgerWithReplay(database, func() time.Time { return now.Add(time.Minute) }, time.Hour, config)
	if err != nil {
		t.Fatal(err)
	}
	loaded, found, err := restarted.LoadModelReplay(ctx, tenantID, requestID)
	if err != nil || !found || loaded.InputSHA256 != inputDigest || !sameNormalizedResponse(loaded.Response, response) {
		t.Fatalf("restarted replay = %#v, found=%t, error=%v", loaded, found, err)
	}
	conflict := replay
	conflict.InputSHA256 = digestBytes([]byte("different-input"))
	if err := restarted.StoreModelReplay(ctx, tenantID, requestID, conflict); !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("conflicting replay error = %v", err)
	}
	wrongKeyConfig := config
	wrongKeyConfig.EncryptionKey = bytes.Repeat([]byte{0x32}, 32)
	wrongKey, err := NewPostgresBudgetLedgerWithReplay(database, time.Now, time.Hour, wrongKeyConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wrongKey.LoadModelReplay(ctx, tenantID, requestID); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("wrong-key replay error = %v", err)
	}
}
