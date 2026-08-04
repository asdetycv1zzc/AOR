//go:build postgres_integration

package modelgateway

import (
	"context"
	"database/sql"
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
