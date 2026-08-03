package modelgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type mockAdapter struct {
	responses []NormalizedResponse
	index     int
}

func (m *mockAdapter) Capabilities(context.Context, string) (ModelCapabilities, error) {
	return ModelCapabilities{MaxInputTokens: 1000, MaxOutputTokens: 100, SupportsJSONSchema: true, ActualModelVersion: "mock-2026-01"}, nil
}
func (m *mockAdapter) CountTokens(context.Context, NormalizedRequest) (TokenEstimate, error) {
	return TokenEstimate{InputTokens: 10}, nil
}
func (m *mockAdapter) Generate(context.Context, NormalizedRequest) (NormalizedResponse, error) {
	if m.index >= len(m.responses) {
		return NormalizedResponse{}, errors.New("provider key sk-" + "test-secret-1234567890")
	}
	response := m.responses[m.index]
	m.index++
	return response, nil
}
func (m *mockAdapter) Stream(context.Context, NormalizedRequest) (ResponseStream, error) {
	return nil, errors.New("stream not implemented")
}
func (m *mockAdapter) Cancel(context.Context, string) error { return nil }
func (m *mockAdapter) NormalizeUsage(raw any) (Usage, error) {
	value, ok := raw.(Usage)
	if !ok {
		return Usage{}, errors.New("invalid usage")
	}
	return value, nil
}

func TestBudgetLedgerSettlementIsIdempotent(t *testing.T) {
	ledger := NewBudgetLedger(func() time.Time { return time.Unix(0, 0) })
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "acct", LimitMicros: 100}); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Reserve(context.Background(), "acct", "res", "req", 80); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Settle(context.Background(), "res", 50); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Settle(context.Background(), "res", 50); err != nil {
		t.Fatal(err)
	}
	account, _ := ledger.Account("acct")
	if account.SpentMicros != 50 || account.ReservedMicros != 0 {
		t.Fatalf("account = %#v", account)
	}
}

func TestGatewayRejectsBudgetBeforeProvider(t *testing.T) {
	adapter := &mockAdapter{responses: []NormalizedResponse{{Content: json.RawMessage(`{"ok":true}`), Usage: Usage{CostMicros: 1}}}}
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "acct", LimitMicros: 1}); err != nil {
		t.Fatal(err)
	}
	gateway := NewGateway(ledger, time.Now)
	if err := gateway.Register("mock", "model", adapter, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	_, err := gateway.Generate(context.Background(), NormalizedRequest{RequestID: "req", TenantID: "ten", ProjectID: "prj", AgentInstanceID: "agt", Role: "EXECUTOR", Model: "model", PromptBundleVersion: "p1", Messages: []Message{{Role: "user", Content: "hello"}}, MaxOutputTokens: 10, DataClassification: "INTERNAL"}, GenerateOptions{Provider: "mock", AccountID: "acct", ReservationID: "res", MaxAttempts: 1})
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("budget error = %v", err)
	}
	if adapter.index != 0 {
		t.Fatal("provider was called after budget denial")
	}
}

func TestGatewayRetriesInvalidStructuredOutputAtMostTwice(t *testing.T) {
	adapter := &mockAdapter{responses: []NormalizedResponse{{Content: json.RawMessage(`{"wrong":true}`), Usage: Usage{CostMicros: 1}}, {Content: json.RawMessage(`{"wrong":true}`), Usage: Usage{CostMicros: 1}}, {Content: json.RawMessage(`{"ok":true}`), Usage: Usage{CostMicros: 1}}}}
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "acct", LimitMicros: 1000}); err != nil {
		t.Fatal(err)
	}
	gateway := NewGateway(ledger, time.Now)
	if err := gateway.Register("mock", "model", adapter, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	response, err := gateway.Generate(context.Background(), NormalizedRequest{RequestID: "req", TenantID: "ten", ProjectID: "prj", AgentInstanceID: "agt", Role: "EXECUTOR", Model: "model", PromptBundleVersion: "p1", Messages: []Message{{Role: "user", Content: "hello"}}, ResponseSchema: json.RawMessage(`{"type":"object","required":["ok"]}`), MaxOutputTokens: 10, DataClassification: "INTERNAL"}, GenerateOptions{Provider: "mock", AccountID: "acct", ReservationID: "res", MaxAttempts: 3})
	if err != nil || string(response.Content) != `{"ok":true}` {
		t.Fatalf("response = %#v, err=%v", response, err)
	}
	if adapter.index != 3 {
		t.Fatalf("attempts = %d", adapter.index)
	}
	account, _ := ledger.Account("acct")
	if account.SpentMicros != 3 || account.ReservedMicros != 0 {
		t.Fatalf("retry costs were not fully settled: %#v", account)
	}
}

func TestGatewayBoundsResponsesAndChargesFailedProviderCalls(t *testing.T) {
	ledger := NewBudgetLedger(func() time.Time { return time.Unix(0, 0) })
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "acct", LimitMicros: 10_000_000}); err != nil {
		t.Fatal(err)
	}
	adapter := &mockAdapter{responses: []NormalizedResponse{{Content: json.RawMessage(bytes.Repeat([]byte("x"), MaximumResponseBytes+1)), Usage: Usage{CostMicros: 7}}}}
	gateway := NewGateway(ledger, time.Now)
	if err := gateway.Register("mock", "model", adapter, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	request := NormalizedRequest{RequestID: "large", TenantID: "ten", ProjectID: "prj", AgentInstanceID: "agt", Role: "EXECUTOR", Model: "model", PromptBundleVersion: "p1", Messages: []Message{{Role: "user", Content: "hello"}}, MaxOutputTokens: 10, DataClassification: "INTERNAL"}
	if _, err := gateway.Generate(context.Background(), request, GenerateOptions{Provider: "mock", AccountID: "acct", ReservationID: "large-res", MaxAttempts: 1}); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("oversized response error = %v", err)
	}
	account, _ := ledger.Account("acct")
	if account.SpentMicros != 7 {
		t.Fatalf("oversized provider call was not charged: %#v", account)
	}

	failing := &mockAdapter{}
	if err := gateway.Register("failing", "model", failing, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	request.RequestID = "failed"
	if _, err := gateway.Generate(context.Background(), request, GenerateOptions{Provider: "failing", AccountID: "acct", ReservationID: "failed-res", MaxAttempts: 1}); err == nil {
		t.Fatal("provider failure was accepted")
	}
	account, _ = ledger.Account("acct")
	if account.SpentMicros != 27 {
		t.Fatalf("failed provider call was not conservatively charged: %#v", account)
	}
}

func TestCacheKeyIncludesTenantAndPolicyInputs(t *testing.T) {
	one, err := CacheKey(CacheKeyInput{TenantID: "ten1", ProjectID: "prj", ModelVersion: "model-v1", PromptBundleDigest: "sha256:a", ToolSchemaDigest: "sha256:b", PolicyDigest: "sha256:c", DataClassification: "INTERNAL", PrefixDigest: "sha256:d", DynamicDigest: "sha256:e"})
	if err != nil {
		t.Fatal(err)
	}
	two, err := CacheKey(CacheKeyInput{TenantID: "ten2", ProjectID: "prj", ModelVersion: "model-v1", PromptBundleDigest: "sha256:a", ToolSchemaDigest: "sha256:b", PolicyDigest: "sha256:c", DataClassification: "INTERNAL", PrefixDigest: "sha256:d", DynamicDigest: "sha256:e"})
	if err != nil || one == two {
		t.Fatalf("cache keys = %s, %s", one, two)
	}
}
