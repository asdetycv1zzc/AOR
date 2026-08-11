package modelgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
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
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "acct", TenantID: "ten", LimitMicros: 100}); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Reserve(context.Background(), "ten", "acct", "res", "req", 80); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Settle(context.Background(), "ten", "res", 50); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Settle(context.Background(), "ten", "res", 50); err != nil {
		t.Fatal(err)
	}
	account, _ := ledger.Account("ten", "acct")
	if account.SpentMicros != 50 || account.ReservedMicros != 0 {
		t.Fatalf("account = %#v", account)
	}
}

func TestGatewayRejectsBudgetBeforeProvider(t *testing.T) {
	adapter := &mockAdapter{responses: []NormalizedResponse{{Content: json.RawMessage(`{"ok":true}`), Usage: Usage{CostMicros: 1}}}}
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "acct", TenantID: "ten", LimitMicros: 1}); err != nil {
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
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "acct", TenantID: "ten", LimitMicros: 1000}); err != nil {
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
	account, _ := ledger.Account("ten", "acct")
	if account.SpentMicros != 3 || account.ReservedMicros != 0 {
		t.Fatalf("retry costs were not fully settled: %#v", account)
	}
}

func TestGatewayPersistsModelCallUsageWithBudgetSettlement(t *testing.T) {
	now := time.Date(2030, 2, 3, 4, 5, 6, 0, time.UTC)
	cacheReadTokens, cacheWriteTokens := int64(8), int64(2)
	ledger := NewBudgetLedger(func() time.Time { return now })
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "acct", TenantID: "ten", ScopeType: "PROJECT", ScopeID: "prj", LimitMicros: 1_000}); err != nil {
		t.Fatal(err)
	}
	adapter := &mockAdapter{responses: []NormalizedResponse{{
		RequestID: "recorded", ProviderRequestID: "provider-request", ModelVersion: "model-2026-08-04",
		Content: json.RawMessage(`{"ok":true}`), Usage: Usage{InputTokens: 12, OutputTokens: 7, CacheReadTokens: &cacheReadTokens, CacheWriteTokens: &cacheWriteTokens, CostMicros: 19},
	}}}
	gateway := NewGateway(ledger, func() time.Time { return now })
	if err := gateway.Register("mock", "model", adapter, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	request := NormalizedRequest{RequestID: "recorded", TenantID: "ten", ProjectID: "prj", TaskID: "task", AgentInstanceID: "agent", Role: "EXECUTOR", Model: "model", PromptBundleVersion: "prompt-v1", Messages: []Message{{Role: "user", Content: "hello"}}, MaxOutputTokens: 10, DataClassification: "INTERNAL"}
	if _, err := gateway.Generate(context.Background(), request, GenerateOptions{Provider: "mock", AccountID: "acct", ReservationID: "reservation", MaxAttempts: 1}); err != nil {
		t.Fatal(err)
	}
	call, found := ledger.ModelCall("ten", "recorded")
	if !found || call.Status != ModelCallSucceeded || call.InputTokens != 12 || call.OutputTokens != 7 || call.CacheReadTokens == nil || *call.CacheReadTokens != 8 || call.CacheWriteTokens == nil || *call.CacheWriteTokens != 2 || call.CostMicros != 19 || call.ActualModelVersion != "model-2026-08-04" || call.ProviderRequestID != "provider-request" || !validModelDigest(call.InputSHA256) || !validModelDigest(call.OutputSHA256) {
		t.Fatalf("model call = %#v, found=%t", call, found)
	}
	usage, err := ledger.Usage(context.Background(), "ten", "prj")
	if err != nil || usage.CallCount != 1 || usage.InputTokens != 12 || usage.OutputTokens != 7 || usage.CostMicros != 19 {
		t.Fatalf("usage = %#v, err=%v", usage, err)
	}
}

func TestGatewayRecordsUnknownProviderOutcomeForReconciliation(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "acct", TenantID: "ten", ScopeType: "PROJECT", ScopeID: "prj", LimitMicros: 100}); err != nil {
		t.Fatal(err)
	}
	gateway := NewGateway(ledger, time.Now)
	if err := gateway.Register("mock", "model", &mockAdapter{}, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	request := NormalizedRequest{RequestID: "unknown", TenantID: "ten", ProjectID: "prj", TaskID: "task", AgentInstanceID: "agent", Role: "EXECUTOR", Model: "model", PromptBundleVersion: "prompt-v1", Messages: []Message{{Role: "user", Content: "hello"}}, MaxOutputTokens: 10, DataClassification: "INTERNAL"}
	if _, err := gateway.Generate(context.Background(), request, GenerateOptions{Provider: "mock", AccountID: "acct", ReservationID: "reservation", MaxAttempts: 1}); err == nil {
		t.Fatal("unknown provider outcome was accepted")
	}
	call, found := ledger.ModelCall("ten", "unknown")
	reservation, reservationFound := ledger.Reservation("ten", "reservation")
	if !found || call.Status != ModelCallReconcile || !reservationFound || reservation.State != ReservationReconcile {
		t.Fatalf("call=%#v found=%t reservation=%#v reservationFound=%t", call, found, reservation, reservationFound)
	}
}

func TestGatewayBoundsResponsesAndChargesFailedProviderCalls(t *testing.T) {
	ledger := NewBudgetLedger(func() time.Time { return time.Unix(0, 0) })
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "acct", TenantID: "ten", LimitMicros: 10_000_000}); err != nil {
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
	account, _ := ledger.Account("ten", "acct")
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
	account, _ = ledger.Account("ten", "acct")
	reservation, found := ledger.Reservation("ten", "failed-res")
	if account.SpentMicros != 7 || account.ReservedMicros != 20 || !found || reservation.State != ReservationReconcile {
		t.Fatalf("unknown provider call was not retained for reconciliation: account=%#v reservation=%#v", account, reservation)
	}
}

func TestGatewayProviderOutageUsesCircuitBreakerWithoutExhaustingBudget(t *testing.T) {
	clock := &gatewayTestClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	ledger := NewBudgetLedger(clock.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "acct", TenantID: "ten", LimitMicros: 1_000}); err != nil {
		t.Fatal(err)
	}
	adapter := &outageAdapter{}
	gateway := NewGatewayWithConfig(ledger, clock.Now, GatewayConfig{InitialProviderBackoff: time.Minute, MaximumProviderBackoff: 5 * time.Minute})
	if err := gateway.Register("outage", "model", adapter, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	request := NormalizedRequest{TenantID: "ten", ProjectID: "prj", AgentInstanceID: "agt", Role: "EXECUTOR", Model: "model", PromptBundleVersion: "p1", Messages: []Message{{Role: "user", Content: "hello"}}, MaxOutputTokens: 10, DataClassification: "INTERNAL"}
	for minute := 0; minute < 30; minute++ {
		request.RequestID = fmt.Sprintf("outage-%d", minute)
		_, err := gateway.Generate(context.Background(), request, GenerateOptions{Provider: "outage", AccountID: "acct", ReservationID: fmt.Sprintf("reservation-%d", minute), MaxAttempts: 1})
		if err == nil {
			t.Fatalf("outage minute %d succeeded", minute)
		}
		clock.Advance(time.Minute)
	}
	account, _ := ledger.Account("ten", "acct")
	if account.SpentMicros != 0 || account.ReservedMicros != 0 || adapter.Calls() > 9 {
		t.Fatalf("outage exhausted budget or retried blindly: account=%#v calls=%d", account, adapter.Calls())
	}
	adapter.Recover()
	var response NormalizedResponse
	var err error
	for probe := 0; probe < 6; probe++ {
		request.RequestID = fmt.Sprintf("recovery-%d", probe)
		response, err = gateway.Generate(context.Background(), request, GenerateOptions{Provider: "outage", AccountID: "acct", ReservationID: fmt.Sprintf("recovery-reservation-%d", probe), MaxAttempts: 1})
		if err == nil {
			break
		}
		clock.Advance(time.Minute)
	}
	if err != nil || string(response.Content) != `{"ok":true}` {
		t.Fatalf("provider did not recover: response=%#v error=%v", response, err)
	}
	account, _ = ledger.Account("ten", "acct")
	if account.SpentMicros != 1 || account.ReservedMicros != 0 {
		t.Fatalf("recovered call did not settle exactly once: %#v", account)
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

type outageAdapter struct {
	mockAdapter
	mu        sync.Mutex
	available bool
	calls     int
}

func (adapter *outageAdapter) Generate(context.Context, NormalizedRequest) (NormalizedResponse, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.calls++
	if !adapter.available {
		return NormalizedResponse{}, &ProviderFailure{Cause: errors.New("provider unavailable"), Retryable: true, OutcomeKnown: true}
	}
	return NormalizedResponse{Content: json.RawMessage(`{"ok":true}`), Usage: Usage{CostMicros: 1}}, nil
}

func (adapter *outageAdapter) Recover() {
	adapter.mu.Lock()
	adapter.available = true
	adapter.mu.Unlock()
}

func (adapter *outageAdapter) Calls() int {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.calls
}

type gatewayTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *gatewayTestClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *gatewayTestClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}
