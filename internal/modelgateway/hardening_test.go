package modelgateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGatewayDeduplicatesConcurrentAndRestartedRequestIDs(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 10_000}); err != nil {
		t.Fatal(err)
	}
	adapter := &hardeningAdapter{response: NormalizedResponse{Content: json.RawMessage(`{"ok":true}`), Usage: Usage{InputTokens: 2, OutputTokens: 1, CostMicros: 3}}}
	gateway := NewGateway(ledger, time.Now)
	if err := gateway.Register("primary", "model", adapter, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	request := hardeningRequest("deduplicated")
	options := GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "reservation", MaxAttempts: 1}

	const callers = 32
	var wait sync.WaitGroup
	errorsSeen := make(chan error, callers)
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			response, err := gateway.Generate(context.Background(), request, options)
			if err != nil {
				errorsSeen <- err
				return
			}
			if response.RequestID != request.RequestID || string(response.Content) != `{"ok":true}` {
				errorsSeen <- errors.New("unexpected replay response")
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatal(err)
	}
	if adapter.Calls() != 1 {
		t.Fatalf("provider calls = %d", adapter.Calls())
	}

	restarted := NewGateway(ledger, time.Now)
	if err := restarted.Register("primary", "model", adapter, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	response, err := restarted.Generate(context.Background(), request, options)
	if err != nil || response.RequestID != request.RequestID || adapter.Calls() != 1 {
		t.Fatalf("restart replay response=%#v calls=%d error=%v", response, adapter.Calls(), err)
	}
	account, _ := ledger.Account("tenant", "account")
	if account.SpentMicros != 3 || account.ReservedMicros != 0 {
		t.Fatalf("account = %#v", account)
	}
}

func TestGatewayRevalidatesDurableReplayWithCurrentSemanticPolicy(t *testing.T) {
	gateway, adapter, ledger := newHardeningGateway(t, GatewayConfig{})
	request := hardeningRequest("replay-semantic-policy")
	request.ResponseSchema = json.RawMessage(`{"type":"object","required":["ok"],"properties":{"ok":{"type":"boolean"}}}`)
	request.ResponseSemanticValidator = func(json.RawMessage) error { return nil }
	options := GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "replay-semantic-reservation", MaxAttempts: 1}

	if _, err := gateway.Generate(context.Background(), request, options); err != nil {
		t.Fatal(err)
	}
	request.ResponseSemanticValidator = func(json.RawMessage) error {
		return errors.New("current semantic policy rejects replay")
	}
	if _, err := gateway.Generate(context.Background(), request, options); !errors.Is(err, ErrOutputSchema) {
		t.Fatalf("replay semantic validation error = %v", err)
	}
	if adapter.Calls() != 1 {
		t.Fatalf("provider calls = %d", adapter.Calls())
	}
	account, _ := ledger.Account("tenant", "account")
	if account.SpentMicros != 3 || account.ReservedMicros != 0 {
		t.Fatalf("account = %#v", account)
	}
}

func TestGatewayClaimsExternalCallAcrossConcurrentInstances(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 10_000}); err != nil {
		t.Fatal(err)
	}
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "other-account", TenantID: "tenant", LimitMicros: 10_000}); err != nil {
		t.Fatal(err)
	}
	adapter := &hardeningAdapter{
		response: NormalizedResponse{Content: json.RawMessage(`{"ok":true}`), Usage: Usage{CostMicros: 3}},
		entered:  make(chan struct{}),
		proceed:  make(chan struct{}),
	}
	gateways := []*Gateway{NewGateway(ledger, time.Now), NewGateway(ledger, time.Now)}
	for _, gateway := range gateways {
		if err := gateway.Register("primary", "model", adapter, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
			t.Fatal(err)
		}
	}
	request := hardeningRequest("concurrent-instances")
	options := GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "concurrent-reservation", MaxAttempts: 1}
	firstResult := make(chan error, 1)
	go func() {
		_, err := gateways[0].Generate(context.Background(), request, options)
		firstResult <- err
	}()
	<-adapter.entered
	if _, err := gateways[1].Generate(context.Background(), request, options); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("duplicate instance error = %v", err)
	}
	otherOptions := GenerateOptions{Provider: "primary", AccountID: "other-account", ReservationID: "other-concurrent-reservation", MaxAttempts: 1}
	if _, err := gateways[1].Generate(context.Background(), request, otherOptions); !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("rebound request error = %v", err)
	}
	close(adapter.proceed)
	if err := <-firstResult; err != nil {
		t.Fatal(err)
	}
	if adapter.Calls() != 1 {
		t.Fatalf("provider calls = %d", adapter.Calls())
	}
}

func TestGatewayRejectsChangedBodyForRequestID(t *testing.T) {
	gateway, adapter, _ := newHardeningGateway(t, GatewayConfig{})
	request := hardeningRequest("conflict")
	options := GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "reservation", MaxAttempts: 1}
	if _, err := gateway.Generate(context.Background(), request, options); err != nil {
		t.Fatal(err)
	}
	request.Messages[0].Content = "different"
	if _, err := gateway.Generate(context.Background(), request, options); !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	for _, changed := range []GenerateOptions{
		{Provider: "primary", AccountID: "other-account", ReservationID: "reservation", MaxAttempts: 1},
		{Provider: "primary", AccountID: "account", ReservationID: "other-reservation", MaxAttempts: 1},
		{Provider: "primary", AccountID: "account", ReservationID: "reservation", MaxAttempts: 2},
		{Provider: "other-provider", AccountID: "account", ReservationID: "reservation", MaxAttempts: 1},
	} {
		if _, err := gateway.Generate(context.Background(), hardeningRequest("conflict"), changed); !errors.Is(err, ErrRequestConflict) {
			t.Fatalf("changed execution options=%#v error=%v", changed, err)
		}
	}
	if adapter.Calls() != 1 {
		t.Fatalf("provider calls = %d", adapter.Calls())
	}
}

func TestGatewayRetriesOnlyKnownRetryableProviderFailuresWithJitter(t *testing.T) {
	var delays []time.Duration
	config := GatewayConfig{
		InitialProviderBackoff: time.Second,
		MaximumProviderBackoff: 4 * time.Second,
		BackoffJitterRatio:     0.25,
		Sleep: func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		},
	}
	gateway, adapter, _ := newHardeningGateway(t, config)
	adapter.failures = []error{
		&ProviderFailure{Cause: errors.New("rate limited"), Retryable: true, OutcomeKnown: true},
		&ProviderFailure{Cause: errors.New("unavailable"), Retryable: true, OutcomeKnown: true},
	}
	request := hardeningRequest("retry")
	response, err := gateway.Generate(context.Background(), request, GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "retry-reservation", MaxAttempts: 3})
	if err != nil || string(response.Content) != `{"ok":true}` {
		t.Fatalf("response=%#v error=%v", response, err)
	}
	if adapter.Calls() != 3 || len(delays) != 2 {
		t.Fatalf("calls=%d delays=%v", adapter.Calls(), delays)
	}
	if delays[0] < 750*time.Millisecond || delays[0] > 1250*time.Millisecond || delays[1] < 1500*time.Millisecond || delays[1] > 2500*time.Millisecond || delays[0] == time.Second && delays[1] == 2*time.Second {
		t.Fatalf("delays do not contain bounded jitter: %v", delays)
	}
}

func TestGatewayPolicyRetriesKnownTimeoutBeforeFallback(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 100_000}); err != nil {
		t.Fatal(err)
	}
	primary := &hardeningAdapter{failures: []error{
		&ProviderFailure{Cause: context.DeadlineExceeded, Retryable: true, OutcomeKnown: true},
		&ProviderFailure{Cause: context.DeadlineExceeded, Retryable: true, OutcomeKnown: true},
	}, response: NormalizedResponse{Content: json.RawMessage(`{"ok":true}`)}}
	fallback := &hardeningAdapter{response: NormalizedResponse{Content: json.RawMessage(`{"ok":true}`)}}
	gateway := NewGatewayWithConfig(ledger, time.Now, GatewayConfig{
		ProviderPolicies: map[string]ProviderPolicy{"resilient": {Candidates: []ProviderCandidate{
			{Provider: "primary", Model: "model", CapabilityRank: 100},
			{Provider: "fallback", Model: "model", CapabilityRank: 100},
		}}},
		Sleep: func(context.Context, time.Duration) error { return nil },
	})
	for provider, adapter := range map[string]*hardeningAdapter{"primary": primary, "fallback": fallback} {
		if err := gateway.Register(provider, "model", adapter, Pricing{}); err != nil {
			t.Fatal(err)
		}
	}
	request := hardeningRequest("policy-timeout-retry")
	request.ProviderPolicy = "resilient"
	response, err := gateway.Generate(context.Background(), request, GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "policy-timeout-retry-reservation", MaxAttempts: 3})
	if err != nil || string(response.Content) != `{"ok":true}` {
		t.Fatalf("response=%#v error=%v", response, err)
	}
	if primary.Calls() != 3 || fallback.Calls() != 0 {
		t.Fatalf("primary calls=%d fallback calls=%d", primary.Calls(), fallback.Calls())
	}
}

func TestGatewayReleasesReservationWhenGenerateRetryWaitIsCanceled(t *testing.T) {
	gateway, adapter, ledger := newHardeningGateway(t, GatewayConfig{
		ProviderPolicies: map[string]ProviderPolicy{"retry": {Candidates: []ProviderCandidate{{Provider: "primary", Model: "model", CapabilityRank: 100}}}},
		Sleep: func(context.Context, time.Duration) error {
			return context.Canceled
		},
	})
	adapter.failures = []error{&ProviderFailure{Cause: errors.New("rate limited"), Retryable: true, OutcomeKnown: true}}
	request := hardeningRequest("generate-canceled-wait")
	request.ProviderPolicy = "retry"

	if _, err := gateway.Generate(context.Background(), request, GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "generate-canceled-reservation", MaxAttempts: 2}); !errors.Is(err, context.Canceled) {
		t.Fatalf("generate error = %v", err)
	}
	reservation, found := ledger.Reservation("tenant", "generate-canceled-reservation")
	if !found || reservation.State != ReservationReleased {
		t.Fatalf("reservation=%#v found=%t", reservation, found)
	}
	call, found := ledger.ModelCall("tenant", "generate-canceled-wait")
	if !found || call.Status != ModelCallFailedProvider {
		t.Fatalf("call=%#v found=%t", call, found)
	}
}

func TestGatewayFallbackRechecksPolicyAndBlocksUnapprovedDowngrade(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 100_000}); err != nil {
		t.Fatal(err)
	}
	primary := &hardeningAdapter{failures: []error{&ProviderFailure{Cause: errors.New("primary unavailable"), Retryable: true, OutcomeKnown: true}}}
	fallback := &hardeningAdapter{response: NormalizedResponse{Content: json.RawMessage(`{"ok":true}`), Usage: Usage{CostMicros: 1}}}
	var mu sync.Mutex
	evaluations := map[string]int{}
	config := GatewayConfig{
		ProviderPolicies: map[string]ProviderPolicy{"resilient": {
			Candidates: []ProviderCandidate{
				{Provider: "primary", Model: "model", CapabilityRank: 100, AllowedDataClassifications: []string{"INTERNAL"}},
				{Provider: "fallback", Model: "model", CapabilityRank: 100, AllowedDataClassifications: []string{"INTERNAL"}},
			},
		}},
		ProviderEligibility: func(_ context.Context, input ProviderEligibilityInput) error {
			mu.Lock()
			evaluations[input.Candidate.Provider]++
			mu.Unlock()
			return nil
		},
	}
	gateway := NewGatewayWithConfig(ledger, time.Now, config)
	for provider, adapter := range map[string]*hardeningAdapter{"primary": primary, "fallback": fallback} {
		if err := gateway.Register(provider, "model", adapter, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
			t.Fatal(err)
		}
	}
	request := hardeningRequest("fallback")
	request.ProviderPolicy = "resilient"
	response, err := gateway.Generate(context.Background(), request, GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "fallback-reservation", MaxAttempts: 1})
	if err != nil || string(response.Content) != `{"ok":true}` || primary.Calls() != 1 || fallback.Calls() != 1 {
		t.Fatalf("response=%#v primary=%d fallback=%d error=%v", response, primary.Calls(), fallback.Calls(), err)
	}
	mu.Lock()
	fallbackEvaluations := evaluations["fallback"]
	mu.Unlock()
	if fallbackEvaluations < 2 {
		t.Fatalf("fallback policy evaluations = %d", fallbackEvaluations)
	}
	unlisted := &hardeningAdapter{response: NormalizedResponse{Content: json.RawMessage(`{"ok":true}`)}}
	if err := gateway.Register("unlisted", "model", unlisted, Pricing{}); err != nil {
		t.Fatal(err)
	}
	unlistedRequest := hardeningRequest("unlisted-provider")
	unlistedRequest.ProviderPolicy = "resilient"
	if _, err := gateway.Generate(context.Background(), unlistedRequest, GenerateOptions{Provider: "unlisted", AccountID: "account", ReservationID: "unlisted-reservation", MaxAttempts: 1}); !errors.Is(err, ErrProviderNotAllowed) {
		t.Fatalf("unlisted provider error = %v", err)
	}
	if unlisted.Calls() != 0 {
		t.Fatalf("unlisted provider calls = %d", unlisted.Calls())
	}

	blockedLedger := NewBudgetLedger(time.Now)
	if err := blockedLedger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 100_000}); err != nil {
		t.Fatal(err)
	}
	blockedFallback := &hardeningAdapter{response: NormalizedResponse{Content: json.RawMessage(`{"ok":true}`), Usage: Usage{CostMicros: 1}}}
	blocked := NewGatewayWithConfig(blockedLedger, time.Now, GatewayConfig{ProviderPolicies: map[string]ProviderPolicy{"strict": {
		Candidates: []ProviderCandidate{{Provider: "primary", Model: "model", CapabilityRank: 100}, {Provider: "fallback", Model: "model", CapabilityRank: 50}},
	}}})
	blockedPrimary := &hardeningAdapter{failures: []error{&ProviderFailure{Cause: errors.New("primary unavailable"), Retryable: true, OutcomeKnown: true}}}
	if err := blocked.Register("primary", "model", blockedPrimary, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	if err := blocked.Register("fallback", "model", blockedFallback, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	blockedRequest := hardeningRequest("blocked-downgrade")
	blockedRequest.ProviderPolicy = "strict"
	if _, err := blocked.Generate(context.Background(), blockedRequest, GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "blocked-reservation", MaxAttempts: 1}); err == nil {
		t.Fatal("unapproved downgrade succeeded")
	}
	if blockedFallback.Calls() != 0 {
		t.Fatalf("downgraded provider calls = %d", blockedFallback.Calls())
	}
}

func TestGatewayDoesNotFallbackAfterKnownNonRetryableFailure(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 10_000}); err != nil {
		t.Fatal(err)
	}
	primary := &hardeningAdapter{failures: []error{&ProviderFailure{Cause: errors.New("invalid parameter"), OutcomeKnown: true}}}
	fallback := &hardeningAdapter{response: NormalizedResponse{Content: json.RawMessage(`{"ok":true}`)}}
	gateway := NewGatewayWithConfig(ledger, time.Now, GatewayConfig{ProviderPolicies: map[string]ProviderPolicy{"strict": {
		Candidates: []ProviderCandidate{{Provider: "primary", Model: "model", CapabilityRank: 100}, {Provider: "fallback", Model: "model", CapabilityRank: 100}},
	}}})
	for provider, adapter := range map[string]*hardeningAdapter{"primary": primary, "fallback": fallback} {
		if err := gateway.Register(provider, "model", adapter, Pricing{}); err != nil {
			t.Fatal(err)
		}
	}
	request := hardeningRequest("nonretryable")
	request.ProviderPolicy = "strict"
	if _, err := gateway.Generate(context.Background(), request, GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "nonretryable-reservation", MaxAttempts: 3}); err == nil {
		t.Fatal("nonretryable provider failure succeeded")
	}
	if primary.Calls() != 1 || fallback.Calls() != 0 {
		t.Fatalf("primary calls=%d fallback calls=%d", primary.Calls(), fallback.Calls())
	}
}

func TestGatewayFallsBackToPolicyApprovedDifferentModel(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 10_000}); err != nil {
		t.Fatal(err)
	}
	primary := &hardeningAdapter{failures: []error{&ProviderFailure{Cause: errors.New("primary unavailable"), Retryable: true, OutcomeKnown: true}}}
	fallback := &hardeningAdapter{response: NormalizedResponse{Content: json.RawMessage(`{"ok":true}`)}}
	gateway := NewGatewayWithConfig(ledger, time.Now, GatewayConfig{ProviderPolicies: map[string]ProviderPolicy{"strict": {
		Candidates: []ProviderCandidate{{Provider: "primary", Model: "model", CapabilityRank: 100}, {Provider: "fallback", Model: "other-model", CapabilityRank: 100}},
	}}})
	if err := gateway.Register("primary", "model", primary, Pricing{}); err != nil {
		t.Fatal(err)
	}
	if err := gateway.Register("fallback", "other-model", fallback, Pricing{}); err != nil {
		t.Fatal(err)
	}
	request := hardeningRequest("different-model-fallback")
	request.ProviderPolicy = "strict"
	response, err := gateway.Generate(context.Background(), request, GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "different-model-reservation", MaxAttempts: 1})
	if err != nil || string(response.Content) != `{"ok":true}` {
		t.Fatalf("response=%#v error=%v", response, err)
	}
	if primary.Calls() != 1 || fallback.Calls() != 1 {
		t.Fatalf("primary calls=%d fallback calls=%d", primary.Calls(), fallback.Calls())
	}
	call, found := ledger.ModelCall("tenant", request.RequestID)
	if !found || call.Provider != "fallback" || call.LogicalModel != request.Model {
		t.Fatalf("model call=%#v found=%t", call, found)
	}
}

func TestGatewayRetriesKnownStreamStartFailureWithBackoff(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 10_000}); err != nil {
		t.Fatal(err)
	}
	var delays []time.Duration
	adapter := &hardeningAdapter{
		streamFailures: []error{&ProviderFailure{Cause: errors.New("rate limited"), Retryable: true, OutcomeKnown: true}},
		stream:         &hardeningUsageStream{usage: Usage{CostMicros: 1}},
	}
	gateway := NewGatewayWithConfig(ledger, time.Now, GatewayConfig{
		ProviderPolicies: map[string]ProviderPolicy{"stream": {Candidates: []ProviderCandidate{{Provider: "primary", Model: "model", CapabilityRank: 100}}}},
		Sleep: func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		},
	})
	if err := gateway.Register("primary", "model", adapter, Pricing{}); err != nil {
		t.Fatal(err)
	}
	request := hardeningRequest("stream-retry")
	request.ProviderPolicy = "stream"
	stream, err := gateway.Stream(context.Background(), request, GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "stream-retry-reservation", MaxAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("stream terminal error = %v", err)
	}
	if adapter.StreamCalls() != 2 || len(delays) != 1 || delays[0] <= 0 {
		t.Fatalf("stream calls=%d delays=%v", adapter.StreamCalls(), delays)
	}
}

func TestGatewayReleasesReservationWhenStreamRetryWaitIsCanceled(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 10_000}); err != nil {
		t.Fatal(err)
	}
	adapter := &hardeningAdapter{streamFailures: []error{&ProviderFailure{Cause: errors.New("rate limited"), Retryable: true, OutcomeKnown: true}}}
	gateway := NewGatewayWithConfig(ledger, time.Now, GatewayConfig{
		ProviderPolicies: map[string]ProviderPolicy{"retry": {Candidates: []ProviderCandidate{{Provider: "primary", Model: "model", CapabilityRank: 100}}}},
		Sleep: func(context.Context, time.Duration) error {
			return context.Canceled
		},
	})
	if err := gateway.Register("primary", "model", adapter, Pricing{}); err != nil {
		t.Fatal(err)
	}
	request := hardeningRequest("stream-canceled-wait")
	request.ProviderPolicy = "retry"

	if _, err := gateway.Stream(context.Background(), request, GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "stream-canceled-reservation", MaxAttempts: 2}); !errors.Is(err, context.Canceled) {
		t.Fatalf("stream error = %v", err)
	}
	reservation, found := ledger.Reservation("tenant", "stream-canceled-reservation")
	if !found || reservation.State != ReservationReleased {
		t.Fatalf("reservation=%#v found=%t", reservation, found)
	}
	call, found := ledger.ModelCall("tenant", "stream-canceled-wait")
	if !found || call.Status != ModelCallFailedProvider {
		t.Fatalf("call=%#v found=%t", call, found)
	}
}

func TestGatewaySettlesAuthoritativeFinalStreamUsage(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 1_000}); err != nil {
		t.Fatal(err)
	}
	stream := &hardeningUsageStream{
		events:  []json.RawMessage{json.RawMessage(`{"delta":"hello"}`)},
		content: json.RawMessage(`"hello"`),
		usage:   Usage{InputTokens: 2, OutputTokens: 3, CostMicros: 5, ProviderRequestID: "provider-stream", ModelVersion: "model-v2"},
	}
	adapter := &hardeningAdapter{stream: stream}
	gateway := NewGateway(ledger, time.Now)
	if err := gateway.Register("primary", "model", adapter, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	request := hardeningRequest("stream-final")
	responseStream, err := gateway.Stream(context.Background(), request, GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "stream-reservation", MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	if value, err := responseStream.Recv(context.Background()); err != nil || string(value) != `{"delta":"hello"}` {
		t.Fatalf("stream value=%s err=%v", value, err)
	}
	if _, err := responseStream.Recv(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal error = %v", err)
	}
	if err := responseStream.Close(); err != nil {
		t.Fatal(err)
	}
	reservation, found := ledger.Reservation("tenant", "stream-reservation")
	if !found || reservation.State != ReservationSettled || reservation.SettledMicros != 5 {
		t.Fatalf("reservation=%#v found=%t", reservation, found)
	}
	call, found := ledger.ModelCall("tenant", "stream-final")
	if !found || call.Status != ModelCallSucceeded || call.InputTokens != 2 || call.OutputTokens != 3 || call.CostMicros != 5 || call.ProviderRequestID != "provider-stream" || call.ActualModelVersion != "model-v2" {
		t.Fatalf("call=%#v found=%t", call, found)
	}
}

func TestGatewayForwardsNormalizedDeltasBeforeTerminalValidation(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 1_000}); err != nil {
		t.Fatal(err)
	}
	stream := &aggregatedUsageStream{
		events: []json.RawMessage{
			json.RawMessage(`{"delta":"{\"ok\""}`),
			json.RawMessage(`{"delta":":true}"}`),
		},
		content: json.RawMessage(`{"ok":true}`),
		usage:   Usage{InputTokens: 2, OutputTokens: 3, ProviderRequestID: "provider-stream", ModelVersion: "model-v2"},
	}
	adapter := &hardeningAdapter{stream: stream}
	gateway := NewGateway(ledger, time.Now)
	if err := gateway.Register("primary", "model", adapter, Pricing{InputMicrosPerToken: 2, OutputMicrosPerToken: 3}); err != nil {
		t.Fatal(err)
	}
	responseStream, err := gateway.Stream(context.Background(), hardeningRequest("stream-aggregate"), GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "stream-aggregate-reservation", MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	value, err := responseStream.Recv(context.Background())
	if err != nil || string(value) != `{"delta":"{\"ok\""}` {
		t.Fatalf("first stream value=%s err=%v", value, err)
	}
	stream.mu.Lock()
	remaining := len(stream.events)
	stream.mu.Unlock()
	if remaining != 1 {
		t.Fatalf("stream was drained before first delta returned: remaining=%d", remaining)
	}
	if strings.Contains(string(value), "choices") || strings.Contains(string(value), "provider-stream") {
		t.Fatalf("provider envelope leaked: %s", value)
	}
	value, err = responseStream.Recv(context.Background())
	if err != nil || string(value) != `{"delta":":true}"}` {
		t.Fatalf("second stream value=%s err=%v", value, err)
	}
	if _, err := responseStream.Recv(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal error=%v", err)
	}
	reservation, found := ledger.Reservation("tenant", "stream-aggregate-reservation")
	if !found || reservation.State != ReservationSettled || reservation.SettledMicros != 13 {
		t.Fatalf("reservation=%#v found=%v", reservation, found)
	}
}

func TestGatewayRejectsProviderSpecificStreamEnvelope(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 1_000}); err != nil {
		t.Fatal(err)
	}
	stream := &aggregatedUsageStream{
		events:  []json.RawMessage{json.RawMessage(`{"id":"provider-stream","choices":[{"delta":{"content":"hello"}}]}`)},
		content: json.RawMessage(`"hello"`),
		usage:   Usage{InputTokens: 1, OutputTokens: 1},
	}
	gateway := NewGateway(ledger, time.Now)
	if err := gateway.Register("primary", "model", &hardeningAdapter{stream: stream}, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	responseStream, err := gateway.Stream(context.Background(), hardeningRequest("stream-provider-envelope"), GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "stream-provider-envelope-reservation", MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	if value, err := responseStream.Recv(context.Background()); !errors.Is(err, ErrOutputSchema) || len(value) != 0 {
		t.Fatalf("provider envelope value=%s err=%v", value, err)
	}
	reservation, found := ledger.Reservation("tenant", "stream-provider-envelope-reservation")
	if !found || reservation.State != ReservationReconcile {
		t.Fatalf("reservation=%#v found=%v", reservation, found)
	}
}

func TestGatewayReconcilesAtTerminalWithoutAuthoritativeUsage(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 1_000}); err != nil {
		t.Fatal(err)
	}
	adapter := &hardeningAdapter{stream: &rawOnlyStream{events: []json.RawMessage{json.RawMessage(`{"delta":"true"}`)}}}
	gateway := NewGateway(ledger, time.Now)
	if err := gateway.Register("primary", "model", adapter, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	responseStream, err := gateway.Stream(context.Background(), hardeningRequest("stream-no-usage"), GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "stream-no-usage-reservation", MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	value, err := responseStream.Recv(context.Background())
	if err != nil || string(value) != `{"delta":"true"}` {
		t.Fatalf("stream value=%s err=%v", value, err)
	}
	value, err = responseStream.Recv(context.Background())
	if !errors.Is(err, ErrReconciliationRequired) || len(value) != 0 {
		t.Fatalf("terminal stream value=%s err=%v", value, err)
	}
	reservation, found := ledger.Reservation("tenant", "stream-no-usage-reservation")
	if !found || reservation.State != ReservationReconcile {
		t.Fatalf("reservation=%#v found=%v", reservation, found)
	}
}

func TestGatewayValidatesAggregatedStreamAtEOFBeforeSuccess(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 1_000}); err != nil {
		t.Fatal(err)
	}
	stream := &hardeningUsageStream{
		events:  []json.RawMessage{json.RawMessage(`{"delta":"{\"ok\":false}"}`)},
		content: json.RawMessage(`{"ok":false}`),
		usage:   Usage{InputTokens: 1, OutputTokens: 1, CostMicros: 4},
	}
	adapter := &hardeningAdapter{stream: stream}
	gateway := NewGateway(ledger, time.Now)
	if err := gateway.Register("primary", "model", adapter, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	request := hardeningRequest("stream-final-schema")
	request.ResponseSchema = json.RawMessage(`{"type":"object","required":["ok"],"properties":{"ok":{"const":true}}}`)
	request.ResponseSemanticValidator = func(content json.RawMessage) error {
		var value struct {
			OK bool `json:"ok"`
		}
		if err := json.Unmarshal(content, &value); err != nil || !value.OK {
			return errors.New("semantic output rejected")
		}
		return nil
	}
	responseStream, err := gateway.Stream(context.Background(), request, GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "stream-final-schema-reservation", MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	if value, err := responseStream.Recv(context.Background()); err != nil || string(value) != `{"delta":"{\"ok\":false}"}` {
		t.Fatalf("stream value=%s err=%v", value, err)
	}
	if _, err := responseStream.Recv(context.Background()); !errors.Is(err, ErrOutputSchema) {
		t.Fatalf("stream schema error = %v", err)
	}
	reservation, found := ledger.Reservation("tenant", "stream-final-schema-reservation")
	if !found || reservation.State != ReservationSettled || reservation.SettledMicros != 2 {
		t.Fatalf("reservation=%#v found=%t", reservation, found)
	}
	call, found := ledger.ModelCall("tenant", "stream-final-schema")
	if !found || call.Status != ModelCallFailedOutputSchema {
		t.Fatalf("call=%#v found=%t", call, found)
	}
}

func TestGatewayRejectsMalformedStreamEventBeforeFinalValidation(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 1_000}); err != nil {
		t.Fatal(err)
	}
	stream := &aggregatedUsageStream{
		events:  []json.RawMessage{json.RawMessage(`{"delta":"valid"}`), json.RawMessage(`{"delta":`)},
		content: json.RawMessage(`{"ok":true}`),
		usage:   Usage{InputTokens: 1, OutputTokens: 1, ProviderRequestID: "provider-stream", ModelVersion: "model-v1"},
	}
	adapter := &hardeningAdapter{stream: stream}
	gateway := NewGateway(ledger, time.Now)
	if err := gateway.Register("primary", "model", adapter, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	responseStream, err := gateway.Stream(context.Background(), hardeningRequest("stream-invalid-event"), GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "stream-invalid-event-reservation", MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	if value, err := responseStream.Recv(context.Background()); err != nil || string(value) != `{"delta":"valid"}` {
		t.Fatalf("valid event value=%s err=%v", value, err)
	}
	if value, err := responseStream.Recv(context.Background()); !errors.Is(err, ErrOutputSchema) || len(value) != 0 {
		t.Fatalf("malformed event value=%s err=%v", value, err)
	}
	reservation, found := ledger.Reservation("tenant", "stream-invalid-event-reservation")
	if !found || reservation.State != ReservationReconcile {
		t.Fatalf("reservation=%#v found=%v", reservation, found)
	}
}

func TestGatewaySettlesAuthoritativeZeroUsageWithoutWorstCaseCharge(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 1_000}); err != nil {
		t.Fatal(err)
	}
	adapter := &hardeningAdapter{response: NormalizedResponse{Content: json.RawMessage(`{"ok":true}`), Usage: Usage{ProviderRequestID: "provider-zero", ModelVersion: "model-v1"}}}
	gateway := NewGateway(ledger, time.Now)
	if err := gateway.Register("primary", "model", adapter, Pricing{InputMicrosPerToken: 2, OutputMicrosPerToken: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.Generate(context.Background(), hardeningRequest("zero-usage"), GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "zero-usage-reservation", MaxAttempts: 1}); err != nil {
		t.Fatal(err)
	}
	account, _ := ledger.Account("tenant", "account")
	reservation, found := ledger.Reservation("tenant", "zero-usage-reservation")
	if !found || reservation.State != ReservationSettled || reservation.SettledMicros != 0 || account.SpentMicros != 0 || account.ReservedMicros != 0 {
		t.Fatalf("account=%#v reservation=%#v found=%v", account, reservation, found)
	}
}

func TestGatewayReconcilesProviderUsageAtomicallyAndIdempotently(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", ScopeType: "PROJECT", ScopeID: "project", LimitMicros: 1_000}); err != nil {
		t.Fatal(err)
	}
	adapter := &hardeningAdapter{failures: []error{&ProviderFailure{Cause: errors.New("provider outcome unknown"), Retryable: true, OutcomeKnown: false}}}
	gateway := NewGateway(ledger, time.Now)
	if err := gateway.Register("primary", "model", adapter, Pricing{InputMicrosPerToken: 2, OutputMicrosPerToken: 3}); err != nil {
		t.Fatal(err)
	}
	request := hardeningRequest("reconcile-usage")
	if _, err := gateway.Generate(context.Background(), request, GenerateOptions{Provider: "primary", AccountID: "account", ReservationID: "reconcile-reservation", MaxAttempts: 1}); err == nil {
		t.Fatal("unknown provider outcome succeeded")
	}
	rawUsage := json.RawMessage(`{"inputTokens":2,"outputTokens":3,"costMicros":999,"providerRequestId":"provider-reconciled","modelVersion":"model-v1"}`)
	reconciliation := UsageReconciliationRequest{TenantID: "tenant", RequestID: request.RequestID, ReservationID: "reconcile-reservation", Provider: "primary", Model: "model", RawUsage: rawUsage}
	first, err := gateway.ReconcileUsage(context.Background(), reconciliation)
	if err != nil {
		t.Fatal(err)
	}
	second, err := gateway.ReconcileUsage(context.Background(), reconciliation)
	if err != nil || second.SettledMicros != first.SettledMicros {
		t.Fatalf("idempotent reconciliation=%#v error=%v", second, err)
	}
	if first.State != ReservationSettled || first.SettledMicros != 13 {
		t.Fatalf("reservation=%#v", first)
	}
	account, _ := ledger.Account("tenant", "account")
	call, found := ledger.ModelCall("tenant", request.RequestID)
	if !found || account.SpentMicros != 13 || account.ReservedMicros != 0 || call.Status != ModelCallReconciled || call.InputTokens != 2 || call.OutputTokens != 3 || call.CostMicros != 13 || call.ProviderRequestID != "provider-reconciled" || !validModelDigest(call.ReconciliationReceiptSHA256) || call.ReconciledAt == nil {
		t.Fatalf("account=%#v call=%#v found=%v", account, call, found)
	}
	reconciliation.RawUsage = json.RawMessage(`{"inputTokens":2,"outputTokens":4,"providerRequestId":"provider-reconciled","modelVersion":"model-v1"}`)
	if _, err := gateway.ReconcileUsage(context.Background(), reconciliation); !errors.Is(err, ErrReservationConflict) {
		t.Fatalf("changed reconciliation error=%v", err)
	}
}

func TestGatewayReconciliationIncludesPreviouslyIncurredUsage(t *testing.T) {
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 1_000}); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Reserve(context.Background(), "tenant", "account", "partial-reservation", "partial-request", 100); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_, err := ledger.FinalizeModelCall(context.Background(), ModelCallFinalization{
		ReservationID: "partial-reservation", Disposition: ReservationDispositionReconcile, ActualMicros: 7,
		Call: ModelCall{
			TenantID: "tenant", RequestID: "partial-request", ProjectID: "project", AgentInstanceID: "agent",
			Provider: "primary", LogicalModel: "model", ActualModelVersion: "model-v1", PromptBundleVersion: "prompt-v1",
			InputSHA256: digestBytes([]byte("partial-input")), InputTokens: 4, OutputTokens: 1, CostMicros: 7,
			Status: ModelCallReconcile, ProviderRequestID: "prior-known-attempt", CreatedAt: now,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &hardeningAdapter{}
	gateway := NewGateway(ledger, time.Now)
	if err := gateway.Register("primary", "model", adapter, Pricing{InputMicrosPerToken: 2, OutputMicrosPerToken: 3}); err != nil {
		t.Fatal(err)
	}
	reservation, err := gateway.ReconcileUsage(context.Background(), UsageReconciliationRequest{
		TenantID: "tenant", RequestID: "partial-request", ReservationID: "partial-reservation", Provider: "primary", Model: "model",
		RawUsage: json.RawMessage(`{"inputTokens":2,"outputTokens":1,"providerRequestId":"unknown-attempt","modelVersion":"model-v1"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	call, _ := ledger.ModelCall("tenant", "partial-request")
	if reservation.SettledMicros != 14 || call.CostMicros != 14 || call.InputTokens != 6 || call.OutputTokens != 2 || call.ProviderRequestID != "unknown-attempt" {
		t.Fatalf("reservation=%#v call=%#v", reservation, call)
	}
}

func newHardeningGateway(t *testing.T, config GatewayConfig) (*Gateway, *hardeningAdapter, *BudgetLedger) {
	t.Helper()
	ledger := NewBudgetLedger(time.Now)
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 100_000}); err != nil {
		t.Fatal(err)
	}
	adapter := &hardeningAdapter{response: NormalizedResponse{Content: json.RawMessage(`{"ok":true}`), Usage: Usage{InputTokens: 2, OutputTokens: 1, CostMicros: 3}}}
	gateway := NewGatewayWithConfig(ledger, time.Now, config)
	if err := gateway.Register("primary", "model", adapter, Pricing{InputMicrosPerToken: 1, OutputMicrosPerToken: 1}); err != nil {
		t.Fatal(err)
	}
	return gateway, adapter, ledger
}

func hardeningRequest(requestID string) NormalizedRequest {
	return NormalizedRequest{
		RequestID: requestID, TenantID: "tenant", ProjectID: "project", TaskID: "task", AgentInstanceID: "agent", Role: "EXECUTOR",
		Model: "model", PromptBundleVersion: "prompt-v1", Messages: []Message{{Role: "user", Content: "hello"}}, MaxOutputTokens: 4, DataClassification: "INTERNAL",
	}
}

func TestContextWindowExceededUsesExplicitTotalWindow(t *testing.T) {
	request := hardeningRequest("context-window")
	request.MaxOutputTokens = 20
	request.ContextWindowTokens = 100
	capabilities := ModelCapabilities{MaxInputTokens: 100, ContextWindowTokens: 120}
	if !contextWindowExceeded(request, capabilities, TokenEstimate{InputTokens: 81}) {
		t.Fatal("request exceeding its configured total context window was accepted")
	}
	if contextWindowExceeded(request, capabilities, TokenEstimate{InputTokens: 80}) {
		t.Fatal("request exactly fitting the configured total context window was rejected")
	}
}

func TestContextWindowExceededSupportsLegacyCapabilities(t *testing.T) {
	request := hardeningRequest("legacy-context-window")
	capabilities := ModelCapabilities{MaxInputTokens: 10}
	if contextWindowExceeded(request, capabilities, TokenEstimate{InputTokens: 10}) {
		t.Fatal("legacy capabilities treated max input tokens as a total context window")
	}
	if !contextWindowExceeded(request, capabilities, TokenEstimate{InputTokens: 11}) {
		t.Fatal("legacy max input limit was not enforced")
	}
}

type hardeningAdapter struct {
	mu             sync.Mutex
	failures       []error
	response       NormalizedResponse
	stream         ResponseStream
	streamFailures []error
	calls          int
	streamCalls    int
	entered        chan struct{}
	proceed        chan struct{}
	once           sync.Once
}

func (adapter *hardeningAdapter) Capabilities(context.Context, string) (ModelCapabilities, error) {
	return ModelCapabilities{SupportsStreaming: true, SupportsJSONSchema: true, SupportsToolCalls: true, MaxInputTokens: 1024, MaxOutputTokens: 128, ActualModelVersion: "model-v1"}, nil
}

func (adapter *hardeningAdapter) CountTokens(context.Context, NormalizedRequest) (TokenEstimate, error) {
	return TokenEstimate{InputTokens: 2}, nil
}

func (adapter *hardeningAdapter) Generate(_ context.Context, request NormalizedRequest) (NormalizedResponse, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.calls++
	if adapter.entered != nil {
		adapter.once.Do(func() { close(adapter.entered) })
	}
	if adapter.proceed != nil {
		<-adapter.proceed
	}
	if len(adapter.failures) != 0 {
		err := adapter.failures[0]
		adapter.failures = adapter.failures[1:]
		return NormalizedResponse{}, err
	}
	response := cloneNormalizedResponse(adapter.response)
	if response.RequestID == "" {
		response.RequestID = request.RequestID
	}
	return response, nil
}

func (adapter *hardeningAdapter) Stream(context.Context, NormalizedRequest) (ResponseStream, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.streamCalls++
	if len(adapter.streamFailures) != 0 {
		err := adapter.streamFailures[0]
		adapter.streamFailures = adapter.streamFailures[1:]
		return nil, err
	}
	if adapter.stream == nil {
		return nil, &ProviderFailure{Cause: errors.New("stream unavailable"), OutcomeKnown: true}
	}
	return adapter.stream, nil
}

func (adapter *hardeningAdapter) StreamCalls() int {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.streamCalls
}

func (*hardeningAdapter) Cancel(context.Context, string) error { return nil }

func (*hardeningAdapter) NormalizeUsage(raw any) (Usage, error) {
	switch value := raw.(type) {
	case Usage:
		return value, nil
	case json.RawMessage:
		var usage Usage
		if json.Unmarshal(value, &usage) != nil {
			return Usage{}, ErrInvalidRequest
		}
		return usage, nil
	default:
		return Usage{}, ErrInvalidRequest
	}
}

func (adapter *hardeningAdapter) Calls() int {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.calls
}

type hardeningUsageStream struct {
	mu      sync.Mutex
	events  []json.RawMessage
	content json.RawMessage
	usage   Usage
	closed  bool
}

type aggregatedUsageStream struct {
	mu      sync.Mutex
	events  []json.RawMessage
	content json.RawMessage
	usage   Usage
	closed  bool
}

type rawOnlyStream struct {
	mu     sync.Mutex
	events []json.RawMessage
	closed bool
}

func (stream *rawOnlyStream) Recv(context.Context) (json.RawMessage, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed || len(stream.events) == 0 {
		return nil, io.EOF
	}
	value := append(json.RawMessage(nil), stream.events[0]...)
	stream.events = stream.events[1:]
	return value, nil
}

func (stream *rawOnlyStream) Close() error {
	stream.mu.Lock()
	stream.closed = true
	stream.mu.Unlock()
	return nil
}

func (stream *aggregatedUsageStream) Recv(context.Context) (json.RawMessage, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed || len(stream.events) == 0 {
		return nil, io.EOF
	}
	event := append(json.RawMessage(nil), stream.events[0]...)
	stream.events = stream.events[1:]
	return event, nil
}

func (stream *aggregatedUsageStream) Close() error {
	stream.mu.Lock()
	stream.closed = true
	stream.mu.Unlock()
	return nil
}

func (stream *aggregatedUsageStream) FinalUsage() (Usage, bool) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return stream.usage, len(stream.events) == 0 && !stream.closed
}

func (stream *aggregatedUsageStream) FinalContent() (json.RawMessage, bool) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return append(json.RawMessage(nil), stream.content...), len(stream.events) == 0 && !stream.closed
}

func (stream *hardeningUsageStream) Recv(context.Context) (json.RawMessage, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed || len(stream.events) == 0 {
		return nil, io.EOF
	}
	event := append(json.RawMessage(nil), stream.events[0]...)
	stream.events = stream.events[1:]
	return event, nil
}

func (stream *hardeningUsageStream) Close() error {
	stream.mu.Lock()
	stream.closed = true
	stream.mu.Unlock()
	return nil
}

func (stream *hardeningUsageStream) FinalUsage() (Usage, bool) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return stream.usage, len(stream.events) == 0
}

func (stream *hardeningUsageStream) FinalContent() (json.RawMessage, bool) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return append(json.RawMessage(nil), stream.content...), len(stream.events) == 0 && !stream.closed
}

var _ ModelAdapter = (*hardeningAdapter)(nil)
var _ UsageAwareStream = (*hardeningUsageStream)(nil)
var _ FinalContentAwareStream = (*hardeningUsageStream)(nil)
