package modelgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

const (
	MaximumResponseBytes       = 4 << 20
	MaximumResponseSchemaBytes = 256 << 10
)

type Gateway struct {
	mu                     sync.RWMutex
	adapters               map[string]ModelAdapter
	allowed                map[string]map[string]bool
	pricing                map[string]Pricing
	ledger                 BudgetLedgerBackend
	callFinalizer          ModelCallFinalizer
	clock                  func() time.Time
	circuits               map[string]providerCircuit
	initialProviderBackoff time.Duration
	maximumProviderBackoff time.Duration
	backoffJitterRatio     float64
	sleep                  func(context.Context, time.Duration) error
	policies               map[string]ProviderPolicy
	eligibility            ProviderEligibility
	replayStore            ModelReplayStore
	replayFinalizer        ModelCallReplayFinalizer
	callLookup             ModelCallLookup
	executions             map[string]*requestExecution
}

type providerCircuit struct {
	failures int
	retryAt  time.Time
}

type Pricing struct {
	InputMicrosPerToken  int64
	OutputMicrosPerToken int64
}

type GatewayConfig struct {
	InitialProviderBackoff time.Duration
	MaximumProviderBackoff time.Duration
	BackoffJitterRatio     float64
	Sleep                  func(context.Context, time.Duration) error
	ProviderPolicies       map[string]ProviderPolicy
	ProviderEligibility    ProviderEligibility
	ReplayStore            ModelReplayStore
	CallLookup             ModelCallLookup
}

type requestExecution struct {
	digest   string
	done     chan struct{}
	response NormalizedResponse
	err      error
}

func NewGateway(ledger BudgetLedgerBackend, clock func() time.Time) *Gateway {
	return NewGatewayWithConfig(ledger, clock, GatewayConfig{})
}

func NewGatewayWithConfig(ledger BudgetLedgerBackend, clock func() time.Time, config GatewayConfig) *Gateway {
	if ledger == nil {
		ledger = NewBudgetLedger(clock)
	}
	if clock == nil {
		clock = time.Now
	}
	if config.InitialProviderBackoff <= 0 {
		config.InitialProviderBackoff = time.Second
	}
	if config.MaximumProviderBackoff < config.InitialProviderBackoff {
		config.MaximumProviderBackoff = 5 * time.Minute
	}
	if config.BackoffJitterRatio <= 0 || config.BackoffJitterRatio > 1 {
		config.BackoffJitterRatio = 0.2
	}
	if config.Sleep == nil {
		config.Sleep = sleepWithContext
	}
	finalizer, _ := ledger.(ModelCallFinalizer)
	policies := make(map[string]ProviderPolicy, len(config.ProviderPolicies))
	for name, policy := range config.ProviderPolicies {
		policy.Candidates = append([]ProviderCandidate(nil), policy.Candidates...)
		policies[name] = policy
	}
	replayStore := config.ReplayStore
	if replayStore == nil {
		if candidate, ok := ledger.(EnabledModelReplayStore); ok && candidate.ReplayEnabled() {
			replayStore = candidate
		}
	}
	callLookup := config.CallLookup
	if callLookup == nil {
		callLookup, _ = ledger.(ModelCallLookup)
	}
	var replayFinalizer ModelCallReplayFinalizer
	if config.ReplayStore == nil && replayStore != nil {
		replayFinalizer, _ = ledger.(ModelCallReplayFinalizer)
	}
	return &Gateway{adapters: make(map[string]ModelAdapter), allowed: make(map[string]map[string]bool), pricing: make(map[string]Pricing), ledger: ledger, callFinalizer: finalizer, clock: clock, circuits: make(map[string]providerCircuit), initialProviderBackoff: config.InitialProviderBackoff, maximumProviderBackoff: config.MaximumProviderBackoff, backoffJitterRatio: config.BackoffJitterRatio, sleep: config.Sleep, policies: policies, eligibility: config.ProviderEligibility, replayStore: replayStore, replayFinalizer: replayFinalizer, callLookup: callLookup, executions: make(map[string]*requestExecution)}
}

func (g *Gateway) Register(provider, model string, adapter ModelAdapter, pricing Pricing) error {
	if provider == "" || model == "" || adapter == nil || pricing.InputMicrosPerToken < 0 || pricing.OutputMicrosPerToken < 0 {
		return ErrInvalidRequest
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.allowed[provider] == nil {
		g.allowed[provider] = make(map[string]bool)
	}
	g.allowed[provider][model] = true
	g.adapters[provider+"\x00"+model] = adapter
	g.pricing[provider+"\x00"+model] = pricing
	return nil
}

type GenerateOptions struct {
	Provider      string `json:"provider"`
	AccountID     string `json:"accountId"`
	ReservationID string `json:"reservationId"`
	MaxAttempts   int    `json:"maxAttempts"`
}

// Capabilities returns provider metadata only for a registered provider/model
// pair. Callers cannot probe arbitrary adapters through the gateway.
func (g *Gateway) Capabilities(ctx context.Context, provider, model string) (ModelCapabilities, error) {
	if ctx == nil || provider == "" || model == "" {
		return ModelCapabilities{}, ErrInvalidRequest
	}
	key := provider + "\x00" + model
	adapter, _, allowed := g.provider(key, provider, model)
	if adapter == nil || !allowed {
		return ModelCapabilities{}, ErrProviderNotAllowed
	}
	if !g.providerReady(key, g.clock().UTC()) {
		return ModelCapabilities{}, ErrProviderUnavailable
	}
	capabilities, err := adapter.Capabilities(ctx, model)
	if err != nil {
		g.recordProviderFailure(key, err)
		return ModelCapabilities{}, redactError(err)
	}
	return capabilities, nil
}

// Stream reserves the worst-case model budget before opening a provider stream.
// Completed streams settle only when the adapter reports authoritative final
// usage; missing usage and interrupted streams remain in reconciliation.
func (g *Gateway) Stream(ctx context.Context, request NormalizedRequest, options GenerateOptions) (ResponseStream, error) {
	if ctx == nil {
		return nil, ErrInvalidRequest
	}
	if policy, found := g.policyFor(request); found {
		return g.streamWithPolicy(ctx, request, options, policy)
	}
	if request.ProviderPolicy != "" {
		return nil, ErrProviderNotAllowed
	}
	adapter, key, capabilities, estimate, reservation, err := g.prepare(ctx, request, options, true)
	if err != nil {
		return nil, err
	}
	startedAt := g.clock().UTC()
	call, err := newModelCall(request, options.Provider, capabilities.ActualModelVersion, estimate.InputTokens, startedAt)
	if err != nil {
		if releaseErr := g.releaseReservation(ctx, request.TenantID, reservation); releaseErr != nil {
			return nil, releaseErr
		}
		return nil, err
	}
	stream, err := adapter.Stream(ctx, request)
	if err != nil {
		g.recordProviderFailure(key, err)
		disposition := ReservationDispositionReconcile
		call.Status = ModelCallReconcile
		var providerFailure *ProviderFailure
		if errors.As(err, &providerFailure) && providerFailure.OutcomeKnown {
			disposition = ReservationDispositionRelease
			call.Status = ModelCallFailedProvider
		}
		call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
		if failureErr := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: reservation, Disposition: disposition, Call: call}); failureErr != nil {
			return nil, failureErr
		}
		return nil, redactError(err)
	}
	return &budgetedStream{
		stream: stream, tenantID: request.TenantID, reservationID: reservation, context: ctx,
		call: call, startedAt: startedAt, finalizeCall: g.finalizeModelCall,
		clock: g.clock, responseSchema: append(json.RawMessage(nil), request.ResponseSchema...), semanticValidator: request.ResponseSemanticValidator,
		maxResponseBytes: MaximumResponseBytes,
	}, nil
}

func (g *Gateway) streamWithPolicy(ctx context.Context, request NormalizedRequest, options GenerateOptions, policy ProviderPolicy) (ResponseStream, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	if options.MaxAttempts <= 0 {
		options.MaxAttempts = 3
	}
	if options.MaxAttempts > 3 || options.AccountID == "" || options.ReservationID == "" {
		return nil, ErrInvalidRequest
	}
	selections, err := g.selectProviders(ctx, "stream", request, options, policy)
	if err != nil {
		return nil, err
	}
	reservedPerAttempt := int64(0)
	for _, selection := range selections {
		reservedPerAttempt, err = addCost(reservedPerAttempt, selection.worstCost)
		if err != nil {
			return nil, err
		}
	}
	if reservedPerAttempt > math.MaxInt64/int64(options.MaxAttempts) {
		return nil, ErrInvalidRequest
	}
	if _, err := g.claimExternalCall(ctx, request.TenantID, options.AccountID, options.ReservationID, request.RequestID, reservedPerAttempt*int64(options.MaxAttempts)); err != nil {
		return nil, err
	}
	startedAt := g.clock().UTC()
	call, err := newModelCall(request, selections[0].candidate.Provider, selections[0].caps.ActualModelVersion, selections[0].estimate.InputTokens, startedAt)
	if err != nil {
		_ = g.releaseReservation(ctx, request.TenantID, options.ReservationID)
		return nil, err
	}
	var lastErr error
	for index, selection := range selections {
		if !selection.caps.SupportsStreaming {
			lastErr = ErrProviderNotAllowed
			continue
		}
		if g.eligibility != nil {
			if eligibilityErr := g.eligibility(ctx, ProviderEligibilityInput{Operation: "stream", Request: request, Candidate: selection.candidate, Capabilities: selection.caps, AccountID: options.AccountID, ReservationID: options.ReservationID}); eligibilityErr != nil {
				lastErr = eligibilityErr
				continue
			}
		}
		call.Provider = selection.candidate.Provider
		call.LogicalModel = request.Model
		call.ActualModelVersion = selection.caps.ActualModelVersion
		call.InputTokens = selection.estimate.InputTokens
		for attempt := 0; attempt < options.MaxAttempts; attempt++ {
			stream, streamErr := selection.adapter.Stream(ctx, selection.request)
			if streamErr == nil {
				g.providerSucceeded(selection.key)
				return &budgetedStream{stream: stream, tenantID: request.TenantID, reservationID: options.ReservationID, context: ctx, call: call, startedAt: startedAt, finalizeCall: g.finalizeModelCall, clock: g.clock, responseSchema: append(json.RawMessage(nil), request.ResponseSchema...), semanticValidator: request.ResponseSemanticValidator, maxResponseBytes: MaximumResponseBytes}, nil
			}
			g.recordProviderFailure(selection.key, streamErr)
			lastErr = streamErr
			var providerFailure *ProviderFailure
			if !errors.As(streamErr, &providerFailure) || !providerFailure.OutcomeKnown {
				call.Status = ModelCallReconcile
				call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
				if finalizeErr := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionReconcile, Call: call}); finalizeErr != nil {
					return nil, finalizeErr
				}
				return nil, redactError(streamErr)
			}
			if !providerFailure.Retryable || attempt+1 == options.MaxAttempts {
				break
			}
			if waitErr := g.waitForRetry(ctx, selection.key, providerFailure); waitErr != nil {
				call.Status = ModelCallFailedProvider
				call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
				if finalizeErr := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionRelease, Call: call}); finalizeErr != nil {
					return nil, finalizeErr
				}
				return nil, waitErr
			}
		}
		if index+1 < len(selections) && providerFallbackAllowed(lastErr) {
			continue
		}
		call.Status = ModelCallFailedProvider
		call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
		if finalizeErr := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionRelease, Call: call}); finalizeErr != nil {
			return nil, finalizeErr
		}
		return nil, redactError(lastErr)
	}
	if lastErr == nil {
		lastErr = ErrProviderNotAllowed
	}
	call.Status = ModelCallFailedProvider
	call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
	if finalizeErr := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionRelease, Call: call}); finalizeErr != nil {
		return nil, finalizeErr
	}
	return nil, redactError(lastErr)
}

// Cancel forwards cancellation only to a registered provider/model adapter.
func (g *Gateway) Cancel(ctx context.Context, provider, model, providerRequestID string) error {
	if ctx == nil || provider == "" || model == "" || providerRequestID == "" {
		return ErrInvalidRequest
	}
	key := provider + "\x00" + model
	adapter, _, allowed := g.provider(key, provider, model)
	if adapter == nil || !allowed {
		return ErrProviderNotAllowed
	}
	if !g.providerReady(key, g.clock().UTC()) {
		return ErrProviderUnavailable
	}
	if err := adapter.Cancel(ctx, providerRequestID); err != nil {
		g.recordProviderFailure(key, err)
		return redactError(err)
	}
	return nil
}

// CancelStream records the affected stream reservation for reconciliation
// before attempting provider cancellation. The provider may already have
// emitted usage when the cancellation request is processed.
func (g *Gateway) CancelStream(ctx context.Context, tenantID, reservationID, provider, model, providerRequestID string) error {
	if ctx == nil || tenantID == "" || reservationID == "" || provider == "" || model == "" || providerRequestID == "" {
		return ErrInvalidRequest
	}
	key := provider + "\x00" + model
	adapter, _, allowed := g.provider(key, provider, model)
	if adapter == nil || !allowed {
		return ErrProviderNotAllowed
	}
	if !g.providerReady(key, g.clock().UTC()) {
		return ErrProviderUnavailable
	}
	if _, err := g.ledger.RequireReconciliation(context.WithoutCancel(ctx), tenantID, reservationID); err != nil {
		return err
	}
	if err := adapter.Cancel(ctx, providerRequestID); err != nil {
		g.recordProviderFailure(key, err)
		return redactError(err)
	}
	return nil
}

func (g *Gateway) Generate(ctx context.Context, request NormalizedRequest, options GenerateOptions) (NormalizedResponse, error) {
	if ctx == nil {
		return NormalizedResponse{}, ErrInvalidRequest
	}
	if err := validateRequest(request); err != nil {
		return NormalizedResponse{}, err
	}
	digest, err := normalizedRequestDigest(request)
	if err != nil {
		return NormalizedResponse{}, err
	}
	execution, leader, err := g.beginExecution(request, digest)
	if err != nil {
		return NormalizedResponse{}, err
	}
	if !leader {
		select {
		case <-execution.done:
			return cloneNormalizedResponse(execution.response), execution.err
		case <-ctx.Done():
			return NormalizedResponse{}, ctx.Err()
		}
	}
	if replay, found, loadErr := g.loadReplay(ctx, request, digest); loadErr != nil {
		g.finishExecution(request, digest, execution, NormalizedResponse{}, loadErr)
		return NormalizedResponse{}, loadErr
	} else if found {
		g.finishExecution(request, digest, execution, replay.Response, nil)
		return replay.Response, nil
	}
	response, runErr := g.generateOnce(ctx, request, options)
	if runErr == nil {
		if response.RequestID == "" {
			response.RequestID = request.RequestID
		}
	}
	g.finishExecution(request, digest, execution, response, runErr)
	return response, runErr
}

func normalizedRequestDigest(request NormalizedRequest) (string, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return "", ErrInvalidRequest
	}
	return canonicaljson.Digest(encoded)
}

func (g *Gateway) loadReplay(ctx context.Context, request NormalizedRequest, digest string) (ModelReplay, bool, error) {
	if g.replayStore != nil {
		replay, found, err := g.replayStore.LoadModelReplay(ctx, request.TenantID, request.RequestID)
		if err != nil {
			return ModelReplay{}, false, err
		}
		if found {
			if replay.InputSHA256 != digest || replay.Response.RequestID != "" && replay.Response.RequestID != request.RequestID {
				return ModelReplay{}, false, ErrRequestConflict
			}
			if replay.Response.RequestID == "" {
				replay.Response.RequestID = request.RequestID
			}
			return replay, true, nil
		}
	}
	if g.callLookup == nil {
		return ModelReplay{}, false, nil
	}
	call, found, err := g.callLookup.LookupModelCall(ctx, request.TenantID, request.RequestID)
	if err != nil {
		return ModelReplay{}, false, err
	}
	if !found {
		return ModelReplay{}, false, nil
	}
	if call.InputSHA256 != digest {
		return ModelReplay{}, false, ErrRequestConflict
	}
	if call.Status == ModelCallReconcile {
		return ModelReplay{}, false, ErrReconciliationRequired
	}
	if call.Status == ModelCallSucceeded {
		return ModelReplay{}, false, ErrReplayUnavailable
	}
	return ModelReplay{}, false, ErrRequestConflict
}

func (g *Gateway) beginExecution(request NormalizedRequest, digest string) (*requestExecution, bool, error) {
	key := budgetKey(request.TenantID, request.RequestID)
	g.mu.Lock()
	defer g.mu.Unlock()
	if existing, found := g.executions[key]; found {
		if existing.digest != digest {
			return nil, false, ErrRequestConflict
		}
		return existing, false, nil
	}
	execution := &requestExecution{digest: digest, done: make(chan struct{})}
	g.executions[key] = execution
	return execution, true, nil
}

func (g *Gateway) finishExecution(request NormalizedRequest, digest string, execution *requestExecution, response NormalizedResponse, err error) {
	key := budgetKey(request.TenantID, request.RequestID)
	g.mu.Lock()
	if current, found := g.executions[key]; found && current == execution && current.digest == digest {
		current.response = cloneNormalizedResponse(response)
		current.err = err
		delete(g.executions, key)
		close(current.done)
	}
	g.mu.Unlock()
}

func (g *Gateway) generateOnce(ctx context.Context, request NormalizedRequest, options GenerateOptions) (NormalizedResponse, error) {
	if policy, found := g.policyFor(request); found {
		return g.generateWithPolicy(ctx, request, options, policy)
	}
	if request.ProviderPolicy != "" {
		return NormalizedResponse{}, ErrProviderNotAllowed
	}
	return g.generateSingle(ctx, request, options)
}

type providerSelection struct {
	candidate ProviderCandidate
	request   NormalizedRequest
	adapter   ModelAdapter
	pricing   Pricing
	caps      ModelCapabilities
	estimate  TokenEstimate
	worstCost int64
	key       string
}

func (g *Gateway) policyFor(request NormalizedRequest) (ProviderPolicy, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if request.ProviderPolicy != "" {
		policy, found := g.policies[request.ProviderPolicy]
		return policy, found && len(policy.Candidates) != 0
	}
	if policy, found := g.policies["default"]; found && len(policy.Candidates) != 0 {
		return policy, true
	}
	return ProviderPolicy{}, false
}

func (g *Gateway) providerCandidates(request NormalizedRequest, options GenerateOptions, policy ProviderPolicy) ([]ProviderCandidate, error) {
	if options.Provider == "" {
		return nil, ErrInvalidRequest
	}
	candidates := make([]ProviderCandidate, 0, len(policy.Candidates)+1)
	seen := make(map[string]struct{}, len(policy.Candidates)+1)
	appendCandidate := func(candidate ProviderCandidate) error {
		if candidate.Provider == "" {
			return ErrInvalidRequest
		}
		if candidate.Model == "" {
			candidate.Model = request.Model
		}
		if candidate.CapabilityRank == 0 {
			candidate.CapabilityRank = 100
		}
		key := candidate.Provider + "\x00" + candidate.Model
		if _, exists := seen[key]; exists {
			return nil
		}
		seen[key] = struct{}{}
		candidates = append(candidates, candidate)
		return nil
	}
	var preferred ProviderCandidate
	preferredFound := false
	for _, candidate := range policy.Candidates {
		if candidate.Provider == options.Provider && (candidate.Model == "" || candidate.Model == request.Model) {
			preferred = candidate
			preferredFound = true
			break
		}
	}
	if !preferredFound {
		return nil, ErrProviderNotAllowed
	}
	if err := appendCandidate(preferred); err != nil {
		return nil, err
	}
	for _, candidate := range policy.Candidates {
		if err := appendCandidate(candidate); err != nil {
			return nil, err
		}
	}
	if len(candidates) == 0 {
		return nil, ErrProviderNotAllowed
	}
	return candidates, nil
}

func (g *Gateway) selectProviders(ctx context.Context, operation string, request NormalizedRequest, options GenerateOptions, policy ProviderPolicy) ([]providerSelection, error) {
	candidates, err := g.providerCandidates(request, options, policy)
	if err != nil {
		return nil, err
	}
	selections := make([]providerSelection, 0, len(candidates))
	var lastErr error
	baselineRank := candidates[0].CapabilityRank
	for index, candidate := range candidates {
		if candidate.CapabilityRank < policy.MinimumCapabilityRank || index > 0 && candidate.CapabilityRank < baselineRank && !policy.AllowDowngrade {
			lastErr = ErrProviderNotAllowed
			continue
		}
		model := candidate.Model
		key := candidate.Provider + "\x00" + model
		adapter, pricing, allowed := g.provider(key, candidate.Provider, model)
		if adapter == nil || !allowed {
			lastErr = ErrProviderNotAllowed
			continue
		}
		if !g.providerReady(key, g.clock().UTC()) {
			lastErr = ErrProviderUnavailable
			continue
		}
		capabilities, capabilityErr := adapter.Capabilities(ctx, model)
		if capabilityErr != nil {
			g.recordProviderFailure(key, capabilityErr)
			lastErr = redactError(capabilityErr)
			continue
		}
		if request.MaxOutputTokens <= 0 || request.MaxOutputTokens > capabilities.MaxOutputTokens || len(request.Tools) != 0 && !capabilities.SupportsToolCalls || len(request.ResponseSchema) != 0 && !capabilities.SupportsJSONSchema {
			lastErr = ErrProviderNotAllowed
			continue
		}
		if !candidateAllowsClassification(candidate, request.DataClassification) {
			lastErr = ErrProviderNotAllowed
			continue
		}
		if g.eligibility != nil {
			if eligibilityErr := g.eligibility(ctx, ProviderEligibilityInput{Operation: operation, Request: request, Candidate: candidate, Capabilities: capabilities, AccountID: options.AccountID, ReservationID: options.ReservationID}); eligibilityErr != nil {
				lastErr = eligibilityErr
				continue
			}
		}
		candidateRequest := request
		candidateRequest.Model = model
		estimate, countErr := adapter.CountTokens(ctx, candidateRequest)
		if countErr != nil {
			g.recordProviderFailure(key, countErr)
			lastErr = redactError(countErr)
			continue
		}
		if estimate.InputTokens < 0 || estimate.InputTokens > int64(capabilities.MaxInputTokens) {
			lastErr = ErrInvalidRequest
			continue
		}
		inputCost, costErr := multiplyCost(estimate.InputTokens, pricing.InputMicrosPerToken)
		if costErr != nil {
			lastErr = costErr
			continue
		}
		outputCost, costErr := multiplyCost(int64(request.MaxOutputTokens), pricing.OutputMicrosPerToken)
		if costErr != nil {
			lastErr = costErr
			continue
		}
		worst, costErr := addCost(inputCost, outputCost)
		if costErr != nil {
			lastErr = costErr
			continue
		}
		if request.WorstCaseCostMicros > worst {
			worst = request.WorstCaseCostMicros
		}
		selections = append(selections, providerSelection{candidate: candidate, request: candidateRequest, adapter: adapter, pricing: pricing, caps: capabilities, estimate: estimate, worstCost: worst, key: key})
	}
	if len(selections) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, ErrProviderNotAllowed
	}
	return selections, nil
}

func candidateAllowsClassification(candidate ProviderCandidate, classification string) bool {
	if len(candidate.AllowedDataClassifications) == 0 {
		return true
	}
	for _, allowed := range candidate.AllowedDataClassifications {
		if allowed == classification {
			return true
		}
	}
	return false
}

func (g *Gateway) generateWithPolicy(ctx context.Context, request NormalizedRequest, options GenerateOptions, policy ProviderPolicy) (NormalizedResponse, error) {
	if err := validateRequest(request); err != nil {
		return NormalizedResponse{}, err
	}
	if options.MaxAttempts <= 0 {
		options.MaxAttempts = 3
	}
	if options.MaxAttempts > 3 || options.AccountID == "" || options.ReservationID == "" {
		return NormalizedResponse{}, ErrInvalidRequest
	}
	selections, err := g.selectProviders(ctx, "generate", request, options, policy)
	if err != nil {
		return NormalizedResponse{}, err
	}
	reservedPerAttempt := int64(0)
	for _, selection := range selections {
		reservedPerAttempt, err = addCost(reservedPerAttempt, selection.worstCost)
		if err != nil {
			return NormalizedResponse{}, err
		}
	}
	if reservedPerAttempt < 0 || reservedPerAttempt > math.MaxInt64/int64(options.MaxAttempts) {
		return NormalizedResponse{}, ErrInvalidRequest
	}
	reserved := reservedPerAttempt * int64(options.MaxAttempts)
	if _, err = g.claimExternalCall(ctx, request.TenantID, options.AccountID, options.ReservationID, request.RequestID, reserved); err != nil {
		return NormalizedResponse{}, err
	}
	startedAt := g.clock().UTC()
	call, err := newModelCall(request, selections[0].candidate.Provider, selections[0].caps.ActualModelVersion, 0, startedAt)
	if err != nil {
		_ = g.releaseReservation(ctx, request.TenantID, options.ReservationID)
		return NormalizedResponse{}, err
	}
	var incurred int64
	var lastErr error
	for selectionIndex, selection := range selections {
		if g.eligibility != nil {
			if eligibilityErr := g.eligibility(ctx, ProviderEligibilityInput{Operation: "generate", Request: request, Candidate: selection.candidate, Capabilities: selection.caps, AccountID: options.AccountID, ReservationID: options.ReservationID}); eligibilityErr != nil {
				lastErr = eligibilityErr
				continue
			}
		}
		call.Provider = selection.candidate.Provider
		call.LogicalModel = request.Model
		call.ActualModelVersion = selection.caps.ActualModelVersion
		for attempt := 0; attempt < options.MaxAttempts; attempt++ {
			response, generateErr := selection.adapter.Generate(ctx, selection.request)
			if generateErr != nil {
				lastErr = generateErr
				g.recordProviderFailure(selection.key, generateErr)
				var providerFailure *ProviderFailure
				if !errors.As(generateErr, &providerFailure) || !providerFailure.OutcomeKnown {
					call.Status = ModelCallReconcile
					call.CostMicros = incurred
					call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
					if finalizeErr := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionReconcile, ActualMicros: incurred, Call: call}); finalizeErr != nil {
						return NormalizedResponse{}, finalizeErr
					}
					return NormalizedResponse{}, redactError(generateErr)
				}
				if !providerFailure.Retryable {
					break
				}
				if attempt+1 < options.MaxAttempts {
					if waitErr := g.waitForRetry(ctx, selection.key, providerFailure); waitErr != nil {
						call.Status = ModelCallFailedProvider
						call.CostMicros = incurred
						call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
						disposition := ReservationDispositionSettle
						if incurred == 0 {
							disposition = ReservationDispositionRelease
						}
						if finalizeErr := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: disposition, ActualMicros: incurred, Call: call}); finalizeErr != nil {
							return NormalizedResponse{}, finalizeErr
						}
						return NormalizedResponse{}, waitErr
					}
					continue
				}
				break
			}
			g.providerSucceeded(selection.key)
			attemptCost := response.Usage.CostMicros
			if attemptCost < 0 || attemptCost == 0 && selection.worstCost > 0 {
				attemptCost = selection.worstCost
			}
			incurred, err = addCost(incurred, attemptCost)
			if err == nil {
				call.InputTokens, err = addCost(call.InputTokens, response.Usage.InputTokens)
			}
			if err == nil {
				call.OutputTokens, err = addCost(call.OutputTokens, response.Usage.OutputTokens)
			}
			if err != nil {
				call.Status = ModelCallReconcile
				call.CostMicros = incurred
				call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
				if finalizeErr := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionReconcile, ActualMicros: incurred, Call: call}); finalizeErr != nil {
					return NormalizedResponse{}, finalizeErr
				}
				return NormalizedResponse{}, err
			}
			if response.ModelVersion == "" {
				response.ModelVersion = selection.caps.ActualModelVersion
			}
			if response.ModelVersion == "" {
				response.ModelVersion = "NON_REPRODUCIBLE_PROVIDER"
			}
			call.ActualModelVersion = response.ModelVersion
			call.ProviderRequestID = response.ProviderRequestID
			if response.Usage.ProviderRequestID != "" {
				call.ProviderRequestID = response.Usage.ProviderRequestID
			}
			call.OutputSHA256 = digestBytes(response.Content)
			call.CostMicros = incurred
			if response.RequestID != "" && response.RequestID != request.RequestID {
				lastErr = ErrOutputSchema
				continue
			}
			if len(response.Content) > MaximumResponseBytes {
				call.Status = ModelCallFailedOutputSize
				call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
				if finalizeErr := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionSettle, ActualMicros: incurred, Call: call}); finalizeErr != nil {
					return NormalizedResponse{}, finalizeErr
				}
				return NormalizedResponse{}, ErrOutputTooLarge
			}
			if containsCredentialLike(string(response.Content)) {
				call.Status = ModelCallFailedCredential
				call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
				if finalizeErr := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionSettle, ActualMicros: incurred, Call: call}); finalizeErr != nil {
					return NormalizedResponse{}, finalizeErr
				}
				return NormalizedResponse{}, ErrCredentialDetected
			}
			if schemaErr := validateResponse(request.ResponseSchema, response.Content); schemaErr != nil {
				lastErr = schemaErr
				continue
			}
			if response.Usage.ProviderRequestID == "" {
				response.Usage.ProviderRequestID = response.ProviderRequestID
			}
			if response.Usage.ModelVersion == "" {
				response.Usage.ModelVersion = response.ModelVersion
			}
			response.RequestID = request.RequestID
			call.Status = ModelCallSucceeded
			call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
			if finalizeErr := g.finalizeSuccessfulModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionSettle, ActualMicros: incurred, Call: call}, response); finalizeErr != nil {
				return NormalizedResponse{}, finalizeErr
			}
			return response, nil
		}
		if selectionIndex+1 < len(selections) && providerFallbackAllowed(lastErr) {
			continue
		}
		break
	}
	if lastErr == nil {
		lastErr = ErrOutputSchema
	}
	if errors.Is(lastErr, ErrOutputSchema) {
		call.Status = ModelCallFailedOutputSchema
	} else {
		call.Status = ModelCallFailedProvider
	}
	call.CostMicros = incurred
	call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
	disposition := ReservationDispositionSettle
	if call.Status == ModelCallFailedProvider && incurred == 0 {
		disposition = ReservationDispositionRelease
	}
	if finalizeErr := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: disposition, ActualMicros: incurred, Call: call}); finalizeErr != nil {
		return NormalizedResponse{}, finalizeErr
	}
	return NormalizedResponse{}, redactError(lastErr)
}

func providerFallbackAllowed(err error) bool {
	if errors.Is(err, ErrOutputSchema) {
		return true
	}
	var failure *ProviderFailure
	return errors.As(err, &failure) && failure.OutcomeKnown && failure.Retryable
}

func (g *Gateway) waitForRetry(ctx context.Context, key string, failure *ProviderFailure) error {
	if failure == nil || !failure.Retryable {
		return nil
	}
	g.mu.RLock()
	circuit := g.circuits[key]
	g.mu.RUnlock()
	if !circuit.retryAt.IsZero() {
		delay := time.Until(circuit.retryAt)
		now := g.clock().UTC()
		if circuit.retryAt.After(now) {
			delay = circuit.retryAt.Sub(now)
		} else {
			delay = 0
		}
		if delay > 0 {
			return g.sleep(ctx, delay)
		}
	}
	return nil
}

func (g *Gateway) generateSingle(ctx context.Context, request NormalizedRequest, options GenerateOptions) (NormalizedResponse, error) {
	if ctx == nil {
		return NormalizedResponse{}, ErrInvalidRequest
	}
	if err := validateRequest(request); err != nil {
		return NormalizedResponse{}, err
	}
	if options.MaxAttempts <= 0 {
		options.MaxAttempts = 3
	}
	if options.MaxAttempts > 3 {
		options.MaxAttempts = 3
	}
	key := options.Provider + "\x00" + request.Model
	adapter, pricing, allowed := g.provider(key, options.Provider, request.Model)
	if adapter == nil || !allowed {
		return NormalizedResponse{}, ErrProviderNotAllowed
	}
	if !g.providerReady(key, g.clock().UTC()) {
		return NormalizedResponse{}, ErrProviderUnavailable
	}
	capabilities, err := adapter.Capabilities(ctx, request.Model)
	if err != nil {
		g.recordProviderFailure(key, err)
		return NormalizedResponse{}, redactError(err)
	}
	if request.MaxOutputTokens > capabilities.MaxOutputTokens || request.MaxOutputTokens <= 0 {
		return NormalizedResponse{}, ErrInvalidRequest
	}
	estimate, err := adapter.CountTokens(ctx, request)
	if err != nil {
		g.recordProviderFailure(key, err)
		return NormalizedResponse{}, redactError(err)
	}
	if estimate.InputTokens < 0 || estimate.InputTokens > int64(capabilities.MaxInputTokens) {
		return NormalizedResponse{}, ErrInvalidRequest
	}
	inputCost, err := multiplyCost(estimate.InputTokens, pricing.InputMicrosPerToken)
	if err != nil {
		return NormalizedResponse{}, err
	}
	outputCost, err := multiplyCost(int64(request.MaxOutputTokens), pricing.OutputMicrosPerToken)
	if err != nil {
		return NormalizedResponse{}, err
	}
	worst, err := addCost(inputCost, outputCost)
	if err != nil {
		return NormalizedResponse{}, err
	}
	if request.WorstCaseCostMicros > worst {
		worst = request.WorstCaseCostMicros
	}
	if worst < 0 || worst > math.MaxInt64/int64(options.MaxAttempts) {
		return NormalizedResponse{}, ErrInvalidRequest
	}
	reserved := worst * int64(options.MaxAttempts)
	if _, err := g.claimExternalCall(ctx, request.TenantID, options.AccountID, options.ReservationID, request.RequestID, reserved); err != nil {
		return NormalizedResponse{}, err
	}
	startedAt := g.clock().UTC()
	call, err := newModelCall(request, options.Provider, capabilities.ActualModelVersion, 0, startedAt)
	if err != nil {
		if releaseErr := g.releaseReservation(ctx, request.TenantID, options.ReservationID); releaseErr != nil {
			return NormalizedResponse{}, releaseErr
		}
		return NormalizedResponse{}, err
	}
	var lastErr error
	var incurred int64
	for attempt := 0; attempt < options.MaxAttempts; attempt++ {
		response, generateErr := adapter.Generate(ctx, request)
		if generateErr != nil {
			g.recordProviderFailure(key, generateErr)
			var providerFailure *ProviderFailure
			if errors.As(generateErr, &providerFailure) && providerFailure.OutcomeKnown && providerFailure.Retryable && attempt+1 < options.MaxAttempts {
				if waitErr := g.waitForRetry(ctx, key, providerFailure); waitErr != nil {
					call.Status = ModelCallFailedProvider
					call.CostMicros = incurred
					call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
					disposition := ReservationDispositionSettle
					if incurred == 0 {
						disposition = ReservationDispositionRelease
					}
					if finalizeErr := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: disposition, ActualMicros: incurred, Call: call}); finalizeErr != nil {
						return NormalizedResponse{}, finalizeErr
					}
					return NormalizedResponse{}, waitErr
				}
				continue
			}
			disposition := ReservationDispositionReconcile
			call.Status = ModelCallReconcile
			if errors.As(generateErr, &providerFailure) && providerFailure.OutcomeKnown {
				if incurred == 0 {
					disposition = ReservationDispositionRelease
				} else {
					disposition = ReservationDispositionSettle
				}
				call.Status = ModelCallFailedProvider
			}
			call.CostMicros = incurred
			call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
			if err := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: disposition, ActualMicros: incurred, Call: call}); err != nil {
				return NormalizedResponse{}, err
			}
			return NormalizedResponse{}, redactError(generateErr)
		}
		g.providerSucceeded(key)
		attemptCost := response.Usage.CostMicros
		if attemptCost < 0 {
			attemptCost = worst
		}
		if attemptCost == 0 && worst > 0 {
			attemptCost = worst
		}
		incurred, err = addCost(incurred, attemptCost)
		if err == nil {
			call.InputTokens, err = addCost(call.InputTokens, response.Usage.InputTokens)
		}
		if err == nil {
			call.OutputTokens, err = addCost(call.OutputTokens, response.Usage.OutputTokens)
		}
		if err != nil {
			call.Status = ModelCallReconcile
			call.CostMicros = incurred
			call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
			if finalizeErr := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionReconcile, ActualMicros: incurred, Call: call}); finalizeErr != nil {
				return NormalizedResponse{}, finalizeErr
			}
			return NormalizedResponse{}, err
		}
		if response.ModelVersion == "" {
			response.ModelVersion = capabilities.ActualModelVersion
		}
		if response.ModelVersion == "" {
			response.ModelVersion = "NON_REPRODUCIBLE_PROVIDER"
		}
		call.ActualModelVersion = response.ModelVersion
		call.ProviderRequestID = response.ProviderRequestID
		if response.Usage.ProviderRequestID != "" {
			call.ProviderRequestID = response.Usage.ProviderRequestID
		}
		call.OutputSHA256 = digestBytes(response.Content)
		call.CostMicros = incurred
		if response.RequestID != "" && response.RequestID != request.RequestID {
			lastErr = ErrOutputSchema
			continue
		}
		if len(response.Content) > MaximumResponseBytes {
			call.Status = ModelCallFailedOutputSize
			call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
			if err := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionSettle, ActualMicros: incurred, Call: call}); err != nil {
				return NormalizedResponse{}, err
			}
			return NormalizedResponse{}, ErrOutputTooLarge
		}
		if containsCredentialLike(string(response.Content)) {
			call.Status = ModelCallFailedCredential
			call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
			if err := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionSettle, ActualMicros: incurred, Call: call}); err != nil {
				return NormalizedResponse{}, err
			}
			return NormalizedResponse{}, ErrCredentialDetected
		}
		if err := validateResponse(request.ResponseSchema, response.Content); err != nil {
			lastErr = err
			continue
		}
		if response.Usage.ProviderRequestID == "" {
			response.Usage.ProviderRequestID = response.ProviderRequestID
		}
		if response.Usage.ModelVersion == "" {
			response.Usage.ModelVersion = response.ModelVersion
		}
		response.RequestID = request.RequestID
		call.Status = ModelCallSucceeded
		call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
		if err := g.finalizeSuccessfulModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionSettle, ActualMicros: incurred, Call: call}, response); err != nil {
			return NormalizedResponse{}, err
		}
		return response, nil
	}
	call.Status = ModelCallFailedOutputSchema
	call.CostMicros = incurred
	call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
	if err := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionSettle, ActualMicros: incurred, Call: call}); err != nil {
		return NormalizedResponse{}, err
	}
	if lastErr != nil {
		return NormalizedResponse{}, lastErr
	}
	return NormalizedResponse{}, ErrOutputSchema
}

func newModelCall(request NormalizedRequest, provider, actualModelVersion string, inputTokens int64, createdAt time.Time) (ModelCall, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return ModelCall{}, ErrInvalidRequest
	}
	inputDigest, err := canonicaljson.Digest(encoded)
	if err != nil {
		return ModelCall{}, ErrInvalidRequest
	}
	if actualModelVersion == "" {
		actualModelVersion = "NON_REPRODUCIBLE_PROVIDER"
	}
	return ModelCall{
		TenantID: request.TenantID, RequestID: request.RequestID, ProjectID: request.ProjectID,
		TaskID: request.TaskID, AgentInstanceID: request.AgentInstanceID, Provider: provider,
		LogicalModel: request.Model, ActualModelVersion: actualModelVersion,
		PromptBundleVersion: request.PromptBundleVersion, InputSHA256: inputDigest,
		InputTokens: inputTokens, CreatedAt: createdAt.UTC(),
	}, nil
}

func (g *Gateway) finalizeModelCall(ctx context.Context, finalization ModelCallFinalization) error {
	finalizeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if g.callFinalizer != nil {
		_, err := g.callFinalizer.FinalizeModelCall(finalizeContext, finalization)
		return err
	}
	switch finalization.Disposition {
	case ReservationDispositionSettle:
		_, err := g.ledger.Settle(finalizeContext, finalization.Call.TenantID, finalization.ReservationID, finalization.ActualMicros)
		return err
	case ReservationDispositionRelease:
		return g.ledger.Release(finalizeContext, finalization.Call.TenantID, finalization.ReservationID)
	case ReservationDispositionReconcile:
		_, err := g.ledger.RequireReconciliation(finalizeContext, finalization.Call.TenantID, finalization.ReservationID)
		return err
	default:
		return ErrInvalidRequest
	}
}

func (g *Gateway) finalizeSuccessfulModelCall(ctx context.Context, finalization ModelCallFinalization, response NormalizedResponse) error {
	if response.RequestID == "" {
		response.RequestID = finalization.Call.RequestID
	}
	if g.replayStore == nil {
		return g.finalizeModelCall(ctx, finalization)
	}
	replay := ModelReplay{InputSHA256: finalization.Call.InputSHA256, Response: cloneNormalizedResponse(response)}
	finalizeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if g.replayFinalizer != nil {
		_, err := g.replayFinalizer.FinalizeModelCallWithReplay(finalizeContext, finalization, replay)
		return err
	}
	if err := g.finalizeModelCall(finalizeContext, finalization); err != nil {
		return err
	}
	return g.replayStore.StoreModelReplay(finalizeContext, finalization.Call.TenantID, finalization.Call.RequestID, replay)
}

func elapsedMilliseconds(startedAt, completedAt time.Time) int64 {
	if startedAt.IsZero() || completedAt.Before(startedAt) {
		return 0
	}
	return completedAt.Sub(startedAt).Milliseconds()
}

func (g *Gateway) prepare(ctx context.Context, request NormalizedRequest, options GenerateOptions, requireStreaming bool) (ModelAdapter, string, ModelCapabilities, TokenEstimate, string, error) {
	if err := validateRequest(request); err != nil {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", err
	}
	if options.MaxAttempts <= 0 {
		options.MaxAttempts = 3
	}
	if options.MaxAttempts > 3 || options.Provider == "" || options.AccountID == "" || options.ReservationID == "" {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", ErrInvalidRequest
	}
	key := options.Provider + "\x00" + request.Model
	adapter, pricing, allowed := g.provider(key, options.Provider, request.Model)
	if adapter == nil || !allowed {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", ErrProviderNotAllowed
	}
	if !g.providerReady(key, g.clock().UTC()) {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", ErrProviderUnavailable
	}
	capabilities, err := adapter.Capabilities(ctx, request.Model)
	if err != nil {
		g.recordProviderFailure(key, err)
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", redactError(err)
	}
	if request.MaxOutputTokens > capabilities.MaxOutputTokens || request.MaxOutputTokens <= 0 || requireStreaming && !capabilities.SupportsStreaming {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", ErrProviderNotAllowed
	}
	estimate, err := adapter.CountTokens(ctx, request)
	if err != nil {
		g.recordProviderFailure(key, err)
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", redactError(err)
	}
	if estimate.InputTokens < 0 || estimate.InputTokens > int64(capabilities.MaxInputTokens) {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", ErrInvalidRequest
	}
	inputCost, err := multiplyCost(estimate.InputTokens, pricing.InputMicrosPerToken)
	if err != nil {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", err
	}
	outputCost, err := multiplyCost(int64(request.MaxOutputTokens), pricing.OutputMicrosPerToken)
	if err != nil {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", err
	}
	worst, err := addCost(inputCost, outputCost)
	if err != nil {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", err
	}
	if request.WorstCaseCostMicros > worst {
		worst = request.WorstCaseCostMicros
	}
	if worst < 0 || worst > math.MaxInt64/int64(options.MaxAttempts) {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", ErrInvalidRequest
	}
	if _, err := g.claimExternalCall(ctx, request.TenantID, options.AccountID, options.ReservationID, request.RequestID, worst*int64(options.MaxAttempts)); err != nil {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", err
	}
	return adapter, key, capabilities, estimate, options.ReservationID, nil
}

func (g *Gateway) claimExternalCall(ctx context.Context, tenantID, accountID, reservationID, requestID string, amountMicros int64) (Reservation, error) {
	if claimer, ok := g.ledger.(BudgetReservationClaimer); ok {
		reservation, claimed, err := claimer.ClaimReservation(ctx, tenantID, accountID, reservationID, requestID, amountMicros)
		if err != nil {
			return Reservation{}, err
		}
		if !claimed {
			return Reservation{}, ErrReconciliationRequired
		}
		return reservation, nil
	}
	return g.ledger.Reserve(ctx, tenantID, accountID, reservationID, requestID, amountMicros)
}

func (g *Gateway) resolveStartFailure(ctx context.Context, tenantID, reservationID string, generateErr error) error {
	var providerFailure *ProviderFailure
	if errors.As(generateErr, &providerFailure) && providerFailure.OutcomeKnown {
		return g.releaseReservation(ctx, tenantID, reservationID)
	}
	_, err := g.ledger.RequireReconciliation(context.WithoutCancel(ctx), tenantID, reservationID)
	return err
}

func (g *Gateway) releaseReservation(ctx context.Context, tenantID, reservationID string) error {
	return g.ledger.Release(context.WithoutCancel(ctx), tenantID, reservationID)
}

type budgetedStream struct {
	stream            ResponseStream
	tenantID          string
	reservationID     string
	context           context.Context
	call              ModelCall
	startedAt         time.Time
	finalizeCall      func(context.Context, ModelCallFinalization) error
	clock             func() time.Time
	maxResponseBytes  int
	responseSchema    json.RawMessage
	semanticValidator func(json.RawMessage) error
	buffer            bytes.Buffer
	once              sync.Once
	finalizeErr       error
}

func (s *budgetedStream) Recv(ctx context.Context) (json.RawMessage, error) {
	value, err := s.stream.Recv(ctx)
	if err == nil {
		if !utf8.Valid(value) || !json.Valid(value) || s.buffer.Len()+len(value) > s.maxResponseBytes {
			if finalizeErr := s.finalizeFailure(ErrOutputSchema); finalizeErr != nil {
				return nil, finalizeErr
			}
			return nil, ErrOutputSchema
		}
		_, _ = s.buffer.Write(value)
		return value, nil
	}
	if errors.Is(err, io.EOF) {
		if finalizeErr := s.finalizeTerminal(); finalizeErr != nil {
			return nil, finalizeErr
		}
		return nil, err
	}
	if finalizeErr := s.finalizeFailure(err); finalizeErr != nil {
		return nil, finalizeErr
	}
	return value, err
}

func (s *budgetedStream) Close() error {
	closeErr := s.stream.Close()
	if finalizeErr := s.finalizeFailure(nil); finalizeErr != nil {
		return finalizeErr
	}
	return closeErr
}

func (s *budgetedStream) finalizeTerminal() error {
	s.once.Do(func() {
		usage, found := streamUsage(s.stream)
		if !found || usage.InputTokens < 0 || usage.OutputTokens < 0 || usage.CostMicros < 0 {
			s.finalizeErr = s.finalizeUnknown()
			return
		}
		call := s.call
		call.InputTokens = usage.InputTokens
		call.OutputTokens = usage.OutputTokens
		call.CostMicros = usage.CostMicros
		call.ProviderRequestID = usage.ProviderRequestID
		if usage.ModelVersion != "" {
			call.ActualModelVersion = usage.ModelVersion
		}
		if s.buffer.Len() != 0 {
			call.OutputSHA256 = digestBytes(s.buffer.Bytes())
		}
		call.LatencyMilliseconds = elapsedMilliseconds(s.startedAt, s.clock().UTC())
		if validationErr := validateStreamFinal(s.responseSchema, s.semanticValidator, s.buffer.Bytes()); validationErr != nil {
			call.Status = ModelCallFailedOutputSchema
			s.finalizeErr = s.finalizeCall(context.WithoutCancel(s.context), ModelCallFinalization{
				ReservationID: s.reservationID, Disposition: ReservationDispositionSettle,
				ActualMicros: usage.CostMicros, Call: call,
			})
			if s.finalizeErr == nil {
				s.finalizeErr = validationErr
			}
			return
		}
		if containsCredentialLike(string(s.buffer.Bytes())) {
			call.Status = ModelCallFailedCredential
			s.finalizeErr = s.finalizeCall(context.WithoutCancel(s.context), ModelCallFinalization{
				ReservationID: s.reservationID, Disposition: ReservationDispositionSettle,
				ActualMicros: usage.CostMicros, Call: call,
			})
			if s.finalizeErr == nil {
				s.finalizeErr = ErrCredentialDetected
			}
			return
		}
		call.Status = ModelCallSucceeded
		s.finalizeErr = s.finalizeCall(context.WithoutCancel(s.context), ModelCallFinalization{
			ReservationID: s.reservationID, Disposition: ReservationDispositionSettle,
			ActualMicros: usage.CostMicros, Call: call,
		})
	})
	return s.finalizeErr
}

func validateStreamFinal(schema json.RawMessage, semanticValidator func(json.RawMessage) error, content []byte) error {
	if len(content) == 0 && len(schema) == 0 && semanticValidator == nil {
		return nil
	}
	if err := validateResponse(schema, content); err != nil {
		return err
	}
	if semanticValidator != nil {
		if err := semanticValidator(append(json.RawMessage(nil), content...)); err != nil {
			return ErrOutputSchema
		}
	}
	return nil
}

func (s *budgetedStream) finalizeFailure(cause error) error {
	s.once.Do(func() {
		var providerFailure *ProviderFailure
		if cause != nil && errors.As(cause, &providerFailure) && providerFailure.OutcomeKnown && s.buffer.Len() == 0 {
			call := s.call
			call.Status = ModelCallFailedProvider
			call.LatencyMilliseconds = elapsedMilliseconds(s.startedAt, s.clock().UTC())
			s.finalizeErr = s.finalizeCall(context.WithoutCancel(s.context), ModelCallFinalization{
				ReservationID: s.reservationID, Disposition: ReservationDispositionRelease, Call: call,
			})
			return
		}
		s.finalizeErr = s.finalizeUnknown()
	})
	return s.finalizeErr
}

func (s *budgetedStream) finalizeUnknown() error {
	call := s.call
	call.Status = ModelCallReconcile
	call.CostMicros = 0
	call.OutputSHA256 = ""
	call.LatencyMilliseconds = elapsedMilliseconds(s.startedAt, s.clock().UTC())
	return s.finalizeCall(context.WithoutCancel(s.context), ModelCallFinalization{
		ReservationID: s.reservationID, Disposition: ReservationDispositionReconcile, Call: call,
	})
}

func streamUsage(stream ResponseStream) (Usage, bool) {
	if usageStream, ok := stream.(UsageAwareStream); ok {
		return usageStream.FinalUsage()
	}
	return Usage{}, false
}

var _ ResponseStream = (*budgetedStream)(nil)

func validateRequest(request NormalizedRequest) error {
	if request.RequestID == "" || request.TenantID == "" || request.ProjectID == "" || request.AgentInstanceID == "" || request.Role == "" || request.Model == "" || request.PromptBundleVersion == "" || len(request.Messages) == 0 || request.MaxOutputTokens <= 0 || request.DataClassification == "" {
		return ErrInvalidRequest
	}
	encoded, err := json.Marshal(request)
	if err != nil || containsCredentialLike(string(encoded)) {
		return ErrCredentialDetected
	}
	if len(request.ResponseSchema) > MaximumResponseSchemaBytes || len(request.ResponseSchema) != 0 && !json.Valid(request.ResponseSchema) {
		return ErrInvalidRequest
	}
	for _, message := range request.Messages {
		if strings.TrimSpace(message.Role) == "" || containsCredentialLike(message.Content) {
			return ErrCredentialDetected
		}
	}
	return nil
}

func validateResponse(schemaJSON, content []byte) error {
	if len(content) == 0 || len(content) > MaximumResponseBytes || !json.Valid(content) {
		return ErrOutputSchema
	}
	if len(schemaJSON) == 0 {
		return nil
	}
	var schemaDoc any
	if err := json.Unmarshal(schemaJSON, &schemaDoc); err != nil {
		return ErrOutputSchema
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource("urn:aor:model-response", schemaDoc); err != nil {
		return ErrOutputSchema
	}
	schema, err := compiler.Compile("urn:aor:model-response")
	if err != nil {
		return ErrOutputSchema
	}
	var value any
	if err := json.Unmarshal(content, &value); err != nil || schema.Validate(value) != nil {
		return ErrOutputSchema
	}
	return nil
}

func addCost(current, additional int64) (int64, error) {
	if current < 0 || additional < 0 || current > math.MaxInt64-additional {
		return 0, ErrInvalidRequest
	}
	return current + additional, nil
}

func multiplyCost(units, rate int64) (int64, error) {
	if units < 0 || rate < 0 || units > 0 && rate > math.MaxInt64/units {
		return 0, ErrInvalidRequest
	}
	return units * rate, nil
}

func (g *Gateway) String() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return fmt.Sprintf("model-gateway adapters=%d", len(g.adapters))
}

func (g *Gateway) provider(key, provider, model string) (ModelAdapter, Pricing, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.adapters[key], g.pricing[key], g.allowed[provider][model]
}

func (g *Gateway) providerReady(key string, now time.Time) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	circuit, found := g.circuits[key]
	return !found || !now.Before(circuit.retryAt)
}

func (g *Gateway) recordProviderFailure(key string, err error) time.Duration {
	var failure *ProviderFailure
	g.mu.Lock()
	defer g.mu.Unlock()
	if !errors.As(err, &failure) || !failure.Retryable {
		delete(g.circuits, key)
		return 0
	}
	circuit := g.circuits[key]
	circuit.failures++
	delay := exponentialBackoff(circuit.failures, g.initialProviderBackoff, g.maximumProviderBackoff)
	delay = jitteredBackoff(key, circuit.failures, delay, g.maximumProviderBackoff, g.backoffJitterRatio)
	circuit.retryAt = g.clock().UTC().Add(delay)
	g.circuits[key] = circuit
	return delay
}

func (g *Gateway) providerSucceeded(key string) {
	g.mu.Lock()
	delete(g.circuits, key)
	g.mu.Unlock()
}

func exponentialBackoff(failures int, initial, maximum time.Duration) time.Duration {
	delay := initial
	for attempt := 1; attempt < failures && delay < maximum; attempt++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

func jitteredBackoff(key string, failures int, base, maximum time.Duration, ratio float64) time.Duration {
	if base <= 0 || ratio <= 0 {
		return base
	}
	if ratio > 1 {
		ratio = 1
	}
	digest := sha256.Sum256([]byte(key + "\x00" + fmt.Sprint(failures)))
	value := binary.BigEndian.Uint64(digest[:8])
	unit := float64(value) / float64(^uint64(0))
	factor := 1 + (unit*2-1)*ratio
	delay := time.Duration(float64(base) * factor)
	if delay < 0 {
		delay = 0
	}
	if delay > maximum {
		delay = maximum
	}
	return delay
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	if ctx == nil {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
