package modelgateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

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
	finalizer, _ := ledger.(ModelCallFinalizer)
	return &Gateway{adapters: make(map[string]ModelAdapter), allowed: make(map[string]map[string]bool), pricing: make(map[string]Pricing), ledger: ledger, callFinalizer: finalizer, clock: clock, circuits: make(map[string]providerCircuit), initialProviderBackoff: config.InitialProviderBackoff, maximumProviderBackoff: config.MaximumProviderBackoff}
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
// Since the normalized streaming contract has no final usage envelope, every
// completed or interrupted stream is held for durable reconciliation.
func (g *Gateway) Stream(ctx context.Context, request NormalizedRequest, options GenerateOptions) (ResponseStream, error) {
	if ctx == nil {
		return nil, ErrInvalidRequest
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
	call.Status = ModelCallReconcile
	call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
	if err := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: reservation, Disposition: ReservationDispositionReconcile, Call: call}); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return &budgetedStream{stream: stream, ledger: g.ledger, tenantID: request.TenantID, reservationID: reservation, context: ctx}, nil
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
	if _, err := g.ledger.Reserve(ctx, request.TenantID, options.AccountID, options.ReservationID, request.RequestID, reserved); err != nil {
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
		call.Status = ModelCallSucceeded
		call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
		if err := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionSettle, ActualMicros: incurred, Call: call}); err != nil {
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
	if _, err := g.ledger.Reserve(ctx, request.TenantID, options.AccountID, options.ReservationID, request.RequestID, worst*int64(options.MaxAttempts)); err != nil {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", err
	}
	return adapter, key, capabilities, estimate, options.ReservationID, nil
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
	stream        ResponseStream
	ledger        BudgetLedgerBackend
	tenantID      string
	reservationID string
	context       context.Context
	once          sync.Once
	finalizeErr   error
}

func (s *budgetedStream) Recv(ctx context.Context) (json.RawMessage, error) {
	value, err := s.stream.Recv(ctx)
	if err != nil {
		if finalizeErr := s.finalize(); finalizeErr != nil {
			return nil, finalizeErr
		}
	}
	return value, err
}

func (s *budgetedStream) Close() error {
	closeErr := s.stream.Close()
	if finalizeErr := s.finalize(); finalizeErr != nil {
		return finalizeErr
	}
	return closeErr
}

func (s *budgetedStream) finalize() error {
	s.once.Do(func() {
		_, s.finalizeErr = s.ledger.RequireReconciliation(context.WithoutCancel(s.context), s.tenantID, s.reservationID)
	})
	return s.finalizeErr
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

func (g *Gateway) recordProviderFailure(key string, err error) {
	var failure *ProviderFailure
	g.mu.Lock()
	defer g.mu.Unlock()
	if !errors.As(err, &failure) || !failure.Retryable {
		delete(g.circuits, key)
		return
	}
	circuit := g.circuits[key]
	circuit.failures++
	delay := exponentialBackoff(circuit.failures, g.initialProviderBackoff, g.maximumProviderBackoff)
	circuit.retryAt = g.clock().UTC().Add(delay)
	g.circuits[key] = circuit
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
