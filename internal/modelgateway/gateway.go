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
	return &Gateway{adapters: make(map[string]ModelAdapter), allowed: make(map[string]map[string]bool), pricing: make(map[string]Pricing), ledger: ledger, clock: clock, circuits: make(map[string]providerCircuit), initialProviderBackoff: config.InitialProviderBackoff, maximumProviderBackoff: config.MaximumProviderBackoff}
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
	Provider      string
	AccountID     string
	ReservationID string
	MaxAttempts   int
}

func (g *Gateway) Generate(ctx context.Context, request NormalizedRequest, options GenerateOptions) (NormalizedResponse, error) {
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
	if estimate.InputTokens < 0 || worst < 0 || worst > math.MaxInt64/int64(options.MaxAttempts) {
		return NormalizedResponse{}, ErrInvalidRequest
	}
	reserved := worst * int64(options.MaxAttempts)
	if _, err := g.ledger.Reserve(ctx, request.TenantID, options.AccountID, options.ReservationID, request.RequestID, reserved); err != nil {
		return NormalizedResponse{}, err
	}
	var lastErr error
	var incurred int64
	for attempt := 0; attempt < options.MaxAttempts; attempt++ {
		response, generateErr := adapter.Generate(ctx, request)
		if generateErr != nil {
			g.recordProviderFailure(key, generateErr)
			var providerFailure *ProviderFailure
			if errors.As(generateErr, &providerFailure) && providerFailure.OutcomeKnown {
				if incurred == 0 {
					err = g.ledger.Release(ctx, request.TenantID, options.ReservationID)
				} else {
					_, err = g.ledger.Settle(ctx, request.TenantID, options.ReservationID, incurred)
				}
			} else {
				_, err = g.ledger.RequireReconciliation(ctx, request.TenantID, options.ReservationID)
			}
			if err != nil {
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
		if err != nil {
			return NormalizedResponse{}, err
		}
		if response.ModelVersion == "" {
			response.ModelVersion = capabilities.ActualModelVersion
		}
		if response.RequestID != "" && response.RequestID != request.RequestID {
			lastErr = ErrOutputSchema
			continue
		}
		if len(response.Content) > MaximumResponseBytes {
			if _, err := g.ledger.Settle(ctx, request.TenantID, options.ReservationID, incurred); err != nil {
				return NormalizedResponse{}, err
			}
			return NormalizedResponse{}, ErrOutputTooLarge
		}
		if containsCredentialLike(string(response.Content)) {
			if _, err := g.ledger.Settle(ctx, request.TenantID, options.ReservationID, incurred); err != nil {
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
		if _, settleErr := g.ledger.Settle(ctx, request.TenantID, options.ReservationID, incurred); settleErr != nil {
			return NormalizedResponse{}, settleErr
		}
		return response, nil
	}
	if _, err := g.ledger.Settle(ctx, request.TenantID, options.ReservationID, incurred); err != nil {
		return NormalizedResponse{}, err
	}
	if lastErr != nil {
		return NormalizedResponse{}, lastErr
	}
	return NormalizedResponse{}, ErrOutputSchema
}

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
