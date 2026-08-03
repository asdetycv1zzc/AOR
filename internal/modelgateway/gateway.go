package modelgateway

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	MaximumResponseBytes       = 4 << 20
	MaximumResponseSchemaBytes = 256 << 10
)

type Gateway struct {
	adapters map[string]ModelAdapter
	allowed  map[string]map[string]bool
	pricing  map[string]Pricing
	ledger   *BudgetLedger
	clock    func() time.Time
}

type Pricing struct {
	InputMicrosPerToken  int64
	OutputMicrosPerToken int64
}

func NewGateway(ledger *BudgetLedger, clock func() time.Time) *Gateway {
	if ledger == nil {
		ledger = NewBudgetLedger(clock)
	}
	if clock == nil {
		clock = time.Now
	}
	return &Gateway{adapters: make(map[string]ModelAdapter), allowed: make(map[string]map[string]bool), pricing: make(map[string]Pricing), ledger: ledger, clock: clock}
}

func (g *Gateway) Register(provider, model string, adapter ModelAdapter, pricing Pricing) error {
	if provider == "" || model == "" || adapter == nil || pricing.InputMicrosPerToken < 0 || pricing.OutputMicrosPerToken < 0 {
		return ErrInvalidRequest
	}
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
	adapter := g.adapters[key]
	if adapter == nil || !g.allowed[options.Provider][request.Model] {
		return NormalizedResponse{}, ErrProviderNotAllowed
	}
	capabilities, err := adapter.Capabilities(ctx, request.Model)
	if err != nil {
		return NormalizedResponse{}, redactError(err)
	}
	if request.MaxOutputTokens > capabilities.MaxOutputTokens || request.MaxOutputTokens <= 0 {
		return NormalizedResponse{}, ErrInvalidRequest
	}
	estimate, err := adapter.CountTokens(ctx, request)
	if err != nil {
		return NormalizedResponse{}, redactError(err)
	}
	pricing := g.pricing[key]
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
	if _, err := g.ledger.Reserve(ctx, options.AccountID, options.ReservationID, request.RequestID, reserved); err != nil {
		return NormalizedResponse{}, err
	}
	var lastErr error
	var incurred int64
	for attempt := 0; attempt < options.MaxAttempts; attempt++ {
		response, generateErr := adapter.Generate(ctx, request)
		if generateErr != nil {
			incurred, err = addCost(incurred, worst)
			if err != nil {
				return NormalizedResponse{}, err
			}
			if _, err := g.ledger.Reconcile(ctx, options.ReservationID, incurred); err != nil {
				return NormalizedResponse{}, err
			}
			return NormalizedResponse{}, redactError(generateErr)
		}
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
			if _, err := g.ledger.Settle(ctx, options.ReservationID, incurred); err != nil {
				return NormalizedResponse{}, err
			}
			return NormalizedResponse{}, ErrOutputTooLarge
		}
		if containsCredentialLike(string(response.Content)) {
			if _, err := g.ledger.Settle(ctx, options.ReservationID, incurred); err != nil {
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
		if _, settleErr := g.ledger.Settle(ctx, options.ReservationID, incurred); settleErr != nil {
			return NormalizedResponse{}, settleErr
		}
		return response, nil
	}
	if _, err := g.ledger.Settle(ctx, options.ReservationID, incurred); err != nil {
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
	return fmt.Sprintf("model-gateway adapters=%d", len(g.adapters))
}
