package modelgateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
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
	worst := estimate.InputTokens*pricing.InputMicrosPerToken + int64(request.MaxOutputTokens)*pricing.OutputMicrosPerToken
	if request.WorstCaseCostMicros > worst {
		worst = request.WorstCaseCostMicros
	}
	if _, err := g.ledger.Reserve(ctx, options.AccountID, options.ReservationID, request.RequestID, worst); err != nil {
		return NormalizedResponse{}, err
	}
	var lastErr error
	for attempt := 0; attempt < options.MaxAttempts; attempt++ {
		response, generateErr := adapter.Generate(ctx, request)
		if generateErr != nil {
			_, _ = g.ledger.Reconcile(ctx, options.ReservationID, worst)
			return NormalizedResponse{}, redactError(generateErr)
		}
		if response.ModelVersion == "" {
			response.ModelVersion = capabilities.ActualModelVersion
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
		if _, settleErr := g.ledger.Settle(ctx, options.ReservationID, response.Usage.CostMicros); settleErr != nil {
			return NormalizedResponse{}, settleErr
		}
		return response, nil
	}
	_ = g.ledger.Release(ctx, options.ReservationID)
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
	if len(request.ResponseSchema) != 0 && !json.Valid(request.ResponseSchema) {
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
	if len(content) == 0 || !json.Valid(content) {
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

func (g *Gateway) String() string {
	return fmt.Sprintf("model-gateway adapters=%d", len(g.adapters))
}
