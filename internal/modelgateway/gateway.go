package modelgateway

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/akimisaka/aor/internal/observability"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
)

const (
	MaximumResponseBytes          = 4 << 20
	MaximumResponseSchemaBytes    = 256 << 10
	MaximumNormalizedRequestBytes = 8 << 20
	maximumGenerateAttempts       = 5
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
	samplingSettings       SamplingSettingsStore
	dynamicProvider        func(string) (ModelAdapter, error)
	dynamicProviderPricing Pricing
	activityRecorder       ActivityRecorder
	activityInterventions  ActivityInterventionSource
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
	SamplingSettings       SamplingSettingsStore
	DynamicProvider        func(string) (ModelAdapter, error)
	DynamicProviderPricing Pricing
	ActivityRecorder       ActivityRecorder
	ActivityInterventions  ActivityInterventionSource
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
		for index := range policy.Candidates {
			policy.Candidates[index].AllowedDataClassifications = append([]string(nil), policy.Candidates[index].AllowedDataClassifications...)
			policy.Candidates[index].AllowedDataResidencies = append([]string(nil), policy.Candidates[index].AllowedDataResidencies...)
		}
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
	return &Gateway{adapters: make(map[string]ModelAdapter), allowed: make(map[string]map[string]bool), pricing: make(map[string]Pricing), ledger: ledger, callFinalizer: finalizer, clock: clock, circuits: make(map[string]providerCircuit), initialProviderBackoff: config.InitialProviderBackoff, maximumProviderBackoff: config.MaximumProviderBackoff, backoffJitterRatio: config.BackoffJitterRatio, sleep: config.Sleep, policies: policies, eligibility: config.ProviderEligibility, replayStore: replayStore, replayFinalizer: replayFinalizer, callLookup: callLookup, samplingSettings: config.SamplingSettings, dynamicProvider: config.DynamicProvider, dynamicProviderPricing: config.DynamicProviderPricing, activityRecorder: config.ActivityRecorder, activityInterventions: config.ActivityInterventions, executions: make(map[string]*requestExecution)}
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

func normalizeGenerateOptions(options GenerateOptions) (GenerateOptions, error) {
	if options.MaxAttempts <= 0 {
		options.MaxAttempts = maximumGenerateAttempts
	}
	if options.Provider == "" || options.AccountID == "" || options.ReservationID == "" || options.MaxAttempts > maximumGenerateAttempts {
		return GenerateOptions{}, ErrInvalidRequest
	}
	return options, nil
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
	var err error
	request, err = g.applySamplingSettings(ctx, request)
	if err != nil {
		return nil, err
	}
	if requestUsesNativeTools(request) {
		return nil, ErrProviderNotAllowed
	}
	options, err = normalizeGenerateOptions(options)
	if err != nil {
		return nil, err
	}
	if !state.ValidModelReasoningEffort(options.Provider, request.ReasoningEffort) {
		return nil, ErrInvalidRequest
	}
	if policy, found := g.policyFor(request); found {
		return g.streamWithPolicy(ctx, request, options, policy)
	}
	if request.ProviderPolicy != "" {
		return nil, ErrProviderNotAllowed
	}
	adapter, key, capabilities, estimate, reservation, pricing, worstCost, err := g.prepare(ctx, request, options, true)
	if err != nil {
		return nil, err
	}
	startedAt := g.clock().UTC()
	call, err := newModelCall(request, options, options.Provider, capabilities.ActualModelVersion, estimate.InputTokens, startedAt)
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
		call.InputTokens = 0
		call.OutputTokens = 0
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
		maxResponseBytes: MaximumResponseBytes, pricing: pricing, worstCost: worstCost,
	}, nil
}

func (g *Gateway) streamWithPolicy(ctx context.Context, request NormalizedRequest, options GenerateOptions, policy ProviderPolicy) (ResponseStream, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	var err error
	options, err = normalizeGenerateOptions(options)
	if err != nil {
		return nil, err
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
	call, err := newModelCall(request, options, selections[0].candidate.Provider, selections[0].caps.ActualModelVersion, selections[0].estimate.InputTokens, startedAt)
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
				return &budgetedStream{stream: stream, tenantID: request.TenantID, reservationID: options.ReservationID, context: ctx, call: call, startedAt: startedAt, finalizeCall: g.finalizeModelCall, clock: g.clock, responseSchema: append(json.RawMessage(nil), request.ResponseSchema...), semanticValidator: request.ResponseSemanticValidator, maxResponseBytes: MaximumResponseBytes, pricing: selection.pricing, worstCost: selection.worstCost}, nil
			}
			g.recordProviderFailure(selection.key, streamErr)
			lastErr = streamErr
			var providerFailure *ProviderFailure
			if !errors.As(streamErr, &providerFailure) || !providerFailure.OutcomeKnown {
				call.Status = ModelCallReconcile
				call.InputTokens = 0
				call.OutputTokens = 0
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

func (g *Gateway) Generate(ctx context.Context, request NormalizedRequest, options GenerateOptions) (response NormalizedResponse, resultErr error) {
	if ctx == nil {
		return NormalizedResponse{}, ErrInvalidRequest
	}
	activityStartedAt := g.clock().UTC()
	var activityFinishOnce sync.Once
	activityLeader := true
	activityRecorded := false
	finishActivity := func() {
		if !activityRecorded {
			return
		}
		activityFinishOnce.Do(func() {
			g.recordActivityFinish(ctx, request, options, response, resultErr, activityStartedAt)
		})
	}
	defer func() {
		if activityLeader {
			finishActivity()
		}
	}()
	var err error
	request, err = g.applySamplingSettings(ctx, request)
	if err != nil {
		return NormalizedResponse{}, err
	}
	if err := validateRequest(request); err != nil {
		return NormalizedResponse{}, err
	}
	options, err = normalizeGenerateOptions(options)
	if err != nil {
		return NormalizedResponse{}, err
	}
	if !state.ValidModelReasoningEffort(options.Provider, request.ReasoningEffort) {
		return NormalizedResponse{}, ErrInvalidRequest
	}
	claimedInterventions, interventionErr := g.claimActivityInterventions(ctx, request)
	if interventionErr != nil {
		return NormalizedResponse{}, ErrProviderUnavailable
	}
	if len(claimedInterventions) != 0 {
		request.Messages = append(append([]Message(nil), request.Messages...), claimedInterventionMessages(claimedInterventions)...)
		claimedIDs := claimedInterventionIDs(claimedInterventions)
		if err := validateRequest(request); err != nil {
			g.completeActivityInterventions(ctx, request, claimedIDs, err)
			return NormalizedResponse{}, err
		}
	}
	ctx, traceSpan := observability.StartSpan(ctx, observability.SpanModelGenerate, modelTraceCorrelation(request), map[string]string{
		"aor.agent.id":         request.AgentInstanceID,
		"aor.agent.role":       request.Role,
		"aor.policy.version":   request.PolicyDigest,
		"aor.prompt.version":   request.PromptBundleVersion,
		"gen_ai.provider.name": options.Provider,
		"gen_ai.request.model": request.Model,
	})
	defer func() {
		attributes := map[string]string{
			"gen_ai.response.model":      response.ModelVersion,
			"gen_ai.usage.input_tokens":  strconv.FormatInt(response.Usage.InputTokens, 10),
			"gen_ai.usage.output_tokens": strconv.FormatInt(response.Usage.OutputTokens, 10),
		}
		if response.ModelVersion == "" {
			attributes["gen_ai.response.model"] = "UNAVAILABLE"
		}
		observability.EndSpan(ctx, traceSpan, resultErr, observability.TraceOutcome{BudgetDenied: errors.Is(resultErr, ErrBudgetExceeded)}, attributes)
	}()
	digest, err := normalizedRequestDigest(request, options)
	if err != nil {
		return NormalizedResponse{}, err
	}
	execution, leader, err := g.beginExecution(request, digest)
	if err != nil {
		g.completeActivityInterventions(ctx, request, claimedInterventionIDs(claimedInterventions), err)
		return NormalizedResponse{}, err
	}
	if !leader {
		activityLeader = false
		select {
		case <-execution.done:
			return cloneNormalizedResponse(execution.response), execution.err
		case <-ctx.Done():
			return NormalizedResponse{}, ctx.Err()
		}
	}
	g.recordActivityStart(ctx, request, options, activityStartedAt)
	activityRecorded = true
	if claimedIDs := claimedInterventionIDs(claimedInterventions); len(claimedIDs) != 0 {
		defer func() {
			g.completeActivityInterventions(ctx, request, claimedIDs, resultErr)
		}()
	}
	if replay, found, loadErr := g.loadReplay(ctx, request, digest); loadErr != nil {
		finishActivity()
		g.finishExecution(request, digest, execution, NormalizedResponse{}, loadErr)
		return NormalizedResponse{}, loadErr
	} else if found {
		// Durable replays are untrusted persisted model output. Re-run the
		// request's current output checks before returning a replay, including
		// the process-local semantic validator.
		if validationErr := validateGeneratedResponse(request, replay.Response); validationErr != nil {
			finishActivity()
			g.finishExecution(request, digest, execution, NormalizedResponse{}, validationErr)
			return NormalizedResponse{}, validationErr
		}
		response = g.decorateActivityResponse(ctx, request, claimedInterventions, replay.Response)
		resultErr = nil
		finishActivity()
		g.finishExecution(request, digest, execution, response, nil)
		return response, nil
	}
	if g.activityRecorder == nil {
		response, resultErr = g.generateOnce(ctx, request, options)
		if resultErr == nil && response.RequestID == "" {
			response.RequestID = request.RequestID
		}
		if resultErr == nil {
			response = g.decorateActivityResponse(ctx, request, claimedInterventions, response)
		}
		finishActivity()
		g.finishExecution(request, digest, execution, response, resultErr)
		return response, resultErr
	}
	activityContext := ctx
	var activityDeltaMu sync.Mutex
	var activityDelta []byte
	var activityReasoningSummary []byte
	flushActivityDelta := func() {
		activityDeltaMu.Lock()
		if len(activityDelta) == 0 && len(activityReasoningSummary) == 0 {
			activityDeltaMu.Unlock()
			return
		}
		pending := string(activityDelta)
		pendingReasoningSummary := string(activityReasoningSummary)
		activityDelta = nil
		activityReasoningSummary = nil
		activityDeltaMu.Unlock()
		g.recordActivityDelta(activityContext, request, pending)
		g.recordActivityReasoningSummary(activityContext, request, pendingReasoningSummary)
	}
	activityDeltaWake := make(chan struct{}, 1)
	activityDeltaStop := make(chan struct{})
	var activityDeltaWorker sync.WaitGroup
	activityDeltaWorker.Add(1)
	go func() {
		defer activityDeltaWorker.Done()
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				flushActivityDelta()
			case <-activityDeltaWake:
				flushActivityDelta()
			case <-activityDeltaStop:
				return
			}
		}
	}()
	parentActivityDelta, _ := ctx.Value(activityDeltaContextKey{}).(func(string))
	ctx = withActivityDeltaRecorder(ctx, func(delta string) {
		if delta == "" {
			return
		}
		if parentActivityDelta != nil {
			parentActivityDelta(delta)
		}
		activityDeltaMu.Lock()
		activityDelta = append(activityDelta, delta...)
		shouldFlush := len(activityDelta) >= 1024
		activityDeltaMu.Unlock()
		if shouldFlush {
			select {
			case activityDeltaWake <- struct{}{}:
			default:
			}
		}
	})
	parentReasoningSummary, _ := ctx.Value(activityReasoningSummaryContextKey{}).(func(string))
	ctx = withActivityReasoningSummaryRecorder(ctx, func(delta string) {
		if delta == "" {
			return
		}
		if parentReasoningSummary != nil {
			parentReasoningSummary(delta)
		}
		activityDeltaMu.Lock()
		activityReasoningSummary = append(activityReasoningSummary, delta...)
		shouldFlush := len(activityReasoningSummary) >= 1024
		activityDeltaMu.Unlock()
		if shouldFlush {
			select {
			case activityDeltaWake <- struct{}{}:
			default:
			}
		}
	})
	var stopActivityDeltasOnce sync.Once
	stopActivityDeltas := func() {
		stopActivityDeltasOnce.Do(func() {
			close(activityDeltaStop)
			activityDeltaWorker.Wait()
			flushActivityDelta()
		})
	}
	defer stopActivityDeltas()
	response, resultErr = g.generateOnce(ctx, request, options)
	if resultErr == nil {
		if response.RequestID == "" {
			response.RequestID = request.RequestID
		}
		response = g.decorateActivityResponse(ctx, request, claimedInterventions, response)
	}
	stopActivityDeltas()
	finishActivity()
	g.finishExecution(request, digest, execution, response, resultErr)
	return response, resultErr
}

func modelTraceCorrelation(request NormalizedRequest) observability.Correlation {
	correlation := observability.Correlation{
		ProjectID:        request.ProjectID,
		WorkflowIDReason: observability.ReasonUnavailable,
		TaskID:           request.TaskID,
		AgentRunIDReason: observability.ReasonUnavailable,
	}
	if request.TaskID == "" {
		correlation.TaskIDReason = observability.ReasonNotApplicable
	}
	return correlation
}

type executionDigestInput struct {
	Request NormalizedRequest `json:"request"`
	Options GenerateOptions   `json:"options"`
}

func normalizedRequestDigest(request NormalizedRequest, options GenerateOptions) (string, error) {
	encoded, err := json.Marshal(executionDigestInput{Request: request, Options: options})
	if err != nil {
		return "", ErrInvalidRequest
	}
	return canonicaljson.Digest(encoded)
}

func (g *Gateway) applySamplingSettings(ctx context.Context, request NormalizedRequest) (NormalizedRequest, error) {
	if g.samplingSettings == nil {
		return request, nil
	}
	if request.TenantID == "" {
		return NormalizedRequest{}, ErrInvalidRequest
	}
	settings, found, err := g.samplingSettings.Get(ctx, request.TenantID)
	if err != nil {
		return NormalizedRequest{}, ErrProviderUnavailable
	}
	if !found {
		settings = DefaultSamplingSettings()
	}
	if ValidateSamplingSettings(settings) != nil {
		return NormalizedRequest{}, ErrProviderUnavailable
	}
	request.Temperature = settings.Temperature
	request.TopP = settings.TopP
	request.TopK = settings.TopK
	return request, nil
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
	if call.Status == ModelCallSucceeded || call.Status == ModelCallReconciled {
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
	// The deployment's default route is an explicit project choice. It must
	// retry that provider/model only; catalog entries are metadata, not hidden
	// fallback targets. Named policies retain their explicit fallback lists.
	if request.ProviderPolicy == "default" {
		return []ProviderCandidate{{
			Provider:                   options.Provider,
			Model:                      request.Model,
			CapabilityRank:             100,
			AllowedDataClassifications: []string{"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"},
		}}, nil
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
		g.mu.RLock()
		dynamic := g.dynamicProvider != nil
		g.mu.RUnlock()
		if !dynamic {
			return nil, ErrProviderNotAllowed
		}
		preferred = ProviderCandidate{
			Provider: options.Provider, Model: request.Model, CapabilityRank: 100,
			AllowedDataClassifications: []string{"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"},
			AllowedDataResidencies:     []string{"provider-defined"}, RetentionPolicy: "provider-defined",
		}
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
		if !state.ValidModelReasoningEffort(candidate.Provider, request.ReasoningEffort) {
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
		if !candidateAllowsProviderMetadata(candidate, capabilities, request.DataClassification) {
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
		if contextWindowExceeded(candidateRequest, capabilities, estimate) {
			lastErr = ErrContextWindowExceeded
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

func candidateAllowsProviderMetadata(candidate ProviderCandidate, capabilities ModelCapabilities, classification string) bool {
	if classification != "PUBLIC" {
		for _, residency := range candidate.AllowedDataResidencies {
			if residency == "provider-defined" {
				return false
			}
		}
		if candidate.RetentionPolicy == "provider-defined" {
			return false
		}
	}
	if len(candidate.AllowedDataResidencies) != 0 {
		if len(capabilities.DataResidency) == 0 {
			return false
		}
		matched := false
		for _, allowed := range candidate.AllowedDataResidencies {
			for _, actual := range capabilities.DataResidency {
				if allowed == actual {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	if candidate.RetentionPolicy != "" && (capabilities.RetentionPolicy == "" || candidate.RetentionPolicy != capabilities.RetentionPolicy) {
		return false
	}
	return true
}

func (g *Gateway) generateWithPolicy(ctx context.Context, request NormalizedRequest, options GenerateOptions, policy ProviderPolicy) (NormalizedResponse, error) {
	if err := validateRequest(request); err != nil {
		return NormalizedResponse{}, err
	}
	if options.MaxAttempts <= 0 {
		options.MaxAttempts = maximumGenerateAttempts
	}
	if options.MaxAttempts > maximumGenerateAttempts || options.AccountID == "" || options.ReservationID == "" {
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
	call, err := newModelCall(request, options, selections[0].candidate.Provider, selections[0].caps.ActualModelVersion, 0, startedAt)
	if err != nil {
		_ = g.releaseReservation(ctx, request.TenantID, options.ReservationID)
		return NormalizedResponse{}, err
	}
	var incurred int64
	var lastErr error
	cacheReadKnown := true
	cacheWriteKnown := true
	remainingAttempts := options.MaxAttempts
	attemptNumber := 0
	retryPending := false
	retryAfter := time.Duration(0)
	for selectionIndex, selection := range selections {
		if remainingAttempts == 0 {
			break
		}
		if g.eligibility != nil {
			if eligibilityErr := g.eligibility(ctx, ProviderEligibilityInput{Operation: "generate", Request: request, Candidate: selection.candidate, Capabilities: selection.caps, AccountID: options.AccountID, ReservationID: options.ReservationID}); eligibilityErr != nil {
				lastErr = eligibilityErr
				continue
			}
		}
		call.Provider = selection.candidate.Provider
		call.LogicalModel = request.Model
		call.ActualModelVersion = selection.caps.ActualModelVersion
		selectionAttempts := remainingAttempts
		if selectionIndex+1 < len(selections) {
			selectionAttempts = 1
		}
		for attempt := 0; attempt < selectionAttempts; attempt++ {
			remainingAttempts--
			attemptNumber++
			if retryPending {
				g.recordActivityAttempt(ctx, request, options, ActivityAttempt{
					Attempt: attemptNumber, MaxAttempts: options.MaxAttempts,
					Provider: selection.candidate.Provider, Model: selection.request.Model,
					Phase: ActivityAttemptRetry, RetryAfter: retryAfter,
				})
				retryPending = false
				retryAfter = 0
			}
			response, generateErr := selection.adapter.Generate(ctx, selection.request)
			if generateErr != nil {
				lastErr = generateErr
				g.recordProviderFailure(selection.key, generateErr)
				var providerFailure *ProviderFailure
				knownProviderFailure := errors.As(generateErr, &providerFailure) && providerFailure.OutcomeKnown
				timedOut := knownProviderFailure && providerFailure.Retryable && errors.Is(generateErr, context.DeadlineExceeded)
				if timedOut && selectionIndex+1 < len(selections) {
					selectionAttempts = attempt + 1 + remainingAttempts
				}
				retryCurrentProvider := knownProviderFailure && providerFailure.Retryable && attempt+1 < selectionAttempts && (timedOut || selectionIndex+1 == len(selections))
				retryFallbackProvider := knownProviderFailure && providerFailure.Retryable && selectionIndex+1 < len(selections) && remainingAttempts > 0
				retryDelay := time.Duration(0)
				if retryCurrentProvider {
					retryDelay = g.retryDelay(selection.key)
				}
				g.recordActivityAttemptFailure(ctx, request, options, attemptNumber, options.MaxAttempts, selection.candidate.Provider, selection.request.Model, generateErr, retryCurrentProvider || retryFallbackProvider, retryDelay)
				if !knownProviderFailure {
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
				if retryCurrentProvider {
					retryAfter = g.retryDelay(selection.key)
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
					retryPending = true
					continue
				}
				break
			}
			g.providerSucceeded(selection.key)
			attemptCost, costErr := usageCost(response.Usage, selection.pricing)
			if costErr != nil {
				err = costErr
			}
			if err == nil {
				incurred, err = addCost(incurred, attemptCost)
			}
			if err == nil {
				response.Usage.CostMicros = attemptCost
			}
			if err == nil {
				call.InputTokens, err = addCost(call.InputTokens, response.Usage.InputTokens)
			}
			if err == nil {
				call.OutputTokens, err = addCost(call.OutputTokens, response.Usage.OutputTokens)
			}
			if err == nil {
				err = accumulateCacheTokens(&call.CacheReadTokens, &cacheReadKnown, response.Usage.CacheReadTokens)
			}
			if err == nil {
				err = accumulateCacheTokens(&call.CacheWriteTokens, &cacheWriteKnown, response.Usage.CacheWriteTokens)
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
			call.OutputSHA256 = responseOutputDigest(response)
			call.CostMicros = incurred
			if response.RequestID != "" && response.RequestID != request.RequestID {
				lastErr = ErrOutputSchema
				willRetry := attempt+1 < selectionAttempts || selectionIndex+1 < len(selections) && remainingAttempts > 0
				g.recordActivityAttemptFailure(ctx, request, options, attemptNumber, options.MaxAttempts, selection.candidate.Provider, selection.request.Model, lastErr, willRetry, 0)
				if willRetry {
					retryPending = true
				}
				continue
			}
			validationErr := validateGeneratedResponse(request, response)
			if errors.Is(validationErr, ErrOutputTooLarge) {
				call.Status = ModelCallFailedOutputSize
				call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
				if finalizeErr := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionSettle, ActualMicros: incurred, Call: call}); finalizeErr != nil {
					return NormalizedResponse{}, finalizeErr
				}
				return NormalizedResponse{}, ErrOutputTooLarge
			}
			if errors.Is(validationErr, ErrCredentialDetected) {
				call.Status = ModelCallFailedCredential
				call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
				if finalizeErr := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionSettle, ActualMicros: incurred, Call: call}); finalizeErr != nil {
					return NormalizedResponse{}, finalizeErr
				}
				return NormalizedResponse{}, ErrCredentialDetected
			}
			if validationErr != nil {
				lastErr = validationErr
				willRetry := attempt+1 < selectionAttempts || selectionIndex+1 < len(selections) && remainingAttempts > 0
				g.recordActivityAttemptFailure(ctx, request, options, attemptNumber, options.MaxAttempts, selection.candidate.Provider, selection.request.Model, validationErr, willRetry, 0)
				if willRetry {
					retryPending = true
				}
				continue
			}
			if response.Usage.ProviderRequestID == "" {
				response.Usage.ProviderRequestID = response.ProviderRequestID
			}
			if response.Usage.ModelVersion == "" {
				response.Usage.ModelVersion = response.ModelVersion
			}
			response.RequestID = request.RequestID
			response.Provider = selection.candidate.Provider
			call.Status = ModelCallSucceeded
			call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
			if finalizeErr := g.finalizeSuccessfulModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionSettle, ActualMicros: incurred, Call: call}, response); finalizeErr != nil {
				return NormalizedResponse{}, finalizeErr
			}
			return response, nil
		}
		if selectionIndex+1 < len(selections) && remainingAttempts > 0 && providerFallbackAllowed(lastErr) {
			retryPending = true
			retryAfter = 0
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
	if delay := g.retryDelay(key); delay > 0 {
		return g.sleep(ctx, delay)
	}
	return nil
}

func (g *Gateway) retryDelay(key string) time.Duration {
	g.mu.RLock()
	circuit := g.circuits[key]
	g.mu.RUnlock()
	if circuit.retryAt.IsZero() {
		return 0
	}
	now := g.clock().UTC()
	if !circuit.retryAt.After(now) {
		return 0
	}
	return circuit.retryAt.Sub(now)
}

func (g *Gateway) generateSingle(ctx context.Context, request NormalizedRequest, options GenerateOptions) (NormalizedResponse, error) {
	if ctx == nil {
		return NormalizedResponse{}, ErrInvalidRequest
	}
	if err := validateRequest(request); err != nil {
		return NormalizedResponse{}, err
	}
	if options.MaxAttempts <= 0 {
		options.MaxAttempts = maximumGenerateAttempts
	}
	if options.MaxAttempts > maximumGenerateAttempts {
		options.MaxAttempts = maximumGenerateAttempts
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
	if contextWindowExceeded(request, capabilities, estimate) {
		return NormalizedResponse{}, ErrContextWindowExceeded
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
	call, err := newModelCall(request, options, options.Provider, capabilities.ActualModelVersion, 0, startedAt)
	if err != nil {
		if releaseErr := g.releaseReservation(ctx, request.TenantID, options.ReservationID); releaseErr != nil {
			return NormalizedResponse{}, releaseErr
		}
		return NormalizedResponse{}, err
	}
	var lastErr error
	var incurred int64
	cacheReadKnown := true
	cacheWriteKnown := true
	attemptNumber := 0
	retryPending := false
	retryAfter := time.Duration(0)
	for attempt := 0; attempt < options.MaxAttempts; attempt++ {
		attemptNumber++
		if retryPending {
			g.recordActivityAttempt(ctx, request, options, ActivityAttempt{
				Attempt: attemptNumber, MaxAttempts: options.MaxAttempts,
				Provider: options.Provider, Model: request.Model,
				Phase: ActivityAttemptRetry, RetryAfter: retryAfter,
			})
			retryPending = false
			retryAfter = 0
		}
		response, generateErr := adapter.Generate(ctx, request)
		if generateErr != nil {
			g.recordProviderFailure(key, generateErr)
			var providerFailure *ProviderFailure
			knownProviderFailure := errors.As(generateErr, &providerFailure) && providerFailure.OutcomeKnown
			retryCurrentProvider := knownProviderFailure && providerFailure.Retryable && attempt+1 < options.MaxAttempts
			retryAfter = time.Duration(0)
			if retryCurrentProvider {
				retryAfter = g.retryDelay(key)
			}
			g.recordActivityAttemptFailure(ctx, request, options, attemptNumber, options.MaxAttempts, options.Provider, request.Model, generateErr, retryCurrentProvider, retryAfter)
			if retryCurrentProvider {
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
				retryPending = true
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
		attemptCost, costErr := usageCost(response.Usage, pricing)
		if costErr != nil {
			err = costErr
		}
		if err == nil {
			incurred, err = addCost(incurred, attemptCost)
		}
		if err == nil {
			response.Usage.CostMicros = attemptCost
		}
		if err == nil {
			call.InputTokens, err = addCost(call.InputTokens, response.Usage.InputTokens)
		}
		if err == nil {
			call.OutputTokens, err = addCost(call.OutputTokens, response.Usage.OutputTokens)
		}
		if err == nil {
			err = accumulateCacheTokens(&call.CacheReadTokens, &cacheReadKnown, response.Usage.CacheReadTokens)
		}
		if err == nil {
			err = accumulateCacheTokens(&call.CacheWriteTokens, &cacheWriteKnown, response.Usage.CacheWriteTokens)
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
		call.OutputSHA256 = responseOutputDigest(response)
		call.CostMicros = incurred
		if response.RequestID != "" && response.RequestID != request.RequestID {
			lastErr = ErrOutputSchema
			willRetry := attempt+1 < options.MaxAttempts
			g.recordActivityAttemptFailure(ctx, request, options, attemptNumber, options.MaxAttempts, options.Provider, request.Model, lastErr, willRetry, 0)
			if willRetry {
				retryPending = true
			}
			continue
		}
		validationErr := validateGeneratedResponse(request, response)
		if errors.Is(validationErr, ErrOutputTooLarge) {
			call.Status = ModelCallFailedOutputSize
			call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
			if err := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionSettle, ActualMicros: incurred, Call: call}); err != nil {
				return NormalizedResponse{}, err
			}
			return NormalizedResponse{}, ErrOutputTooLarge
		}
		if errors.Is(validationErr, ErrCredentialDetected) {
			call.Status = ModelCallFailedCredential
			call.LatencyMilliseconds = elapsedMilliseconds(startedAt, g.clock().UTC())
			if err := g.finalizeModelCall(ctx, ModelCallFinalization{ReservationID: options.ReservationID, Disposition: ReservationDispositionSettle, ActualMicros: incurred, Call: call}); err != nil {
				return NormalizedResponse{}, err
			}
			return NormalizedResponse{}, ErrCredentialDetected
		}
		if validationErr != nil {
			lastErr = validationErr
			willRetry := attempt+1 < options.MaxAttempts
			g.recordActivityAttemptFailure(ctx, request, options, attemptNumber, options.MaxAttempts, options.Provider, request.Model, validationErr, willRetry, 0)
			if willRetry {
				retryPending = true
			}
			continue
		}
		if response.Usage.ProviderRequestID == "" {
			response.Usage.ProviderRequestID = response.ProviderRequestID
		}
		if response.Usage.ModelVersion == "" {
			response.Usage.ModelVersion = response.ModelVersion
		}
		response.RequestID = request.RequestID
		response.Provider = options.Provider
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

func newModelCall(request NormalizedRequest, options GenerateOptions, provider, actualModelVersion string, inputTokens int64, createdAt time.Time) (ModelCall, error) {
	encoded, err := json.Marshal(executionDigestInput{Request: request, Options: options})
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

func (g *Gateway) prepare(ctx context.Context, request NormalizedRequest, options GenerateOptions, requireStreaming bool) (ModelAdapter, string, ModelCapabilities, TokenEstimate, string, Pricing, int64, error) {
	if err := validateRequest(request); err != nil {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", Pricing{}, 0, err
	}
	var err error
	options, err = normalizeGenerateOptions(options)
	if err != nil {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", Pricing{}, 0, err
	}
	key := options.Provider + "\x00" + request.Model
	adapter, pricing, allowed := g.provider(key, options.Provider, request.Model)
	if adapter == nil || !allowed {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", Pricing{}, 0, ErrProviderNotAllowed
	}
	if !g.providerReady(key, g.clock().UTC()) {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", Pricing{}, 0, ErrProviderUnavailable
	}
	capabilities, err := adapter.Capabilities(ctx, request.Model)
	if err != nil {
		g.recordProviderFailure(key, err)
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", Pricing{}, 0, redactError(err)
	}
	if request.MaxOutputTokens > capabilities.MaxOutputTokens || request.MaxOutputTokens <= 0 || requireStreaming && !capabilities.SupportsStreaming {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", Pricing{}, 0, ErrProviderNotAllowed
	}
	estimate, err := adapter.CountTokens(ctx, request)
	if err != nil {
		g.recordProviderFailure(key, err)
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", Pricing{}, 0, redactError(err)
	}
	if contextWindowExceeded(request, capabilities, estimate) {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", Pricing{}, 0, ErrContextWindowExceeded
	}
	inputCost, err := multiplyCost(estimate.InputTokens, pricing.InputMicrosPerToken)
	if err != nil {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", Pricing{}, 0, err
	}
	outputCost, err := multiplyCost(int64(request.MaxOutputTokens), pricing.OutputMicrosPerToken)
	if err != nil {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", Pricing{}, 0, err
	}
	worst, err := addCost(inputCost, outputCost)
	if err != nil {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", Pricing{}, 0, err
	}
	if request.WorstCaseCostMicros > worst {
		worst = request.WorstCaseCostMicros
	}
	if worst < 0 || worst > math.MaxInt64/int64(options.MaxAttempts) {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", Pricing{}, 0, ErrInvalidRequest
	}
	if _, err := g.claimExternalCall(ctx, request.TenantID, options.AccountID, options.ReservationID, request.RequestID, worst*int64(options.MaxAttempts)); err != nil {
		return nil, "", ModelCapabilities{}, TokenEstimate{}, "", Pricing{}, 0, err
	}
	return adapter, key, capabilities, estimate, options.ReservationID, pricing, worst, nil
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
	pricing           Pricing
	worstCost         int64
	recvMu            sync.Mutex
	terminal          bool
	terminalErr       error
	rawBytes          int
	once              sync.Once
	finalizeErr       error
}

func (s *budgetedStream) Recv(ctx context.Context) (json.RawMessage, error) {
	if ctx == nil {
		return nil, ErrInvalidRequest
	}
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	if s.terminal {
		if s.terminalErr != nil {
			return nil, s.terminalErr
		}
		return nil, io.EOF
	}
	value, err := s.stream.Recv(ctx)
	if err == nil {
		if validationErr := s.validateEvent(value); validationErr != nil {
			s.terminal = true
			if finalizeErr := s.finalizeFailure(validationErr); finalizeErr != nil {
				s.terminalErr = finalizeErr
				return nil, finalizeErr
			}
			s.terminalErr = validationErr
			return nil, validationErr
		}
		s.rawBytes += len(value)
		return append(json.RawMessage(nil), value...), nil
	}
	s.terminal = true
	if errors.Is(err, io.EOF) {
		s.terminalErr = s.finalizeTerminal()
		if s.terminalErr != nil {
			return nil, s.terminalErr
		}
		return nil, io.EOF
	}
	if finalizeErr := s.finalizeFailure(err); finalizeErr != nil {
		s.terminalErr = finalizeErr
		return nil, finalizeErr
	}
	s.terminalErr = err
	return nil, err
}

func (s *budgetedStream) Close() error {
	closeErr := s.stream.Close()
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	s.terminal = true
	if finalizeErr := s.finalizeFailure(nil); finalizeErr != nil {
		return finalizeErr
	}
	return closeErr
}

func (s *budgetedStream) validateEvent(value json.RawMessage) error {
	if len(value) == 0 || s.maxResponseBytes <= 0 || len(value) > s.maxResponseBytes || s.rawBytes > s.maxResponseBytes-len(value) || !utf8.Valid(value) || !json.Valid(value) {
		return ErrOutputSchema
	}
	if containsCredentialLike(string(value)) {
		return ErrCredentialDetected
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(value, &fields); err != nil || len(fields) != 1 {
		return ErrOutputSchema
	}
	delta, found := fields["delta"]
	if !found {
		return ErrOutputSchema
	}
	var fragment string
	if err := json.Unmarshal(delta, &fragment); err != nil {
		return ErrOutputSchema
	}
	return nil
}

func (s *budgetedStream) finalContentValue() ([]byte, error) {
	contentStream, ok := s.stream.(FinalContentAwareStream)
	if !ok {
		return nil, ErrReconciliationRequired
	}
	content, ready := contentStream.FinalContent()
	if !ready {
		return nil, ErrReconciliationRequired
	}
	return append([]byte(nil), content...), nil
}

func (s *budgetedStream) finalizeTerminal() error {
	s.once.Do(func() {
		usage, found := streamUsage(s.stream)
		content, contentErr := s.finalContentValue()
		if contentErr != nil && !errors.Is(contentErr, ErrOutputSchema) {
			s.finalizeErr = s.finalizeUnknown()
			if s.finalizeErr == nil {
				s.finalizeErr = contentErr
			}
			return
		}
		if !found || usage.InputTokens < 0 || usage.OutputTokens < 0 || usage.CostMicros < 0 {
			s.finalizeErr = s.finalizeUnknown()
			if s.finalizeErr == nil {
				if contentErr != nil {
					s.finalizeErr = contentErr
				} else {
					s.finalizeErr = ErrReconciliationRequired
				}
			}
			return
		}
		if contentErr != nil {
			s.finalizeErr = s.finishRejected(ErrOutputSchema, usage, nil)
			return
		}
		cost, costErr := usageCost(usage, s.pricing)
		if costErr != nil {
			s.finalizeErr = s.finalizeUnknown()
			if s.finalizeErr == nil {
				s.finalizeErr = costErr
			}
			return
		}
		call := s.call
		call.InputTokens = usage.InputTokens
		call.OutputTokens = usage.OutputTokens
		call.CacheReadTokens = cloneOptionalInt64(usage.CacheReadTokens)
		call.CacheWriteTokens = cloneOptionalInt64(usage.CacheWriteTokens)
		call.CostMicros = cost
		call.ProviderRequestID = usage.ProviderRequestID
		if usage.ModelVersion != "" {
			call.ActualModelVersion = usage.ModelVersion
		}
		if len(content) != 0 {
			call.OutputSHA256 = digestBytes(content)
		}
		call.LatencyMilliseconds = elapsedMilliseconds(s.startedAt, s.clock().UTC())
		if containsCredentialLike(string(content)) {
			s.finalizeErr = s.finishRejected(ErrCredentialDetected, usage, content)
			return
		}
		if validationErr := validateStreamFinal(s.responseSchema, s.semanticValidator, content); validationErr != nil {
			s.finalizeErr = s.finishRejected(validationErr, usage, content)
			return
		}
		call.Status = ModelCallSucceeded
		s.finalizeErr = s.finalizeCall(context.WithoutCancel(s.context), ModelCallFinalization{
			ReservationID: s.reservationID, Disposition: ReservationDispositionSettle,
			ActualMicros: cost, Call: call,
		})
	})
	return s.finalizeErr
}

func (s *budgetedStream) finishRejected(rejection error, usage Usage, content []byte) error {
	call := s.call
	call.InputTokens = usage.InputTokens
	call.OutputTokens = usage.OutputTokens
	call.CacheReadTokens = cloneOptionalInt64(usage.CacheReadTokens)
	call.CacheWriteTokens = cloneOptionalInt64(usage.CacheWriteTokens)
	call.CostMicros, _ = usageCost(usage, s.pricing)
	call.Status = ModelCallFailedOutputSchema
	if errors.Is(rejection, ErrCredentialDetected) {
		call.Status = ModelCallFailedCredential
	}
	if len(content) != 0 {
		call.OutputSHA256 = digestBytes(content)
	}
	call.LatencyMilliseconds = elapsedMilliseconds(s.startedAt, s.clock().UTC())
	finalizeErr := s.finalizeCall(context.WithoutCancel(s.context), ModelCallFinalization{
		ReservationID: s.reservationID, Disposition: ReservationDispositionSettle,
		ActualMicros: call.CostMicros, Call: call,
	})
	if finalizeErr != nil {
		return finalizeErr
	}
	return rejection
}

func validateStreamFinal(schema json.RawMessage, semanticValidator func(json.RawMessage) error, content []byte) error {
	if len(content) == 0 && len(schema) == 0 && semanticValidator == nil {
		return nil
	}
	if err := validateResponse(schema, content); err != nil {
		return err
	}
	return validateResponseSemantics(semanticValidator, content)
}

func validateResponseSemantics(semanticValidator func(json.RawMessage) error, content []byte) error {
	if semanticValidator == nil {
		return nil
	}
	if err := semanticValidator(append(json.RawMessage(nil), content...)); err != nil {
		return ErrOutputSchema
	}
	return nil
}

func (s *budgetedStream) finalizeFailure(cause error) error {
	s.once.Do(func() {
		var providerFailure *ProviderFailure
		if cause != nil && errors.As(cause, &providerFailure) && providerFailure.OutcomeKnown && s.rawBytes == 0 {
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
	call.InputTokens = 0
	call.OutputTokens = 0
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

func requestUsesNativeTools(request NormalizedRequest) bool {
	if len(request.Tools) != 0 {
		return true
	}
	for _, message := range request.Messages {
		if len(message.ToolCalls) != 0 || message.ToolCallID != "" {
			return true
		}
	}
	return false
}

func validateRequest(request NormalizedRequest) error {
	if request.RequestID == "" || request.TenantID == "" || request.ProjectID == "" || request.AgentInstanceID == "" || request.Role == "" || request.Model == "" || request.PromptBundleVersion == "" || len(request.Messages) == 0 || len(request.Messages) > MaximumMessages || len(request.Tools) > MaximumTools || request.MaxOutputTokens <= 0 || request.MaxOutputTokens > 1_000_000 || request.ThinkingBudget < 0 || request.ThinkingBudget >= request.MaxOutputTokens || request.ContextWindowTokens < 0 || request.ContextWindowTokens > 10_000_000 || request.ContextWindowTokens > 0 && request.ContextWindowTokens <= request.MaxOutputTokens || request.CompactionThresholdTokens < 0 || request.CompactionThresholdTokens > request.ContextWindowTokens || request.CompactionThresholdTokens > 0 && (request.ContextWindowTokens == 0 || request.CompactionThresholdTokens <= request.MaxOutputTokens || request.CompactionThresholdTokens > request.ContextWindowTokens*9/10) || request.DataClassification == "" {
		return ErrInvalidRequest
	}
	if ValidateSamplingSettings(SamplingSettings{Temperature: request.Temperature, TopP: request.TopP, TopK: request.TopK}) != nil {
		return ErrInvalidRequest
	}
	if len(request.ResponseSchema) > MaximumResponseSchemaBytes || len(request.ResponseSchema) != 0 && !json.Valid(request.ResponseSchema) {
		return ErrInvalidRequest
	}
	for _, message := range request.Messages {
		if message.Validate() != nil {
			return ErrInvalidRequest
		}
	}
	seenTools := make(map[string]struct{}, len(request.Tools))
	for _, tool := range request.Tools {
		if tool.Validate() != nil {
			return ErrInvalidRequest
		}
		if _, found := seenTools[tool.Name]; found {
			return ErrInvalidRequest
		}
		seenTools[tool.Name] = struct{}{}
	}
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) > MaximumNormalizedRequestBytes {
		return ErrInvalidRequest
	}
	if containsCredentialLike(string(encoded)) {
		return ErrCredentialDetected
	}
	return nil
}

func contextWindowExceeded(request NormalizedRequest, capabilities ModelCapabilities, estimate TokenEstimate) bool {
	if estimate.InputTokens < 0 || capabilities.MaxInputTokens > 0 && estimate.InputTokens > int64(capabilities.MaxInputTokens) {
		return true
	}
	window := capabilities.ContextWindowTokens
	if request.ContextWindowTokens > 0 {
		if window <= 0 || request.ContextWindowTokens < window {
			window = request.ContextWindowTokens
		}
	}
	return window > 0 && estimate.InputTokens+int64(request.MaxOutputTokens) > int64(window)
}

type normalizedResponseOutput struct {
	Content   json.RawMessage `json:"content,omitempty"`
	ToolCalls []ToolCall      `json:"toolCalls,omitempty"`
}

func validateNormalizedResponseOutput(response NormalizedResponse) error {
	hasContent := len(response.Content) != 0
	hasToolCalls := len(response.ToolCalls) != 0
	if hasContent == hasToolCalls {
		return ErrOutputSchema
	}
	outputBytes := len(response.Content)
	for _, call := range response.ToolCalls {
		callBytes := len(call.ID) + len(call.Name) + len(call.Arguments)
		if callBytes > MaximumResponseBytes-outputBytes {
			return ErrOutputTooLarge
		}
		outputBytes += callBytes
	}
	if outputBytes > MaximumResponseBytes {
		return ErrOutputTooLarge
	}
	if hasContent {
		if !utf8.Valid(response.Content) || !json.Valid(response.Content) {
			return ErrOutputSchema
		}
		if containsCredentialLike(string(response.Content)) {
			return ErrCredentialDetected
		}
	} else {
		if validateToolCallList(response.ToolCalls) != nil {
			return ErrOutputSchema
		}
		for _, call := range response.ToolCalls {
			if containsCredentialLike(call.ID) || containsCredentialLike(call.Name) || containsCredentialLike(string(call.Arguments)) {
				return ErrCredentialDetected
			}
		}
	}
	if hasContent {
		return nil
	}
	encoded, err := json.Marshal(normalizedResponseOutput{Content: response.Content, ToolCalls: response.ToolCalls})
	if err != nil {
		return ErrOutputSchema
	}
	if len(encoded) > MaximumResponseBytes {
		return ErrOutputTooLarge
	}
	return nil
}

func validateGeneratedResponse(request NormalizedRequest, response NormalizedResponse) error {
	if err := validateNormalizedResponseOutput(response); err != nil {
		return err
	}
	if len(response.ToolCalls) != 0 {
		allowed := make(map[string]struct{}, len(request.Tools))
		for _, tool := range request.Tools {
			allowed[tool.Name] = struct{}{}
		}
		for _, call := range response.ToolCalls {
			if _, found := allowed[call.Name]; !found {
				return ErrOutputSchema
			}
		}
		return nil
	}
	if err := validateResponse(request.ResponseSchema, response.Content); err != nil {
		return err
	}
	return validateResponseSemantics(request.ResponseSemanticValidator, response.Content)
}

func responseOutputDigest(response NormalizedResponse) string {
	if len(response.ToolCalls) == 0 {
		return digestBytes(response.Content)
	}
	type digestToolCall struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}
	calls := make([]digestToolCall, 0, len(response.ToolCalls))
	for _, call := range response.ToolCalls {
		calls = append(calls, digestToolCall{ID: call.ID, Name: call.Name, Arguments: string(call.Arguments)})
	}
	encoded, _ := json.Marshal(struct {
		Content   string           `json:"content"`
		ToolCalls []digestToolCall `json:"toolCalls"`
	}{Content: string(response.Content), ToolCalls: calls})
	digest, err := canonicaljson.Digest(encoded)
	if err != nil {
		return digestBytes(encoded)
	}
	return digest
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

func accumulateCacheTokens(total **int64, known *bool, value *int64) error {
	if total == nil || known == nil {
		return ErrInvalidRequest
	}
	if !*known {
		return nil
	}
	if value == nil {
		*known = false
		*total = nil
		return nil
	}
	current := int64(0)
	if *total != nil {
		current = **total
	}
	next, err := addCost(current, *value)
	if err != nil {
		return err
	}
	*total = &next
	return nil
}

func cloneOptionalInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func usageCost(usage Usage, pricing Pricing) (int64, error) {
	if usage.InputTokens < 0 || usage.OutputTokens < 0 || usage.CostMicros < 0 ||
		usage.CacheReadTokens != nil && *usage.CacheReadTokens < 0 ||
		usage.CacheWriteTokens != nil && *usage.CacheWriteTokens < 0 {
		return 0, ErrInvalidRequest
	}
	if usage.InputTokens != 0 || usage.OutputTokens != 0 {
		input, err := multiplyCost(usage.InputTokens, pricing.InputMicrosPerToken)
		if err != nil {
			return 0, err
		}
		output, err := multiplyCost(usage.OutputTokens, pricing.OutputMicrosPerToken)
		if err != nil {
			return 0, err
		}
		return addCost(input, output)
	}
	return usage.CostMicros, nil
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
	adapter, pricing := g.adapters[key], g.pricing[key]
	if adapter == nil {
		wildcardKey := provider + "\x00*"
		adapter, pricing = g.adapters[wildcardKey], g.pricing[wildcardKey]
	}
	allowed := g.allowed[provider]
	dynamic := g.dynamicProvider
	dynamicPricing := g.dynamicProviderPricing
	permitted := allowed[model] || allowed["*"]
	g.mu.RUnlock()
	if adapter != nil || dynamic == nil {
		return adapter, pricing, permitted
	}
	created, err := dynamic(provider)
	if err != nil || created == nil || dynamicPricing.InputMicrosPerToken < 0 || dynamicPricing.OutputMicrosPerToken < 0 {
		return nil, Pricing{}, false
	}
	wildcardKey := provider + "\x00*"
	g.mu.Lock()
	adapter = g.adapters[wildcardKey]
	if adapter == nil {
		adapter = created
		g.adapters[wildcardKey] = adapter
		g.pricing[wildcardKey] = dynamicPricing
		if g.allowed[provider] == nil {
			g.allowed[provider] = make(map[string]bool)
		}
		g.allowed[provider]["*"] = true
	}
	pricing = g.pricing[wildcardKey]
	g.mu.Unlock()
	return adapter, pricing, true
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
