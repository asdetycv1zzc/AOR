package modelgateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	MaximumMessages             = 1024
	MaximumMessageContentBytes  = 4 << 20
	MaximumTools                = 128
	MaximumToolCalls            = 64
	MaximumToolCallIDBytes      = 512
	MaximumToolNameBytes        = 128
	MaximumToolDescriptionBytes = 16 << 10
	MaximumToolSchemaBytes      = 256 << 10
	MaximumToolArgumentsBytes   = 1 << 20
	MaximumToolResultBytes      = 1 << 20
)

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"toolCalls,omitempty"`
	ToolCallID string     `json:"toolCallId,omitempty"`
}

// ToolCall is the provider-independent form of one native function call.
// Arguments remain JSON rather than an encoded JSON string at this boundary.
type ToolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (call ToolCall) Validate() error {
	if !validToolProtocolString(call.ID, MaximumToolCallIDBytes) || !validToolProtocolString(call.Name, MaximumToolNameBytes) || len(call.Arguments) == 0 || len(call.Arguments) > MaximumToolArgumentsBytes || !utf8.Valid(call.Arguments) || !json.Valid(call.Arguments) {
		return ErrInvalidRequest
	}
	var arguments map[string]json.RawMessage
	if json.Unmarshal(call.Arguments, &arguments) != nil || arguments == nil {
		return ErrInvalidRequest
	}
	return nil
}

func (message Message) Validate() error {
	if len(message.Role) > 32 || !utf8.ValidString(message.Role) || len(message.Content) > MaximumMessageContentBytes || !utf8.ValidString(message.Content) {
		return ErrInvalidRequest
	}
	switch message.Role {
	case "system", "user":
		if strings.TrimSpace(message.Content) == "" || len(message.ToolCalls) != 0 || message.ToolCallID != "" {
			return ErrInvalidRequest
		}
	case "assistant":
		if message.ToolCallID != "" || (strings.TrimSpace(message.Content) == "") == (len(message.ToolCalls) == 0) {
			return ErrInvalidRequest
		}
		if err := validateToolCallList(message.ToolCalls); err != nil {
			return err
		}
	case "tool":
		if !validToolProtocolString(message.ToolCallID, MaximumToolCallIDBytes) || len(message.ToolCalls) != 0 || strings.TrimSpace(message.Content) == "" || len(message.Content) > MaximumToolResultBytes {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Schema      json.RawMessage `json:"schema,omitempty"`
}

func (definition ToolDefinition) Validate() error {
	if !validToolProtocolString(definition.Name, MaximumToolNameBytes) || len(definition.Description) > MaximumToolDescriptionBytes || !utf8.ValidString(definition.Description) || len(definition.Schema) > MaximumToolSchemaBytes || len(definition.Schema) != 0 && (!utf8.Valid(definition.Schema) || !json.Valid(definition.Schema)) {
		return ErrInvalidRequest
	}
	if len(definition.Schema) != 0 {
		var schema map[string]json.RawMessage
		if json.Unmarshal(definition.Schema, &schema) != nil || schema == nil {
			return ErrInvalidRequest
		}
	}
	return nil
}

func validateToolCallList(calls []ToolCall) error {
	if len(calls) > MaximumToolCalls {
		return ErrInvalidRequest
	}
	seen := make(map[string]struct{}, len(calls))
	for _, call := range calls {
		if call.Validate() != nil {
			return ErrInvalidRequest
		}
		if _, found := seen[call.ID]; found {
			return ErrInvalidRequest
		}
		seen[call.ID] = struct{}{}
	}
	return nil
}

func validToolProtocolString(value string, maximum int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsAny(value, "\r\n\x00")
}

type ModelCapabilities struct {
	SupportsStreaming     bool     `json:"supportsStreaming"`
	SupportsToolCalls     bool     `json:"supportsToolCalls"`
	SupportsJSONSchema    bool     `json:"supportsJsonSchema"`
	SupportsSeed          bool     `json:"supportsSeed"`
	SupportsPromptCaching bool     `json:"supportsPromptCaching"`
	MaxInputTokens        int      `json:"maxInputTokens"`
	MaxOutputTokens       int      `json:"maxOutputTokens"`
	DataResidency         []string `json:"dataResidency"`
	RetentionPolicy       string   `json:"retentionPolicy"`
	Modalities            []string `json:"modalities"`
	ActualModelVersion    string   `json:"actualModelVersion"`
}

type NormalizedRequest struct {
	RequestID           string           `json:"requestId"`
	TenantID            string           `json:"tenantId"`
	ProjectID           string           `json:"projectId"`
	TaskID              string           `json:"taskId"`
	AgentInstanceID     string           `json:"agentInstanceId"`
	Role                string           `json:"role"`
	Model               string           `json:"model"`
	PromptBundleVersion string           `json:"promptBundleVersion"`
	Messages            []Message        `json:"messages"`
	Tools               []ToolDefinition `json:"tools,omitempty"`
	ResponseSchemaRef   string           `json:"responseSchemaRef,omitempty"`
	ResponseSchema      json.RawMessage  `json:"responseSchema,omitempty"`
	// ResponseSemanticValidator is process-local policy code and is excluded
	// from request digests. It runs only after the complete stream is assembled.
	ResponseSemanticValidator func(json.RawMessage) error `json:"-"`
	MaxOutputTokens           int                         `json:"maxOutputTokens"`
	Temperature               float64                     `json:"temperature"`
	Seed                      *int64                      `json:"seed,omitempty"`
	ProviderPolicy            string                      `json:"providerPolicy"`
	DataClassification        string                      `json:"dataClassification"`
	CachePolicy               string                      `json:"cachePolicy"`
	PromptDigest              string                      `json:"promptDigest"`
	ToolSchemaDigest          string                      `json:"toolSchemaDigest"`
	PolicyDigest              string                      `json:"policyDigest"`
	WorstCaseCostMicros       int64                       `json:"worstCaseCostMicros"`
}

type Usage struct {
	InputTokens       int64  `json:"inputTokens"`
	OutputTokens      int64  `json:"outputTokens"`
	CostMicros        int64  `json:"costMicros"`
	ProviderRequestID string `json:"providerRequestId"`
	ModelVersion      string `json:"modelVersion"`
}

type NormalizedResponse struct {
	RequestID         string          `json:"requestId"`
	ProviderRequestID string          `json:"providerRequestId"`
	ModelVersion      string          `json:"modelVersion"`
	Content           json.RawMessage `json:"content,omitempty"`
	ToolCalls         []ToolCall      `json:"toolCalls,omitempty"`
	FinishReason      string          `json:"finishReason"`
	Usage             Usage           `json:"usage"`
}

type ResponseStream interface {
	Recv(ctx context.Context) (json.RawMessage, error)
	Close() error
}

// UsageAwareStream is implemented by adapters that can report authoritative
// provider usage after a stream reaches its terminal event. A stream that
// cannot provide this information must remain in RECONCILE state; callers must
// never infer that an interrupted stream was free.
type UsageAwareStream interface {
	ResponseStream
	FinalUsage() (Usage, bool)
}

// FinalContentAwareStream exposes the provider's normalized response after a
// stream has reached its terminal event. The gateway uses this value for
// validation and never forwards individual provider envelopes to callers.
type FinalContentAwareStream interface {
	ResponseStream
	FinalContent() (json.RawMessage, bool)
}

// ProviderCandidate describes one explicitly approved route in a provider
// policy. Model is optional and defaults to the logical model in the request.
// CapabilityRank is an organization-defined quality floor; larger values are
// stronger and a lower-ranked route is a downgrade.
type ProviderCandidate struct {
	Provider                   string   `json:"provider"`
	Model                      string   `json:"model,omitempty"`
	CapabilityRank             int      `json:"capabilityRank"`
	AllowedDataClassifications []string `json:"allowedDataClassifications,omitempty"`
	AllowedDataResidencies     []string `json:"allowedDataResidencies,omitempty"`
	RetentionPolicy            string   `json:"retentionPolicy,omitempty"`
}

type ProviderPolicy struct {
	Candidates            []ProviderCandidate `json:"candidates"`
	AllowDowngrade        bool                `json:"allowDowngrade"`
	MinimumCapabilityRank int                 `json:"minimumCapabilityRank"`
}

// ProviderEligibility is called for every candidate, including a fallback.
// Implementations should re-evaluate tenant policy, data classification and
// residency instead of assuming that the primary provider's authorization
// applies to a fallback.
type ProviderEligibilityInput struct {
	Operation     string
	Request       NormalizedRequest
	Candidate     ProviderCandidate
	Capabilities  ModelCapabilities
	AccountID     string
	ReservationID string
}

type ProviderEligibility func(context.Context, ProviderEligibilityInput) error

type ModelReplay struct {
	InputSHA256 string
	Response    NormalizedResponse
}

// ModelReplayStore is an optional durable response store. Implementations must
// make Load and Store idempotent by (tenantID, requestID), and must reject a
// different input digest for an existing request ID.
type ModelReplayStore interface {
	LoadModelReplay(context.Context, string, string) (ModelReplay, bool, error)
	StoreModelReplay(context.Context, string, string, ModelReplay) error
}

type EnabledModelReplayStore interface {
	ModelReplayStore
	ReplayEnabled() bool
}

// ModelCallLookup lets the gateway fail closed after a process restart when a
// request was durably finalized but its response payload was not retained.
type ModelCallLookup interface {
	LookupModelCall(context.Context, string, string) (ModelCall, bool, error)
}

type ModelAdapter interface {
	Capabilities(ctx context.Context, model string) (ModelCapabilities, error)
	CountTokens(ctx context.Context, req NormalizedRequest) (TokenEstimate, error)
	Generate(ctx context.Context, req NormalizedRequest) (NormalizedResponse, error)
	Stream(ctx context.Context, req NormalizedRequest) (ResponseStream, error)
	Cancel(ctx context.Context, providerRequestID string) error
	NormalizeUsage(raw any) (Usage, error)
}

type TokenEstimate struct {
	InputTokens int64 `json:"inputTokens"`
}

type AdapterFactory struct {
	Provider string
	Adapter  ModelAdapter
}

// ProviderFailure classifies whether a failed adapter call reached the
// provider and whether a later probe may recover. Unknown outcomes must retain
// their budget reservation for reconciliation.
type ProviderFailure struct {
	Cause        error
	Retryable    bool
	OutcomeKnown bool
}

func (failure *ProviderFailure) Error() string {
	if failure == nil || failure.Cause == nil {
		return ErrProviderUnavailable.Error()
	}
	return fmt.Sprintf("provider failure: %v", failure.Cause)
}

func (failure *ProviderFailure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}
