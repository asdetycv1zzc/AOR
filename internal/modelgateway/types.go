package modelgateway

import (
	"context"
	"encoding/json"
	"fmt"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Schema      json.RawMessage `json:"schema,omitempty"`
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
	MaxOutputTokens     int              `json:"maxOutputTokens"`
	Temperature         float64          `json:"temperature"`
	Seed                *int64           `json:"seed,omitempty"`
	ProviderPolicy      string           `json:"providerPolicy"`
	DataClassification  string           `json:"dataClassification"`
	CachePolicy         string           `json:"cachePolicy"`
	PromptDigest        string           `json:"promptDigest"`
	ToolSchemaDigest    string           `json:"toolSchemaDigest"`
	PolicyDigest        string           `json:"policyDigest"`
	WorstCaseCostMicros int64            `json:"worstCaseCostMicros"`
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
	Content           json.RawMessage `json:"content"`
	FinishReason      string          `json:"finishReason"`
	Usage             Usage           `json:"usage"`
}

type ResponseStream interface {
	Recv(ctx context.Context) (json.RawMessage, error)
	Close() error
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
