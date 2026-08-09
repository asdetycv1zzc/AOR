// Package modelproviders owns the user-managed model provider catalog.
//
// Provider credentials are deliberately absent from the catalog.  They are
// supplied through ProviderSettings and are only available to the adapter
// factory after being decrypted by Store.
package modelproviders

import (
	"net"
	"net/url"
	"strings"

	"github.com/akimisaka/aor/internal/modelgateway"
)

const (
	ProviderOpenAI   = "openai"
	ProviderDeepSeek = "deepseek"
	ProviderClaude   = "claude"
	ProviderGrok     = "grok"
)

// ProviderCatalog is the non-secret, fixed catalog shown by the control UI.
// Deployments can enable a subset of Models for a provider, but cannot create
// an arbitrary provider family through this package.
type ProviderCatalog struct {
	ID          string
	DisplayName string
	Protocol    Protocol
	Protocols   []Protocol
	Models      []CatalogModel
}

type Protocol string

const (
	ProtocolOpenAICompatible Protocol = "openai-compatible"
	ProtocolAnthropic        Protocol = "anthropic-messages"
)

type CatalogModel struct {
	ID          string
	MaxInput    int
	MaxOutput   int
	ToolCalls   bool
	JSONSchema  bool
	Streaming   bool
	PromptCache bool
}

// Catalog returns a defensive copy of the supported provider/model catalog.
// The aliases cover the model names used by the classroom deployment while
// keeping the provider credentials and endpoints out of source and Compose.
func Catalog() []ProviderCatalog {
	return cloneCatalog([]ProviderCatalog{
		{
			ID: ProviderOpenAI, DisplayName: "OpenAI", Protocol: ProtocolOpenAICompatible, Protocols: []Protocol{ProtocolOpenAICompatible},
			Models: openAIModels(),
		},
		{
			ID: ProviderDeepSeek, DisplayName: "DeepSeek", Protocol: ProtocolOpenAICompatible, Protocols: []Protocol{ProtocolOpenAICompatible},
			Models: []CatalogModel{
				{ID: "deepseek-v4-pro", MaxInput: 32768, MaxOutput: 8192, ToolCalls: true, JSONSchema: true, Streaming: true},
				{ID: "deepseek-v4-flash", MaxInput: 32768, MaxOutput: 8192, ToolCalls: true, JSONSchema: true, Streaming: true},
			},
		},
		{
			ID: ProviderClaude, DisplayName: "Claude", Protocol: ProtocolAnthropic, Protocols: []Protocol{ProtocolAnthropic, ProtocolOpenAICompatible},
			Models: []CatalogModel{
				{ID: "claude-sonnet-4-5", MaxInput: 200000, MaxOutput: 8192, ToolCalls: true, JSONSchema: true},
				{ID: "claude-sonnet-4-6", MaxInput: 200000, MaxOutput: 8192, ToolCalls: true, JSONSchema: true},
				{ID: "claude-sonnet-4-7", MaxInput: 200000, MaxOutput: 8192, ToolCalls: true, JSONSchema: true},
				{ID: "claude-sonnet-4-8", MaxInput: 200000, MaxOutput: 8192, ToolCalls: true, JSONSchema: true},
				{ID: "claude-sonnet-5", MaxInput: 200000, MaxOutput: 8192, ToolCalls: true, JSONSchema: true},
				{ID: "claude-opus-4-1", MaxInput: 200000, MaxOutput: 8192, ToolCalls: true, JSONSchema: true},
				{ID: "claude-opus-4-5", MaxInput: 200000, MaxOutput: 8192, ToolCalls: true, JSONSchema: true},
				{ID: "claude-opus-4-6", MaxInput: 200000, MaxOutput: 8192, ToolCalls: true, JSONSchema: true},
				{ID: "claude-opus-4-7", MaxInput: 200000, MaxOutput: 8192, ToolCalls: true, JSONSchema: true},
				{ID: "claude-opus-4-8", MaxInput: 200000, MaxOutput: 8192, ToolCalls: true, JSONSchema: true},
				{ID: "claude-opus-5", MaxInput: 200000, MaxOutput: 8192, ToolCalls: true, JSONSchema: true},
				{ID: "claude-fable-5", MaxInput: 200000, MaxOutput: 8192, ToolCalls: true, JSONSchema: true},
				{ID: "claude-haiku-4-5", MaxInput: 200000, MaxOutput: 8192, ToolCalls: true, JSONSchema: true},
			},
		},
		{
			ID: ProviderGrok, DisplayName: "Grok", Protocol: ProtocolOpenAICompatible, Protocols: []Protocol{ProtocolOpenAICompatible},
			Models: []CatalogModel{
				{ID: "grok-4.5", MaxInput: 131072, MaxOutput: 8192, ToolCalls: true, JSONSchema: true, Streaming: true},
			},
		},
	})
}

func openAIModels() []CatalogModel {
	models := []string{
		"gpt-5.4", "gpt-5.4-mini",
		"gpt-5.5",
		"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna",
	}
	result := make([]CatalogModel, 0, len(models))
	for _, id := range models {
		result = append(result, CatalogModel{ID: id, MaxInput: 128000, MaxOutput: 8192, ToolCalls: true, JSONSchema: true, Streaming: true})
	}
	return result
}

func cloneCatalog(value []ProviderCatalog) []ProviderCatalog {
	result := make([]ProviderCatalog, len(value))
	for index, provider := range value {
		result[index] = provider
		result[index].Protocols = append([]Protocol(nil), provider.Protocols...)
		result[index].Models = append([]CatalogModel(nil), provider.Models...)
	}
	return result
}

func validProtocol(provider ProviderCatalog, protocol Protocol) bool {
	for _, candidate := range provider.Protocols {
		if candidate == protocol {
			return true
		}
	}
	return false
}

func findCatalog(provider string) (ProviderCatalog, bool) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	for _, item := range Catalog() {
		if item.ID == provider {
			return item, true
		}
	}
	return ProviderCatalog{}, false
}

func findModel(provider, model string) (CatalogModel, bool) {
	item, found := findCatalog(provider)
	if !found {
		return CatalogModel{}, false
	}
	for _, candidate := range item.Models {
		if candidate.ID == model {
			return candidate, true
		}
	}
	return CatalogModel{}, false
}

func modelCapabilities(model CatalogModel) modelgateway.ModelCapabilities {
	return modelgateway.ModelCapabilities{
		SupportsStreaming:     model.Streaming,
		SupportsToolCalls:     model.ToolCalls,
		SupportsJSONSchema:    model.JSONSchema,
		SupportsPromptCaching: model.PromptCache,
		MaxInputTokens:        model.MaxInput,
		MaxOutputTokens:       model.MaxOutput,
		DataResidency:         []string{"provider-defined"},
		RetentionPolicy:       "provider-defined",
		Modalities:            []string{"text"},
		ActualModelVersion:    "NON_REPRODUCIBLE_PROVIDER",
	}
}

func validateURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Scheme != "https" && parsed.Scheme != "http" {
		return ErrInvalidSettings
	}
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return ErrInvalidSettings
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
