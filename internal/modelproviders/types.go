package modelproviders

import (
	"context"
	"net/http"
	"time"

	"github.com/akimisaka/aor/internal/modelgateway"
)

// ProviderSettings is safe to return to a control-plane client. APIKey is
// deliberately not a field on this type; callers can only observe whether a
// key is configured.
type ProviderSettings struct {
	ID                         string     `json:"id"`
	DisplayName                string     `json:"displayName"`
	Provider                   string     `json:"provider"`
	Custom                     bool       `json:"custom"`
	BaseURL                    string     `json:"baseUrl"`
	Protocol                   Protocol   `json:"protocol"`
	Protocols                  []Protocol `json:"protocols"`
	Enabled                    bool       `json:"enabled"`
	Models                     []string   `json:"models"`
	APIKeyConfigured           bool       `json:"apiKeyConfigured"`
	InputMicrosPerToken        int64      `json:"inputMicrosPerToken"`
	OutputMicrosPerToken       int64      `json:"outputMicrosPerToken"`
	SupportsStreaming          bool       `json:"supportsStreaming"`
	SupportsToolCalls          bool       `json:"supportsToolCalls"`
	SupportsJSONSchema         bool       `json:"supportsJsonSchema"`
	SupportsSeed               bool       `json:"supportsSeed"`
	SupportsPromptCaching      bool       `json:"supportsPromptCaching"`
	MaxInputTokens             int        `json:"maxInputTokens"`
	MaxOutputTokens            int        `json:"maxOutputTokens"`
	AllowedDataClassifications []string   `json:"allowedDataClassifications"`
	DataResidency              []string   `json:"dataResidency"`
	RetentionPolicy            string     `json:"retentionPolicy"`
	Modalities                 []string   `json:"modalities"`
	Version                    int64      `json:"version"`
}

// PutRequest is accepted by the settings API. An empty APIKey on an existing
// row preserves its encrypted key; a new row must provide one.
type PutRequest struct {
	DisplayName string   `json:"displayName"`
	BaseURL     string   `json:"baseUrl"`
	APIKey      string   `json:"apiKey"`
	Protocol    Protocol `json:"protocol"`
	Models      []string `json:"models"`
	Enabled     bool     `json:"enabled"`
}

type ResolvedSettings struct {
	ProviderSettings
	APIKey string
}

type SettingsStore interface {
	List(context.Context, string) ([]ProviderSettings, error)
	Get(context.Context, string, string) (ProviderSettings, bool, error)
	Resolve(context.Context, string, string) (ResolvedSettings, bool, error)
	Put(context.Context, string, string, PutRequest) (ProviderSettings, error)
}

type AdapterFactory struct {
	HTTPClient     *http.Client
	RequestTimeout time.Duration
}

func (factory AdapterFactory) New(provider, baseURL, apiKey string, models []string) (modelgateway.ModelAdapter, error) {
	catalog, found := findCatalog(provider)
	if !found {
		return nil, ErrInvalidSettings
	}
	return newAdapter(factory, provider, catalog.Protocol, baseURL, apiKey, models)
}

func (factory AdapterFactory) NewWithProtocol(provider string, protocol Protocol, baseURL, apiKey string, models []string) (modelgateway.ModelAdapter, error) {
	return newAdapter(factory, provider, protocol, baseURL, apiKey, models)
}
