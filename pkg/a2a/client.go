// Package a2a contains the A2A 1.0 HTTP+JSON interoperability boundary used
// by AOR. Authentication remains the responsibility of the caller's HTTP
// transport; this package only negotiates declared protocol capabilities.
package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/akimisaka/aor/pkg/aop"
)

const ProtocolVersion = "1.0"

var (
	ErrIncompatibleCard     = errors.New("incompatible A2A agent card")
	ErrUnsupportedExtension = errors.New("unsupported required A2A extension")
	ErrUnsupportedOperation = errors.New("unsupported A2A operation")
	ErrInvalidMessage       = errors.New("invalid A2A message")
)

type AgentCard struct {
	Name                string           `json:"name"`
	Description         string           `json:"description"`
	Version             string           `json:"version"`
	SupportedInterfaces []AgentInterface `json:"supportedInterfaces"`
	Capabilities        Capabilities     `json:"capabilities"`
	DefaultInputModes   []string         `json:"defaultInputModes"`
	DefaultOutputModes  []string         `json:"defaultOutputModes"`
	Skills              []Skill          `json:"skills"`
}

type AgentInterface struct {
	URL             string `json:"url"`
	ProtocolBinding string `json:"protocolBinding"`
	ProtocolVersion string `json:"protocolVersion"`
	Tenant          string `json:"tenant,omitempty"`
}

type Capabilities struct {
	Streaming         bool        `json:"streaming,omitempty"`
	PushNotifications bool        `json:"pushNotifications,omitempty"`
	Extensions        []Extension `json:"extensions,omitempty"`
}

type Extension struct {
	URI      string `json:"uri"`
	Required bool   `json:"required"`
}

type Skill struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type Negotiation struct {
	Extensions []string
}

type Message struct {
	MessageID  string         `json:"messageId"`
	ContextID  string         `json:"contextId,omitempty"`
	TaskID     string         `json:"taskId,omitempty"`
	Role       string         `json:"role"`
	Parts      []Part         `json:"parts"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	Extensions []string       `json:"extensions,omitempty"`
}

type Part struct {
	Text string `json:"text,omitempty"`
}

type SendMessageRequest struct {
	Message Message `json:"message"`
}

type SendMessageResponse struct {
	Task    json.RawMessage `json:"task,omitempty"`
	Message json.RawMessage `json:"message,omitempty"`
}

type Client struct {
	endpoint   *url.URL
	extensions []string
	httpClient *http.Client
}

func NewHTTPJSONClient(card AgentCard, negotiation Negotiation, httpClient *http.Client) (*Client, error) {
	endpoint, extensions, err := SelectHTTPJSONInterface(card, negotiation)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{endpoint: endpoint, extensions: extensions, httpClient: httpClient}, nil
}

func SelectHTTPJSONInterface(card AgentCard, negotiation Negotiation) (*url.URL, []string, error) {
	if card.Name == "" || card.Description == "" || card.Version == "" || len(card.SupportedInterfaces) == 0 || len(card.DefaultInputModes) == 0 || len(card.DefaultOutputModes) == 0 || len(card.Skills) == 0 {
		return nil, nil, ErrIncompatibleCard
	}
	requested := uniqueSorted(negotiation.Extensions)
	known := map[string]bool{aop.ExtensionURI: true}
	for _, extension := range card.Capabilities.Extensions {
		if extension.URI == "" {
			return nil, nil, ErrIncompatibleCard
		}
		if extension.Required && (!known[extension.URI] || !contains(requested, extension.URI)) {
			return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedExtension, extension.URI)
		}
	}
	for _, candidate := range card.SupportedInterfaces {
		if candidate.ProtocolBinding != "HTTP+JSON" || candidate.ProtocolVersion != ProtocolVersion {
			continue
		}
		endpoint, err := url.Parse(candidate.URL)
		if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil {
			return nil, nil, ErrIncompatibleCard
		}
		return endpoint, requested, nil
	}
	return nil, nil, ErrUnsupportedOperation
}

func (c *Client) SendMessage(ctx context.Context, request SendMessageRequest) (SendMessageResponse, error) {
	if c == nil || c.endpoint == nil || c.httpClient == nil || !validMessage(request.Message) {
		return SendMessageResponse{}, ErrInvalidMessage
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return SendMessageResponse{}, ErrInvalidMessage
	}
	target := *c.endpoint
	target.Path = strings.TrimRight(target.Path, "/") + "/message:send"
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(payload))
	if err != nil {
		return SendMessageResponse{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/a2a+json")
	httpRequest.Header.Set("A2A-Version", ProtocolVersion)
	if len(c.extensions) > 0 {
		httpRequest.Header.Set("A2A-Extensions", strings.Join(c.extensions, ","))
	}
	response, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return SendMessageResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return SendMessageResponse{}, fmt.Errorf("A2A SendMessage: unexpected HTTP status %d", response.StatusCode)
	}
	var decoded SendMessageResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return SendMessageResponse{}, err
	}
	if len(decoded.Task) == 0 && len(decoded.Message) == 0 {
		return SendMessageResponse{}, ErrInvalidMessage
	}
	return decoded, nil
}

func validMessage(message Message) bool {
	if message.MessageID == "" || (message.Role != "ROLE_USER" && message.Role != "ROLE_AGENT") || len(message.Parts) == 0 {
		return false
	}
	for _, part := range message.Parts {
		if part.Text == "" {
			return false
		}
	}
	return true
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
