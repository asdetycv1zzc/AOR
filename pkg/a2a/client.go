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
	"strconv"
	"strings"
)

const ProtocolVersion = "1.0"

var (
	ErrIncompatibleCard     = errors.New("incompatible A2A agent card")
	ErrUnsupportedExtension = errors.New("unsupported required A2A extension")
	ErrUnsupportedOperation = errors.New("unsupported A2A operation")
	ErrInvalidMessage       = errors.New("invalid A2A message")
)

type AgentCard struct {
	Name                 string                    `json:"name"`
	Description          string                    `json:"description"`
	Provider             *AgentProvider            `json:"provider,omitempty"`
	Version              string                    `json:"version"`
	DocumentationURL     string                    `json:"documentationUrl,omitempty"`
	SupportedInterfaces  []AgentInterface          `json:"supportedInterfaces"`
	Capabilities         Capabilities              `json:"capabilities"`
	SecuritySchemes      map[string]SecurityScheme `json:"securitySchemes,omitempty"`
	SecurityRequirements []SecurityRequirement     `json:"securityRequirements,omitempty"`
	Security             []map[string][]string     `json:"security,omitempty"`
	DefaultInputModes    []string                  `json:"defaultInputModes"`
	DefaultOutputModes   []string                  `json:"defaultOutputModes"`
	Skills               []Skill                   `json:"skills"`
	Signatures           []AgentCardSignature      `json:"signatures,omitempty"`
	IconURL              string                    `json:"iconUrl,omitempty"`
	// Signature and KID are retained for compatibility with the AOR profile
	// used by existing deployments. New cards should prefer Signatures.
	Signature string `json:"signature,omitempty"`
	KID       string `json:"kid,omitempty"`
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
	ExtendedAgentCard bool        `json:"extendedAgentCard,omitempty"`
	Extensions        []Extension `json:"extensions,omitempty"`
}

type Extension struct {
	URI         string         `json:"uri"`
	Description string         `json:"description,omitempty"`
	Required    bool           `json:"required"`
	Params      map[string]any `json:"params,omitempty"`
}

type Skill struct {
	ID                   string                `json:"id"`
	Name                 string                `json:"name"`
	Description          string                `json:"description,omitempty"`
	Tags                 []string              `json:"tags"`
	Examples             []string              `json:"examples,omitempty"`
	InputModes           []string              `json:"inputModes,omitempty"`
	OutputModes          []string              `json:"outputModes,omitempty"`
	SecurityRequirements []SecurityRequirement `json:"securityRequirements,omitempty"`
	Security             []map[string][]string `json:"-"`
}

type Negotiation struct {
	Extensions []string
}

func Negotiate(card AgentCard, negotiation Negotiation) error {
	_, _, err := SelectHTTPJSONInterface(card, negotiation)
	return err
}

type Message struct {
	MessageID        string         `json:"messageId"`
	ContextID        string         `json:"contextId,omitempty"`
	TaskID           string         `json:"taskId,omitempty"`
	Role             string         `json:"role"`
	Parts            []Part         `json:"parts"`
	Metadata         map[string]any `json:"metadata,omitempty"`
	Extensions       []string       `json:"extensions,omitempty"`
	ReferenceTaskIDs []string       `json:"referenceTaskIds,omitempty"`
}

type Part struct {
	Text      string         `json:"text,omitempty"`
	Raw       []byte         `json:"raw,omitempty"`
	URL       string         `json:"url,omitempty"`
	Data      any            `json:"data,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	Filename  string         `json:"filename,omitempty"`
	MediaType string         `json:"mediaType,omitempty"`
}

type SendMessageResponse struct {
	Task    json.RawMessage `json:"task,omitempty"`
	Message json.RawMessage `json:"message,omitempty"`
}

type Client struct {
	endpoint   *url.URL
	extensions []string
	tenant     string
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
	tenant := ""
	for _, candidate := range card.SupportedInterfaces {
		if candidate.URL == endpoint.String() && candidate.ProtocolBinding == "HTTP+JSON" && protocolVersionEqual(candidate.ProtocolVersion, ProtocolVersion) {
			tenant = candidate.Tenant
			break
		}
	}
	return &Client{endpoint: endpoint, extensions: extensions, tenant: tenant, httpClient: httpClient}, nil
}

func SelectHTTPJSONInterface(card AgentCard, negotiation Negotiation) (*url.URL, []string, error) {
	if card.Name == "" || card.Description == "" || card.Version == "" || len(card.SupportedInterfaces) == 0 || len(card.DefaultInputModes) == 0 || len(card.DefaultOutputModes) == 0 || len(card.Skills) == 0 {
		return nil, nil, ErrIncompatibleCard
	}
	requested := uniqueSorted(negotiation.Extensions)
	for _, extension := range card.Capabilities.Extensions {
		if extension.URI == "" {
			return nil, nil, ErrIncompatibleCard
		}
		if extension.Required && !contains(requested, extension.URI) {
			return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedExtension, extension.URI)
		}
	}
	for _, candidate := range card.SupportedInterfaces {
		if candidate.ProtocolBinding != "HTTP+JSON" || !protocolVersionEqual(candidate.ProtocolVersion, ProtocolVersion) {
			continue
		}
		endpoint, err := url.Parse(candidate.URL)
		if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return nil, nil, ErrIncompatibleCard
		}
		return endpoint, requested, nil
	}
	return nil, nil, ErrUnsupportedOperation
}

func protocolVersionEqual(left, right string) bool {
	leftParts, leftOK := protocolMajorMinor(left)
	rightParts, rightOK := protocolMajorMinor(right)
	return leftOK && rightOK && leftParts == rightParts
}

func protocolMajorMinor(value string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) < 2 || len(parts) > 3 {
		return "", false
	}
	for _, part := range parts {
		if part == "" {
			return "", false
		}
		if _, err := strconv.Atoi(part); err != nil {
			return "", false
		}
	}
	return parts[0] + "." + parts[1], true
}

func (c *Client) SendMessage(ctx context.Context, request SendMessageRequest) (SendMessageResponse, error) {
	if c == nil || c.endpoint == nil || c.httpClient == nil || !validMessage(request.Message) {
		return SendMessageResponse{}, ErrInvalidMessage
	}
	if c.tenant != "" {
		if request.Tenant != "" && request.Tenant != c.tenant {
			return SendMessageResponse{}, ErrInvalidMessage
		}
		request.Tenant = c.tenant
		if request.Configuration != nil && request.Configuration.TaskPushNotificationConfig != nil {
			config := request.Configuration.TaskPushNotificationConfig
			if config.Tenant != "" && config.Tenant != c.tenant {
				return SendMessageResponse{}, ErrInvalidMessage
			}
			config.Tenant = c.tenant
		}
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
	httpRequest.Header.Set("Accept", "application/a2a+json")
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
		return SendMessageResponse{}, decodeProtocolError(response)
	}
	var decoded SendMessageResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return SendMessageResponse{}, err
	}
	if (len(decoded.Task) == 0) == (len(decoded.Message) == 0) {
		return SendMessageResponse{}, ErrInvalidMessage
	}
	if len(decoded.Task) != 0 {
		var task Task
		if json.Unmarshal(decoded.Task, &task) != nil || task.Validate() != nil {
			return SendMessageResponse{}, ErrInvalidMessage
		}
	} else {
		var message Message
		if json.Unmarshal(decoded.Message, &message) != nil || ValidateMessage(message) != nil {
			return SendMessageResponse{}, ErrInvalidMessage
		}
	}
	return decoded, nil
}

func validMessage(message Message) bool {
	return ValidateMessage(message) == nil
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
