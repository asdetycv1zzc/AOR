package mcp

// This file contains the transport-neutral JSON-RPC envelope used by the
// 2025-11-25 MCP server and host.  It intentionally keeps extension fields
// opaque: MCP clients are allowed to add optional fields while the methods
// implemented by AOR validate the fields they consume.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"
)

const MaxMessageBytes = 1 << 20

const (
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603
)

var (
	ErrInvalidMessage  = errors.New("invalid JSON-RPC message")
	ErrMessageTooLarge = errors.New("JSON-RPC message too large")
)

// Message is one JSON-RPC request, notification, response, or error response.
// HasID distinguishes a request with id 0/"" from a notification.
type Message struct {
	JSONRPC string
	ID      json.RawMessage
	HasID   bool
	Method  string
	Params  json.RawMessage
	Result  json.RawMessage
	Error   *Error
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type Implementation struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	WebsiteURL  string `json:"websiteUrl,omitempty"`
}

type InitializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      Implementation `json:"clientInfo"`
}

type InitializeResponse struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ServerInfo      Implementation `json:"serverInfo"`
	Instructions    string         `json:"instructions,omitempty"`
}

type Tool struct {
	Name         string         `json:"name"`
	Title        string         `json:"title,omitempty"`
	Description  string         `json:"description,omitempty"`
	InputSchema  map[string]any `json:"inputSchema"`
	OutputSchema map[string]any `json:"outputSchema,omitempty"`
	Annotations  map[string]any `json:"annotations,omitempty"`
	Execution    map[string]any `json:"execution,omitempty"`
}

type ToolListParams struct {
	Cursor string `json:"cursor,omitempty"`
}

type ToolListResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
	Meta      map[string]any `json:"_meta,omitempty"`
}

type Content struct {
	Type     string         `json:"type"`
	Text     string         `json:"text,omitempty"`
	Data     string         `json:"data,omitempty"`
	MIMEType string         `json:"mimeType,omitempty"`
	URI      string         `json:"uri,omitempty"`
	Name     string         `json:"name,omitempty"`
	Resource map[string]any `json:"resource,omitempty"`
}

type ToolCallResult struct {
	Content           []Content      `json:"content"`
	IsError           bool           `json:"isError,omitempty"`
	StructuredContent map[string]any `json:"structuredContent,omitempty"`
}

var toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

func (message Message) IsRequest() bool      { return message.Method != "" && message.HasID }
func (message Message) IsNotification() bool { return message.Method != "" && !message.HasID }
func (message Message) IsResponse() bool {
	return message.Method == "" && message.HasID && (len(message.Result) > 0 || message.Error != nil)
}

func Request(id json.RawMessage, method string, params any) ([]byte, error) {
	if !validID(id) || !validMethod(method) {
		return nil, ErrInvalidMessage
	}
	value := map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "method": method}
	if params != nil {
		encoded, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		value["params"] = json.RawMessage(encoded)
	}
	return json.Marshal(value)
}

func Response(id json.RawMessage, result any) ([]byte, error) {
	if !validID(id) {
		return nil, ErrInvalidMessage
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "result": json.RawMessage(encoded)})
}

func ErrorResponse(id json.RawMessage, code int, message string, data map[string]any) ([]byte, error) {
	if len(id) > 0 && !validID(id) {
		return nil, ErrInvalidMessage
	}
	if message == "" || len(message) > 512 || strings.ContainsAny(message, "\r\n\x00") {
		return nil, ErrInvalidMessage
	}
	return json.Marshal(map[string]any{"jsonrpc": "2.0", "id": nullableID(id), "error": Error{Code: code, Message: message, Data: data}})
}

func Notification(method string, params any) ([]byte, error) {
	if !validMethod(method) {
		return nil, ErrInvalidMessage
	}
	value := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		encoded, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		value["params"] = json.RawMessage(encoded)
	}
	return json.Marshal(value)
}

func Decode(data []byte) (Message, error) {
	if len(data) == 0 || len(data) > MaxMessageBytes {
		if len(data) > MaxMessageBytes {
			return Message{}, ErrMessageTooLarge
		}
		return Message{}, ErrInvalidMessage
	}
	if !json.Valid(data) || duplicateMembers(data) {
		return Message{}, ErrInvalidMessage
	}
	var raw map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&raw); err != nil {
		return Message{}, ErrInvalidMessage
	}
	if err := ensureEOF(decoder); err != nil || string(raw["jsonrpc"]) != `"2.0"` {
		return Message{}, ErrInvalidMessage
	}
	message := Message{JSONRPC: "2.0"}
	if value, ok := raw["id"]; ok {
		if !validID(value) {
			return Message{}, ErrInvalidMessage
		}
		message.ID = append(json.RawMessage(nil), value...)
		message.HasID = true
	}
	if value, ok := raw["method"]; ok {
		if err := json.Unmarshal(value, &message.Method); err != nil || !validMethod(message.Method) {
			return Message{}, ErrInvalidMessage
		}
	}
	if value, ok := raw["params"]; ok {
		if !json.Valid(value) || string(value) == "null" {
			return Message{}, ErrInvalidMessage
		}
		message.Params = append(json.RawMessage(nil), value...)
	}
	if value, ok := raw["result"]; ok {
		if !message.HasID || message.Method != "" || !json.Valid(value) {
			return Message{}, ErrInvalidMessage
		}
		message.Result = append(json.RawMessage(nil), value...)
	}
	if value, ok := raw["error"]; ok {
		if !message.HasID || message.Method != "" {
			return Message{}, ErrInvalidMessage
		}
		var errorFields map[string]json.RawMessage
		if json.Unmarshal(value, &errorFields) != nil || len(errorFields["code"]) == 0 || len(errorFields["message"]) == 0 {
			return Message{}, ErrInvalidMessage
		}
		var rpcError Error
		if json.Unmarshal(value, &rpcError) != nil || rpcError.Message == "" || len(rpcError.Message) > 512 || strings.ContainsAny(rpcError.Message, "\r\n\x00") {
			return Message{}, ErrInvalidMessage
		}
		message.Error = &rpcError
	}
	if len(message.Result) > 0 && message.Error != nil {
		return Message{}, ErrInvalidMessage
	}
	if message.Method == "" && !message.IsResponse() || message.Method != "" && (len(message.Result) > 0 || message.Error != nil) {
		return Message{}, ErrInvalidMessage
	}
	if message.Method == "" && !message.HasID {
		return Message{}, ErrInvalidMessage
	}
	return message, nil
}

func ParseParams[T any](message Message, target *T) error {
	if target == nil || len(message.Params) == 0 {
		return ErrInvalidMessage
	}
	decoder := json.NewDecoder(bytes.NewReader(message.Params))
	if err := decoder.Decode(target); err != nil || ensureEOF(decoder) != nil {
		return ErrInvalidMessage
	}
	return nil
}

func ValidateInitialize(params InitializeParams) error {
	if params.ProtocolVersion == "" || len(params.ProtocolVersion) > 64 || params.Capabilities == nil || params.ClientInfo.Name == "" || params.ClientInfo.Version == "" || len(params.ClientInfo.Name) > 128 || len(params.ClientInfo.Version) > 128 {
		return ErrInvalidMessage
	}
	if strings.ContainsAny(params.ProtocolVersion, "\r\n\x00") || strings.ContainsAny(params.ClientInfo.Name+params.ClientInfo.Version, "\r\n\x00") {
		return ErrInvalidMessage
	}
	return nil
}

func ValidateToolName(name string) bool { return toolNamePattern.MatchString(name) }

func SortTools(tools []Tool) {
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
}

func validMethod(method string) bool {
	return method != "" && len(method) <= 256 && !strings.ContainsAny(method, "\r\n\x00")
}

func validID(value json.RawMessage) bool {
	if len(value) == 0 || bytes.Equal(value, []byte("null")) || !json.Valid(value) {
		return false
	}
	var stringID string
	if json.Unmarshal(value, &stringID) == nil {
		return stringID != "" && len(stringID) <= 256 && !strings.ContainsAny(stringID, "\r\n\x00")
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	if decoder.Decode(&number) != nil || ensureEOF(decoder) != nil {
		return false
	}
	floatValue, err := number.Float64()
	return err == nil && !math.IsNaN(floatValue) && !math.IsInf(floatValue, 0)
}

func nullableID(value json.RawMessage) any {
	if len(value) == 0 {
		return nil
	}
	return json.RawMessage(value)
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidMessage
	}
	return nil
}

// duplicateMembers rejects duplicate object keys at every nesting level. Go's
// standard decoder otherwise keeps the last value, which is unsafe for signed
// envelopes and authorization metadata.
func duplicateMembers(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() bool
	walk = func() bool {
		token, err := decoder.Token()
		if err != nil {
			return true
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				seen := map[string]struct{}{}
				for decoder.More() {
					key, keyErr := decoder.Token()
					if keyErr != nil {
						return true
					}
					name, ok := key.(string)
					if !ok {
						return true
					}
					if _, exists := seen[name]; exists {
						return true
					}
					seen[name] = struct{}{}
					if walk() {
						return true
					}
				}
				_, err = decoder.Token()
				return err != nil
			case '[':
				for decoder.More() {
					if walk() {
						return true
					}
				}
				_, err = decoder.Token()
				return err != nil
			}
		}
		return false
	}
	if walk() {
		return true
	}
	return decoder.More()
}
