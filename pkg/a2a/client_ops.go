package a2a

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type ProtocolError struct {
	StatusCode int
	Status     string
	Message    string
	Reason     string
}

func (err *ProtocolError) Error() string {
	if err == nil {
		return "A2A protocol error"
	}
	if err.Reason != "" {
		return fmt.Sprintf("A2A %s: %s", err.Reason, err.Message)
	}
	return fmt.Sprintf("A2A HTTP %d: %s", err.StatusCode, err.Message)
}

func (err *ProtocolError) Is(target error) bool {
	if err == nil {
		return false
	}
	switch err.Reason {
	case "TASK_NOT_FOUND":
		return target == ErrTaskNotFound
	case "TASK_NOT_CANCELABLE":
		return target == ErrTaskNotCancelable || target == ErrTaskTerminal
	case "PUSH_NOTIFICATION_NOT_SUPPORTED":
		return target == ErrPushNotSupported
	case "UNSUPPORTED_OPERATION":
		return target == ErrUnsupportedOperation || target == ErrStreamingNotSupported
	case "EXTENSION_SUPPORT_REQUIRED":
		return target == ErrExtensionSupportRequired
	case "VERSION_NOT_SUPPORTED":
		return target == ErrVersionNotSupported
	case "IDEMPOTENCY_CONFLICT":
		return target == ErrIdempotencyConflict
	default:
		return false
	}
}

type taskEnvelope struct {
	Task    *Task    `json:"task,omitempty"`
	Message *Message `json:"message,omitempty"`
}

type EventStream struct {
	response *http.Response
	scanner  *bufio.Scanner
	closed   bool
}

func (stream *EventStream) Next(ctx context.Context) (StreamResponse, error) {
	if stream == nil || stream.response == nil || stream.closed {
		return StreamResponse{}, io.EOF
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for stream.scanner.Scan() {
		line := stream.scanner.Text()
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		select {
		case <-ctx.Done():
			return StreamResponse{}, ctx.Err()
		default:
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			if payload == "[DONE]" {
				_ = stream.Close()
				return StreamResponse{}, io.EOF
			}
			continue
		}
		var event StreamResponse
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			return StreamResponse{}, err
		}
		if err := event.Validate(); err != nil {
			return StreamResponse{}, err
		}
		return event, nil
	}
	if err := stream.scanner.Err(); err != nil {
		return StreamResponse{}, err
	}
	_ = stream.Close()
	return StreamResponse{}, io.EOF
}

func (stream *EventStream) Close() error {
	if stream == nil || stream.response == nil || stream.closed {
		return nil
	}
	stream.closed = true
	return stream.response.Body.Close()
}

func (client *Client) GetTask(ctx context.Context, id string, historyLength *int) (Task, error) {
	if client == nil || client.endpoint == nil || id == "" || strings.Contains(id, "/") {
		return Task{}, ErrInvalidMessage
	}
	if err := validateHistoryLength(historyLength); err != nil {
		return Task{}, err
	}
	query := url.Values{}
	if historyLength != nil {
		query.Set("historyLength", strconv.Itoa(*historyLength))
	}
	if client.tenant != "" {
		query.Set("tenant", client.tenant)
	}
	var task Task
	if err := client.doJSON(ctx, http.MethodGet, "/tasks/"+url.PathEscape(id), query, nil, &task, "application/a2a+json"); err != nil {
		return Task{}, err
	}
	return task, nil
}

func (client *Client) CancelTask(ctx context.Context, id string) (Task, error) {
	if client == nil || client.endpoint == nil || id == "" || strings.Contains(id, "/") {
		return Task{}, ErrInvalidMessage
	}
	var task Task
	var input any
	if client.tenant != "" {
		input = TaskOperationRequest{Tenant: client.tenant}
	}
	if err := client.doJSON(ctx, http.MethodPost, "/tasks/"+url.PathEscape(id)+":cancel", nil, input, &task, "application/a2a+json"); err != nil {
		return Task{}, err
	}
	return task, nil
}

func (client *Client) SendStreamingMessage(ctx context.Context, request SendMessageRequest) (*EventStream, error) {
	return client.openStream(ctx, "/message:stream", request)
}

func (client *Client) SubscribeToTask(ctx context.Context, id string) (*EventStream, error) {
	if client == nil || client.endpoint == nil || id == "" || strings.Contains(id, "/") {
		return nil, ErrInvalidMessage
	}
	path := "/tasks/" + url.PathEscape(id) + ":subscribe"
	if client.tenant != "" {
		path += "?tenant=" + url.QueryEscape(client.tenant)
	}
	return client.openStream(ctx, path, nil)
}

func (client *Client) openStream(ctx context.Context, path string, body any) (*EventStream, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return nil, ErrInvalidMessage
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, ErrInvalidMessage
		}
		reader = bytes.NewReader(encoded)
	}
	target := client.target(path)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/a2a+json")
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("A2A-Version", ProtocolVersion)
	if len(client.extensions) > 0 {
		request.Header.Set("A2A-Extensions", strings.Join(client.extensions, ","))
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		defer response.Body.Close()
		return nil, decodeProtocolError(response)
	}
	if media := strings.ToLower(response.Header.Get("Content-Type")); !strings.HasPrefix(media, "text/event-stream") {
		defer response.Body.Close()
		return nil, errors.New("A2A streaming response has an invalid content type")
	}
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 4096), 8<<20)
	return &EventStream{response: response, scanner: scanner}, nil
}

func (client *Client) CreatePushNotificationConfig(ctx context.Context, taskID string, config TaskPushNotificationConfig) (TaskPushNotificationConfig, error) {
	if client == nil || client.endpoint == nil || taskID == "" || strings.Contains(taskID, "/") {
		return TaskPushNotificationConfig{}, ErrInvalidMessage
	}
	var result TaskPushNotificationConfig
	if err := client.doJSON(ctx, http.MethodPost, "/tasks/"+url.PathEscape(taskID)+"/pushNotificationConfigs", nil, PushNotificationConfigRequest{Tenant: client.tenant, Config: config}, &result, "application/a2a+json"); err != nil {
		return TaskPushNotificationConfig{}, err
	}
	return result, nil
}

func (client *Client) GetPushNotificationConfig(ctx context.Context, taskID, configID string) (TaskPushNotificationConfig, error) {
	if client == nil || client.endpoint == nil || taskID == "" || configID == "" || strings.Contains(taskID, "/") || strings.Contains(configID, "/") {
		return TaskPushNotificationConfig{}, ErrInvalidMessage
	}
	var result TaskPushNotificationConfig
	path := "/tasks/" + url.PathEscape(taskID) + "/pushNotificationConfigs/" + url.PathEscape(configID)
	query := url.Values{}
	if client.tenant != "" {
		query.Set("tenant", client.tenant)
	}
	if err := client.doJSON(ctx, http.MethodGet, path, query, nil, &result, "application/a2a+json"); err != nil {
		return TaskPushNotificationConfig{}, err
	}
	return result, nil
}

func (client *Client) ListPushNotificationConfigs(ctx context.Context, taskID string) (PushNotificationConfigList, error) {
	if client == nil || client.endpoint == nil || taskID == "" || strings.Contains(taskID, "/") {
		return PushNotificationConfigList{}, ErrInvalidMessage
	}
	var result PushNotificationConfigList
	query := url.Values{}
	if client.tenant != "" {
		query.Set("tenant", client.tenant)
	}
	if err := client.doJSON(ctx, http.MethodGet, "/tasks/"+url.PathEscape(taskID)+"/pushNotificationConfigs", query, nil, &result, "application/a2a+json"); err != nil {
		return PushNotificationConfigList{}, err
	}
	return result, nil
}

func (client *Client) DeletePushNotificationConfig(ctx context.Context, taskID, configID string) error {
	if client == nil || client.endpoint == nil || taskID == "" || configID == "" || strings.Contains(taskID, "/") || strings.Contains(configID, "/") {
		return ErrInvalidMessage
	}
	query := url.Values{}
	if client.tenant != "" {
		query.Set("tenant", client.tenant)
	}
	return client.doJSON(ctx, http.MethodDelete, "/tasks/"+url.PathEscape(taskID)+"/pushNotificationConfigs/"+url.PathEscape(configID), query, nil, nil, "")
}

func (client *Client) doJSON(ctx context.Context, method, path string, query url.Values, input, output any, accept string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var reader io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return ErrInvalidMessage
		}
		reader = bytes.NewReader(encoded)
	}
	target := client.target(path)
	if query != nil {
		target.RawQuery = query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return err
	}
	if input != nil {
		request.Header.Set("Content-Type", "application/a2a+json")
	}
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	request.Header.Set("A2A-Version", ProtocolVersion)
	if len(client.extensions) > 0 {
		request.Header.Set("A2A-Extensions", strings.Join(client.extensions, ","))
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return decodeProtocolError(response)
	}
	if output == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<20)).Decode(output); err != nil {
		return err
	}
	return nil
}

func (client *Client) target(path string) *url.URL {
	target := *client.endpoint
	relative, err := url.Parse(path)
	if err != nil {
		relative = &url.URL{Path: path}
	}
	target.Path = strings.TrimRight(target.Path, "/") + relative.Path
	target.RawQuery = relative.RawQuery
	return &target
}

func DiscoverAgentCard(ctx context.Context, endpoint string, httpClient *http.Client) (AgentCard, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return AgentCard{}, ErrIncompatibleCard
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	parsed.Path = "/.well-known/agent-card.json"
	parsed.RawPath = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return AgentCard{}, err
	}
	request.Header.Set("Accept", "application/a2a+json")
	request.Header.Set("A2A-Version", ProtocolVersion)
	response, err := httpClient.Do(request)
	if err != nil {
		return AgentCard{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return AgentCard{}, decodeProtocolError(response)
	}
	var card AgentCard
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&card); err != nil {
		return AgentCard{}, err
	}
	if err := ValidateAgentCard(card); err != nil {
		return AgentCard{}, err
	}
	return card, nil
}

func decodeProtocolError(response *http.Response) error {
	if response == nil {
		return ErrInvalidMessage
	}
	var payload struct {
		Error struct {
			Status  string `json:"status"`
			Message string `json:"message"`
			Details []struct {
				Reason string `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload)
	reason := ""
	if len(payload.Error.Details) > 0 {
		reason = payload.Error.Details[0].Reason
	}
	message := payload.Error.Message
	if message == "" {
		message = http.StatusText(response.StatusCode)
	}
	return &ProtocolError{StatusCode: response.StatusCode, Status: payload.Error.Status, Message: message, Reason: reason}
}
