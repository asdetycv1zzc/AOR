package a2a

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TaskState is the A2A task lifecycle state. The values intentionally use the
// protocol's canonical names so the HTTP binding is interoperable with other
// A2A 1.0 implementations.
type TaskState string

const (
	TaskStateUnspecified   TaskState = "TASK_STATE_UNSPECIFIED"
	TaskStateSubmitted     TaskState = "TASK_STATE_SUBMITTED"
	TaskStateWorking       TaskState = "TASK_STATE_WORKING"
	TaskStateCompleted     TaskState = "TASK_STATE_COMPLETED"
	TaskStateFailed        TaskState = "TASK_STATE_FAILED"
	TaskStateCanceled      TaskState = "TASK_STATE_CANCELED"
	TaskStateInputRequired TaskState = "TASK_STATE_INPUT_REQUIRED"
	TaskStateRejected      TaskState = "TASK_STATE_REJECTED"
	TaskStateAuthRequired  TaskState = "TASK_STATE_AUTH_REQUIRED"
)

func (state TaskState) Terminal() bool {
	switch state {
	case TaskStateCompleted, TaskStateFailed, TaskStateCanceled, TaskStateRejected:
		return true
	default:
		return false
	}
}

func (state TaskState) Interrupted() bool {
	return state == TaskStateInputRequired || state == TaskStateAuthRequired
}

func (state TaskState) Valid() bool {
	switch state {
	case TaskStateUnspecified, TaskStateSubmitted, TaskStateWorking, TaskStateCompleted,
		TaskStateFailed, TaskStateCanceled, TaskStateInputRequired, TaskStateRejected,
		TaskStateAuthRequired:
		return true
	default:
		return false
	}
}

type TaskStatus struct {
	State     TaskState `json:"state"`
	Message   *Message  `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

type Task struct {
	ID           string         `json:"id"`
	ContextID    string         `json:"contextId,omitempty"`
	Status       TaskStatus     `json:"status"`
	Artifacts    []Artifact     `json:"artifacts,omitempty"`
	History      []Message      `json:"history,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	CreatedAt    time.Time      `json:"createdAt,omitempty"`
	LastModified time.Time      `json:"lastModified,omitempty"`
}

type Artifact struct {
	ArtifactID  string         `json:"artifactId"`
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
	Parts       []Part         `json:"parts"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	Extensions  []string       `json:"extensions,omitempty"`
}

type TaskStatusUpdateEvent struct {
	TaskID    string         `json:"taskId"`
	ContextID string         `json:"contextId"`
	Status    TaskStatus     `json:"status"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type TaskArtifactUpdateEvent struct {
	TaskID    string         `json:"taskId"`
	ContextID string         `json:"contextId"`
	Artifact  Artifact       `json:"artifact"`
	Append    bool           `json:"append,omitempty"`
	LastChunk bool           `json:"lastChunk,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// StreamResponse is a discriminated union. Exactly one member is permitted by
// the A2A HTTP+JSON binding.
type StreamResponse struct {
	Task           *Task                    `json:"task,omitempty"`
	Message        *Message                 `json:"message,omitempty"`
	StatusUpdate   *TaskStatusUpdateEvent   `json:"statusUpdate,omitempty"`
	ArtifactUpdate *TaskArtifactUpdateEvent `json:"artifactUpdate,omitempty"`
}

func (response StreamResponse) Validate() error {
	count := 0
	if response.Task != nil {
		count++
	}
	if response.Message != nil {
		count++
	}
	if response.StatusUpdate != nil {
		count++
	}
	if response.ArtifactUpdate != nil {
		count++
	}
	if count != 1 {
		return errors.New("A2A stream response must contain exactly one payload")
	}
	switch {
	case response.Task != nil:
		return response.Task.Validate()
	case response.Message != nil:
		return ValidateMessage(*response.Message)
	case response.StatusUpdate != nil:
		update := response.StatusUpdate
		if update.TaskID == "" || update.ContextID == "" || !update.Status.State.Valid() || update.Status.State == TaskStateUnspecified {
			return errors.New("status update is invalid")
		}
		if update.Status.Message != nil {
			return ValidateMessage(*update.Status.Message)
		}
	case response.ArtifactUpdate != nil:
		update := response.ArtifactUpdate
		if update.TaskID == "" || update.ContextID == "" {
			return errors.New("artifact update is invalid")
		}
		return update.Artifact.Validate()
	}
	return nil
}

type SendMessageConfiguration struct {
	AcceptedOutputModes        []string                    `json:"acceptedOutputModes,omitempty"`
	HistoryLength              *int                        `json:"historyLength,omitempty"`
	ReturnImmediately          bool                        `json:"returnImmediately,omitempty"`
	TaskPushNotificationConfig *TaskPushNotificationConfig `json:"taskPushNotificationConfig,omitempty"`
}

type SendMessageRequest struct {
	Message       Message                   `json:"message"`
	Configuration *SendMessageConfiguration `json:"configuration,omitempty"`
	Metadata      map[string]any            `json:"metadata,omitempty"`
	Tenant        string                    `json:"tenant,omitempty"`
}

type TaskQuery struct {
	ID            string
	HistoryLength *int
	Tenant        string
}

type ListTasksOptions struct {
	Tenant               string
	ContextID            string
	Status               TaskState
	PageSize             int
	PageToken            string
	HistoryLength        *int
	IncludeArtifacts     bool
	StatusTimestampAfter *time.Time
}

type ListTasksResponse struct {
	Tasks         []Task `json:"tasks"`
	NextPageToken string `json:"nextPageToken"`
	PageSize      int    `json:"pageSize"`
	TotalSize     int    `json:"totalSize"`
}

type TaskPushNotificationConfig struct {
	Tenant         string              `json:"tenant,omitempty"`
	ID             string              `json:"id,omitempty"`
	TaskID         string              `json:"taskId,omitempty"`
	URL            string              `json:"url"`
	Token          string              `json:"token,omitempty"`
	Authentication *AuthenticationInfo `json:"authentication,omitempty"`
}

type AuthenticationInfo struct {
	Scheme      string `json:"scheme"`
	Credentials string `json:"credentials,omitempty"`
}

type PushNotificationConfigRequest struct {
	Tenant string                     `json:"tenant,omitempty"`
	Config TaskPushNotificationConfig `json:"config"`
}

type TaskOperationRequest struct {
	Tenant string `json:"tenant,omitempty"`
}

type PushNotificationConfigList struct {
	Configs       []TaskPushNotificationConfig `json:"configs"`
	NextPageToken string                       `json:"nextPageToken"`
}

type PushNotificationListOptions struct {
	Tenant    string
	PageSize  int
	PageToken string
}

type AgentProvider struct {
	URL          string `json:"url"`
	Organization string `json:"organization"`
}

type AgentCardSignature struct {
	Protected string         `json:"protected"`
	Signature string         `json:"signature"`
	Header    map[string]any `json:"header,omitempty"`
}

type SecurityScheme struct {
	APIKeySecurityScheme        map[string]any `json:"apiKeySecurityScheme,omitempty"`
	HTTPAuthSecurityScheme      map[string]any `json:"httpAuthSecurityScheme,omitempty"`
	OAuth2SecurityScheme        map[string]any `json:"oauth2SecurityScheme,omitempty"`
	OpenIDConnectSecurityScheme map[string]any `json:"openIdConnectSecurityScheme,omitempty"`
	MTLSSecurityScheme          map[string]any `json:"mtlsSecurityScheme,omitempty"`
}

type StringList struct {
	List []string `json:"list"`
}

type SecurityRequirement struct {
	Schemes map[string]StringList `json:"schemes"`
}

func (requirement SecurityRequirement) Validate() error {
	if len(requirement.Schemes) == 0 {
		return errors.New("security requirement must name at least one scheme")
	}
	for name := range requirement.Schemes {
		if strings.TrimSpace(name) == "" {
			return errors.New("security requirement scheme is invalid")
		}
	}
	return nil
}

func (scheme SecurityScheme) Validate() error {
	count := 0
	if scheme.APIKeySecurityScheme != nil {
		count++
	}
	if scheme.HTTPAuthSecurityScheme != nil {
		count++
	}
	if scheme.OAuth2SecurityScheme != nil {
		count++
	}
	if scheme.OpenIDConnectSecurityScheme != nil {
		count++
	}
	if scheme.MTLSSecurityScheme != nil {
		count++
	}
	if count != 1 {
		return errors.New("security scheme must contain exactly one scheme")
	}
	return nil
}

// ValidateMessage enforces the A2A one-of rules for a Message and its parts.
func ValidateMessage(message Message) error {
	if strings.TrimSpace(message.MessageID) == "" || (message.Role != "ROLE_USER" && message.Role != "ROLE_AGENT") || len(message.Parts) == 0 {
		return errors.New("messageId, role, and at least one part are required")
	}
	for _, part := range message.Parts {
		if err := part.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (part Part) Validate() error {
	count := 0
	if part.Text != "" {
		count++
	}
	if len(part.Raw) > 0 {
		count++
	}
	if part.URL != "" {
		count++
	}
	if part.Data != nil {
		count++
	}
	if count != 1 {
		return errors.New("part must contain exactly one of text, raw, url, or data")
	}
	if part.URL != "" {
		parsed, err := url.Parse(part.URL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
			return errors.New("part url must be an absolute URL")
		}
	}
	return nil
}

func (artifact Artifact) Validate() error {
	if strings.TrimSpace(artifact.ArtifactID) == "" || len(artifact.Parts) == 0 {
		return errors.New("artifactId and at least one part are required")
	}
	for _, part := range artifact.Parts {
		if err := part.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (task Task) Validate() error {
	if strings.TrimSpace(task.ID) == "" || !task.Status.State.Valid() || task.Status.State == TaskStateUnspecified {
		return errors.New("task id and valid status are required")
	}
	if task.Status.Message != nil {
		if err := ValidateMessage(*task.Status.Message); err != nil {
			return err
		}
	}
	for _, artifact := range task.Artifacts {
		if err := artifact.Validate(); err != nil {
			return err
		}
	}
	for _, message := range task.History {
		if err := ValidateMessage(message); err != nil {
			return err
		}
	}
	return nil
}

func (config TaskPushNotificationConfig) Validate() error {
	if strings.TrimSpace(config.URL) == "" || strings.ContainsAny(config.URL, "\r\n\x00") {
		return errors.New("push notification url is required")
	}
	parsed, err := url.Parse(config.URL)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("push notification url must be an absolute HTTP(S) URL")
	}
	if config.Authentication != nil {
		if strings.TrimSpace(config.Authentication.Scheme) == "" || strings.ContainsAny(config.Authentication.Scheme+config.Authentication.Credentials, "\r\n\x00") {
			return errors.New("push notification authentication is invalid")
		}
	}
	return nil
}

func cloneTask(task Task) Task {
	encoded, err := json.Marshal(task)
	if err != nil {
		return task
	}
	var copy Task
	if json.Unmarshal(encoded, &copy) != nil {
		return task
	}
	return copy
}

func cloneMessage(message Message) Message {
	encoded, err := json.Marshal(message)
	if err != nil {
		return message
	}
	var copy Message
	if json.Unmarshal(encoded, &copy) != nil {
		return message
	}
	return copy
}

func validateHistoryLength(value *int) error {
	if value != nil && (*value < 0 || *value > 1<<20) {
		return fmt.Errorf("historyLength is out of range")
	}
	return nil
}
