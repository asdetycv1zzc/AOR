package a2a

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

const (
	defaultA2ABodyLimit = int64(8 << 20)
	defaultPushTimeout  = 10 * time.Second
)

var (
	ErrTaskNotFound                   = errors.New("A2A task not found")
	ErrTaskNotCancelable              = errors.New("A2A task is not cancelable")
	ErrTaskTerminal                   = errors.New("A2A task is terminal")
	ErrVersionNotSupported            = errors.New("A2A version not supported")
	ErrStreamingNotSupported          = errors.New("A2A streaming is not supported")
	ErrPushNotSupported               = errors.New("A2A push notifications are not supported")
	ErrExtensionSupportRequired       = errors.New("A2A extension support is required")
	ErrExtendedAgentCardNotConfigured = errors.New("A2A extended agent card is not configured")
	ErrContentTypeNotSupported        = errors.New("A2A content type is not supported")
	ErrIdempotencyConflict            = errors.New("A2A message id conflicts with an earlier request")
	ErrInvalidRequest                 = errors.New("invalid A2A request")
	ErrCardInvalid                    = errors.New("invalid A2A agent card")
)

// TaskRequest is passed to the application processor for each accepted A2A
// message. The Task is a snapshot at the time processing begins.
type TaskRequest struct {
	Task          Task
	Message       Message
	Configuration SendMessageConfiguration
	Metadata      map[string]any
	Tenant        string
}

// TaskResult describes the application result. State defaults to COMPLETED;
// callers may return INPUT_REQUIRED or AUTH_REQUIRED to pause a task.
type TaskResult struct {
	State     TaskState
	Message   *Message
	Artifacts []Artifact
	Metadata  map[string]any
	Events    []StreamResponse
}

type TaskProcessor interface {
	Process(context.Context, TaskRequest) (TaskResult, error)
}

type TaskProcessorFunc func(context.Context, TaskRequest) (TaskResult, error)

func (function TaskProcessorFunc) Process(ctx context.Context, request TaskRequest) (TaskResult, error) {
	return function(ctx, request)
}

// EchoProcessor is a deterministic default processor useful for health checks
// and protocol conformance tests. Production deployments should provide their
// own processor backed by the orchestrator.
type EchoProcessor struct{}

func (EchoProcessor) Process(_ context.Context, request TaskRequest) (TaskResult, error) {
	return TaskResult{State: TaskStateCompleted, Artifacts: []Artifact{{
		ArtifactID: "artifact-" + request.Task.ID,
		Parts:      append([]Part(nil), request.Message.Parts...),
	}}}, nil
}

// ServerConfig controls the protocol boundary. Authentication and caller
// authorization remain HTTP middleware concerns and are deliberately not
// inferred from an A2A message.
type ServerConfig struct {
	Card              AgentCard
	Processor         TaskProcessor
	Store             TaskStore
	Clock             func() time.Time
	HTTPClient        *http.Client
	BasePath          string
	MaxBodyBytes      int64
	RequireSignedCard bool
	AllowHTTPPush     bool
	PushTimeout       time.Duration
	PushRetries       int
	CardSigner        AgentCardSigner
}

type AgentCardSigner interface {
	Sign([]byte) (string, error)
}

type AgentCardVerifier interface {
	Verify([]byte, string) error
}

type keyedCardSigner interface {
	AgentCardSigner
	KeyID() string
}

// Server implements the A2A 1.0 HTTP+JSON/REST binding.
type Server struct {
	card          AgentCard
	processor     TaskProcessor
	store         TaskStore
	clock         func() time.Time
	httpClient    *http.Client
	basePath      string
	maxBodyBytes  int64
	allowHTTPPush bool
	pushTimeout   time.Duration
	pushRetries   int
	tenant        string

	mu       sync.Mutex
	tasks    map[string]*taskRecord
	messages map[string]messageIdentity
}

type HTTPJSONServer = Server
type HTTPJSONServerConfig = ServerConfig

func NewHTTPJSONServer(config ServerConfig) (*Server, error) {
	return NewServer(config)
}

type messageIdentity struct {
	digest string
	taskID string
}

type taskRecord struct {
	task       Task
	controller context.CancelFunc
	done       chan struct{}
	closed     bool
	events     []StreamResponse
	watchers   map[int]chan StreamResponse
	nextWatch  int
	pushes     map[string]TaskPushNotificationConfig
	emitMu     sync.Mutex
}

func NewServer(config ServerConfig) (*Server, error) {
	if err := ValidateAgentCard(config.Card); err != nil {
		return nil, err
	}
	if config.CardSigner != nil && len(config.Card.Signatures) == 0 && config.Card.Signature == "" {
		card, err := SignAgentCard(config.Card, config.CardSigner)
		if err != nil {
			return nil, err
		}
		config.Card = card
	}
	if config.RequireSignedCard && len(config.Card.Signatures) == 0 && config.Card.Signature == "" {
		return nil, ErrCardInvalid
	}
	if config.Processor == nil {
		config.Processor = EchoProcessor{}
	}
	if config.Store == nil {
		config.Store = NewMemoryTaskStore()
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = defaultA2ABodyLimit
	}
	if config.MaxBodyBytes <= 0 || config.MaxBodyBytes > 64<<20 {
		return nil, ErrInvalidRequest
	}
	if config.PushTimeout == 0 {
		config.PushTimeout = defaultPushTimeout
	}
	if config.PushTimeout <= 0 || config.PushTimeout > 2*time.Minute || config.PushRetries < 0 || config.PushRetries > 5 {
		return nil, ErrInvalidRequest
	}
	basePath := strings.TrimRight(strings.TrimSpace(config.BasePath), "/")
	if basePath == "/" {
		basePath = ""
	}
	if basePath != "" && (!strings.HasPrefix(basePath, "/") || strings.ContainsAny(basePath, "?#\r\n\x00")) {
		return nil, ErrInvalidRequest
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: config.PushTimeout}
	}
	tenant := ""
	if len(config.Card.SupportedInterfaces) > 0 {
		tenant = config.Card.SupportedInterfaces[0].Tenant
	}
	server := &Server{
		card:          cloneCard(config.Card),
		processor:     config.Processor,
		store:         config.Store,
		clock:         config.Clock,
		httpClient:    config.HTTPClient,
		basePath:      basePath,
		maxBodyBytes:  config.MaxBodyBytes,
		allowHTTPPush: config.AllowHTTPPush,
		pushTimeout:   config.PushTimeout,
		pushRetries:   config.PushRetries,
		tenant:        tenant,
		tasks:         make(map[string]*taskRecord),
		messages:      make(map[string]messageIdentity),
	}
	if stored, err := config.Store.List(context.Background()); err != nil {
		return nil, err
	} else {
		for _, task := range stored {
			record := &taskRecord{task: cloneTask(task), done: make(chan struct{}), watchers: make(map[int]chan StreamResponse), pushes: make(map[string]TaskPushNotificationConfig)}
			record.events = []StreamResponse{{Task: ptrTask(task)}}
			if task.Status.State.Terminal() || task.Status.State.Interrupted() {
				record.closed = true
				close(record.done)
			}
			server.tasks[task.ID] = record
			for _, message := range task.History {
				if digest, digestErr := messageDigest(SendMessageRequest{Message: message}); digestErr == nil {
					server.messages[message.MessageID] = messageIdentity{digest: digest, taskID: task.ID}
				}
			}
		}
	}
	return server, nil
}

func (server *Server) Handler() http.Handler {
	if server == nil {
		return http.NotFoundHandler()
	}
	return http.HandlerFunc(server.ServeHTTP)
}

func (server *Server) AgentCard() AgentCard {
	if server == nil {
		return AgentCard{}
	}
	return cloneCard(server.card)
}

func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if server == nil || writer == nil || request == nil {
		return
	}
	path := server.relativePath(request.URL.Path)
	if server.tenant != "" {
		prefix := "/" + url.PathEscape(server.tenant)
		if strings.HasPrefix(path, prefix+"/") {
			path = strings.TrimPrefix(path, prefix)
			query := request.URL.Query()
			if value := query.Get("tenant"); value != "" && value != server.tenant {
				server.writeError(writer, http.StatusBadRequest, ErrInvalidRequest, "INVALID_ARGUMENT")
				return
			}
			query.Set("tenant", server.tenant)
			request.URL.RawQuery = query.Encode()
		}
	}
	if request.Method == http.MethodGet && (path == "/.well-known/agent-card.json" || path == "/agent-card.json") {
		server.writeJSON(writer, http.StatusOK, server.card)
		return
	}
	if !server.validVersion(request) {
		server.writeError(writer, http.StatusBadRequest, ErrVersionNotSupported, "VERSION_NOT_SUPPORTED")
		return
	}
	switch {
	case request.Method == http.MethodPost && path == "/message:send":
		server.serveSend(writer, request, false)
	case request.Method == http.MethodPost && path == "/message:stream":
		server.serveSend(writer, request, true)
	case request.Method == http.MethodGet && path == "/tasks":
		server.serveListTasks(writer, request)
	case strings.HasPrefix(path, "/tasks/") && strings.Contains(path, "/pushNotificationConfigs"):
		server.servePushConfig(writer, request, strings.TrimPrefix(path, "/tasks/"))
	case request.Method == http.MethodGet && strings.HasPrefix(path, "/tasks/"):
		server.serveGetTask(writer, request, strings.TrimPrefix(path, "/tasks/"))
	case request.Method == http.MethodPost && strings.HasSuffix(path, ":cancel") && strings.HasPrefix(path, "/tasks/"):
		server.serveCancel(writer, request, strings.TrimSuffix(strings.TrimPrefix(path, "/tasks/"), ":cancel"))
	case request.Method == http.MethodPost && strings.HasSuffix(path, ":subscribe") && strings.HasPrefix(path, "/tasks/"):
		server.serveSubscribe(writer, request, strings.TrimSuffix(strings.TrimPrefix(path, "/tasks/"), ":subscribe"))
	case request.Method == http.MethodGet && path == "/extendedAgentCard":
		if !server.card.Capabilities.ExtendedAgentCard {
			server.writeError(writer, http.StatusBadRequest, ErrExtendedAgentCardNotConfigured, "EXTENDED_AGENT_CARD_NOT_CONFIGURED")
			return
		}
		server.writeJSON(writer, http.StatusOK, server.card)
	default:
		server.writeError(writer, http.StatusNotFound, ErrUnsupportedOperation, "UNSUPPORTED_OPERATION")
	}
}

func (server *Server) relativePath(path string) string {
	if server.basePath != "" {
		if path == server.basePath {
			return "/"
		}
		if strings.HasPrefix(path, server.basePath+"/") {
			path = strings.TrimPrefix(path, server.basePath)
		}
	}
	if path == "" {
		return "/"
	}
	return path
}

func (server *Server) validVersion(request *http.Request) bool {
	version := request.Header.Get("A2A-Version")
	if version == "" {
		version = request.URL.Query().Get("A2A-Version")
	}
	return protocolVersionEqual(version, ProtocolVersion)
}

func (server *Server) supportsExtensions(request *http.Request) error {
	requested := parseExtensions(request.Header.Get("A2A-Extensions"))
	for _, extension := range server.card.Capabilities.Extensions {
		if extension.Required && !contains(requested, extension.URI) {
			return fmt.Errorf("%w: %s", ErrExtensionSupportRequired, extension.URI)
		}
	}
	return nil
}

func (server *Server) validateTenant(value string) error {
	if server.tenant != "" && value != server.tenant {
		return ErrInvalidRequest
	}
	return nil
}

func (server *Server) serveSend(writer http.ResponseWriter, request *http.Request, streaming bool) {
	if err := server.supportsExtensions(request); err != nil {
		server.writeError(writer, http.StatusBadRequest, err, "EXTENSION_SUPPORT_REQUIRED")
		return
	}
	if streaming && !server.card.Capabilities.Streaming {
		server.writeError(writer, http.StatusBadRequest, ErrStreamingNotSupported, "UNSUPPORTED_OPERATION")
		return
	}
	var input SendMessageRequest
	if err := server.decodeJSON(writer, request, &input); err != nil {
		status, reason := statusForError(err)
		server.writeError(writer, status, err, reason)
		return
	}
	if err := ValidateMessage(input.Message); err != nil {
		server.writeError(writer, http.StatusBadRequest, err, "INVALID_ARGUMENT")
		return
	}
	if err := server.validateTenant(input.Tenant); err != nil {
		server.writeError(writer, http.StatusBadRequest, err, "INVALID_ARGUMENT")
		return
	}
	if input.Configuration != nil && validateHistoryLength(input.Configuration.HistoryLength) != nil {
		server.writeError(writer, http.StatusBadRequest, ErrInvalidRequest, "INVALID_ARGUMENT")
		return
	}
	record, created, err := server.acceptMessage(request.Context(), input)
	if err != nil {
		status, reason := statusForError(err)
		server.writeError(writer, status, err, reason)
		return
	}
	if streaming {
		server.streamRecord(writer, request, record, created)
		return
	}
	if created {
		if !requestReturnImmediately(input) {
			select {
			case <-record.done:
			case <-request.Context().Done():
				return
			}
		}
	}
	task := server.snapshot(record, input.Configuration)
	server.writeJSON(writer, http.StatusOK, map[string]any{"task": task})
}

func requestReturnImmediately(input SendMessageRequest) bool {
	return input.Configuration != nil && input.Configuration.ReturnImmediately
}

func (server *Server) acceptMessage(ctx context.Context, input SendMessageRequest) (*taskRecord, bool, error) {
	digest, err := messageDigest(input)
	if err != nil {
		return nil, false, ErrInvalidRequest
	}
	server.mu.Lock()
	if previous, ok := server.messages[input.Message.MessageID]; ok {
		server.mu.Unlock()
		if previous.digest != digest {
			return nil, false, ErrIdempotencyConflict
		}
		server.mu.Lock()
		record := server.tasks[previous.taskID]
		server.mu.Unlock()
		if record == nil {
			return nil, false, ErrTaskNotFound
		}
		return record, false, nil
	}
	message := cloneMessage(input.Message)
	if message.TaskID != "" {
		record := server.tasks[message.TaskID]
		if record == nil {
			server.mu.Unlock()
			return nil, false, ErrTaskNotFound
		}
		if record.task.Status.State.Terminal() {
			server.mu.Unlock()
			return nil, false, ErrTaskTerminal
		}
		if !record.task.Status.State.Interrupted() || !record.closed {
			server.mu.Unlock()
			return nil, false, ErrInvalidRequest
		}
		if message.ContextID != "" && message.ContextID != record.task.ContextID {
			server.mu.Unlock()
			return nil, false, ErrInvalidRequest
		}
		message.ContextID = record.task.ContextID
		record.task.History = append(record.task.History, message)
		now := server.clock().UTC()
		record.task.Status = TaskStatus{State: TaskStateSubmitted, Timestamp: now}
		record.task.LastModified = now
		record.closed = false
		record.done = make(chan struct{})
		record.controller = nil
		record.events = nil
		server.messages[message.MessageID] = messageIdentity{digest: digest, taskID: message.TaskID}
		server.mu.Unlock()
		if err := server.store.Put(ctx, record.task); err != nil {
			return nil, false, err
		}
		server.appendEvent(record, StreamResponse{Task: ptrTask(record.task)})
		server.startProcessing(ctx, record, input)
		return record, true, nil
	}
	taskID := newA2AID("task")
	contextID := message.ContextID
	if contextID == "" {
		contextID = newA2AID("context")
	}
	message.ContextID = contextID
	now := server.clock().UTC()
	task := Task{ID: taskID, ContextID: contextID, Status: TaskStatus{State: TaskStateSubmitted, Timestamp: now}, History: []Message{message}, CreatedAt: now, LastModified: now}
	if input.Metadata != nil {
		task.Metadata = cloneMap(input.Metadata)
	}
	record := &taskRecord{task: task, done: make(chan struct{}), watchers: make(map[int]chan StreamResponse), pushes: make(map[string]TaskPushNotificationConfig)}
	server.tasks[taskID] = record
	server.messages[message.MessageID] = messageIdentity{digest: digest, taskID: taskID}
	server.mu.Unlock()
	if err := server.store.Put(ctx, task); err != nil {
		server.mu.Lock()
		delete(server.tasks, taskID)
		delete(server.messages, message.MessageID)
		server.mu.Unlock()
		return nil, false, err
	}
	server.appendEvent(record, StreamResponse{Task: ptrTask(task)})
	if input.Configuration != nil && input.Configuration.TaskPushNotificationConfig != nil {
		if !server.card.Capabilities.PushNotifications {
			return nil, false, ErrPushNotSupported
		}
		if err := server.addPushConfig(record, *input.Configuration.TaskPushNotificationConfig); err != nil {
			return nil, false, err
		}
	}
	server.startProcessing(ctx, record, input)
	return record, true, nil
}

func (server *Server) startProcessing(ctx context.Context, record *taskRecord, input SendMessageRequest) {
	server.mu.Lock()
	if record.controller != nil || record.closed {
		server.mu.Unlock()
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	processingContext, cancel := context.WithCancel(context.WithoutCancel(ctx))
	record.controller = cancel
	server.mu.Unlock()
	go server.process(processingContext, record, input)
}

func (server *Server) process(ctx context.Context, record *taskRecord, input SendMessageRequest) {
	server.updateState(record, TaskStateWorking, nil)
	taskSnapshot := server.snapshot(record, nil)
	message := cloneMessage(input.Message)
	if len(taskSnapshot.History) > 0 {
		message = cloneMessage(taskSnapshot.History[len(taskSnapshot.History)-1])
	}
	request := TaskRequest{Task: taskSnapshot, Message: message, Metadata: cloneMap(input.Metadata), Tenant: input.Tenant}
	if input.Configuration != nil {
		request.Configuration = *input.Configuration
	}
	result, err := server.processor.Process(ctx, request)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return
		}
		server.updateState(record, TaskStateFailed, nil)
		failed := server.snapshot(record, nil)
		server.appendEvent(record, StreamResponse{Task: &failed})
		server.finish(record)
		return
	}
	if result.State == "" {
		result.State = TaskStateCompleted
	}
	if !server.normalizeResult(record, &result) {
		server.updateState(record, TaskStateFailed, nil)
		failed := server.snapshot(record, nil)
		server.appendEvent(record, StreamResponse{Task: &failed})
		server.finish(record)
		return
	}
	for _, event := range result.Events {
		if event.Validate() == nil {
			server.appendEvent(record, event)
		}
	}
	server.mu.Lock()
	if record.closed || record.task.Status.State == TaskStateCanceled {
		server.mu.Unlock()
		return
	}
	record.task.Artifacts = cloneArtifacts(result.Artifacts)
	if result.Metadata != nil {
		record.task.Metadata = cloneMap(result.Metadata)
	}
	if result.Message != nil {
		message := cloneMessage(*result.Message)
		if message.ContextID == "" {
			message.ContextID = record.task.ContextID
		}
		if message.TaskID == "" {
			message.TaskID = record.task.ID
		}
		record.task.Status.Message = &message
	}
	record.task.Status.State = result.State
	record.task.Status.Timestamp = server.clock().UTC()
	record.task.LastModified = record.task.Status.Timestamp
	task := cloneTask(record.task)
	server.mu.Unlock()
	if err := server.store.Put(context.Background(), task); err != nil {
		server.updateState(record, TaskStateFailed, nil)
		server.finish(record)
		return
	}
	if result.Message != nil {
		message := cloneMessage(*result.Message)
		message.ContextID = task.ContextID
		message.TaskID = task.ID
		server.appendEvent(record, StreamResponse{Message: &message})
	}
	for _, artifact := range result.Artifacts {
		artifact := artifact
		server.appendEvent(record, StreamResponse{ArtifactUpdate: &TaskArtifactUpdateEvent{TaskID: task.ID, ContextID: task.ContextID, Artifact: artifact, LastChunk: true}})
	}
	server.appendEvent(record, StreamResponse{StatusUpdate: &TaskStatusUpdateEvent{TaskID: task.ID, ContextID: task.ContextID, Status: task.Status}})
	server.appendEvent(record, StreamResponse{Task: &task})
	if result.State.Terminal() || result.State.Interrupted() {
		server.finish(record)
	}
}

func (server *Server) normalizeResult(record *taskRecord, result *TaskResult) bool {
	if result == nil || !result.State.Valid() || result.State == TaskStateUnspecified || !result.State.Terminal() && !result.State.Interrupted() {
		return false
	}
	server.mu.Lock()
	taskID, contextID := record.task.ID, record.task.ContextID
	server.mu.Unlock()
	seenArtifacts := make(map[string]struct{}, len(result.Artifacts))
	for index := range result.Artifacts {
		artifact := &result.Artifacts[index]
		if artifact.Validate() != nil {
			return false
		}
		if _, exists := seenArtifacts[artifact.ArtifactID]; exists {
			return false
		}
		seenArtifacts[artifact.ArtifactID] = struct{}{}
	}
	if result.Message != nil {
		if result.Message.MessageID == "" {
			result.Message.MessageID = newA2AID("message")
		}
		result.Message.Role = "ROLE_AGENT"
		result.Message.TaskID = taskID
		result.Message.ContextID = contextID
		if ValidateMessage(*result.Message) != nil {
			return false
		}
	}
	for _, event := range result.Events {
		if event.Validate() != nil {
			return false
		}
	}
	return true
}

func (server *Server) updateState(record *taskRecord, state TaskState, message *Message) {
	server.mu.Lock()
	if record.closed || record.task.Status.State.Terminal() {
		server.mu.Unlock()
		return
	}
	record.task.Status = TaskStatus{State: state, Message: message, Timestamp: server.clock().UTC()}
	record.task.LastModified = record.task.Status.Timestamp
	task := cloneTask(record.task)
	server.mu.Unlock()
	_ = server.store.Put(context.Background(), task)
	server.appendEvent(record, StreamResponse{StatusUpdate: &TaskStatusUpdateEvent{TaskID: task.ID, ContextID: task.ContextID, Status: task.Status}})
}

func (server *Server) finish(record *taskRecord) {
	record.emitMu.Lock()
	defer record.emitMu.Unlock()
	server.mu.Lock()
	if record.closed {
		server.mu.Unlock()
		return
	}
	record.closed = true
	record.controller = nil
	close(record.done)
	watchers := make([]chan StreamResponse, 0, len(record.watchers))
	for id, watcher := range record.watchers {
		watchers = append(watchers, watcher)
		delete(record.watchers, id)
	}
	server.mu.Unlock()
	for _, watcher := range watchers {
		close(watcher)
	}
}

func (server *Server) snapshot(record *taskRecord, configuration *SendMessageConfiguration) Task {
	server.mu.Lock()
	task := cloneTask(record.task)
	server.mu.Unlock()
	if configuration != nil && configuration.HistoryLength != nil {
		if *configuration.HistoryLength == 0 {
			task.History = nil
		} else if len(task.History) > *configuration.HistoryLength {
			task.History = append([]Message(nil), task.History[len(task.History)-*configuration.HistoryLength:]...)
		}
	}
	return task
}

func (server *Server) streamRecord(writer http.ResponseWriter, request *http.Request, record *taskRecord, created bool) {
	if !created {
		// A replayed idempotent request still gets a complete stream from the
		// beginning of the task's event history.
	}
	replay, events, cancel := server.subscribe(record)
	defer cancel()
	flusher, ok := writer.(http.Flusher)
	if !ok {
		server.writeError(writer, http.StatusInternalServerError, ErrInvalidRequest, "INTERNAL")
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	writeEvent := func(event StreamResponse) bool {
		encoded, err := json.Marshal(event)
		if err != nil {
			return false
		}
		if _, err = writer.Write([]byte("data: ")); err != nil {
			return false
		}
		if _, err = writer.Write(encoded); err != nil {
			return false
		}
		if _, err = writer.Write([]byte("\n\n")); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	for _, event := range replay {
		if !writeEvent(event) {
			return
		}
	}
	for {
		select {
		case event, open := <-events:
			if !open {
				return
			}
			if !writeEvent(event) {
				return
			}
		case <-request.Context().Done():
			return
		}
	}
}

func (server *Server) subscribe(record *taskRecord) ([]StreamResponse, <-chan StreamResponse, func()) {
	server.mu.Lock()
	replay := append([]StreamResponse(nil), record.events...)
	id := record.nextWatch
	record.nextWatch++
	channel := make(chan StreamResponse, 128)
	if record.closed {
		close(channel)
	} else {
		record.watchers[id] = channel
	}
	server.mu.Unlock()
	return replay, channel, func() {
		record.emitMu.Lock()
		defer record.emitMu.Unlock()
		server.mu.Lock()
		if existing, ok := record.watchers[id]; ok {
			delete(record.watchers, id)
			close(existing)
		}
		server.mu.Unlock()
	}
}

func (server *Server) appendEvent(record *taskRecord, event StreamResponse) {
	if event.Validate() != nil {
		return
	}
	record.emitMu.Lock()
	defer record.emitMu.Unlock()
	server.mu.Lock()
	if record.closed && len(record.events) > 0 {
		server.mu.Unlock()
		return
	}
	record.events = append(record.events, event)
	watchers := make([]chan StreamResponse, 0, len(record.watchers))
	for _, watcher := range record.watchers {
		watchers = append(watchers, watcher)
	}
	task := cloneTask(record.task)
	pushes := make([]TaskPushNotificationConfig, 0, len(record.pushes))
	for _, config := range record.pushes {
		pushes = append(pushes, config)
	}
	server.mu.Unlock()
	for _, watcher := range watchers {
		select {
		case watcher <- event:
		default:
			// A slow stream is disconnected rather than allowing one client to
			// block task progress for every other subscriber.
		}
	}
	for _, config := range pushes {
		server.dispatchPush(config, event, task)
	}
}

func (server *Server) dispatchPush(config TaskPushNotificationConfig, event StreamResponse, task Task) {
	go func() {
		payload := event
		if payload.Validate() != nil {
			return
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return
		}
		for attempt := 0; attempt <= server.pushRetries; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), server.pushTimeout)
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, config.URL, bytes.NewReader(encoded))
			if reqErr == nil {
				req.Header.Set("Content-Type", "application/a2a+json")
				req.Header.Set("Accept", "application/a2a+json")
				if config.Token != "" {
					req.Header.Set("A2A-Notification-Token", config.Token)
				}
				if config.Authentication != nil {
					req.Header.Set("Authorization", config.Authentication.Scheme+" "+config.Authentication.Credentials)
				}
				response, doErr := server.httpClient.Do(req)
				if doErr == nil {
					_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
					_ = response.Body.Close()
					cancel()
					if response.StatusCode >= 200 && response.StatusCode < 300 {
						return
					}
				} else {
					cancel()
				}
			}
			cancel()
			if attempt < server.pushRetries {
				time.Sleep(time.Duration(attempt+1) * 25 * time.Millisecond)
			}
		}
	}()
}

func (server *Server) addPushConfig(record *taskRecord, config TaskPushNotificationConfig) error {
	if !server.card.Capabilities.PushNotifications {
		return ErrPushNotSupported
	}
	if err := config.Validate(); err != nil {
		return err
	}
	if err := server.validateTenant(config.Tenant); err != nil {
		return err
	}
	if !server.allowHTTPPush {
		parsed, _ := url.Parse(config.URL)
		if parsed.Scheme != "https" {
			return errors.New("push notification URL must use HTTPS")
		}
	}
	server.mu.Lock()
	if record.task.Status.State.Terminal() {
		server.mu.Unlock()
		return ErrTaskTerminal
	}
	if config.ID == "" {
		config.ID = newA2AID("push")
	}
	config.TaskID = record.task.ID
	record.pushes[config.ID] = config
	server.mu.Unlock()
	return nil
}

func (server *Server) serveGetTask(writer http.ResponseWriter, request *http.Request, id string) {
	if err := server.validateTenant(request.URL.Query().Get("tenant")); err != nil {
		server.writeError(writer, http.StatusBadRequest, err, "INVALID_ARGUMENT")
		return
	}
	if id == "" || strings.Contains(id, "/") {
		server.writeError(writer, http.StatusBadRequest, ErrInvalidRequest, "INVALID_ARGUMENT")
		return
	}
	server.mu.Lock()
	record := server.tasks[id]
	server.mu.Unlock()
	if record == nil {
		server.writeError(writer, http.StatusNotFound, ErrTaskNotFound, "TASK_NOT_FOUND")
		return
	}
	historyLength, err := queryHistoryLength(request)
	if err != nil {
		server.writeError(writer, http.StatusBadRequest, err, "INVALID_ARGUMENT")
		return
	}
	configuration := &SendMessageConfiguration{HistoryLength: historyLength}
	task := server.snapshot(record, configuration)
	server.writeJSON(writer, http.StatusOK, task)
}

func (server *Server) serveListTasks(writer http.ResponseWriter, request *http.Request) {
	if err := server.validateTenant(request.URL.Query().Get("tenant")); err != nil {
		server.writeError(writer, http.StatusBadRequest, err, "INVALID_ARGUMENT")
		return
	}
	query := request.URL.Query()
	contextID := query.Get("contextId")
	status := TaskState(query.Get("status"))
	if status != "" && (!status.Valid() || status == TaskStateUnspecified) {
		server.writeError(writer, http.StatusBadRequest, ErrInvalidRequest, "INVALID_ARGUMENT")
		return
	}
	pageSize := 50
	if value := query.Get("pageSize"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100 {
			server.writeError(writer, http.StatusBadRequest, ErrInvalidRequest, "INVALID_ARGUMENT")
			return
		}
		pageSize = parsed
	}
	historyLength, err := queryHistoryLength(request)
	if err != nil {
		server.writeError(writer, http.StatusBadRequest, err, "INVALID_ARGUMENT")
		return
	}
	includeArtifacts := false
	if value := query.Get("includeArtifacts"); value != "" {
		parsed, parseErr := strconv.ParseBool(value)
		if parseErr != nil {
			server.writeError(writer, http.StatusBadRequest, ErrInvalidRequest, "INVALID_ARGUMENT")
			return
		}
		includeArtifacts = parsed
	}
	var statusTimestampAfter time.Time
	if value := query.Get("statusTimestampAfter"); value != "" {
		statusTimestampAfter, err = time.Parse(time.RFC3339, value)
		if err != nil {
			server.writeError(writer, http.StatusBadRequest, ErrInvalidRequest, "INVALID_ARGUMENT")
			return
		}
		statusTimestampAfter = statusTimestampAfter.UTC()
	}
	offset := 0
	if value := query.Get("pageToken"); value != "" {
		offset, err = strconv.Atoi(value)
		if err != nil || offset < 0 {
			server.writeError(writer, http.StatusBadRequest, ErrInvalidRequest, "INVALID_ARGUMENT")
			return
		}
	}
	server.mu.Lock()
	tasks := make([]Task, 0, len(server.tasks))
	for _, record := range server.tasks {
		if contextID != "" && record.task.ContextID != contextID || status != "" && record.task.Status.State != status {
			continue
		}
		if !statusTimestampAfter.IsZero() && record.task.Status.Timestamp.Before(statusTimestampAfter) {
			continue
		}
		tasks = append(tasks, cloneTask(record.task))
	}
	server.mu.Unlock()
	sort.Slice(tasks, func(left, right int) bool { return tasks[left].ID < tasks[right].ID })
	totalSize := len(tasks)
	if offset > totalSize {
		server.writeError(writer, http.StatusBadRequest, ErrInvalidRequest, "INVALID_ARGUMENT")
		return
	}
	end := offset + pageSize
	if end > totalSize {
		end = totalSize
	}
	page := tasks[offset:end]
	for index := range page {
		page[index] = listTaskSnapshot(page[index], historyLength, includeArtifacts)
	}
	nextPageToken := ""
	if end < totalSize {
		nextPageToken = strconv.Itoa(end)
	}
	response := ListTasksResponse{Tasks: page, NextPageToken: nextPageToken, PageSize: pageSize, TotalSize: totalSize}
	if !includeArtifacts {
		server.writeJSON(writer, http.StatusOK, response)
		return
	}
	encoded, err := marshalListTasksResponse(response)
	if err != nil {
		server.writeError(writer, http.StatusInternalServerError, err, "INTERNAL")
		return
	}
	server.writeJSON(writer, http.StatusOK, encoded)
}

func listTaskSnapshot(task Task, historyLength *int, includeArtifacts bool) Task {
	if historyLength != nil {
		switch {
		case *historyLength == 0:
			task.History = nil
		case len(task.History) > *historyLength:
			task.History = append([]Message(nil), task.History[len(task.History)-*historyLength:]...)
		}
	}
	if !includeArtifacts {
		task.Artifacts = nil
	}
	return task
}

func marshalListTasksResponse(response ListTasksResponse) (any, error) {
	tasks := make([]json.RawMessage, len(response.Tasks))
	for index, task := range response.Tasks {
		encoded, err := json.Marshal(task)
		if err != nil {
			return nil, err
		}
		var object map[string]any
		if err := json.Unmarshal(encoded, &object); err != nil {
			return nil, err
		}
		if len(task.Artifacts) == 0 {
			object["artifacts"] = []Artifact{}
		}
		encoded, err = json.Marshal(object)
		if err != nil {
			return nil, err
		}
		tasks[index] = encoded
	}
	return struct {
		Tasks         []json.RawMessage `json:"tasks"`
		NextPageToken string            `json:"nextPageToken"`
		PageSize      int               `json:"pageSize"`
		TotalSize     int               `json:"totalSize"`
	}{Tasks: tasks, NextPageToken: response.NextPageToken, PageSize: response.PageSize, TotalSize: response.TotalSize}, nil
}

func (server *Server) serveCancel(writer http.ResponseWriter, request *http.Request, id string) {
	tenant := request.URL.Query().Get("tenant")
	if request.Body != nil && request.ContentLength != 0 {
		var input TaskOperationRequest
		if err := server.decodeJSON(writer, request, &input); err != nil {
			status, reason := statusForError(err)
			server.writeError(writer, status, err, reason)
			return
		}
		if input.Tenant != "" {
			tenant = input.Tenant
		}
	}
	if err := server.validateTenant(tenant); err != nil {
		server.writeError(writer, http.StatusBadRequest, err, "INVALID_ARGUMENT")
		return
	}
	server.mu.Lock()
	record := server.tasks[id]
	if record == nil {
		server.mu.Unlock()
		server.writeError(writer, http.StatusNotFound, ErrTaskNotFound, "TASK_NOT_FOUND")
		return
	}
	if record.task.Status.State.Terminal() {
		server.mu.Unlock()
		server.writeError(writer, http.StatusBadRequest, ErrTaskNotCancelable, "TASK_NOT_CANCELABLE")
		return
	}
	if record.controller != nil {
		record.controller()
	}
	record.task.Status = TaskStatus{State: TaskStateCanceled, Timestamp: server.clock().UTC()}
	record.task.LastModified = record.task.Status.Timestamp
	task := cloneTask(record.task)
	server.mu.Unlock()
	_ = server.store.Put(context.Background(), task)
	server.appendEvent(record, StreamResponse{StatusUpdate: &TaskStatusUpdateEvent{TaskID: task.ID, ContextID: task.ContextID, Status: task.Status}})
	server.appendEvent(record, StreamResponse{Task: &task})
	server.finish(record)
	server.writeJSON(writer, http.StatusOK, task)
}

func (server *Server) serveSubscribe(writer http.ResponseWriter, request *http.Request, id string) {
	if err := server.validateTenant(request.URL.Query().Get("tenant")); err != nil {
		server.writeError(writer, http.StatusBadRequest, err, "INVALID_ARGUMENT")
		return
	}
	if !server.card.Capabilities.Streaming {
		server.writeError(writer, http.StatusBadRequest, ErrStreamingNotSupported, "UNSUPPORTED_OPERATION")
		return
	}
	server.mu.Lock()
	record := server.tasks[id]
	server.mu.Unlock()
	if record == nil {
		server.writeError(writer, http.StatusNotFound, ErrTaskNotFound, "TASK_NOT_FOUND")
		return
	}
	server.mu.Lock()
	terminal := record.task.Status.State.Terminal()
	server.mu.Unlock()
	if terminal {
		server.writeError(writer, http.StatusBadRequest, ErrUnsupportedOperation, "UNSUPPORTED_OPERATION")
		return
	}
	server.streamRecord(writer, request, record, false)
}

func (server *Server) servePushConfig(writer http.ResponseWriter, request *http.Request, suffix string) {
	if err := server.validateTenant(request.URL.Query().Get("tenant")); err != nil {
		server.writeError(writer, http.StatusBadRequest, err, "INVALID_ARGUMENT")
		return
	}
	if !server.card.Capabilities.PushNotifications {
		server.writeError(writer, http.StatusBadRequest, ErrPushNotSupported, "PUSH_NOTIFICATION_NOT_SUPPORTED")
		return
	}
	parts := strings.Split(strings.TrimSuffix(suffix, "/"), "/pushNotificationConfigs")
	if len(parts) == 0 || parts[0] == "" {
		server.writeError(writer, http.StatusBadRequest, ErrInvalidRequest, "INVALID_ARGUMENT")
		return
	}
	taskID := strings.Trim(parts[0], "/")
	server.mu.Lock()
	record := server.tasks[taskID]
	server.mu.Unlock()
	if record == nil {
		server.writeError(writer, http.StatusNotFound, ErrTaskNotFound, "TASK_NOT_FOUND")
		return
	}
	rest := ""
	if len(parts) == 2 {
		rest = strings.Trim(parts[1], "/")
	}
	switch {
	case request.Method == http.MethodPost && rest == "":
		config, tenant, err := server.decodePushConfig(request)
		if err != nil {
			status, reason := statusForError(err)
			server.writeError(writer, status, err, reason)
			return
		}
		if err := server.validateTenant(tenant); err != nil {
			server.writeError(writer, http.StatusBadRequest, err, "INVALID_ARGUMENT")
			return
		}
		if err := server.addPushConfig(record, config); err != nil {
			status, reason := statusForError(err)
			server.writeError(writer, status, err, reason)
			return
		}
		server.mu.Lock()
		selected := record.pushes[config.ID]
		if selected.ID == "" {
			for _, value := range record.pushes {
				if value.URL == config.URL && value.TaskID == taskID {
					selected = value
					break
				}
			}
		}
		server.mu.Unlock()
		server.writeJSON(writer, http.StatusOK, publicPushConfig(selected))
	case request.Method == http.MethodGet && rest == "":
		pageSize := 50
		if value := request.URL.Query().Get("pageSize"); value != "" {
			parsed, parseErr := strconv.Atoi(value)
			if parseErr != nil || parsed < 1 || parsed > 100 {
				server.writeError(writer, http.StatusBadRequest, ErrInvalidRequest, "INVALID_ARGUMENT")
				return
			}
			pageSize = parsed
		}
		offset := 0
		if value := request.URL.Query().Get("pageToken"); value != "" {
			parsed, parseErr := strconv.Atoi(value)
			if parseErr != nil || parsed < 0 {
				server.writeError(writer, http.StatusBadRequest, ErrInvalidRequest, "INVALID_ARGUMENT")
				return
			}
			offset = parsed
		}
		server.mu.Lock()
		configs := make([]TaskPushNotificationConfig, 0, len(record.pushes))
		for _, config := range record.pushes {
			configs = append(configs, publicPushConfig(config))
		}
		server.mu.Unlock()
		sort.Slice(configs, func(left, right int) bool { return configs[left].ID < configs[right].ID })
		if offset > len(configs) {
			server.writeError(writer, http.StatusBadRequest, ErrInvalidRequest, "INVALID_ARGUMENT")
			return
		}
		end := offset + pageSize
		if end > len(configs) {
			end = len(configs)
		}
		nextPageToken := ""
		if end < len(configs) {
			nextPageToken = strconv.Itoa(end)
		}
		server.writeJSON(writer, http.StatusOK, PushNotificationConfigList{Configs: configs[offset:end], NextPageToken: nextPageToken})
	case (request.Method == http.MethodGet || request.Method == http.MethodDelete) && rest != "":
		server.mu.Lock()
		config, found := record.pushes[rest]
		if found && request.Method == http.MethodDelete {
			delete(record.pushes, rest)
		}
		server.mu.Unlock()
		if request.Method == http.MethodGet {
			if !found {
				server.writeError(writer, http.StatusNotFound, ErrTaskNotFound, "TASK_NOT_FOUND")
				return
			}
			server.writeJSON(writer, http.StatusOK, publicPushConfig(config))
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	default:
		writer.Header().Set("Allow", "GET, POST, DELETE")
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (server *Server) decodeJSON(writer http.ResponseWriter, request *http.Request, target any) error {
	encoded, err := server.readJSON(request)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(encoded, target); err != nil {
		return err
	}
	return nil
}

func (server *Server) decodePushConfig(request *http.Request) (TaskPushNotificationConfig, string, error) {
	encoded, err := server.readJSON(request)
	if err != nil {
		return TaskPushNotificationConfig{}, "", err
	}
	var envelope struct {
		Tenant string                      `json:"tenant"`
		Config *TaskPushNotificationConfig `json:"config"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return TaskPushNotificationConfig{}, "", err
	}
	if envelope.Config != nil && envelope.Config.URL != "" {
		if envelope.Tenant == "" {
			envelope.Tenant = envelope.Config.Tenant
		}
		return *envelope.Config, envelope.Tenant, nil
	}
	var direct TaskPushNotificationConfig
	if err := json.Unmarshal(encoded, &direct); err != nil {
		return TaskPushNotificationConfig{}, "", err
	}
	if envelope.Tenant == "" {
		envelope.Tenant = direct.Tenant
	}
	return direct, envelope.Tenant, nil
}

func (server *Server) readJSON(request *http.Request) ([]byte, error) {
	contentType := request.Header.Get("Content-Type")
	if contentType != "" && !strings.HasPrefix(strings.ToLower(contentType), "application/a2a+json") && !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		return nil, ErrContentTypeNotSupported
	}
	body := io.LimitReader(request.Body, server.maxBodyBytes+1)
	encoded, err := io.ReadAll(body)
	if err != nil || int64(len(encoded)) > server.maxBodyBytes {
		return nil, errors.New("request body is too large")
	}
	canonical, err := canonicaljson.Canonicalize(encoded)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

func (server *Server) writeJSON(writer http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		server.writeError(writer, http.StatusInternalServerError, err, "INTERNAL")
		return
	}
	writer.Header().Set("Content-Type", "application/a2a+json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func (server *Server) writeError(writer http.ResponseWriter, status int, err error, reason string) {
	if reason == "" {
		reason = "INTERNAL"
	}
	message := "A2A request failed"
	if err != nil {
		message = err.Error()
	}
	// Never expose implementation paths or processor errors over the protocol.
	if status >= 500 {
		message = "A2A server error"
	}
	server.writeJSON(writer, status, map[string]any{"error": map[string]any{
		"code": status, "status": reason, "message": message,
		"details": []map[string]any{{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": reason, "domain": "a2a-protocol.org"}},
	}})
}

func statusForError(err error) (int, string) {
	switch {
	case errors.Is(err, ErrTaskNotFound):
		return http.StatusNotFound, "TASK_NOT_FOUND"
	case errors.Is(err, ErrTaskTerminal), errors.Is(err, ErrTaskNotCancelable):
		return http.StatusBadRequest, "TASK_NOT_CANCELABLE"
	case errors.Is(err, ErrPushNotSupported):
		return http.StatusBadRequest, "PUSH_NOTIFICATION_NOT_SUPPORTED"
	case errors.Is(err, ErrStreamingNotSupported), errors.Is(err, ErrUnsupportedOperation):
		return http.StatusBadRequest, "UNSUPPORTED_OPERATION"
	case errors.Is(err, ErrIdempotencyConflict):
		return http.StatusConflict, "IDEMPOTENCY_CONFLICT"
	case errors.Is(err, ErrVersionNotSupported):
		return http.StatusBadRequest, "VERSION_NOT_SUPPORTED"
	case errors.Is(err, ErrExtendedAgentCardNotConfigured):
		return http.StatusBadRequest, "EXTENDED_AGENT_CARD_NOT_CONFIGURED"
	case errors.Is(err, ErrContentTypeNotSupported):
		return http.StatusBadRequest, "CONTENT_TYPE_NOT_SUPPORTED"
	default:
		return http.StatusBadRequest, "INVALID_ARGUMENT"
	}
}

func queryHistoryLength(request *http.Request) (*int, error) {
	value := request.URL.Query().Get("historyLength")
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	if err := validateHistoryLength(&parsed); err != nil {
		return nil, err
	}
	return &parsed, nil
}

func parseExtensions(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" && !contains(result, part) {
			result = append(result, part)
		}
	}
	return result
}

func messageDigest(input SendMessageRequest) (string, error) {
	// A2A messageId identifies the message itself. Request-level routing and
	// execution preferences are intentionally excluded so a persisted task can
	// recognize a replay after a server restart.
	encoded, err := json.Marshal(input.Message)
	if err != nil {
		return "", err
	}
	digest, err := canonicaljson.Digest(encoded)
	if err != nil {
		return "", err
	}
	return digest, nil
}

func newA2AID(prefix string) string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		fallback := sha256.Sum256([]byte(time.Now().UTC().String()))
		return prefix + "-" + hex.EncodeToString(fallback[:16])
	}
	return prefix + "-" + hex.EncodeToString(raw[:])
}

func ptrTask(task Task) *Task {
	copy := cloneTask(task)
	return &copy
}

func cloneArtifacts(values []Artifact) []Artifact {
	if len(values) == 0 {
		return nil
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return append([]Artifact(nil), values...)
	}
	var copy []Artifact
	if json.Unmarshal(encoded, &copy) != nil {
		return append([]Artifact(nil), values...)
	}
	return copy
}

func cloneMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var copy map[string]any
	if json.Unmarshal(encoded, &copy) != nil {
		return nil
	}
	return copy
}

func publicPushConfig(config TaskPushNotificationConfig) TaskPushNotificationConfig {
	copy := config
	if config.Authentication != nil {
		authentication := *config.Authentication
		authentication.Credentials = ""
		copy.Authentication = &authentication
	}
	return copy
}

func cloneCard(card AgentCard) AgentCard {
	encoded, err := json.Marshal(card)
	if err != nil {
		return card
	}
	var copy AgentCard
	if json.Unmarshal(encoded, &copy) != nil {
		return card
	}
	return copy
}

// ValidateAgentCard applies the protocol's mandatory discovery checks. A
// signature is optional in the base A2A protocol and can be required by the
// server's deployment policy.
func ValidateAgentCard(card AgentCard) error {
	if strings.TrimSpace(card.Name) == "" || strings.TrimSpace(card.Description) == "" || strings.TrimSpace(card.Version) == "" || len(card.SupportedInterfaces) == 0 || len(card.DefaultInputModes) == 0 || len(card.DefaultOutputModes) == 0 || len(card.Skills) == 0 {
		return ErrCardInvalid
	}
	if card.Provider != nil {
		providerURL, err := url.Parse(card.Provider.URL)
		if err != nil || providerURL.Scheme == "" || providerURL.Host == "" || providerURL.User != nil || providerURL.RawQuery != "" || providerURL.Fragment != "" || strings.TrimSpace(card.Provider.Organization) == "" {
			return ErrCardInvalid
		}
	}
	for _, value := range []string{card.DocumentationURL, card.IconURL} {
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return ErrCardInvalid
		}
	}
	for _, supported := range card.SupportedInterfaces {
		parsed, err := url.Parse(supported.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || supported.ProtocolBinding != "HTTP+JSON" || !protocolVersionEqual(supported.ProtocolVersion, ProtocolVersion) {
			return ErrCardInvalid
		}
	}
	for _, extension := range card.Capabilities.Extensions {
		parsed, err := url.Parse(extension.URI)
		if strings.TrimSpace(extension.URI) == "" || err != nil || parsed.Scheme == "" {
			return ErrCardInvalid
		}
	}
	for _, requirement := range card.SecurityRequirements {
		if err := requirement.Validate(); err != nil {
			return ErrCardInvalid
		}
	}
	for _, scheme := range card.SecuritySchemes {
		if err := scheme.Validate(); err != nil {
			return ErrCardInvalid
		}
	}
	for _, skill := range card.Skills {
		if strings.TrimSpace(skill.ID) == "" || strings.TrimSpace(skill.Name) == "" || strings.TrimSpace(skill.Description) == "" || len(skill.Tags) == 0 {
			return ErrCardInvalid
		}
		for _, requirement := range skill.SecurityRequirements {
			if err := requirement.Validate(); err != nil {
				return ErrCardInvalid
			}
		}
	}
	return nil
}

func (card AgentCard) Validate() error {
	return ValidateAgentCard(card)
}

// CardCanonicalPayload returns the RFC 8785 payload used when signing an
// Agent Card. Signature members are excluded from the signed representation.
func CardCanonicalPayload(card AgentCard) ([]byte, error) {
	card = cloneCard(card)
	card.Signatures = nil
	card.Signature = ""
	encoded, err := json.Marshal(card)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Canonicalize(encoded)
}

func SignAgentCard(card AgentCard, signer AgentCardSigner) (AgentCard, error) {
	if signer == nil {
		return AgentCard{}, ErrCardInvalid
	}
	if err := ValidateAgentCard(card); err != nil {
		return AgentCard{}, err
	}
	if keyed, ok := signer.(keyedCardSigner); ok {
		card.KID = keyed.KeyID()
	}
	header := map[string]string{"alg": "HS256"}
	if card.KID != "" {
		header["kid"] = card.KID
	}
	protected, _ := json.Marshal(header)
	protectedValue := base64.RawURLEncoding.EncodeToString(protected)
	payload, err := CardCanonicalPayload(card)
	if err != nil {
		return AgentCard{}, ErrCardInvalid
	}
	signingInput := []byte(protectedValue + "." + base64.RawURLEncoding.EncodeToString(payload))
	signature, err := signer.Sign(signingInput)
	if err != nil || strings.TrimSpace(signature) == "" || strings.ContainsAny(signature, "\r\n\x00") {
		return AgentCard{}, ErrCardInvalid
	}
	card.Signature = signature
	card.Signatures = []AgentCardSignature{{Protected: protectedValue, Signature: signature}}
	return card, nil
}

func VerifyAgentCardSignature(card AgentCard, verifier AgentCardVerifier) error {
	if verifier == nil || len(card.Signatures) == 0 {
		return ErrCardInvalid
	}
	payload, err := CardCanonicalPayload(card)
	if err != nil {
		return ErrCardInvalid
	}
	for _, signature := range card.Signatures {
		if signature.Protected == "" || signature.Signature == "" {
			continue
		}
		protected, decodeErr := base64.RawURLEncoding.DecodeString(signature.Protected)
		var header map[string]any
		if decodeErr != nil || json.Unmarshal(protected, &header) != nil || header["alg"] == nil || header["alg"] == "none" {
			continue
		}
		signingInput := []byte(signature.Protected + "." + base64.RawURLEncoding.EncodeToString(payload))
		if verifier.Verify(signingInput, signature.Signature) == nil {
			return nil
		}
	}
	return ErrCardInvalid
}
