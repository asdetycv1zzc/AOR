package a2a

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/aop"
)

func TestHTTPJSONServerPublishesCardAndImplementsLifecycle(t *testing.T) {
	card := serverCard(true, true)
	server, err := NewServer(ServerConfig{
		Card:     card,
		BasePath: "/a2a/v1",
		Processor: TaskProcessorFunc(func(_ context.Context, request TaskRequest) (TaskResult, error) {
			return TaskResult{
				State:     TaskStateCompleted,
				Message:   &Message{MessageID: "message_agent_1", Role: "ROLE_AGENT", Parts: []Part{{Text: "done"}}},
				Artifacts: []Artifact{{ArtifactID: "artifact_1", Parts: []Part{{Data: map[string]any{"task": request.Task.ID}}}}},
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewTLSServer(server.Handler())
	defer httpServer.Close()

	discovered, err := DiscoverAgentCard(context.Background(), httpServer.URL, httpServer.Client())
	if err != nil || discovered.Name != card.Name || len(discovered.Signatures) != len(card.Signatures) {
		t.Fatalf("discovered = %#v, err = %v", discovered, err)
	}
	client := protocolClient(t, httpServer, "/a2a/v1", true, true)
	response, err := client.SendMessage(context.Background(), SendMessageRequest{Message: Message{
		MessageID: "message_user_1", Role: "ROLE_USER", Parts: []Part{{Text: "run"}}, Extensions: []string{aop.ExtensionURI},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var task Task
	if err := json.Unmarshal(response.Task, &task); err != nil {
		t.Fatal(err)
	}
	if task.Status.State != TaskStateCompleted || task.ID == "" || task.ContextID == "" || len(task.Artifacts) != 1 {
		t.Fatalf("task = %#v", task)
	}
	zero := 0
	polled, err := client.GetTask(context.Background(), task.ID, &zero)
	if err != nil || polled.Status.State != TaskStateCompleted || polled.History != nil {
		t.Fatalf("polled = %#v, err = %v", polled, err)
	}
	if _, err := client.CancelTask(context.Background(), task.ID); protocolReason(err) != "TASK_NOT_CANCELABLE" {
		t.Fatalf("cancel terminal err = %v", err)
	}
	if _, err := client.GetExtendedAgentCard(context.Background()); !errors.Is(err, ErrExtendedAgentCardNotConfigured) {
		t.Fatalf("extended card capability err = %v", err)
	}
}

func TestHTTPJSONServerCancelsRunningTask(t *testing.T) {
	started := make(chan struct{})
	processorCanceled := make(chan struct{})
	var startedOnce sync.Once
	var canceledOnce sync.Once
	server, err := NewServer(ServerConfig{Card: serverCard(true, false), Processor: TaskProcessorFunc(func(ctx context.Context, _ TaskRequest) (TaskResult, error) {
		startedOnce.Do(func() { close(started) })
		<-ctx.Done()
		canceledOnce.Do(func() { close(processorCanceled) })
		return TaskResult{}, ctx.Err()
	})})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewTLSServer(server.Handler())
	defer httpServer.Close()
	client := protocolClient(t, httpServer, "", true, false)
	response, err := client.SendMessage(context.Background(), SendMessageRequest{
		Message:       Message{MessageID: "message_cancel", Role: "ROLE_USER", Parts: []Part{{Text: "wait"}}, Extensions: []string{aop.ExtensionURI}},
		Configuration: &SendMessageConfiguration{ReturnImmediately: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	var submitted Task
	if err := json.Unmarshal(response.Task, &submitted); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("processor did not start")
	}
	canceled, err := client.CancelTask(context.Background(), submitted.ID)
	if err != nil || canceled.Status.State != TaskStateCanceled {
		t.Fatalf("canceled = %#v, err = %v", canceled, err)
	}
	select {
	case <-processorCanceled:
	case <-time.After(time.Second):
		t.Fatal("processor did not observe cancellation")
	}
	polled, err := client.GetTask(context.Background(), submitted.ID, nil)
	if err != nil || polled.Status.State != TaskStateCanceled {
		t.Fatalf("polled = %#v, err = %v", polled, err)
	}
}

func TestHTTPJSONStreamingIsOrderedAndCapabilityGuarded(t *testing.T) {
	server, err := NewServer(ServerConfig{Card: serverCard(true, false), Processor: TaskProcessorFunc(func(_ context.Context, request TaskRequest) (TaskResult, error) {
		return TaskResult{State: TaskStateCompleted, Artifacts: []Artifact{{ArtifactID: "artifact_stream", Parts: []Part{{Text: request.Message.Parts[0].Text}}}}}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewTLSServer(server.Handler())
	defer httpServer.Close()
	client := protocolClient(t, httpServer, "", true, false)
	stream, err := client.SendStreamingMessage(context.Background(), SendMessageRequest{Message: Message{MessageID: "message_stream", Role: "ROLE_USER", Parts: []Part{{Text: "stream"}}, Extensions: []string{aop.ExtensionURI}}})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	var events []StreamResponse
	for {
		event, nextErr := stream.Next(context.Background())
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			t.Fatal(nextErr)
		}
		events = append(events, event)
	}
	if len(events) < 5 || events[0].Task == nil || events[0].Task.Status.State != TaskStateSubmitted || events[len(events)-1].Task == nil || events[len(events)-1].Task.Status.State != TaskStateCompleted {
		t.Fatalf("events = %#v", events)
	}
	seenArtifact := false
	for _, event := range events {
		seenArtifact = seenArtifact || event.ArtifactUpdate != nil
	}
	if !seenArtifact {
		t.Fatal("stream did not contain an artifact update")
	}

	unsupported, err := NewServer(ServerConfig{Card: serverCard(false, false)})
	if err != nil {
		t.Fatal(err)
	}
	unsupportedHTTP := httptest.NewTLSServer(unsupported.Handler())
	defer unsupportedHTTP.Close()
	unsupportedClient := protocolClient(t, unsupportedHTTP, "", false, false)
	_, err = unsupportedClient.SendStreamingMessage(context.Background(), SendMessageRequest{Message: Message{MessageID: "message_no_stream", Role: "ROLE_USER", Parts: []Part{{Text: "no"}}, Extensions: []string{aop.ExtensionURI}}})
	if protocolReason(err) != "UNSUPPORTED_OPERATION" {
		t.Fatalf("stream capability err = %v", err)
	}
}

func TestHTTPJSONServerContinuesInterruptedTask(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	server, err := NewServer(ServerConfig{Card: serverCard(false, false), Processor: TaskProcessorFunc(func(_ context.Context, _ TaskRequest) (TaskResult, error) {
		mu.Lock()
		calls++
		call := calls
		mu.Unlock()
		if call == 1 {
			return TaskResult{State: TaskStateInputRequired, Message: &Message{Parts: []Part{{Text: "more input"}}}}, nil
		}
		return TaskResult{State: TaskStateCompleted}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewTLSServer(server.Handler())
	defer httpServer.Close()
	client := protocolClient(t, httpServer, "", false, false)
	first, err := client.SendMessage(context.Background(), SendMessageRequest{Message: Message{MessageID: "message_turn_1", Role: "ROLE_USER", Parts: []Part{{Text: "start"}}, Extensions: []string{aop.ExtensionURI}}})
	if err != nil {
		t.Fatal(err)
	}
	var task Task
	if err := json.Unmarshal(first.Task, &task); err != nil || task.Status.State != TaskStateInputRequired {
		t.Fatalf("first task = %#v, err = %v", task, err)
	}
	second, err := client.SendMessage(context.Background(), SendMessageRequest{Message: Message{
		MessageID: "message_turn_2", ContextID: task.ContextID, TaskID: task.ID, Role: "ROLE_USER", Parts: []Part{{Text: "continue"}}, Extensions: []string{aop.ExtensionURI},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second.Task, &task); err != nil || task.Status.State != TaskStateCompleted || len(task.History) != 2 {
		t.Fatalf("second task = %#v, err = %v", task, err)
	}
}

func TestHTTPJSONServerRestoresTaskSnapshotsFromStore(t *testing.T) {
	store := NewMemoryTaskStore()
	now := time.Date(2026, time.August, 4, 0, 0, 0, 0, time.UTC)
	task := Task{ID: "task_persisted", ContextID: "context_persisted", Status: TaskStatus{State: TaskStateCompleted, Timestamp: now}, CreatedAt: now, LastModified: now, History: []Message{{MessageID: "message_persisted", Role: "ROLE_USER", Parts: []Part{{Text: "done"}}}}}
	if err := store.Put(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{Card: serverCard(false, false), Store: store})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewTLSServer(server.Handler())
	defer httpServer.Close()
	client := protocolClient(t, httpServer, "", false, false)
	restored, err := client.GetTask(context.Background(), task.ID, nil)
	if err != nil || restored.ID != task.ID || restored.Status.State != TaskStateCompleted {
		t.Fatalf("restored = %#v, err = %v", restored, err)
	}
}

func TestHTTPJSONListsTasksWithPaginationFiltersAndProjection(t *testing.T) {
	server, err := NewServer(ServerConfig{Card: serverCard(false, false), Processor: TaskProcessorFunc(func(_ context.Context, request TaskRequest) (TaskResult, error) {
		return TaskResult{State: TaskStateCompleted, Artifacts: []Artifact{{ArtifactID: "artifact_" + request.Task.ID, Parts: []Part{{Text: "result"}}}}}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewTLSServer(server.Handler())
	defer httpServer.Close()
	client := protocolClient(t, httpServer, "", false, false)
	for index := 0; index < 3; index++ {
		_, err := client.SendMessage(context.Background(), SendMessageRequest{Message: Message{
			MessageID: "message_list_" + strconv.Itoa(index), Role: "ROLE_USER", Parts: []Part{{Text: "list"}}, Extensions: []string{aop.ExtensionURI},
		}})
		if err != nil {
			t.Fatal(err)
		}
	}
	zero := 0
	first, err := client.ListTasks(context.Background(), ListTasksOptions{PageSize: 2, HistoryLength: &zero})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Tasks) != 2 || first.PageSize != 2 || first.TotalSize != 3 || first.NextPageToken == "" {
		t.Fatalf("first page = %#v", first)
	}
	for _, task := range first.Tasks {
		if task.History != nil || task.Artifacts != nil {
			t.Fatalf("default projection leaked fields: %#v", task)
		}
	}
	second, err := client.ListTasks(context.Background(), ListTasksOptions{PageSize: 2, PageToken: first.NextPageToken, IncludeArtifacts: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Tasks) != 1 || second.NextPageToken != "" || second.Tasks[0].Artifacts == nil {
		t.Fatalf("second page = %#v", second)
	}
	if _, err := client.ListTasks(context.Background(), ListTasksOptions{PageSize: 101}); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("client page-size validation = %v", err)
	}
}

func TestHTTPJSONPushConfigurationAndDelivery(t *testing.T) {
	release := make(chan struct{})
	processorStarted := make(chan struct{})
	var startOnce sync.Once
	pushes := make(chan StreamResponse, 16)
	pushServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		if request.Header.Get("Content-Type") != "application/a2a+json" || request.Header.Get("Authorization") != "Bearer secret" || request.Header.Get("A2A-Notification-Token") != "token_1" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		var payload StreamResponse
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil || payload.Validate() != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		pushes <- payload
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer pushServer.Close()

	server, err := NewServer(ServerConfig{
		Card:          serverCard(false, true),
		AllowHTTPPush: true,
		Processor: TaskProcessorFunc(func(_ context.Context, _ TaskRequest) (TaskResult, error) {
			startOnce.Do(func() { close(processorStarted) })
			<-release
			return TaskResult{State: TaskStateCompleted}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewTLSServer(server.Handler())
	defer httpServer.Close()
	client := protocolClient(t, httpServer, "", false, true)
	response, err := client.SendMessage(context.Background(), SendMessageRequest{
		Message: Message{MessageID: "message_push", Role: "ROLE_USER", Parts: []Part{{Text: "push"}}, Extensions: []string{aop.ExtensionURI}},
		Configuration: &SendMessageConfiguration{ReturnImmediately: true, TaskPushNotificationConfig: &TaskPushNotificationConfig{
			URL: pushServer.URL, Token: "token_1", Authentication: &AuthenticationInfo{Scheme: "Bearer", Credentials: "secret"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var task Task
	if err := json.Unmarshal(response.Task, &task); err != nil {
		t.Fatal(err)
	}
	select {
	case <-processorStarted:
	case <-time.After(time.Second):
		t.Fatal("processor did not start")
	}
	listed, err := client.ListPushNotificationConfigs(context.Background(), task.ID)
	if err != nil || len(listed.Configs) != 1 || listed.Configs[0].TaskID != task.ID || listed.Configs[0].Authentication == nil || listed.Configs[0].Authentication.Credentials != "" {
		t.Fatalf("configs = %#v, err = %v", listed, err)
	}
	config, err := client.GetPushNotificationConfig(context.Background(), task.ID, listed.Configs[0].ID)
	if err != nil || config.URL != pushServer.URL {
		t.Fatalf("config = %#v, err = %v", config, err)
	}
	close(release)
	select {
	case payload := <-pushes:
		if payload.StatusUpdate == nil && payload.Task == nil {
			t.Fatalf("push payload = %#v", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("push notification not delivered")
	}
	if err := client.DeletePushNotificationConfig(context.Background(), task.ID, config.ID); err != nil {
		t.Fatal(err)
	}
}

func TestServerRejectsMissingVersionExtensionAndMessageConflict(t *testing.T) {
	server, err := NewServer(ServerConfig{Card: serverCard(false, false)})
	if err != nil {
		t.Fatal(err)
	}
	requestBody := `{"message":{"messageId":"message_1","role":"ROLE_USER","parts":[{"text":"one"}],"extensions":["urn:aor:aop:v1"]}}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "https://runtime.test/message:send", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/a2a+json")
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || errorReason(recorder.Body.Bytes()) != "VERSION_NOT_SUPPORTED" {
		t.Fatalf("version status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "https://runtime.test/message:send", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/a2a+json")
	request.Header.Set("A2A-Version", ProtocolVersion)
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || errorReason(recorder.Body.Bytes()) != "EXTENSION_SUPPORT_REQUIRED" {
		t.Fatalf("extension status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "https://runtime.test/message:send", strings.NewReader(`{"message":{"messageId":"message_future","role":"ROLE_USER","parts":[{"text":"one","futurePart":true}],"extensions":["urn:aor:aop:v1"]},"futureOptional":{"enabled":true}}`))
	request.Header.Set("Content-Type", "application/a2a+json")
	request.Header.Set("A2A-Version", ProtocolVersion)
	request.Header.Set("A2A-Extensions", aop.ExtensionURI)
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("optional field status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	httpServer := httptest.NewTLSServer(server.Handler())
	defer httpServer.Close()
	client := protocolClient(t, httpServer, "", false, false)
	first := SendMessageRequest{Message: Message{MessageID: "message_same", Role: "ROLE_USER", Parts: []Part{{Text: "one"}}, Extensions: []string{aop.ExtensionURI}}}
	firstResponse, err := client.SendMessage(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := client.SendMessage(context.Background(), first)
	if err != nil || string(firstResponse.Task) != string(replayed.Task) {
		t.Fatalf("replayed = %#v, err = %v", replayed, err)
	}
	first.Message.Parts[0].Text = "two"
	_, err = client.SendMessage(context.Background(), first)
	if protocolReason(err) != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("conflict err = %v", err)
	}
}

func TestAgentCardSigningUsesCanonicalPayload(t *testing.T) {
	signer := &testCardSigner{key: []byte("0123456789abcdef0123456789abcdef"), kid: "kid_test"}
	card, err := SignAgentCard(serverCard(false, false), signer)
	if err != nil {
		t.Fatal(err)
	}
	if card.KID != "kid_test" || len(card.Signatures) != 1 || card.Signatures[0].Protected == "" || card.Signature == "" {
		t.Fatalf("signed card = %#v", card)
	}
	if err := VerifyAgentCardSignature(card, signer); err != nil {
		t.Fatal(err)
	}
	card.Name = "tampered"
	if err := VerifyAgentCardSignature(card, signer); !errors.Is(err, ErrCardInvalid) {
		t.Fatalf("tampered card err = %v", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(card.Signatures[0].Protected); err != nil {
		t.Fatalf("protected header = %v", err)
	}
}

type testCardSigner struct {
	key []byte
	kid string
}

func (signer *testCardSigner) Sign(payload []byte) (string, error) {
	digest := hmac.New(sha256.New, signer.key)
	_, _ = digest.Write(payload)
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil)), nil
}

func (signer *testCardSigner) Verify(payload []byte, signature string) error {
	expected, _ := signer.Sign(payload)
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return errors.New("invalid signature")
	}
	return nil
}

func (signer *testCardSigner) KeyID() string { return signer.kid }

func serverCard(streaming, push bool) AgentCard {
	card := validCard("https://runtime.example.invalid/a2a/v1")
	card.Capabilities.Streaming = streaming
	card.Capabilities.PushNotifications = push
	card.Skills[0].Description = "Executes one test task"
	return card
}

func protocolClient(t *testing.T, server *httptest.Server, path string, streaming, push bool) *Client {
	t.Helper()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Path = path
	card := validCard(endpoint.String())
	card.Capabilities.Streaming = streaming
	card.Capabilities.PushNotifications = push
	client, err := NewHTTPJSONClient(card, Negotiation{Extensions: []string{aop.ExtensionURI}}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func protocolReason(err error) string {
	var protocolErr *ProtocolError
	if errors.As(err, &protocolErr) {
		return protocolErr.Reason
	}
	return ""
}

func errorReason(encoded []byte) string {
	var payload struct {
		Error struct {
			Details []struct {
				Reason string `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(encoded, &payload)
	if len(payload.Error.Details) == 0 {
		return ""
	}
	return payload.Error.Details[0].Reason
}
