package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/akimisaka/aor/pkg/aop"
)

func TestHTTPJSONClientSendsA2AOneWireRequest(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/a2a/v1/message:send" || request.Header.Get("Content-Type") != "application/a2a+json" || request.Header.Get("Accept") != "application/a2a+json" || request.Header.Get("A2A-Version") != ProtocolVersion || request.Header.Get("A2A-Extensions") != aop.ExtensionURI {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		var body SendMessageRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.Message.MessageID != "message_1" || body.Message.Role != "ROLE_USER" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = writer.Write([]byte(`{"task":{"id":"task_1","contextId":"context_1","status":{"state":"TASK_STATE_COMPLETED"}}}`))
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Path = "/a2a/v1"
	client, err := NewHTTPJSONClient(validCard(endpoint.String()), Negotiation{Extensions: []string{aop.ExtensionURI}}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.SendMessage(context.Background(), SendMessageRequest{Message: Message{MessageID: "message_1", Role: "ROLE_USER", Parts: []Part{{Text: "start"}}, Extensions: []string{aop.ExtensionURI}}})
	if err != nil || !strings.Contains(string(response.Task), "task_1") {
		t.Fatalf("response = %#v, err = %v", response, err)
	}
}

func TestHTTPJSONClientAcceptsMultilineSSEData(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		_, _ = writer.Write([]byte("data: {\"task\": {\n"))
		_, _ = writer.Write([]byte("data: \"id\": \"task_1\",\n"))
		_, _ = writer.Write([]byte("data: \"status\": {\"state\": \"TASK_STATE_COMPLETED\"}}}\n\n"))
		_, _ = writer.Write([]byte("data: [DONE]\n\n"))
	}))
	defer server.Close()
	client := protocolClient(t, server, "", true, false)
	stream, err := client.SendStreamingMessage(context.Background(), SendMessageRequest{Message: Message{MessageID: "message_sse", Role: "ROLE_USER", Parts: []Part{{Text: "stream"}}, Extensions: []string{aop.ExtensionURI}}})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	event, err := stream.Next(context.Background())
	if err != nil || event.Task == nil || event.Task.ID != "task_1" {
		t.Fatalf("event = %#v, err = %v", event, err)
	}
	if _, err := stream.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("stream completion = %v", err)
	}
}

func TestRequiredExtensionsFailClosedAndOptionalExtensionsDoNot(t *testing.T) {
	card := validCard("https://agent.example.invalid/a2a/v1")
	card.Capabilities.Extensions = append(card.Capabilities.Extensions, Extension{URI: "urn:example:optional:v1"})
	if _, _, err := SelectHTTPJSONInterface(card, Negotiation{Extensions: []string{aop.ExtensionURI}}); err != nil {
		t.Fatalf("optional extension = %v", err)
	}
	card.Capabilities.Extensions[1].Required = true
	if _, _, err := SelectHTTPJSONInterface(card, Negotiation{Extensions: []string{aop.ExtensionURI}}); !errors.Is(err, ErrUnsupportedExtension) {
		t.Fatalf("required extension = %v", err)
	}
	if _, _, err := SelectHTTPJSONInterface(card, Negotiation{Extensions: []string{aop.ExtensionURI, "urn:example:optional:v1"}}); err != nil {
		t.Fatalf("declared required extension = %v", err)
	}
}

func TestSelectInterfaceRejectsWrongVersionAndInsecureURL(t *testing.T) {
	card := validCard("https://agent.example.invalid/a2a/v1")
	card.SupportedInterfaces[0].ProtocolVersion = "0.3"
	if _, _, err := SelectHTTPJSONInterface(card, Negotiation{Extensions: []string{aop.ExtensionURI}}); !errors.Is(err, ErrUnsupportedOperation) {
		t.Fatalf("version = %v", err)
	}
	card = validCard("http://agent.example.invalid/a2a/v1")
	if _, _, err := SelectHTTPJSONInterface(card, Negotiation{Extensions: []string{aop.ExtensionURI}}); !errors.Is(err, ErrIncompatibleCard) {
		t.Fatalf("url = %v", err)
	}
	card = validCard("https://agent.example.invalid/a2a/v1")
	card.SupportedInterfaces[0].ProtocolVersion = "1.0.1"
	if _, _, err := SelectHTTPJSONInterface(card, Negotiation{Extensions: []string{aop.ExtensionURI}}); err != nil {
		t.Fatalf("patch version = %v", err)
	}
}

func validCard(endpoint string) AgentCard {
	return AgentCard{
		Name: "AOR runtime", Description: "Runs AOR tasks", Version: "1.0.0",
		SupportedInterfaces: []AgentInterface{{URL: endpoint, ProtocolBinding: "HTTP+JSON", ProtocolVersion: ProtocolVersion}},
		Capabilities:        Capabilities{Extensions: []Extension{{URI: aop.ExtensionURI, Required: true}}},
		DefaultInputModes:   []string{"application/json"}, DefaultOutputModes: []string{"application/json"},
		Skills: []Skill{{ID: "executor", Name: "Executor", Tags: []string{"aor"}}},
	}
}
