package eventing

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/cloudevents"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestJetStreamEventBusPublishesValidatedCloudEvent(t *testing.T) {
	client := &recordingJetStream{ack: &jetstream.PubAck{Stream: "AOR", Sequence: 42}}
	bus, err := NewJetStreamEventBus(client, JetStreamEventBusConfig{Stream: "AOR", Source: "https://aor.local/orchestrator"})
	if err != nil {
		t.Fatalf("NewJetStreamEventBus() error = %v", err)
	}
	event := externalEvent("project", "io.aor.project.created.v1", `{"projectId":"project-1","aggregateVersion":1}`)
	event.Traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	event.Tracestate = "aor=eventing"
	if err := bus.Publish(context.Background(), event); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if client.message == nil || client.message.Subject != "aor.events.tenant-1.project" {
		t.Fatalf("published subject = %#v", client.message)
	}
	if got := client.message.Header.Get(nats.MsgIdHdr); got != event.EventID {
		t.Fatalf("Nats-Msg-Id = %q, want %q", got, event.EventID)
	}
	if got := client.message.Header.Get(tenantHeader); got != event.TenantID {
		t.Fatalf("tenant header = %q, want %q", got, event.TenantID)
	}
	if got := client.message.Header.Get(traceparentHeader); got != event.Traceparent {
		t.Fatalf("traceparent header = %q, want %q", got, event.Traceparent)
	}
	if got := client.message.Header.Get(tracestateHeader); got != event.Tracestate {
		t.Fatalf("tracestate header = %q, want %q", got, event.Tracestate)
	}
	var published cloudevents.Event
	if err := json.Unmarshal(client.message.Data, &published); err != nil {
		t.Fatalf("decode published CloudEvent: %v", err)
	}
	if err := published.Validate(); err != nil {
		t.Fatalf("published CloudEvent validation: %v", err)
	}
}

func TestJetStreamEventBusRejectsUnsafeTenantAndUnexpectedAck(t *testing.T) {
	client := &recordingJetStream{ack: &jetstream.PubAck{Stream: "OTHER", Sequence: 1}}
	bus, err := NewJetStreamEventBus(client, JetStreamEventBusConfig{Stream: "AOR", Source: "https://aor.local/orchestrator"})
	if err != nil {
		t.Fatalf("NewJetStreamEventBus() error = %v", err)
	}
	event := externalEvent("project", "io.aor.project.created.v1", `{"projectId":"project-1","aggregateVersion":1}`)
	event.Traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	event.TenantID = "other.tenant"
	if err := bus.Publish(context.Background(), event); !errors.Is(err, ErrJetStreamEnvelope) {
		t.Fatalf("Publish() error = %v, want invalid envelope", err)
	}
	if client.message != nil {
		t.Fatal("Publish() called JetStream with an unsafe tenant")
	}
	event.TenantID = "tenant-1"
	if err := bus.Publish(context.Background(), event); !errors.Is(err, ErrJetStreamEnvelope) {
		t.Fatalf("Publish() acknowledgement error = %v, want invalid envelope", err)
	}
}

func TestJetStreamConsumerConfigScopesTenantAndExposesReplay(t *testing.T) {
	bus := &JetStreamEventBus{stream: "AOR", source: "https://aor.local/orchestrator", subjectPrefix: defaultJetStreamSubjectPrefix}
	start := time.Date(2030, 2, 3, 4, 5, 6, 0, time.FixedZone("offset", 3600))
	config, err := bus.consumerConfig(DurableConsumerConfig{
		Durable: "audit-reader", TenantID: "tenant-1", Start: ReplayFromTime, StartTime: start,
		Pacing: ReplayAtOriginalRate, AckWait: 15 * time.Second, MaxDeliver: 4,
	})
	if err != nil {
		t.Fatalf("consumerConfig() error = %v", err)
	}
	if config.AckPolicy != jetstream.AckExplicitPolicy || config.FilterSubject != "aor.events.tenant-1.>" {
		t.Fatalf("consumer config = %#v", config)
	}
	if config.DeliverPolicy != jetstream.DeliverByStartTimePolicy || config.OptStartTime == nil || !config.OptStartTime.Equal(start.UTC()) {
		t.Fatalf("replay start config = %#v", config)
	}
	if config.ReplayPolicy != jetstream.ReplayOriginalPolicy || config.MaxDeliver != 4 {
		t.Fatalf("replay/ack config = %#v", config)
	}
	if _, err := bus.consumerConfig(DurableConsumerConfig{Durable: "audit-reader", TenantID: "tenant-1", FilterSubject: "aor.events.tenant-2.>"}); !errors.Is(err, ErrJetStreamEnvelope) {
		t.Fatalf("cross-tenant filter error = %v, want invalid envelope", err)
	}
	if _, err := bus.consumerConfig(DurableConsumerConfig{Durable: "audit-reader", TenantID: "tenant-1", Start: ReplayFromSequence}); !errors.Is(err, ErrJetStreamEnvelope) {
		t.Fatalf("missing replay sequence error = %v, want invalid envelope", err)
	}
}

func TestDecodeJetStreamDeliveryRequiresMatchingEnvelopeAndHeaders(t *testing.T) {
	external := cloudevents.Event{
		SpecVersion: "1.0", ID: "evt_1", Source: "https://aor.local/orchestrator", Type: "io.aor.project.created.v1",
		Subject: "projects/project-1", Time: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), DataContentType: "application/json",
		DataSchema: "https://schemas.aor.local/events/project-created.v1.schema.json", Traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		ProjectID: "project-1", TaskIDReason: "NOT_CREATED", AgentRunReason: "NOT_CREATED", Data: json.RawMessage(`{"projectId":"project-1","aggregateVersion":1}`),
	}
	payload, err := json.Marshal(external)
	if err != nil {
		t.Fatalf("marshal CloudEvent: %v", err)
	}
	message := &fakeJetStreamMessage{subject: "aor.events.tenant-1.project", data: payload, headers: nats.Header{
		nats.MsgIdHdr: {external.ID}, tenantHeader: {"tenant-1"}, traceparentHeader: {external.Traceparent},
	}, metadata: &jetstream.MsgMetadata{NumDelivered: 2}}
	delivery, err := decodeJetStreamDelivery(message, defaultJetStreamSubjectPrefix, "tenant-1")
	if err != nil {
		t.Fatalf("decodeJetStreamDelivery() error = %v", err)
	}
	if delivery.Event.ID != external.ID || delivery.DeliveryAttempt != 2 {
		t.Fatalf("delivery = %#v", delivery)
	}
	if err := delivery.Ack(); err != nil || message.acks != 1 {
		t.Fatalf("Ack() error = %v, acknowledgements = %d", err, message.acks)
	}
	if err := delivery.Nak(); err != nil || message.naks != 1 {
		t.Fatalf("Nak() error = %v, negative acknowledgements = %d", err, message.naks)
	}
	message.headers.Set(nats.MsgIdHdr, "different")
	if _, err := decodeJetStreamDelivery(message, defaultJetStreamSubjectPrefix, "tenant-1"); !errors.Is(err, ErrJetStreamEnvelope) {
		t.Fatalf("mismatched message ID error = %v, want invalid envelope", err)
	}
}

type recordingJetStream struct {
	message *nats.Msg
	ack     *jetstream.PubAck
	err     error
}

func (c *recordingJetStream) PublishMsg(_ context.Context, message *nats.Msg, _ ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	c.message = message
	return c.ack, c.err
}

func (c *recordingJetStream) CreateOrUpdateConsumer(context.Context, string, jetstream.ConsumerConfig) (jetstream.Consumer, error) {
	return nil, errors.New("not implemented")
}

type fakeJetStreamMessage struct {
	subject  string
	data     []byte
	headers  nats.Header
	metadata *jetstream.MsgMetadata
	acks     int
	naks     int
}

func (m *fakeJetStreamMessage) Metadata() (*jetstream.MsgMetadata, error) { return m.metadata, nil }
func (m *fakeJetStreamMessage) Data() []byte                              { return m.data }
func (m *fakeJetStreamMessage) Headers() nats.Header                      { return m.headers }
func (m *fakeJetStreamMessage) Subject() string                           { return m.subject }
func (m *fakeJetStreamMessage) Reply() string                             { return "" }
func (m *fakeJetStreamMessage) Ack() error                                { m.acks++; return nil }
func (m *fakeJetStreamMessage) DoubleAck(context.Context) error           { return m.Ack() }
func (m *fakeJetStreamMessage) Nak() error                                { m.naks++; return nil }
func (m *fakeJetStreamMessage) NakWithDelay(time.Duration) error          { return m.Nak() }
func (m *fakeJetStreamMessage) InProgress() error                         { return nil }
func (m *fakeJetStreamMessage) Term() error                               { return nil }
func (m *fakeJetStreamMessage) TermWithReason(string) error               { return nil }
