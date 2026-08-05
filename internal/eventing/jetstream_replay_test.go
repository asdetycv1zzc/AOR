package eventing

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestDurableConsumerReplayPendingRequiresFreshConsumerAndAcknowledgesBatch(t *testing.T) {
	event := externalEvent("project", "io.aor.project.created.v1", `{"projectId":"project-1","aggregateVersion":1}`)
	event.Traceparent = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
	external, err := Externalize(event, CloudEventOptions{Source: "urn:aor:service:orchestrator"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(external)
	if err != nil {
		t.Fatal(err)
	}
	message := &fakeJetStreamMessage{
		subject: "aor.events.tenant-1.project", data: payload,
		headers: nats.Header{
			nats.MsgIdHdr: {external.ID}, tenantHeader: {"tenant-1"}, traceparentHeader: {external.Traceparent},
		},
		metadata: &jetstream.MsgMetadata{NumDelivered: 1},
	}
	consumer := &replayPullConsumer{info: &jetstream.ConsumerInfo{NumPending: 1}, messages: []jetstream.Msg{message}}
	replay := &DurableConsumer{consumer: consumer, subjectPrefix: defaultJetStreamSubjectPrefix, tenantID: "tenant-1"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	count, err := replay.ReplayPending(ctx, func(_ context.Context, delivery JetStreamDelivery) error {
		if delivery.Event.ID != external.ID {
			t.Fatalf("replayed event = %#v", delivery.Event)
		}
		return nil
	})
	if err != nil || count != 1 || message.acks != 1 {
		t.Fatalf("replay count = %d, acknowledgements = %d, error = %v", count, message.acks, err)
	}

	consumer.info = &jetstream.ConsumerInfo{Delivered: jetstream.SequenceInfo{Consumer: 1}}
	if _, err := replay.ReplayPending(ctx, func(context.Context, JetStreamDelivery) error { return nil }); !errors.Is(err, ErrJetStreamEnvelope) {
		t.Fatalf("reused consumer error = %v", err)
	}
}

type replayPullConsumer struct {
	info     *jetstream.ConsumerInfo
	messages []jetstream.Msg
}

func (consumer *replayPullConsumer) Next(...jetstream.FetchOpt) (jetstream.Msg, error) {
	if len(consumer.messages) == 0 {
		return nil, errors.New("no replay message")
	}
	message := consumer.messages[0]
	consumer.messages = consumer.messages[1:]
	return message, nil
}

func (consumer *replayPullConsumer) Info(context.Context) (*jetstream.ConsumerInfo, error) {
	return consumer.info, nil
}
