package toolbroker

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type capturedAuditPublisher struct{ message *nats.Msg }

func (publisher *capturedAuditPublisher) PublishMsg(_ context.Context, message *nats.Msg, _ ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	publisher.message = message
	return &jetstream.PubAck{Stream: "AOR_EVENTS", Sequence: 1}, nil
}

func TestJetStreamInvocationRecorderPublishesBoundedTenantAudit(t *testing.T) {
	publisher := &capturedAuditPublisher{}
	recorder, err := NewJetStreamInvocationRecorder(publisher, "AOR_EVENTS")
	if err != nil {
		t.Fatal(err)
	}
	invocation := Invocation{InvocationID: "inv_1", RequestID: "request-1", TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", PrincipalID: "agent-1", ToolID: "repo.read", ToolVersion: "1", PolicyVersion: "policy-1", OutputSHA256: testSHA256("output"), TrustLevel: "UNTRUSTED", Status: "SUCCEEDED", OccurredAt: time.Now().UTC()}
	if err := recorder.Record(context.Background(), invocation); err != nil {
		t.Fatal(err)
	}
	if publisher.message == nil || publisher.message.Subject != "aor.audit.tenant-1.tool-invocation" || publisher.message.Header.Get(nats.MsgIdHdr) != "inv_1" || len(publisher.message.Data) == 0 || len(publisher.message.Data) > 64<<10 {
		t.Fatalf("audit message=%#v", publisher.message)
	}
}
