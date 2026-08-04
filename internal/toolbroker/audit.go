package toolbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

var ErrAuditUnavailable = errors.New("tool invocation audit unavailable")

type AuditPublisher interface {
	PublishMsg(context.Context, *nats.Msg, ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

type JetStreamInvocationRecorder struct {
	publisher AuditPublisher
	stream    string
}

func NewJetStreamInvocationRecorder(publisher AuditPublisher, stream string) (*JetStreamInvocationRecorder, error) {
	if publisher == nil || stream == "" || strings.ContainsAny(stream, " \t\r\n.*>") {
		return nil, ErrAuditUnavailable
	}
	return &JetStreamInvocationRecorder{publisher: publisher, stream: stream}, nil
}

func (recorder *JetStreamInvocationRecorder) Record(ctx context.Context, invocation Invocation) error {
	if invocation.Status != "SUCCEEDED" || invocation.OutputSHA256 == "" || invocation.PolicyVersion == "" || invocation.OccurredAt.IsZero() {
		return ErrAuditUnavailable
	}
	return recorder.publish(ctx, invocation.InvocationID, invocation.TenantID, invocation)
}

func (recorder *JetStreamInvocationRecorder) RecordAttempt(ctx context.Context, attempt InvocationAttempt) error {
	if attempt.Status != "FAILED" || attempt.ReasonCode == "" || attempt.OccurredAt.IsZero() {
		return ErrAuditUnavailable
	}
	return recorder.publish(ctx, attempt.InvocationID+"."+strings.ToLower(attempt.ReasonCode), attempt.TenantID, attempt)
}

func (recorder *JetStreamInvocationRecorder) publish(ctx context.Context, messageID, tenantID string, payload any) error {
	if recorder == nil || recorder.publisher == nil || ctx == nil || !safeNATSToken(tenantID) || !safeMessageID(messageID) {
		return ErrAuditUnavailable
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > 64<<10 {
		return ErrAuditUnavailable
	}
	message := nats.NewMsg("aor.audit." + tenantID + ".tool-invocation")
	message.Header.Set(nats.MsgIdHdr, messageID)
	message.Header.Set("Content-Type", "application/json")
	message.Header.Set("Aor-Tenant-Id", tenantID)
	message.Data = encoded
	ack, err := recorder.publisher.PublishMsg(ctx, message, jetstream.WithExpectStream(recorder.stream))
	if err != nil || ack == nil || ack.Stream != recorder.stream || ack.Sequence == 0 {
		return fmt.Errorf("%w", ErrAuditUnavailable)
	}
	return nil
}

func safeNATSToken(value string) bool {
	return value != "" && !strings.ContainsAny(value, ".*>/\\ \t\r\n")
}

func safeMessageID(value string) bool {
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n")
}

var _ InvocationRecorder = (*JetStreamInvocationRecorder)(nil)
var _ InvocationAttemptRecorder = (*JetStreamInvocationRecorder)(nil)
