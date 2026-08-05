package eventing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/akimisaka/aor/pkg/cloudevents"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	defaultJetStreamSubjectPrefix = "aor.events"
	defaultConsumerAckWait        = 30 * time.Second
	tenantHeader                  = "Aor-Tenant-Id"
	traceparentHeader             = "traceparent"
	tracestateHeader              = "tracestate"
)

var ErrJetStreamEnvelope = errors.New("invalid JetStream event envelope")

// JetStreamClient is the portion of JetStream used by the event bus. The
// runtime client satisfies this interface, and it keeps unit tests independent
// of a running NATS server.
type JetStreamClient interface {
	PublishMsg(context.Context, *nats.Msg, ...jetstream.PublishOpt) (*jetstream.PubAck, error)
	CreateOrUpdateConsumer(context.Context, string, jetstream.ConsumerConfig) (jetstream.Consumer, error)
}

type jetStreamPullConsumer interface {
	Next(...jetstream.FetchOpt) (jetstream.Msg, error)
	Info(context.Context) (*jetstream.ConsumerInfo, error)
}

type JetStreamEventBusConfig struct {
	Stream        string
	Source        string
	SubjectPrefix string
}

// JetStreamEventBus publishes the AOR CloudEvents profile to JetStream. A
// successful Publish is durable according to the stream configuration; it is
// not an exactly-once processing guarantee.
type JetStreamEventBus struct {
	client        JetStreamClient
	stream        string
	source        string
	subjectPrefix string
}

func NewJetStreamEventBus(client JetStreamClient, config JetStreamEventBusConfig) (*JetStreamEventBus, error) {
	if client == nil || config.Stream == "" || config.Source == "" {
		return nil, fmt.Errorf("%w: JetStream client, stream, and source are required", ErrJetStreamEnvelope)
	}
	if config.SubjectPrefix == "" {
		config.SubjectPrefix = defaultJetStreamSubjectPrefix
	}
	if !validNATSSubject(config.SubjectPrefix, false) || strings.ContainsAny(config.Stream, "\r\n") {
		return nil, fmt.Errorf("%w: invalid stream or subject prefix", ErrJetStreamEnvelope)
	}
	return &JetStreamEventBus{client: client, stream: config.Stream, source: config.Source, subjectPrefix: config.SubjectPrefix}, nil
}

// Publish externalizes event as a validated CloudEvent and uses EventID for
// Nats-Msg-Id. Retries therefore retain a deterministic broker message ID.
func (b *JetStreamEventBus) Publish(ctx context.Context, event DomainEvent) error {
	if b == nil || b.client == nil {
		return fmt.Errorf("%w: event bus is not initialized", ErrJetStreamEnvelope)
	}
	if !validNATSToken(event.TenantID) || !validHeaderValue(event.EventID) || event.EventID == "" {
		return fmt.Errorf("%w: invalid tenant or event ID", ErrJetStreamEnvelope)
	}
	external, err := Externalize(event, CloudEventOptions{Source: b.source})
	if err != nil {
		return fmt.Errorf("externalize event: %w", err)
	}
	payload, err := json.Marshal(external)
	if err != nil {
		return fmt.Errorf("marshal CloudEvent: %w", err)
	}
	message := nats.NewMsg(b.subject(event.AggregateType, event.TenantID))
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, event.EventID)
	message.Header.Set(tenantHeader, event.TenantID)
	message.Header.Set(traceparentHeader, external.Traceparent)
	if external.Tracestate != "" {
		message.Header.Set(tracestateHeader, external.Tracestate)
	}
	ack, err := b.client.PublishMsg(ctx, message, jetstream.WithExpectStream(b.stream))
	if err != nil {
		return fmt.Errorf("publish CloudEvent to JetStream: %w", err)
	}
	if ack == nil || ack.Stream != b.stream || ack.Sequence == 0 {
		return fmt.Errorf("%w: publish acknowledgement does not confirm stream %q", ErrJetStreamEnvelope, b.stream)
	}
	return nil
}

func (b *JetStreamEventBus) subject(aggregateType, tenantID string) string {
	if aggregateType == "" {
		aggregateType = "event"
	}
	return b.subjectPrefix + "." + tenantID + "." + aggregateType
}

type ReplayStart string

const (
	ReplayFromBeginning ReplayStart = "beginning"
	ReplayNewMessages   ReplayStart = "new"
	ReplayFromSequence  ReplayStart = "sequence"
	ReplayFromTime      ReplayStart = "time"
)

type ReplayPacing string

const (
	ReplayAsFastAsPossible ReplayPacing = "instant"
	ReplayAtOriginalRate   ReplayPacing = "original"
)

// DurableConsumerConfig defines a pull consumer. FilterSubject is optional;
// when supplied it must remain within TenantID's subject namespace.
type DurableConsumerConfig struct {
	Durable       string
	TenantID      string
	FilterSubject string
	Start         ReplayStart
	StartSequence uint64
	StartTime     time.Time
	Pacing        ReplayPacing
	AckWait       time.Duration
	MaxDeliver    int
}

// DurableConsumer wraps a durable JetStream pull consumer. Every delivery must
// be acknowledged or negatively acknowledged by the caller.
type DurableConsumer struct {
	consumer      jetStreamPullConsumer
	subjectPrefix string
	tenantID      string
}

// OpenDurableConsumer creates or updates a durable pull consumer using
// explicit acknowledgement. For an existing durable, JetStream preserves its
// acknowledged position; create a new durable name to replay from a new start.
func (b *JetStreamEventBus) OpenDurableConsumer(ctx context.Context, config DurableConsumerConfig) (*DurableConsumer, error) {
	if b == nil || b.client == nil {
		return nil, fmt.Errorf("%w: event bus is not initialized", ErrJetStreamEnvelope)
	}
	consumerConfig, err := b.consumerConfig(config)
	if err != nil {
		return nil, err
	}
	consumer, err := b.client.CreateOrUpdateConsumer(ctx, b.stream, consumerConfig)
	if err != nil {
		return nil, fmt.Errorf("create durable JetStream consumer: %w", err)
	}
	if consumer == nil {
		return nil, fmt.Errorf("%w: JetStream returned a nil consumer", ErrJetStreamEnvelope)
	}
	return &DurableConsumer{consumer: consumer, subjectPrefix: b.subjectPrefix, tenantID: config.TenantID}, nil
}

func (b *JetStreamEventBus) consumerConfig(config DurableConsumerConfig) (jetstream.ConsumerConfig, error) {
	if !validDurableName(config.Durable) || !validNATSToken(config.TenantID) {
		return jetstream.ConsumerConfig{}, fmt.Errorf("%w: invalid durable name or tenant", ErrJetStreamEnvelope)
	}
	if config.AckWait < 0 || config.MaxDeliver < -1 {
		return jetstream.ConsumerConfig{}, fmt.Errorf("%w: invalid acknowledgement configuration", ErrJetStreamEnvelope)
	}
	if config.AckWait == 0 {
		config.AckWait = defaultConsumerAckWait
	}
	if config.FilterSubject == "" {
		config.FilterSubject = b.subjectPrefix + "." + config.TenantID + ".>"
	}
	if !validTenantFilter(config.FilterSubject, b.subjectPrefix, config.TenantID) {
		return jetstream.ConsumerConfig{}, fmt.Errorf("%w: filter subject must remain in the tenant namespace", ErrJetStreamEnvelope)
	}
	consumerConfig := jetstream.ConsumerConfig{
		Durable:       config.Durable,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       config.AckWait,
		MaxDeliver:    config.MaxDeliver,
		FilterSubject: config.FilterSubject,
	}
	switch config.Start {
	case "", ReplayFromBeginning:
		consumerConfig.DeliverPolicy = jetstream.DeliverAllPolicy
	case ReplayNewMessages:
		consumerConfig.DeliverPolicy = jetstream.DeliverNewPolicy
	case ReplayFromSequence:
		if config.StartSequence == 0 {
			return jetstream.ConsumerConfig{}, fmt.Errorf("%w: replay sequence is required", ErrJetStreamEnvelope)
		}
		consumerConfig.DeliverPolicy = jetstream.DeliverByStartSequencePolicy
		consumerConfig.OptStartSeq = config.StartSequence
	case ReplayFromTime:
		if config.StartTime.IsZero() {
			return jetstream.ConsumerConfig{}, fmt.Errorf("%w: replay start time is required", ErrJetStreamEnvelope)
		}
		startTime := config.StartTime.UTC()
		consumerConfig.DeliverPolicy = jetstream.DeliverByStartTimePolicy
		consumerConfig.OptStartTime = &startTime
	default:
		return jetstream.ConsumerConfig{}, fmt.Errorf("%w: unknown replay start", ErrJetStreamEnvelope)
	}
	switch config.Pacing {
	case "", ReplayAsFastAsPossible:
		consumerConfig.ReplayPolicy = jetstream.ReplayInstantPolicy
	case ReplayAtOriginalRate:
		consumerConfig.ReplayPolicy = jetstream.ReplayOriginalPolicy
	default:
		return jetstream.ConsumerConfig{}, fmt.Errorf("%w: unknown replay pacing", ErrJetStreamEnvelope)
	}
	return consumerConfig, nil
}

// Next receives one message before ctx's deadline. A deadline is required so
// the blocking JetStream pull cannot outlive the caller's intended wait.
func (c *DurableConsumer) Next(ctx context.Context) (JetStreamDelivery, error) {
	if c == nil || c.consumer == nil {
		return JetStreamDelivery{}, fmt.Errorf("%w: durable consumer is not initialized", ErrJetStreamEnvelope)
	}
	if err := ctx.Err(); err != nil {
		return JetStreamDelivery{}, err
	}
	deadline, found := ctx.Deadline()
	if !found {
		return JetStreamDelivery{}, fmt.Errorf("%w: consumer receive context requires a deadline", ErrJetStreamEnvelope)
	}
	wait := time.Until(deadline)
	if wait <= 0 {
		return JetStreamDelivery{}, context.DeadlineExceeded
	}
	message, err := c.consumer.Next(jetstream.FetchMaxWait(wait))
	if err != nil {
		return JetStreamDelivery{}, err
	}
	return decodeJetStreamDelivery(message, c.subjectPrefix, c.tenantID)
}

type JetStreamDelivery struct {
	Event           cloudevents.Event
	TenantID        string
	Subject         string
	DeliveryAttempt uint64
	message         jetstream.Msg
}

func (d JetStreamDelivery) Ack() error {
	if d.message == nil {
		return fmt.Errorf("%w: delivery has no message", ErrJetStreamEnvelope)
	}
	return d.message.Ack()
}

func (d JetStreamDelivery) Nak() error {
	if d.message == nil {
		return fmt.Errorf("%w: delivery has no message", ErrJetStreamEnvelope)
	}
	return d.message.Nak()
}

func (d JetStreamDelivery) InProgress() error {
	if d.message == nil {
		return fmt.Errorf("%w: delivery has no message", ErrJetStreamEnvelope)
	}
	return d.message.InProgress()
}

func decodeJetStreamDelivery(message jetstream.Msg, subjectPrefix, tenantID string) (JetStreamDelivery, error) {
	if message == nil || !validNATSToken(tenantID) {
		return JetStreamDelivery{}, fmt.Errorf("%w: message or tenant is invalid", ErrJetStreamEnvelope)
	}
	subject := message.Subject()
	expectedPrefix := subjectPrefix + "." + tenantID + "."
	if !validNATSSubject(subject, false) || !strings.HasPrefix(subject, expectedPrefix) || len(subject) == len(expectedPrefix) {
		return JetStreamDelivery{}, fmt.Errorf("%w: subject is outside the tenant namespace", ErrJetStreamEnvelope)
	}
	headers := message.Headers()
	if headers.Get(tenantHeader) != tenantID {
		return JetStreamDelivery{}, fmt.Errorf("%w: tenant header does not match subject", ErrJetStreamEnvelope)
	}
	var external cloudevents.Event
	if err := json.Unmarshal(message.Data(), &external); err != nil {
		return JetStreamDelivery{}, fmt.Errorf("%w: decode CloudEvent: %v", ErrJetStreamEnvelope, err)
	}
	if err := external.Validate(); err != nil {
		return JetStreamDelivery{}, fmt.Errorf("%w: validate CloudEvent: %v", ErrJetStreamEnvelope, err)
	}
	if headers.Get(nats.MsgIdHdr) != external.ID || headers.Get(traceparentHeader) != external.Traceparent || headers.Get(tracestateHeader) != external.Tracestate {
		return JetStreamDelivery{}, fmt.Errorf("%w: message headers do not match CloudEvent correlation", ErrJetStreamEnvelope)
	}
	metadata, err := message.Metadata()
	if err != nil {
		return JetStreamDelivery{}, fmt.Errorf("%w: message metadata: %v", ErrJetStreamEnvelope, err)
	}
	return JetStreamDelivery{Event: external, TenantID: tenantID, Subject: subject, DeliveryAttempt: metadata.NumDelivered, message: message}, nil
}

func validDurableName(value string) bool {
	return value != "" && validNATSToken(value)
}

func validNATSToken(value string) bool {
	if value == "" || strings.ContainsAny(value, ".*>/\\ \t\r\n") {
		return false
	}
	for _, character := range value {
		if character < 33 || character > 126 {
			return false
		}
	}
	return true
}

func validNATSSubject(value string, allowWildcards bool) bool {
	if value == "" || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") || strings.ContainsAny(value, " \t\r\n/\\") {
		return false
	}
	for _, token := range strings.Split(value, ".") {
		if token == "" {
			return false
		}
		if strings.ContainsAny(token, "*>") && (!allowWildcards || (token != "*" && token != ">")) {
			return false
		}
		for _, character := range token {
			if character < 33 || character > 126 {
				return false
			}
		}
	}
	return true
}

func validTenantFilter(subject, subjectPrefix, tenantID string) bool {
	prefix := subjectPrefix + "." + tenantID + "."
	return validNATSSubject(subject, true) && strings.HasPrefix(subject, prefix) && len(subject) > len(prefix)
}

func validHeaderValue(value string) bool {
	return !strings.ContainsAny(value, "\r\n")
}
