package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

type Severity string

const (
	SeverityDebug    Severity = "DEBUG"
	SeverityInfo     Severity = "INFO"
	SeverityWarn     Severity = "WARN"
	SeverityError    Severity = "ERROR"
	SeverityCritical Severity = "CRITICAL"
)

const EventModelCost = "aor.model.cost"

type LogRecord struct {
	Timestamp   time.Time         `json:"timestamp"`
	Severity    Severity          `json:"severity"`
	EventName   string            `json:"event_name"`
	Correlation Correlation       `json:"correlation"`
	TraceID     string            `json:"trace_id"`
	SpanID      string            `json:"span_id"`
	Attributes  map[string]string `json:"attributes"`
}

type ApplicationSink interface {
	ApplicationDestination() string
	WriteApplication(context.Context, []byte) error
}

type Logger struct {
	sink   ApplicationSink
	limits Limits
	clock  func() time.Time
}

func NewLogger(sink ApplicationSink, limits Limits) (*Logger, error) {
	if sink == nil || sink.ApplicationDestination() == "" {
		return nil, fmt.Errorf("%w: application sink is required", ErrInvalidAttribute)
	}
	return &Logger{sink: sink, limits: limits.normalized(), clock: time.Now}, nil
}

func (l *Logger) SetClockForTest(clock func() time.Time) {
	if clock != nil {
		l.clock = clock
	}
}

func (l *Logger) Emit(ctx context.Context, severity Severity, eventName string, correlation Correlation, trace TraceContext, attributes map[string]string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if !validSeverity(severity) || !attributeKeyPattern.MatchString(eventName) || len(eventName) > 128 {
		return ErrInvalidAttribute
	}
	if err := correlation.Validate(); err != nil {
		return err
	}
	if !trace.Empty() {
		if err := trace.Validate(); err != nil {
			return err
		}
	}
	safe, _, err := sanitizeAttributes(attributes, l.limits)
	if err != nil {
		return err
	}
	record := LogRecord{
		Timestamp:   l.clock().UTC(),
		Severity:    severity,
		EventName:   eventName,
		Correlation: correlation,
		TraceID:     trace.TraceID,
		SpanID:      trace.SpanID,
		Attributes:  safe,
	}
	payload, err := boundedLogPayload(record, l.limits.MaxEventBytes)
	if err != nil {
		return err
	}
	return l.sink.WriteApplication(ctx, payload)
}

func boundedLogPayload(record LogRecord, maximum int) ([]byte, error) {
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if len(payload) <= maximum {
		return payload, nil
	}
	keys := make([]string, 0, len(record.Attributes))
	for key := range record.Attributes {
		keys = append(keys, key)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	for _, key := range keys {
		delete(record.Attributes, key)
		payload, err = json.Marshal(record)
		if err != nil {
			return nil, err
		}
		if len(payload) <= maximum {
			return payload, nil
		}
	}
	return nil, ErrEventTooLarge
}

func validSeverity(severity Severity) bool {
	switch severity {
	case SeverityDebug, SeverityInfo, SeverityWarn, SeverityError, SeverityCritical:
		return true
	default:
		return false
	}
}

type JSONLineApplicationSink struct {
	destination string
	writer      io.Writer
	mu          sync.Mutex
}

func NewJSONLineApplicationSink(destination string, writer io.Writer) (*JSONLineApplicationSink, error) {
	if destination == "" || writer == nil {
		return nil, ErrInvalidAttribute
	}
	return &JSONLineApplicationSink{destination: destination, writer: writer}, nil
}

func (s *JSONLineApplicationSink) ApplicationDestination() string {
	return s.destination
}

func (s *JSONLineApplicationSink) WriteApplication(_ context.Context, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := append(append([]byte(nil), payload...), '\n')
	_, err := s.writer.Write(line)
	return err
}

type MemoryApplicationSink struct {
	Destination string
	mu          sync.Mutex
	Records     [][]byte
}

func (s *MemoryApplicationSink) ApplicationDestination() string {
	return s.Destination
}

func (s *MemoryApplicationSink) WriteApplication(_ context.Context, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Records = append(s.Records, append([]byte(nil), payload...))
	return nil
}
