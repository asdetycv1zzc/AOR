package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoggerRequiresIdentifierOrExplicitReason(t *testing.T) {
	sink := &MemoryApplicationSink{Destination: "app://logs"}
	logger, err := NewLogger(sink, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	correlation := validCorrelation()
	correlation.TaskID = ""
	if err := logger.Emit(context.Background(), SeverityInfo, "aor.test", correlation, TraceContext{}, nil); !errors.Is(err, ErrInvalidCorrelation) {
		t.Fatalf("expected invalid correlation, got %v", err)
	}
	correlation.TaskIDReason = ReasonNotCreated
	if err := logger.Emit(context.Background(), SeverityInfo, "aor.test", correlation, TraceContext{}, nil); err != nil {
		t.Fatal(err)
	}
	var record LogRecord
	if err := json.Unmarshal(sink.Records[0], &record); err != nil {
		t.Fatal(err)
	}
	if record.Correlation.TaskID != "" || record.Correlation.TaskIDReason != ReasonNotCreated {
		t.Fatalf("missing identifier reason was not retained: %#v", record.Correlation)
	}
}

func TestLoggerBoundsAndRedactsSensitiveContent(t *testing.T) {
	sink := &MemoryApplicationSink{Destination: "app://logs"}
	logger, err := NewLogger(sink, Limits{MaxEventBytes: 1024, MaxAttributes: 12, MaxAttributeValueBytes: 80})
	if err != nil {
		t.Fatal(err)
	}
	logger.SetClockForTest(func() time.Time { return time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC) })
	attributes := map[string]string{
		"prompt.body":        "do not persist this prompt",
		"source.code":        "package secret",
		"hidden_test.output": "private assertion",
		"authorization":      "Bearer abcdefghijklmnop",
		"error.code":         "provider failed for admin@example.com with api_key=abcdefghijk",
		"aor.module.id":      strings.Repeat("m", 400),
	}
	if err := logger.Emit(context.Background(), SeverityError, "aor.model.failed", validCorrelation(), TraceContext{}, attributes); err != nil {
		t.Fatal(err)
	}
	payload := sink.Records[0]
	if len(payload) > 1024 {
		t.Fatalf("event exceeded bound: %d", len(payload))
	}
	for _, forbidden := range []string{"do not persist", "package secret", "private assertion", "abcdefghijklmnop", "admin@example.com", "abcdefghijk"} {
		if bytes.Contains(payload, []byte(forbidden)) {
			t.Fatalf("sensitive value leaked: %s", forbidden)
		}
	}
	if !bytes.Contains(payload, []byte("REDACTED")) {
		t.Fatal("redaction marker missing")
	}
}

func TestApplicationAndAuditDestinationsMustDiffer(t *testing.T) {
	application := &MemoryApplicationSink{Destination: "otlp://logs"}
	audit := &MemoryAuditStore{Destination: "otlp://logs"}
	if !errors.Is(ValidateSinkSeparation(application, audit), ErrSinkNotSeparated) {
		t.Fatal("same destination was accepted")
	}
	audit.Destination = "worm://audit"
	if err := ValidateSinkSeparation(application, audit); err != nil {
		t.Fatal(err)
	}
}

func validCorrelation() Correlation {
	return Correlation{ProjectID: "project:1", WorkflowID: "workflow:1", TaskID: "task:1", AgentRunID: "run:1"}
}
