package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

const (
	TraceParentHeader = "traceparent"
	TraceStateHeader  = "tracestate"
)

type TraceContext struct {
	TraceID    string `json:"trace_id"`
	SpanID     string `json:"span_id"`
	TraceFlags byte   `json:"trace_flags"`
	TraceState string `json:"tracestate,omitempty"`
}

func (t TraceContext) Empty() bool {
	return t.TraceID == "" && t.SpanID == "" && t.TraceFlags == 0 && t.TraceState == ""
}

func (t TraceContext) Validate() error {
	if !validHexID(t.TraceID, 16) || !validHexID(t.SpanID, 8) || !validTraceState(t.TraceState) {
		return ErrInvalidTraceContext
	}
	return nil
}

func (t TraceContext) TraceParent() (string, error) {
	if err := t.Validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf("00-%s-%s-%02x", t.TraceID, t.SpanID, t.TraceFlags), nil
}

func ParseTraceParent(value, traceState string) (TraceContext, error) {
	if len(value) != 55 || value[2] != '-' || value[35] != '-' || value[52] != '-' || value[:2] != "00" {
		return TraceContext{}, ErrInvalidTraceContext
	}
	flags, err := hex.DecodeString(value[53:55])
	if err != nil || len(flags) != 1 {
		return TraceContext{}, ErrInvalidTraceContext
	}
	parsed := TraceContext{TraceID: value[3:35], SpanID: value[36:52], TraceFlags: flags[0], TraceState: traceState}
	if err := parsed.Validate(); err != nil {
		return TraceContext{}, err
	}
	return parsed, nil
}

func NewRootTraceContext(sampled bool) (TraceContext, error) {
	traceID, err := randomHex(16)
	if err != nil {
		return TraceContext{}, err
	}
	spanID, err := randomHex(8)
	if err != nil {
		return TraceContext{}, err
	}
	var flags byte
	if sampled {
		flags = 1
	}
	return TraceContext{TraceID: traceID, SpanID: spanID, TraceFlags: flags}, nil
}

type TextMapCarrier interface {
	Get(string) string
	Set(string, string)
}

type MapCarrier map[string]string

func (m MapCarrier) Get(key string) string {
	for existing, value := range m {
		if strings.EqualFold(existing, key) {
			return value
		}
	}
	return ""
}

func (m MapCarrier) Set(key, value string) {
	m[strings.ToLower(key)] = value
}

func InjectTrace(carrier TextMapCarrier, trace TraceContext) error {
	if carrier == nil {
		return ErrInvalidTraceContext
	}
	if mapped, ok := carrier.(MapCarrier); ok && mapped == nil {
		return ErrInvalidTraceContext
	}
	parent, err := trace.TraceParent()
	if err != nil {
		return err
	}
	carrier.Set(TraceParentHeader, parent)
	if trace.TraceState != "" {
		carrier.Set(TraceStateHeader, trace.TraceState)
	}
	return nil
}

func ExtractTrace(carrier TextMapCarrier) (TraceContext, error) {
	if carrier == nil {
		return TraceContext{}, ErrTraceContextMissing
	}
	parent := carrier.Get(TraceParentHeader)
	if parent == "" {
		return TraceContext{}, ErrTraceContextMissing
	}
	return ParseTraceParent(parent, carrier.Get(TraceStateHeader))
}

type traceContextKey struct{}

func ContextWithTrace(ctx context.Context, trace TraceContext) (context.Context, error) {
	if err := trace.Validate(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, traceContextKey{}, trace), nil
}

func TraceFromContext(ctx context.Context) (TraceContext, bool) {
	if ctx == nil {
		return TraceContext{}, false
	}
	trace, ok := ctx.Value(traceContextKey{}).(TraceContext)
	return trace, ok
}

func randomHex(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func validHexID(value string, bytes int) bool {
	if len(value) != bytes*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return false
	}
	for _, item := range decoded {
		if item != 0 {
			return true
		}
	}
	return false
}

var traceStateKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_*/-]{0,255}(?:@[a-z0-9][a-z0-9_*/-]{0,13})?$`)

func validTraceState(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 512 {
		return false
	}
	members := strings.Split(value, ",")
	if len(members) > 32 {
		return false
	}
	seen := map[string]struct{}{}
	for _, raw := range members {
		member := strings.TrimSpace(raw)
		parts := strings.SplitN(member, "=", 2)
		if len(parts) != 2 || !traceStateKeyPattern.MatchString(parts[0]) || parts[1] == "" || len(parts[1]) > 256 || strings.ContainsAny(parts[1], ",=") {
			return false
		}
		if _, exists := seen[parts[0]]; exists {
			return false
		}
		seen[parts[0]] = struct{}{}
		for _, character := range parts[1] {
			if character < 0x20 || character > 0x7e {
				return false
			}
		}
	}
	return true
}
