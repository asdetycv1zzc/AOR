package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/observability"
)

func applyEventTrace(ctx context.Context, requestDigest string, events []eventing.DomainEvent) {
	traceparent := fallbackTraceParent(requestDigest)
	tracestate := ""
	if trace, found := observability.TraceFromContext(ctx); found {
		if propagated, err := trace.TraceParent(); err == nil {
			traceparent = propagated
			tracestate = trace.TraceState
		}
	}
	for index := range events {
		events[index].Traceparent = traceparent
		events[index].Tracestate = tracestate
	}
}

func fallbackTraceParent(requestDigest string) string {
	value := strings.TrimPrefix(requestDigest, "sha256:")
	if len(value) < 48 || strings.Trim(value[:48], "0123456789abcdef") != "" {
		digest := sha256.Sum256([]byte(requestDigest))
		value = hex.EncodeToString(digest[:])
	}
	traceID := value[:32]
	spanID := value[32:48]
	if strings.Trim(traceID, "0") == "" || strings.Trim(spanID, "0") == "" {
		digest := sha256.Sum256([]byte("aor-trace\x00" + requestDigest))
		value = hex.EncodeToString(digest[:])
		traceID = value[:32]
		spanID = value[32:48]
	}
	return "00-" + traceID + "-" + spanID + "-00"
}
