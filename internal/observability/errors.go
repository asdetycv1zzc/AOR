package observability

import "errors"

var (
	ErrInvalidCorrelation   = errors.New("invalid telemetry correlation context")
	ErrInvalidAttribute     = errors.New("invalid telemetry attribute")
	ErrEventTooLarge        = errors.New("telemetry event exceeds configured bounds")
	ErrInvalidTraceContext  = errors.New("invalid W3C trace context")
	ErrTraceContextMissing  = errors.New("W3C trace context is missing")
	ErrSpanEnded            = errors.New("span has already ended")
	ErrInvalidMetric        = errors.New("invalid metric point")
	ErrAuditIntegrity       = errors.New("audit log integrity verification failed")
	ErrAuditSecurityContext = errors.New("security audit event is missing mandatory context")
	ErrSinkNotSeparated     = errors.New("application and audit logs must use separate destinations")
)
