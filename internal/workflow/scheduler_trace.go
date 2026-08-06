package workflow

import (
	"context"
	"database/sql"

	"github.com/akimisaka/aor/internal/observability"
)

func loadSchedulerTrace(ctx context.Context, database *sql.DB, tenantID, projectID, taskID string) (string, string) {
	if ctx == nil || database == nil {
		return "", ""
	}
	var task any
	if taskID != "" {
		task = taskID
	}
	var traceparent, tracestate string
	err := database.QueryRowContext(ctx, `
SELECT traceparent, tracestate
FROM aor_scheduler_trace_context($1::uuid, $2::uuid, $3::uuid)`, tenantID, projectID, task).Scan(&traceparent, &tracestate)
	if err != nil || traceparent == "" {
		return "", ""
	}
	if _, err := observability.ParseTraceParent(traceparent, tracestate); err != nil {
		return "", ""
	}
	return traceparent, tracestate
}
