package workflow

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/akimisaka/aor/pkg/contracts"
	temporalclient "go.temporal.io/sdk/client"
)

func TestPostgresReadyExecutionSourceAcceptsNullableReusableIdentity(t *testing.T) {
	database, err := sql.Open("execution-scheduler-test", "")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	source, err := NewPostgresReadyExecutionSource(database)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := source.ReadyExecutions(context.Background(), 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(ready) != 2 || ready[0].ReusableExecutionID != "" || ready[1].ReusableExecutionID != "exec_"+strings.Repeat("a", 64) {
		t.Fatalf("ready = %#v", ready)
	}
}

func TestProjectExecutionStarterReusesUnboundAssignmentIdentity(t *testing.T) {
	tests := []struct {
		name           string
		executionID    string
		wantActivityID string
		wantRecovery   bool
	}{
		{
			name:           "initial execution",
			executionID:    "exec_" + strings.Repeat("a", 64),
			wantActivityID: "execute_" + strings.Repeat("a", 64),
		},
		{
			name:           "recovery execution",
			executionID:    "recover_" + strings.Repeat("b", 64),
			wantActivityID: "recover_" + strings.Repeat("b", 64),
			wantRecovery:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &executionStarterClient{}
			starter, err := NewProjectExecutionStarter(client, "execution-queue")
			if err != nil {
				t.Fatal(err)
			}
			ready := ReadyExecution{
				TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1",
				TaskVersion: 4, TaskState: contracts.TaskExecuting, FencingToken: 3,
				Recovery: true, ReusableExecutionID: test.executionID,
			}
			result, err := starter.Ensure(context.Background(), ready)
			if err != nil {
				t.Fatal(err)
			}
			identity := strings.TrimPrefix(strings.TrimPrefix(test.executionID, "exec_"), "recover_")
			if result.WorkflowID != executionWorkflowIdentityPrefix+identity || len(client.calls) != 1 {
				t.Fatalf("result = %#v calls = %#v", result, client.calls)
			}
			call := client.calls[0]
			if call.options.ID != executionWorkflowIdentityPrefix+identity || call.options.TaskQueue != "execution-queue" || call.workflow != ProjectExecutionWorkflowName {
				t.Fatalf("call = %#v", call)
			}
			if call.input.ActivityID != test.wantActivityID {
				t.Fatalf("activity ID = %q", call.input.ActivityID)
			}
			var payload struct {
				Action      string `json:"action"`
				ExecutionID string `json:"executionId"`
				Recovery    bool   `json:"recovery"`
			}
			if err := json.Unmarshal(call.input.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Action != ExecutionActivityAction || payload.ExecutionID != test.executionID || payload.Recovery != test.wantRecovery {
				t.Fatalf("payload = %#v", payload)
			}
		})
	}
}

func TestProjectExecutionStarterRejectsInvalidReusableIdentity(t *testing.T) {
	tests := []ReadyExecution{
		{ReusableExecutionID: "execute_" + strings.Repeat("a", 64)},
		{ReusableExecutionID: "exec_" + strings.Repeat("a", 63)},
		{ReusableExecutionID: "recover_" + strings.Repeat("g", 64)},
		{ReusableExecutionID: "exec_" + strings.Repeat("A", 64)},
		{TaskState: contracts.TaskReadyExecution, Recovery: false, ReusableExecutionID: "exec_" + strings.Repeat("a", 64)},
	}
	for _, ready := range tests {
		client := &executionStarterClient{}
		starter, err := NewProjectExecutionStarter(client, "execution-queue")
		if err != nil {
			t.Fatal(err)
		}
		ready.TenantID = "tenant-1"
		ready.ProjectID = "project-1"
		ready.TaskID = "task-1"
		ready.TaskVersion = 4
		if ready.TaskState == "" {
			ready.TaskState = contracts.TaskExecuting
			ready.Recovery = true
		}
		ready.FencingToken = 3
		if _, err := starter.Ensure(context.Background(), ready); !errors.Is(err, ErrInvalidExecutionScheduler) {
			t.Fatalf("execution ID %q error = %v", ready.ReusableExecutionID, err)
		}
		if len(client.calls) != 0 {
			t.Fatalf("execution ID %q dispatched %#v", ready.ReusableExecutionID, client.calls)
		}
	}
}

type executionStarterCall struct {
	options  temporalclient.StartWorkflowOptions
	workflow interface{}
	input    ExecutionInput
}

type executionStarterClient struct {
	calls []executionStarterCall
}

func (client *executionStarterClient) ExecuteWorkflow(_ context.Context, options temporalclient.StartWorkflowOptions, workflow interface{}, args ...interface{}) (temporalclient.WorkflowRun, error) {
	if len(args) != 1 {
		return nil, errors.New("invalid execution input")
	}
	input, ok := args[0].(ExecutionInput)
	if !ok {
		return nil, errors.New("invalid execution input")
	}
	client.calls = append(client.calls, executionStarterCall{options: options, workflow: workflow, input: input})
	return nil, nil
}

var _ executionWorkflowClient = (*executionStarterClient)(nil)

type executionSchedulerTestDriver struct{}

func (executionSchedulerTestDriver) Open(string) (driver.Conn, error) {
	return executionSchedulerTestConn{}, nil
}

type executionSchedulerTestConn struct{}

func (executionSchedulerTestConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not supported")
}

func (executionSchedulerTestConn) Close() error { return nil }

func (executionSchedulerTestConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not supported")
}

func (executionSchedulerTestConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "aor_ready_execution_tasks_v3") {
		return &executionSchedulerTestRows{
			columns: []string{"tenant_id", "project_id", "task_id", "state_version", "task_state", "fencing_token", "recovery", "reusable_execution_id"},
			values: [][]driver.Value{
				{"tenant-1", "project-1", "task-1", int64(1), string(contracts.TaskReadyExecution), int64(0), false, nil},
				{"tenant-1", "project-1", "task-2", int64(2), string(contracts.TaskExecuting), int64(1), true, "exec_" + strings.Repeat("a", 64)},
			},
		}, nil
	}
	if strings.Contains(query, "aor_scheduler_trace_context") {
		return &executionSchedulerTestRows{columns: []string{"traceparent", "tracestate"}}, nil
	}
	return nil, errors.New("unexpected query")
}

type executionSchedulerTestRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (rows *executionSchedulerTestRows) Columns() []string { return rows.columns }

func (rows *executionSchedulerTestRows) Close() error { return nil }

func (rows *executionSchedulerTestRows) Next(destination []driver.Value) error {
	if rows.index >= len(rows.values) {
		return io.EOF
	}
	copy(destination, rows.values[rows.index])
	rows.index++
	return nil
}

func init() {
	sql.Register("execution-scheduler-test", executionSchedulerTestDriver{})
}

var _ driver.QueryerContext = executionSchedulerTestConn{}
