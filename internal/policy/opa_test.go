package policy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
)

func TestNewOPAClientValidatesBaseURL(t *testing.T) {
	for _, raw := range []string{"", "ftp://opa.example", "http://", "http://user@opa.example", "http://opa.example?x=1", "http://opa.example/aor"} {
		if _, err := NewOPAClient(raw); !errors.Is(err, ErrInvalidBaseURL) {
			t.Errorf("NewOPAClient(%q) error = %v, want invalid URL", raw, err)
		}
	}
}

func TestOPAClientEvaluateAllowsAndPostsExpectedInput(t *testing.T) {
	input := policyInput()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != decisionPath {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		defer request.Body.Close()
		var payload struct {
			Input authz.PolicyInput `json:"input"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Input.Action != input.Action || payload.Input.Principal.ID != input.Principal.ID {
			t.Fatalf("unexpected policy input: %#v", payload.Input)
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"result": validDecision(authz.DecisionAllow)})
	}))
	defer server.Close()

	client := mustOPAClient(t, server.URL)
	decision, err := client.Evaluate(context.Background(), input)
	if err != nil || decision.Decision != authz.DecisionAllow {
		t.Fatalf("Evaluate() = %#v, %v", decision, err)
	}
}

func TestOPAClientEvaluateReturnsDeny(t *testing.T) {
	server := decisionServer(t, http.StatusOK, map[string]any{"result": validDecision(authz.DecisionDeny)})
	defer server.Close()

	decision, err := mustOPAClient(t, server.URL).Evaluate(context.Background(), policyInput())
	if err != nil || decision.Decision != authz.DecisionDeny {
		t.Fatalf("Evaluate() = %#v, %v", decision, err)
	}
}

func TestOPAClientEvaluateLeaseGrantUsesDedicatedEntrypoint(t *testing.T) {
	input := leaseGrantInput()
	expected := authz.DecisionBinding{
		PrincipalID: input.Principal.ID, TenantID: input.Project.TenantID,
		ProjectID: input.Project.ID, ProjectVersion: input.Project.StateVersion,
		TaskID: input.Task.ID, TaskVersion: input.Task.StateVersion,
		SpecDigest: input.Task.SpecDigest, Role: input.Principal.Role,
		Action: input.Action, Resource: input.Resource,
		ParameterDigest: input.ParameterDigest, BudgetAccountID: input.Budget.AccountID,
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != leaseGrantPath {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		decision := validDecision(authz.DecisionAllow)
		decision.Binding = &expected
		_ = json.NewEncoder(writer).Encode(map[string]any{"result": decision})
	}))
	defer server.Close()

	decision, err := mustOPAClient(t, server.URL).EvaluateLeaseGrant(context.Background(), input)
	if err != nil || decision.Decision != authz.DecisionAllow || decision.Binding == nil || !reflect.DeepEqual(*decision.Binding, expected) {
		t.Fatalf("EvaluateLeaseGrant() = %#v, %v", decision, err)
	}
}

func TestOPAClientEvaluateLeaseGrantFailsClosedWithoutBinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != leaseGrantPath {
			t.Fatalf("path = %q", request.URL.Path)
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"result": validDecision(authz.DecisionAllow)})
	}))
	defer server.Close()

	decision, err := mustOPAClient(t, server.URL).EvaluateLeaseGrant(context.Background(), leaseGrantInput())
	if err == nil || decision.Decision != authz.DecisionDeny {
		t.Fatalf("EvaluateLeaseGrant() = %#v, %v; want denial", decision, err)
	}
}

func TestOPAClientEvaluateLeaseGrantRejectsInvalidInputBeforeRequest(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer server.Close()
	input := leaseGrantInput()
	input.Budget.Available = false

	decision, err := mustOPAClient(t, server.URL).EvaluateLeaseGrant(context.Background(), input)
	if err == nil || decision.Decision != authz.DecisionDeny || called {
		t.Fatalf("EvaluateLeaseGrant() = %#v, %v, called=%t", decision, err, called)
	}
}

func TestOPAClientEvaluateFailsClosedForInvalidResponses(t *testing.T) {
	oversized := `{"result":"` + strings.Repeat("x", maxResponseSize) + `"}`
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{name: "non_success", status: http.StatusServiceUnavailable, body: "unavailable"},
		{name: "missing_result", status: http.StatusOK, body: `{}`},
		{name: "unknown_field", status: http.StatusOK, body: `{"result":{"decision":"ALLOW","policyVersion":"policy_1","reasonCodes":["ALLOWED"],"extra":true}}`},
		{name: "unknown_decision", status: http.StatusOK, body: `{"result":{"decision":"MAYBE","policyVersion":"policy_1","reasonCodes":["ALLOWED"]}}`},
		{name: "multiple_documents", status: http.StatusOK, body: `{"result":{"decision":"ALLOW","policyVersion":"policy_1","reasonCodes":["ALLOWED"]}} {}`},
		{name: "oversized", status: http.StatusOK, body: oversized},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server := decisionServer(t, testCase.status, testCase.body)
			defer server.Close()

			decision, err := mustOPAClient(t, server.URL).Evaluate(context.Background(), policyInput())
			if err == nil || decision.Decision != authz.DecisionDeny {
				t.Fatalf("Evaluate() = %#v, %v; want denial and error", decision, err)
			}
		})
	}
}

func TestOPAClientEvaluateRejectsInvalidInputBeforeRequest(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer server.Close()
	input := policyInput()
	input.Action = "invalid\ninput"

	decision, err := mustOPAClient(t, server.URL).Evaluate(context.Background(), input)
	if err == nil || decision.Decision != authz.DecisionDeny || called {
		t.Fatalf("Evaluate() = %#v, %v, called=%t", decision, err, called)
	}
}

func TestOPAClientEvaluateHonorsCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(started)
		select {
		case <-request.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result := make(chan error, 1)
	go func() {
		_, err := mustOPAClient(t, server.URL).Evaluate(ctx, policyInput())
		result <- err
	}()
	<-started
	cancel()
	err := <-result
	close(release)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Evaluate() error = %v, want context canceled", err)
	}
}

func TestOPAClientHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != healthPath {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := mustOPAClient(t, server.URL).Health(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOPAClientHealthHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := mustOPAClient(t, "http://127.0.0.1:1")
	if err := client.Health(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Health() error = %v, want context canceled", err)
	}
}

func mustOPAClient(t *testing.T, baseURL string) *OPAClient {
	t.Helper()
	client, err := NewOPAClient(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func decisionServer(t *testing.T, status int, body any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != decisionPath {
			t.Fatalf("path = %q, want %q", request.URL.Path, decisionPath)
		}
		writer.WriteHeader(status)
		switch typed := body.(type) {
		case string:
			_, _ = io.WriteString(writer, typed)
		default:
			_ = json.NewEncoder(writer).Encode(typed)
		}
	}))
}

func validDecision(decision authz.Decision) authz.PolicyDecision {
	return authz.PolicyDecision{
		Decision:      decision,
		PolicyVersion: "policy_1",
		ReasonCodes:   []string{"ALLOWED"},
		RuleID:        "aor.test",
	}
}

func policyInput() authz.PolicyInput {
	return authz.PolicyInput{
		Principal: authn.Principal{ID: "service_1", Type: authn.PrincipalService, Role: authn.RoleService, TenantID: "tenant_1", ProjectID: "project_1"},
		Project:   authz.ProjectScope{TenantID: "tenant_1", ID: "project_1", State: "EXECUTING", StateVersion: 1, Classification: "INTERNAL"},
		Action:    authz.ActionGoalRead,
		Resource:  authz.Resource{Type: "goal", ID: "goal_1"},
	}
}

func leaseGrantInput() authz.PolicyInput {
	return authz.PolicyInput{
		Principal: authn.Principal{ID: "agent_1", Type: authn.PrincipalAgentInstance, Role: authn.RoleExecutor, TenantID: "tenant_1", ProjectID: "project_1"},
		Project:   authz.ProjectScope{TenantID: "tenant_1", ID: "project_1", State: "EXECUTING", StateVersion: 7, Classification: "INTERNAL"},
		Task: authz.TaskScope{
			TenantID: "tenant_1", ProjectID: "project_1", ID: "task_1", State: "EXECUTING", StateVersion: 9,
			SpecDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			OwnedPaths: []string{"internal/auth/**"}, ExecutionPlatform: "LINUX", SandboxLevel: "CONTAINER",
			WorkloadTrust: "UNTRUSTED", DeploymentProfile: "PRODUCTION",
		},
		Action:          authz.ActionToolInvoke,
		Resource:        authz.Resource{Type: "tool", ID: "tool://repository/repo.read@1.0.0"},
		ParameterDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		Budget:          authz.BudgetScope{AccountID: "budget_1", Available: true},
		Context:         authz.ExecutionContext{Platform: "LINUX", SandboxLevel: "CONTAINER"},
	}
}
