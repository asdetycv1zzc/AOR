package agentruntime

import (
	"errors"
	"testing"
	"time"
)

func TestLifecycleTransitionMatrix(t *testing.T) {
	expected := map[State][]State{
		StateDeclared:          {StateQueued, StateCanceled, StateTerminated},
		StateQueued:            {StateLeased, StateCanceled, StateTerminated},
		StateLeased:            {StateStarting, StateCanceled, StateExpired, StateTerminated},
		StateStarting:          {StateRunning, StateFailed, StateCanceled, StateExpired, StateTerminated},
		StateRunning:           {StateWaitingInput, StateWaitingTool, StateWaitingDependency, StateCompleted, StateFailed, StateCanceled, StateExpired, StateTerminated},
		StateWaitingInput:      {StateRunning, StateFailed, StateCanceled, StateExpired, StateTerminated},
		StateWaitingTool:       {StateRunning, StateFailed, StateCanceled, StateExpired, StateTerminated},
		StateWaitingDependency: {StateRunning, StateFailed, StateCanceled, StateExpired, StateTerminated},
	}
	states := []State{
		StateDeclared, StateQueued, StateLeased, StateStarting, StateRunning, StateWaitingInput, StateWaitingTool,
		StateWaitingDependency, StateCompleted, StateFailed, StateCanceled, StateExpired, StateTerminated,
	}
	for _, from := range states {
		allowed := make(map[State]struct{}, len(expected[from]))
		for _, target := range expected[from] {
			allowed[target] = struct{}{}
		}
		for _, to := range states {
			_, want := allowed[to]
			if got := validTransition(from, to); got != want {
				t.Errorf("transition %s -> %s = %t, want %t", from, to, got, want)
			}
		}
	}
	for _, state := range states {
		wantTerminal := state == StateCompleted || state == StateFailed || state == StateCanceled || state == StateExpired || state == StateTerminated
		if state.Terminal() != wantTerminal {
			t.Errorf("terminal(%s) = %t, want %t", state, state.Terminal(), wantTerminal)
		}
	}
}

func TestRenewalMayRotateNonceButHeartbeatMayNot(t *testing.T) {
	now := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	previous := AgentLease{
		LeaseID: "lease_1", AgentInstanceID: "agent_1", TenantID: "tenant_1", ProjectID: "project_1",
		TaskID: "task_1", Role: RoleExecutor, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute),
		LastHeartbeatAt: now.Add(-time.Second), HeartbeatIntervalSeconds: DefaultHeartbeatSeconds,
		Capabilities: []string{"model.generate"}, PolicyVersion: "policy_1", BudgetAccountID: "budget_1",
		Nonce: "nonce_1", FencingToken: 1, Signature: "signature_1",
	}
	renewed := previous
	renewed.ExpiresAt = renewed.ExpiresAt.Add(time.Minute)
	renewed.LastHeartbeatAt = now
	renewed.Nonce = "nonce_2"
	renewed.FencingToken++
	renewed.Signature = "signature_2"
	if err := validateRenewedLease(previous, renewed, now); err != nil {
		t.Fatalf("renewed nonce rejected: %v", err)
	}
	heartbeat := previous
	heartbeat.LastHeartbeatAt = now
	heartbeat.Nonce = "nonce_2"
	heartbeat.Signature = "signature_2"
	if err := validateHeartbeatLease(previous, heartbeat); !errors.Is(err, ErrLeaseBinding) {
		t.Fatalf("heartbeat nonce mutation error = %v", err)
	}
}
