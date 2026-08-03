package agentruntime

import "testing"

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
