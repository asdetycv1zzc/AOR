package goalplan

import (
	"context"
	"errors"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/pkg/aop"
)

// RuntimeInvocation is the fully authorized, immutable input needed to execute
// one Goal or Plan layer model call through Agent Runtime.
type RuntimeInvocation struct {
	Declaration agentruntime.Declaration
	Lease       agentruntime.AgentLease
	ModelCall   agentruntime.ModelCall
	Intent      aop.Intent
}

// RuntimeInvocationPreparer resolves policy, identity, prompt, context, budget,
// and lease bindings from authoritative services. It must not trust fields in
// AgentInvocation when constructing those bindings.
type RuntimeInvocationPreparer interface {
	Prepare(context.Context, AgentInvocation) (RuntimeInvocation, error)
}

// RuntimeAgentInvoker executes each model request through the complete Runtime
// declaration, lease, generation, and result-validation lifecycle.
type RuntimeAgentInvoker struct {
	runtime runtimeExecutor
	prepare RuntimeInvocationPreparer
}

type runtimeExecutor interface {
	Declare(agentruntime.Declaration) error
	Queue(string) error
	AssignLease(context.Context, string, agentruntime.AgentLease) error
	Start(context.Context, string) error
	Heartbeat(context.Context, string) error
	Generate(context.Context, string, agentruntime.ModelCall) (modelgateway.NormalizedResponse, error)
	Complete(context.Context, string, agentruntime.AgentOutput) (agentruntime.AcceptedResult, error)
	AcceptedResult(string) (agentruntime.AcceptedResult, bool)
	Fail(string) error
}

func NewRuntimeAgentInvoker(runtime runtimeExecutor, prepare RuntimeInvocationPreparer) (*RuntimeAgentInvoker, error) {
	if runtime == nil || prepare == nil {
		return nil, ErrInvalidRequest
	}
	return &RuntimeAgentInvoker{runtime: runtime, prepare: prepare}, nil
}

func (invoker *RuntimeAgentInvoker) Invoke(ctx context.Context, request AgentInvocation) (AgentRecord, error) {
	if invoker == nil || invoker.runtime == nil || invoker.prepare == nil || ctx == nil || !validAgentInvocation(request) {
		return AgentRecord{}, ErrInvalidRequest
	}
	prepared, err := invoker.prepare.Prepare(ctx, request)
	if err != nil {
		return AgentRecord{}, err
	}
	if err := validateRuntimeInvocation(request, prepared); err != nil {
		return AgentRecord{}, err
	}
	runID := prepared.Declaration.RunID
	if err := invoker.runtime.Declare(prepared.Declaration); err != nil {
		if errors.Is(err, agentruntime.ErrRunExists) {
			return invoker.completedRecord(request, prepared)
		}
		return AgentRecord{}, err
	}
	fail := func(cause error) (AgentRecord, error) {
		_ = invoker.runtime.Fail(runID)
		return AgentRecord{}, cause
	}
	if err := invoker.runtime.Queue(runID); err != nil {
		return fail(err)
	}
	if err := invoker.runtime.AssignLease(ctx, runID, prepared.Lease); err != nil {
		return fail(err)
	}
	if err := invoker.runtime.Start(ctx, runID); err != nil {
		return fail(err)
	}
	response, err := invoker.generateWithHeartbeat(ctx, runID, prepared.Lease, prepared.ModelCall)
	if err != nil {
		return fail(err)
	}
	if response.RequestID != prepared.ModelCall.RequestID || len(response.Content) == 0 {
		return fail(ErrAgentOutput)
	}
	accepted, err := invoker.runtime.Complete(ctx, runID, agentruntime.AgentOutput{Intent: prepared.Intent, Payload: append([]byte(nil), response.Content...)})
	if err != nil {
		return fail(err)
	}
	if accepted.RunID != runID || accepted.Intent != prepared.Intent || len(accepted.Payload) == 0 {
		return AgentRecord{}, ErrAgentOutput
	}
	return AgentRecord{RunID: runID, AgentInstanceID: prepared.Declaration.AgentInstanceID, Role: request.Role, Payload: append([]byte(nil), accepted.Payload...)}, nil
}

func (invoker *RuntimeAgentInvoker) generateWithHeartbeat(ctx context.Context, runID string, lease agentruntime.AgentLease, call agentruntime.ModelCall) (modelgateway.NormalizedResponse, error) {
	interval := time.Duration(lease.HeartbeatIntervalSeconds) * time.Second
	if interval <= 0 {
		return modelgateway.NormalizedResponse{}, agentruntime.ErrLeaseInvalid
	}
	heartbeatCtx, cancel := context.WithCancel(ctx)
	heartbeatErr := make(chan error, 1)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := invoker.runtime.Heartbeat(heartbeatCtx, runID); err != nil {
					if heartbeatCtx.Err() == nil {
						heartbeatErr <- err
						cancel()
					}
					return
				}
			case <-heartbeatCtx.Done():
				return
			}
		}
	}()
	response, err := invoker.runtime.Generate(heartbeatCtx, runID, call)
	cancel()
	<-heartbeatDone
	select {
	case err = <-heartbeatErr:
	default:
	}
	return response, err
}

func (invoker *RuntimeAgentInvoker) completedRecord(request AgentInvocation, prepared RuntimeInvocation) (AgentRecord, error) {
	runID := prepared.Declaration.RunID
	accepted, found := invoker.runtime.AcceptedResult(runID)
	if !found || accepted.RunID != runID || accepted.Intent != expectedRuntimeIntent(request) || len(accepted.Payload) == 0 {
		return AgentRecord{}, ErrInvalidRequest
	}
	return AgentRecord{RunID: runID, AgentInstanceID: prepared.Declaration.AgentInstanceID, Role: request.Role, Payload: append([]byte(nil), accepted.Payload...)}, nil
}

func validAgentInvocation(request AgentInvocation) bool {
	if request.InvocationID == "" || request.TenantID == "" || request.ProjectID == "" || !request.Role.Valid() || request.Stage == "" || expectedRuntimeIntent(request) == "" {
		return false
	}
	if request.Role == agentruntime.RoleKnowledgeCurator {
		return request.TaskID == ""
	}
	return (request.Role == agentruntime.RoleModulePlanner) == (request.TaskID != "")
}

func validateRuntimeInvocation(request AgentInvocation, prepared RuntimeInvocation) error {
	declaration := prepared.Declaration
	if declaration.RunID != request.InvocationID || declaration.TenantID != request.TenantID || declaration.ProjectID != request.ProjectID || declaration.TaskID != request.TaskID || declaration.Role != request.Role || declaration.AgentInstanceID == "" || prepared.Lease.AgentInstanceID != declaration.AgentInstanceID || prepared.Lease.TenantID != request.TenantID || prepared.Lease.ProjectID != request.ProjectID || prepared.Lease.TaskID != request.TaskID || prepared.Lease.Role != request.Role || prepared.Intent != expectedRuntimeIntent(request) || prepared.ModelCall.RequestID == "" {
		return ErrInvalidRequest
	}
	return nil
}

func expectedRuntimeIntent(request AgentInvocation) aop.Intent {
	switch request.Stage {
	case "GOAL_DRAFT", "GOAL_REVISION":
		if request.Role == agentruntime.RoleGoalProposer {
			return aop.IntentProposeGoal
		}
	case "GOAL_CHALLENGE":
		if request.Role == agentruntime.RoleGoalChallenger {
			return aop.IntentChallengeGoal
		}
	case "PLAN_DRAFT":
		if request.Role == agentruntime.RolePlanSupervisor {
			return aop.IntentProposePlan
		}
	case "PLAN_SUMMARY":
		if request.Role == agentruntime.RolePlanSupervisor {
			return aop.IntentReportPlanComplete
		}
	case "MODULE_SPEC":
		if request.Role == agentruntime.RoleModulePlanner {
			return aop.IntentDefineModule
		}
	case "KNOWLEDGE_UPDATE_DRAFT":
		if request.Role == agentruntime.RoleKnowledgeCurator {
			return aop.IntentReturnKnowledgeRefs
		}
	}
	return ""
}

var _ AgentInvoker = (*RuntimeAgentInvoker)(nil)
