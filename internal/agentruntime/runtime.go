package agentruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/toolbroker"
	"github.com/akimisaka/aor/pkg/aop"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type ModelGateway interface {
	Generate(ctx context.Context, request modelgateway.NormalizedRequest, options modelgateway.GenerateOptions) (modelgateway.NormalizedResponse, error)
}

type ToolBroker interface {
	Invoke(ctx context.Context, request toolbroker.ToolRequest) (toolbroker.ToolResult, error)
}

type SlotAllocator interface {
	Acquire(ctx context.Context, role Role, priority int) (func(), error)
}

type Runtime struct {
	mu        sync.RWMutex
	runs      map[string]*agentRun
	authority LeaseAuthority
	gateway   ModelGateway
	broker    ToolBroker
	slots     SlotAllocator
	clock     func() time.Time
}

type agentRun struct {
	declaration Declaration
	prompt      AssembledPrompt
	state       State
	lease       AgentLease
	busy        bool
	cancel      context.CancelFunc
	result      *AcceptedResult
}

func New(authority LeaseAuthority, gateway ModelGateway, broker ToolBroker, slots SlotAllocator, clock func() time.Time) (*Runtime, error) {
	if authority == nil || slots == nil {
		return nil, ErrInvalidDeclaration
	}
	if clock == nil {
		clock = time.Now
	}
	return &Runtime{runs: make(map[string]*agentRun), authority: authority, gateway: gateway, broker: broker, slots: slots, clock: clock}, nil
}

func (r *Runtime) Declare(declaration Declaration) error {
	assembled, err := validateDeclaration(declaration, r.clock())
	if err != nil {
		return err
	}
	declaration = cloneDeclaration(declaration)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.runs[declaration.RunID]; exists {
		return ErrRunExists
	}
	r.runs[declaration.RunID] = &agentRun{declaration: declaration, prompt: assembled, state: StateDeclared}
	return nil
}

func (r *Runtime) Queue(runID string) error {
	return r.transition(runID, StateQueued)
}

func (r *Runtime) AssignLease(ctx context.Context, runID string, lease AgentLease) error {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.RLock()
	run := r.runs[runID]
	if run == nil {
		r.mu.RUnlock()
		return ErrRunNotFound
	}
	declaration := run.declaration
	state := run.state
	r.mu.RUnlock()
	if state != StateQueued {
		return ErrInvalidTransition
	}
	if err := validateLeaseShape(lease, r.clock()); err != nil {
		return err
	}
	if err := validateLeaseBinding(lease, declaration); err != nil {
		return err
	}
	if err := r.authority.Validate(ctx, cloneLease(lease), LeaseOperationAssign); err != nil {
		return ErrLeaseInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	run = r.runs[runID]
	if run == nil {
		return ErrRunNotFound
	}
	if run.state != StateQueued || run.busy {
		return ErrInvalidTransition
	}
	run.lease = cloneLease(lease)
	run.state = StateLeased
	return nil
}

func (r *Runtime) Start(ctx context.Context, runID string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	run := r.runs[runID]
	if run == nil {
		r.mu.Unlock()
		return ErrRunNotFound
	}
	if run.state != StateLeased || run.busy {
		r.mu.Unlock()
		return ErrInvalidTransition
	}
	run.state = StateStarting
	lease := cloneLease(run.lease)
	r.mu.Unlock()
	if err := r.validateLease(ctx, runID, lease, "", LeaseOperationAssign); err != nil {
		r.rollbackStart(runID)
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	run = r.runs[runID]
	if run == nil {
		return ErrRunNotFound
	}
	if run.state != StateStarting {
		return ErrInvalidTransition
	}
	run.state = StateRunning
	return nil
}

func (r *Runtime) Wait(runID string, waiting State) error {
	if waiting != StateWaitingInput && waiting != StateWaitingTool && waiting != StateWaitingDependency {
		return ErrInvalidTransition
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	run := r.runs[runID]
	if run == nil {
		return ErrRunNotFound
	}
	if run.busy || !validTransition(run.state, waiting) {
		return ErrInvalidTransition
	}
	run.state = waiting
	return nil
}

func (r *Runtime) Resume(runID string) error {
	return r.transition(runID, StateRunning)
}

func (r *Runtime) Fail(runID string) error {
	return r.transition(runID, StateFailed)
}

func (r *Runtime) Cancel(runID string) error {
	return r.stop(runID, StateCanceled)
}

func (r *Runtime) Terminate(runID string) error {
	return r.stop(runID, StateTerminated)
}

func (r *Runtime) Heartbeat(ctx context.Context, runID string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	lease, err := r.currentLease(runID)
	if err != nil {
		return err
	}
	if err := validateLeaseShape(lease, r.clock()); err != nil {
		r.expire(runID)
		return err
	}
	updated, err := r.authority.Heartbeat(ctx, cloneLease(lease))
	if err != nil {
		return r.authorityFailure(runID, err)
	}
	if err := validateRenewedLease(lease, updated, r.clock()); err != nil || validateHeartbeatRenewalLease(lease, updated, r.clock()) != nil {
		r.expire(runID)
		if err != nil {
			return err
		}
		return ErrLeaseInvalid
	}
	return r.replaceLease(runID, lease, updated)
}

func (r *Runtime) RenewLease(ctx context.Context, runID string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	lease, err := r.currentLease(runID)
	if err != nil {
		return err
	}
	if err := validateLeaseShape(lease, r.clock()); err != nil {
		r.expire(runID)
		return err
	}
	updated, err := r.authority.Renew(ctx, cloneLease(lease))
	if err != nil {
		return r.authorityFailure(runID, err)
	}
	expectedFencing := lease.FencingToken + 1
	if lease.TaskID != "" && lease.Role == RoleExecutor {
		expectedFencing = lease.FencingToken
	}
	if err := validateRenewedLease(lease, updated, r.clock()); err != nil || !updated.ExpiresAt.After(lease.ExpiresAt) || updated.FencingToken != expectedFencing {
		r.expire(runID)
		if err != nil {
			return err
		}
		return ErrLeaseInvalid
	}
	if err := r.authority.Validate(ctx, cloneLease(updated), LeaseOperationRenew); err != nil {
		return r.authorityFailure(runID, err)
	}
	return r.replaceLease(runID, lease, updated)
}

func (r *Runtime) Generate(ctx context.Context, runID string, call ModelCall) (modelgateway.NormalizedResponse, error) {
	return r.generate(ctx, runID, call, nil)
}

func (r *Runtime) generate(ctx context.Context, runID string, call ModelCall, messages []modelgateway.Message) (modelgateway.NormalizedResponse, error) {
	if r.gateway == nil {
		return modelgateway.NormalizedResponse{}, ErrProviderUnavailable
	}
	if validateModelCall(call) != nil {
		return modelgateway.NormalizedResponse{}, modelgateway.ErrInvalidRequest
	}
	opCtx, executionLease, declaration, prompt, finish, err := r.beginOperation(ctx, runID, "model.generate", LeaseOperationModel, false)
	if err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	defer finish()
	lease, err := r.operationLease(opCtx, executionLease, OperationLeaseRequest{
		Operation: LeaseOperationModel, RequestID: call.RequestID, Provider: call.Provider, Model: call.Model, ModelCall: call,
	})
	if err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	release, err := r.slots.Acquire(opCtx, declaration.Role, declarationPriority(declaration))
	if err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	defer release()
	if err := r.operationReady(opCtx, runID, executionLease, "model.generate", LeaseOperationModel, false); err != nil {
		return modelgateway.NormalizedResponse{}, err
	}
	if messages == nil {
		messages = prompt.Messages
	}
	request := modelgateway.NormalizedRequest{
		RequestID: call.RequestID, TenantID: declaration.TenantID, ProjectID: declaration.ProjectID,
		TaskID: declaration.TaskID, AgentInstanceID: declaration.AgentInstanceID, Role: string(declaration.Role),
		Model: call.Model, PromptBundleVersion: declaration.PromptBundle.Version, Messages: cloneMessages(messages),
		Tools: cloneToolDefinitions(declaration.Tools), ResponseSchemaRef: declaration.ResponseSchemaRef,
		ResponseSchema: append(json.RawMessage(nil), declaration.ResponseSchema...), ResponseSemanticValidator: declaration.ResponseSemanticValidator,
		MaxOutputTokens: call.MaxOutputTokens,
		Temperature:     call.Temperature, ProviderPolicy: call.ProviderPolicy,
		DataClassification: declaration.DataClassification, CachePolicy: call.CachePolicy, PromptDigest: prompt.SHA256,
		ToolSchemaDigest: declaration.ToolSchemaDigest, PolicyDigest: declaration.PolicyDigest, WorstCaseCostMicros: call.WorstCaseCostMicros,
	}
	if call.Seed != nil {
		seed := *call.Seed
		request.Seed = &seed
	}
	response, callErr := r.gateway.Generate(opCtx, request, modelgateway.GenerateOptions{Provider: call.Provider, AccountID: lease.BudgetAccountID, ReservationID: call.ReservationID, MaxAttempts: call.MaxAttempts})
	if callErr != nil {
		return modelgateway.NormalizedResponse{}, callErr
	}
	if sameLeaseRevision(lease, executionLease) {
		if err := r.validateLease(opCtx, runID, lease, "model.generate", LeaseOperationResult); err != nil {
			return modelgateway.NormalizedResponse{}, err
		}
	} else {
		if err := r.validateDetachedLease(opCtx, lease, LeaseOperationResult); err != nil {
			return modelgateway.NormalizedResponse{}, err
		}
		if err := r.validateLease(opCtx, runID, executionLease, "", LeaseOperationResult); err != nil {
			return modelgateway.NormalizedResponse{}, err
		}
	}
	return response, nil
}

func validateModelCall(call ModelCall) error {
	if !safeProtocolString(call.RequestID, 256) || !safeProtocolString(call.Provider, 128) || !safeProtocolString(call.Model, 256) ||
		!safeProtocolString(call.ReservationID, 256) || !safeProtocolString(call.ProviderPolicy, 256) || !safeProtocolString(call.CachePolicy, 128) ||
		call.MaxOutputTokens <= 0 || call.WorstCaseCostMicros < 0 || call.MaxAttempts < 0 || call.MaxAttempts > 3 ||
		math.IsNaN(call.Temperature) || math.IsInf(call.Temperature, 0) || call.Temperature < 0 || call.Temperature > 2 {
		return modelgateway.ErrInvalidRequest
	}
	return nil
}

func (r *Runtime) InvokeTool(ctx context.Context, runID string, call ToolCall) (toolbroker.ToolResult, error) {
	if r.broker == nil {
		return toolbroker.ToolResult{}, ErrToolBrokerUnavailable
	}
	if !safeProtocolString(call.RequestID, 256) || !safeProtocolString(call.ToolID, 256) || !safeProtocolString(call.Version, 128) ||
		len(call.Parameters) == 0 || len(call.Parameters) > MaximumAgentOutputBytes || !json.Valid(call.Parameters) {
		return toolbroker.ToolResult{}, toolbroker.ErrInvalidRequest
	}
	opCtx, executionLease, declaration, _, finish, err := r.beginOperation(ctx, runID, "tool.invoke", LeaseOperationTool, true)
	if err != nil {
		return toolbroker.ToolResult{}, err
	}
	defer finish()
	lease, err := r.operationLease(opCtx, executionLease, OperationLeaseRequest{
		Operation: LeaseOperationTool, RequestID: call.RequestID, ToolID: call.ToolID,
		ToolVersion: call.Version, Parameters: append(json.RawMessage(nil), call.Parameters...),
	})
	if err != nil {
		return toolbroker.ToolResult{}, err
	}
	release, err := r.slots.Acquire(opCtx, declaration.Role, declarationPriority(declaration))
	if err != nil {
		return toolbroker.ToolResult{}, err
	}
	defer release()
	if err := r.operationReady(opCtx, runID, executionLease, "tool.invoke", LeaseOperationTool, true); err != nil {
		return toolbroker.ToolResult{}, err
	}
	request := toolbroker.ToolRequest{
		RequestID: call.RequestID, TenantID: declaration.TenantID, ProjectID: declaration.ProjectID, TaskID: declaration.TaskID,
		Principal: toolbroker.Principal{ID: declaration.AgentInstanceID, Type: "AGENT_INSTANCE", Role: string(declaration.Role)},
		Lease:     toolbroker.Lease{ID: lease.LeaseID, ExpiresAt: lease.ExpiresAt.UTC().Format(time.RFC3339Nano), FencingToken: lease.FencingToken}, ExecutionLeaseID: executionLease.LeaseID, Approval: cloneApproval(call.Approval),
		ToolID: call.ToolID, Version: call.Version, Parameters: append([]byte(nil), call.Parameters...),
		PolicyVersion: lease.PolicyVersion, BudgetAccountID: lease.BudgetAccountID,
	}
	result, callErr := r.broker.Invoke(opCtx, request)
	if callErr != nil {
		return toolbroker.ToolResult{}, callErr
	}
	if sameLeaseRevision(lease, executionLease) {
		if err := r.validateLease(opCtx, runID, lease, "tool.invoke", LeaseOperationResult); err != nil {
			return toolbroker.ToolResult{}, err
		}
	} else {
		if err := r.validateDetachedLease(opCtx, lease, LeaseOperationResult); err != nil {
			return toolbroker.ToolResult{}, err
		}
		if err := r.validateLease(opCtx, runID, executionLease, "", LeaseOperationResult); err != nil {
			return toolbroker.ToolResult{}, err
		}
	}
	return result, nil
}

func (r *Runtime) Complete(ctx context.Context, runID string, output AgentOutput) (AcceptedResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if output.Intent == "" || len(output.Payload) == 0 || len(output.Payload) > MaximumAgentOutputBytes || !json.Valid(output.Payload) {
		return AcceptedResult{}, ErrOutputInvalid
	}
	r.mu.RLock()
	run := r.runs[runID]
	if run == nil {
		r.mu.RUnlock()
		return AcceptedResult{}, ErrRunNotFound
	}
	if run.state != StateRunning || run.busy {
		r.mu.RUnlock()
		return AcceptedResult{}, ErrInvalidTransition
	}
	role := run.declaration.Role
	lease := cloneLease(run.lease)
	envelope := run.declaration.Envelope
	promptDigest := run.prompt.SHA256
	contextDigest := run.declaration.ContextManifest.SHA256
	responseSchema := append(json.RawMessage(nil), run.declaration.ResponseSchema...)
	responseSemanticValidator := run.declaration.ResponseSemanticValidator
	r.mu.RUnlock()
	if !intentAllowed(role, output.Intent) {
		return AcceptedResult{}, ErrIntentDenied
	}
	if err := validateAgentOutput(responseSchema, responseSemanticValidator, output); err != nil {
		return AcceptedResult{}, err
	}
	if err := r.validateLease(ctx, runID, lease, "", LeaseOperationResult); err != nil {
		return AcceptedResult{}, err
	}
	sum := sha256.Sum256(output.Payload)
	result := AcceptedResult{
		RunID: runID, MessageID: envelope.MessageID, IdempotencyKey: envelope.IdempotencyKey,
		CorrelationID: envelope.CorrelationID, ExpectedAggregateVersion: envelope.ExpectedAggregateVersion,
		Traceparent: envelope.TraceContext.Traceparent, Intent: output.Intent, Payload: append(json.RawMessage(nil), output.Payload...),
		OutputSHA256: "sha256:" + hex.EncodeToString(sum[:]), AcceptedAt: r.clock().UTC(), LeaseID: lease.LeaseID, FencingToken: lease.FencingToken,
		PromptDigest: promptDigest, ContextDigest: contextDigest,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	run = r.runs[runID]
	if run == nil {
		return AcceptedResult{}, ErrRunNotFound
	}
	if run.state != StateRunning || run.busy || !sameLeaseRevision(run.lease, lease) {
		return AcceptedResult{}, ErrInvalidTransition
	}
	if err := validateLeaseShape(run.lease, r.clock()); err != nil {
		run.state = StateExpired
		return AcceptedResult{}, err
	}
	run.state = StateCompleted
	run.result = &result
	return cloneResult(result), nil
}

func (r *Runtime) Snapshot(runID string) (Snapshot, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	run := r.runs[runID]
	if run == nil {
		return Snapshot{}, ErrRunNotFound
	}
	return Snapshot{
		RunID: run.declaration.RunID, TenantID: run.declaration.TenantID, ProjectID: run.declaration.ProjectID,
		TaskID: run.declaration.TaskID, AgentInstanceID: run.declaration.AgentInstanceID, Role: run.declaration.Role,
		State: run.state, LeaseID: run.lease.LeaseID, PromptBundleVersion: run.declaration.PromptBundle.Version,
		PromptDigest: run.prompt.SHA256, ContextDigest: run.declaration.ContextManifest.SHA256, Busy: run.busy,
	}, nil
}

func (r *Runtime) AcceptedResult(runID string) (AcceptedResult, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	run := r.runs[runID]
	if run == nil || run.result == nil {
		return AcceptedResult{}, false
	}
	return cloneResult(*run.result), true
}

func (r *Runtime) ExpireStale() []string {
	now := r.clock()
	r.mu.Lock()
	defer r.mu.Unlock()
	var expired []string
	for id, run := range r.runs {
		if run.state.Terminal() || run.lease.LeaseID == "" || !leaseExpired(run.lease, now) {
			continue
		}
		if validTransition(run.state, StateExpired) {
			run.state = StateExpired
			if run.cancel != nil {
				run.cancel()
			}
			expired = append(expired, id)
		}
	}
	sort.Strings(expired)
	return expired
}

func (r *Runtime) beginOperation(ctx context.Context, runID, capability string, operation LeaseOperation, tool bool) (context.Context, AgentLease, Declaration, AssembledPrompt, func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	run := r.runs[runID]
	if run == nil {
		r.mu.Unlock()
		return nil, AgentLease{}, Declaration{}, AssembledPrompt{}, nil, ErrRunNotFound
	}
	if run.state != StateRunning || run.busy {
		r.mu.Unlock()
		return nil, AgentLease{}, Declaration{}, AssembledPrompt{}, nil, ErrRunBusy
	}
	opCtx, cancel := context.WithCancel(ctx)
	run.busy = true
	run.cancel = cancel
	if tool {
		run.state = StateWaitingTool
	}
	lease := cloneLease(run.lease)
	declaration := cloneDeclaration(run.declaration)
	prompt := clonePrompt(run.prompt)
	r.mu.Unlock()
	finish := func() { r.finishOperation(runID, tool) }
	if _, dynamic := r.authority.(OperationLeaseAuthority); dynamic {
		capability = ""
		operation = LeaseOperationAssign
	}
	if err := r.validateLease(opCtx, runID, lease, capability, operation); err != nil {
		finish()
		return nil, AgentLease{}, Declaration{}, AssembledPrompt{}, nil, err
	}
	return opCtx, lease, declaration, prompt, finish, nil
}

func (r *Runtime) finishOperation(runID string, tool bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	run := r.runs[runID]
	if run == nil {
		return
	}
	if run.cancel != nil {
		run.cancel()
	}
	run.cancel = nil
	run.busy = false
	if tool && run.state == StateWaitingTool {
		run.state = StateRunning
	}
}

func (r *Runtime) validateLease(ctx context.Context, runID string, lease AgentLease, capability string, operation LeaseOperation) error {
	current, err := r.currentLease(runID)
	if err != nil {
		return err
	}
	if current.LeaseID != lease.LeaseID {
		return ErrLeaseBinding
	}
	if err := validateLeaseShape(current, r.clock()); err != nil {
		r.expire(runID)
		return err
	}
	if capability != "" && !hasCapability(current, capability) {
		return ErrCapabilityDenied
	}
	if err := r.authority.Validate(ctx, cloneLease(current), operation); err != nil {
		return r.authorityFailure(runID, err)
	}
	return nil
}

func (r *Runtime) operationReady(ctx context.Context, runID string, lease AgentLease, capability string, operation LeaseOperation, tool bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.RLock()
	run := r.runs[runID]
	if run == nil {
		r.mu.RUnlock()
		return ErrRunNotFound
	}
	expectedState := StateRunning
	if tool {
		expectedState = StateWaitingTool
	}
	ready := run.busy && run.state == expectedState
	r.mu.RUnlock()
	if !ready {
		if err := ctx.Err(); err != nil {
			return err
		}
		return ErrInvalidTransition
	}
	if _, dynamic := r.authority.(OperationLeaseAuthority); dynamic {
		capability = ""
		operation = LeaseOperationAssign
	}
	return r.validateLease(ctx, runID, lease, capability, operation)
}

func (r *Runtime) operationLease(ctx context.Context, executionLease AgentLease, request OperationLeaseRequest) (AgentLease, error) {
	authority, dynamic := r.authority.(OperationLeaseAuthority)
	if !dynamic {
		return executionLease, nil
	}
	lease, err := authority.AcquireOperationLease(ctx, cloneLease(executionLease), request)
	if err != nil || validateLeaseShape(lease, r.clock()) != nil || !operationLeaseBinding(executionLease, lease) {
		return AgentLease{}, ErrLeaseInvalid
	}
	if err := authority.Validate(ctx, cloneLease(lease), request.Operation); err != nil {
		return AgentLease{}, ErrLeaseInvalid
	}
	return lease, nil
}

func (r *Runtime) validateDetachedLease(ctx context.Context, lease AgentLease, operation LeaseOperation) error {
	if validateLeaseShape(lease, r.clock()) != nil {
		return ErrLeaseInvalid
	}
	if err := r.authority.Validate(ctx, cloneLease(lease), operation); err != nil {
		return ErrLeaseInvalid
	}
	return nil
}

func operationLeaseBinding(executionLease, operationLease AgentLease) bool {
	return executionLease.AgentInstanceID == operationLease.AgentInstanceID &&
		executionLease.TenantID == operationLease.TenantID && executionLease.ProjectID == operationLease.ProjectID &&
		executionLease.TaskID == operationLease.TaskID && executionLease.Role == operationLease.Role &&
		executionLease.PolicyVersion == operationLease.PolicyVersion && executionLease.BudgetAccountID == operationLease.BudgetAccountID &&
		executionLease.FencingToken == operationLease.FencingToken
}

func (r *Runtime) currentLease(runID string) (AgentLease, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	run := r.runs[runID]
	if run == nil {
		return AgentLease{}, ErrRunNotFound
	}
	if run.state == StateExpired {
		return AgentLease{}, ErrLeaseExpired
	}
	if run.state.Terminal() || run.lease.LeaseID == "" {
		return AgentLease{}, ErrInvalidTransition
	}
	return cloneLease(run.lease), nil
}

func (r *Runtime) replaceLease(runID string, expected, updated AgentLease) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	run := r.runs[runID]
	if run == nil {
		return ErrRunNotFound
	}
	if run.state.Terminal() || run.lease.LeaseID != expected.LeaseID || run.lease.Signature != expected.Signature || run.lease.FencingToken != expected.FencingToken ||
		!run.lease.LastHeartbeatAt.Equal(expected.LastHeartbeatAt) || !run.lease.ExpiresAt.Equal(expected.ExpiresAt) {
		return ErrInvalidTransition
	}
	run.lease = cloneLease(updated)
	return nil
}

func (r *Runtime) rollbackStart(runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	run := r.runs[runID]
	if run != nil && run.state == StateStarting {
		run.state = StateLeased
	}
}

func sameLeaseRevision(left, right AgentLease) bool {
	return left.LeaseID == right.LeaseID && left.Signature == right.Signature && left.FencingToken == right.FencingToken && left.LastHeartbeatAt.Equal(right.LastHeartbeatAt) && left.ExpiresAt.Equal(right.ExpiresAt)
}

func (r *Runtime) authorityFailure(runID string, err error) error {
	if errors.Is(err, ErrLeaseExpired) {
		r.expire(runID)
		return ErrLeaseExpired
	}
	return ErrLeaseInvalid
}

func (r *Runtime) transition(runID string, target State) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	run := r.runs[runID]
	if run == nil {
		return ErrRunNotFound
	}
	if run.busy || !validTransition(run.state, target) {
		return ErrInvalidTransition
	}
	run.state = target
	return nil
}

func (r *Runtime) stop(runID string, target State) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	run := r.runs[runID]
	if run == nil {
		return ErrRunNotFound
	}
	if !validTransition(run.state, target) {
		return ErrInvalidTransition
	}
	run.state = target
	if run.cancel != nil {
		run.cancel()
	}
	return nil
}

func (r *Runtime) expire(runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	run := r.runs[runID]
	if run == nil || run.state.Terminal() || !validTransition(run.state, StateExpired) {
		return
	}
	run.state = StateExpired
	if run.cancel != nil {
		run.cancel()
	}
}

func validateDeclaration(declaration Declaration, now time.Time) (AssembledPrompt, error) {
	if err := declaration.Envelope.Validate(now); err != nil || declaration.Envelope.TraceContext == nil ||
		declaration.Envelope.ProjectID != declaration.ProjectID || declaration.Envelope.TaskID != declaration.TaskID {
		return AssembledPrompt{}, ErrInvalidDeclaration
	}
	if !safeIdentifier(declaration.RunID) || !safeIdentifier(declaration.TenantID) || !safeIdentifier(declaration.ProjectID) ||
		!safeIdentifier(declaration.AgentInstanceID) || !declaration.Role.Valid() ||
		(roleRequiresTask(declaration.Role) && !safeIdentifier(declaration.TaskID)) ||
		(declaration.TaskID != "" && !safeIdentifier(declaration.TaskID)) || declaration.PromptBundle.Role != declaration.Role ||
		declaration.ContextManifest.Role != declaration.Role || !validClassification(declaration.DataClassification) ||
		declaration.Priority < 0 || declaration.Priority > 10000 ||
		!safeProtocolString(declaration.PolicyVersion, 256) || !validDigest(declaration.PolicyDigest) || !validDigest(declaration.ToolSchemaDigest) ||
		declaration.ToolSchemaDigest != DigestToolDefinitions(declaration.Tools) || len(declaration.ResponseSchema) > MaximumResponseSchemaBytes ||
		declaration.ResponseSemanticValidator == nil || len(declaration.Tools) > 100 {
		return AssembledPrompt{}, ErrInvalidDeclaration
	}
	seenTools := make(map[string]struct{}, len(declaration.Tools))
	totalToolSchemaBytes := 0
	for _, tool := range declaration.Tools {
		if !safeIdentifier(tool.Name) || !safeProtocolString(tool.Version, 128) || (tool.Description != "" && !safeProtocolString(tool.Description, 4096)) || containsCredential(tool.Description) ||
			len(tool.Schema) == 0 || !json.Valid(tool.Schema) {
			return AssembledPrompt{}, ErrInvalidDeclaration
		}
		totalToolSchemaBytes += len(tool.Schema)
		if totalToolSchemaBytes > MaximumContextBytes {
			return AssembledPrompt{}, ErrInvalidDeclaration
		}
		if _, exists := seenTools[tool.Name]; exists {
			return AssembledPrompt{}, ErrInvalidDeclaration
		}
		seenTools[tool.Name] = struct{}{}
	}
	assembled, err := AssemblePrompt(declaration.PromptBundle, declaration.ContextManifest, declaration.ResponseSchemaRef, declaration.ResponseSchema)
	if err != nil {
		return AssembledPrompt{}, err
	}
	if !contextMatchesEnvelope(declaration) {
		return AssembledPrompt{}, ErrInvalidDeclaration
	}
	return assembled, nil
}

func contextMatchesEnvelope(declaration Declaration) bool {
	expected := make(map[ContextKind]string, 3)
	if declaration.Envelope.GoalSpec != nil {
		expected[ContextGoalReference] = declaration.Envelope.GoalSpec.SHA256
	}
	if declaration.Envelope.PlanSpec != nil {
		expected[ContextPlanReference] = declaration.Envelope.PlanSpec.SHA256
	}
	if declaration.Envelope.ModuleSpec != nil {
		expected[ContextModuleReference] = declaration.Envelope.ModuleSpec.SHA256
	}
	counts := make(map[ContextKind]int, len(expected))
	for _, item := range declaration.ContextManifest.Items {
		switch item.Kind {
		case ContextGoalReference, ContextPlanReference, ContextModuleReference:
			digest, exists := expected[item.Kind]
			if !exists || item.SourceSHA256 != digest || !validReferenceTrust(declaration.Envelope.Intent, item.Kind, item.Trust) {
				return false
			}
			counts[item.Kind]++
			if counts[item.Kind] > 1 {
				return false
			}
		}
	}
	if declaration.Envelope.GoalSpec != nil && counts[ContextGoalReference] != 1 {
		return false
	}
	if declaration.Envelope.GoalSpec == nil {
		curatorDraft := declaration.Role == RoleKnowledgeCurator && declaration.Envelope.Intent == aop.IntentReturnKnowledgeRefs
		if !curatorDraft && (declaration.Role != RoleGoalProposer || declaration.Envelope.Intent != aop.IntentProposeGoal) {
			return false
		}
		hasUserInput := false
		for _, item := range declaration.ContextManifest.Items {
			if item.Kind == ContextUserInput {
				hasUserInput = true
				break
			}
		}
		if !hasUserInput {
			return false
		}
	}
	switch declaration.Role {
	case RoleModulePlanner, RoleExecutor, RoleGlobalAuditor:
		if counts[ContextPlanReference] != 1 {
			return false
		}
	}
	switch declaration.Role {
	case RoleExecutor, RoleModuleAuditor:
		if counts[ContextModuleReference] != 1 {
			return false
		}
	}
	if declaration.Role == RoleModulePlanner {
		hasTaskAssignment := false
		for _, item := range declaration.ContextManifest.Items {
			if item.Kind == ContextTaskState {
				hasTaskAssignment = true
				break
			}
		}
		if !hasTaskAssignment {
			return false
		}
	}
	return true
}

func validReferenceTrust(intent aop.Intent, kind ContextKind, trust TrustLevel) bool {
	switch {
	case kind == ContextGoalReference && intent == aop.IntentProposeGoal:
		return trust == TrustGeneratedUnreviewed || trust == TrustProjectApproved
	case kind == ContextGoalReference && intent == aop.IntentChallengeGoal:
		return trust == TrustGeneratedUnreviewed
	case kind == ContextPlanReference && intent == aop.IntentDefineModule:
		return trust == TrustGeneratedUnreviewed
	default:
		return trust == TrustProjectApproved
	}
}

func validClassification(value string) bool {
	switch value {
	case "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED":
		return true
	default:
		return false
	}
}

func validateAgentOutput(schemaJSON json.RawMessage, semanticValidator func(json.RawMessage) error, output AgentOutput) error {
	var schemaDocument any
	if err := json.Unmarshal(schemaJSON, &schemaDocument); err != nil {
		return ErrOutputInvalid
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource("urn:aor:agent-runtime-output", schemaDocument); err != nil {
		return ErrOutputInvalid
	}
	schema, err := compiler.Compile("urn:aor:agent-runtime-output")
	if err != nil {
		return ErrOutputInvalid
	}
	var instance any
	if err := json.Unmarshal(output.Payload, &instance); err != nil || schema.Validate(instance) != nil {
		return ErrOutputInvalid
	}
	if semanticValidator == nil || semanticValidator(append(json.RawMessage(nil), output.Payload...)) != nil {
		return ErrOutputInvalid
	}
	return nil
}

func intentAllowed(role Role, intent aop.Intent) bool {
	allowed := map[Role]map[aop.Intent]struct{}{
		RoleGoalProposer:     intentSet(aop.IntentProposeGoal, aop.IntentRequestUserReview, aop.IntentRequestKnowledge, aop.IntentRequestTool),
		RoleGoalChallenger:   intentSet(aop.IntentChallengeGoal, aop.IntentRequestUserReview, aop.IntentRequestKnowledge, aop.IntentRequestTool),
		RolePlanSupervisor:   intentSet(aop.IntentProposePlan, aop.IntentDefineModule, aop.IntentRequestAgent, aop.IntentReportPlanComplete, aop.IntentRequestGlobalAudit, aop.IntentReportModuleBlocked, aop.IntentRequestKnowledge, aop.IntentRequestTool),
		RoleModulePlanner:    intentSet(aop.IntentDefineModule, aop.IntentRequestAgent, aop.IntentReportModuleBlocked, aop.IntentRequestKnowledge, aop.IntentRequestTool),
		RoleExecutor:         intentSet(aop.IntentSubmitImplementation, aop.IntentReportModuleBlocked, aop.IntentRequestKnowledge, aop.IntentRequestTool),
		RoleModuleAuditor:    intentSet(aop.IntentReportLLMAudit, aop.IntentRequestRework, aop.IntentReportModuleBlocked, aop.IntentRequestKnowledge, aop.IntentRequestTool),
		RoleGlobalAuditor:    intentSet(aop.IntentReportGlobalAudit, aop.IntentRequestUserDecision, aop.IntentRequestKnowledge, aop.IntentRequestTool),
		RoleKnowledgeCurator: intentSet(aop.IntentReturnKnowledgeRefs, aop.IntentRequestUserDecision, aop.IntentRequestTool),
	}
	_, ok := allowed[role][intent]
	return ok
}

func intentSet(values ...aop.Intent) map[aop.Intent]struct{} {
	result := make(map[aop.Intent]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func cloneDeclaration(value Declaration) Declaration {
	value.Envelope = cloneEnvelope(value.Envelope)
	value.ContextManifest.Items = append([]ContextItem(nil), value.ContextManifest.Items...)
	value.ResponseSchema = append(json.RawMessage(nil), value.ResponseSchema...)
	value.Tools = cloneToolDefinitions(value.Tools)
	return value
}

func cloneEnvelope(value aop.Envelope) aop.Envelope {
	value.ArtifactRefs = append([]string(nil), value.ArtifactRefs...)
	value.KnowledgeRefs = append([]string(nil), value.KnowledgeRefs...)
	if value.GoalSpec != nil {
		copyValue := *value.GoalSpec
		value.GoalSpec = &copyValue
	}
	if value.PlanSpec != nil {
		copyValue := *value.PlanSpec
		value.PlanSpec = &copyValue
	}
	if value.ModuleSpec != nil {
		copyValue := *value.ModuleSpec
		value.ModuleSpec = &copyValue
	}
	if value.BudgetContext != nil {
		copyValue := *value.BudgetContext
		value.BudgetContext = &copyValue
	}
	if value.TraceContext != nil {
		copyValue := *value.TraceContext
		value.TraceContext = &copyValue
	}
	return value
}

func declarationPriority(value Declaration) int {
	if value.Priority > 0 {
		return value.Priority
	}
	return DefaultPriority(value.Role)
}

func cloneToolDefinitions(values []modelgateway.ToolDefinition) []modelgateway.ToolDefinition {
	result := append([]modelgateway.ToolDefinition(nil), values...)
	for index := range result {
		result[index].Schema = append(json.RawMessage(nil), result[index].Schema...)
	}
	return result
}

func cloneApproval(value *toolbroker.Approval) *toolbroker.Approval {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func clonePrompt(value AssembledPrompt) AssembledPrompt {
	value.Messages = cloneMessages(value.Messages)
	return value
}

func cloneMessages(values []modelgateway.Message) []modelgateway.Message {
	result := append([]modelgateway.Message(nil), values...)
	for index := range result {
		result[index].ToolCalls = append([]modelgateway.ToolCall(nil), result[index].ToolCalls...)
		for callIndex := range result[index].ToolCalls {
			result[index].ToolCalls[callIndex].Arguments = append(json.RawMessage(nil), result[index].ToolCalls[callIndex].Arguments...)
		}
	}
	return result
}

func cloneResult(value AcceptedResult) AcceptedResult {
	value.Payload = append(json.RawMessage(nil), value.Payload...)
	return value
}
