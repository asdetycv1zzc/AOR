package toolbroker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/akimisaka/aor/internal/credentials"
	"github.com/akimisaka/aor/pkg/canonicaljson"
)

const (
	maxInputBytes  = 1 << 20
	maxOutputBytes = 1 << 20
	maxCachedCalls = 10000
	maxRateWindows = 10000
	cacheTTL       = 15 * time.Minute
)

var (
	ErrUnknownTool         = errors.New("unknown tool")
	ErrInvalidRequest      = errors.New("invalid tool request")
	ErrPolicyDenied        = errors.New("tool policy denied")
	ErrLeaseInvalid        = errors.New("tool lease invalid")
	ErrApprovalRequired    = errors.New("tool approval required")
	ErrOutputTooLarge      = errors.New("tool output too large")
	ErrNetworkDenied       = errors.New("tool network destination denied")
	ErrInvocationRecord    = errors.New("tool invocation could not be recorded")
	ErrIdempotencyConflict = errors.New("tool invocation idempotency conflict")
	ErrRateLimited         = errors.New("tool invocation rate limited")
)

type cachedInvocation struct {
	digest    string
	result    ToolResult
	createdAt time.Time
}

type inFlightInvocation struct {
	digest string
	done   chan struct{}
	result ToolResult
	err    error
}

type invocationRequestIDContextKey struct{}

func InvocationRequestIDFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	requestID, ok := ctx.Value(invocationRequestIDContextKey{}).(string)
	return requestID, ok
}

type rateWindow struct {
	started time.Time
	count   int
}

type Broker struct {
	mu          sync.RWMutex
	descriptors map[string]ToolDescriptor
	lease       LeaseChecker
	policy      PolicyEvaluator
	executor    ToolExecutor
	artifacts   ArtifactStore
	recorder    InvocationRecorder
	revalidate  func(context.Context, ToolRequest, ToolDescriptor) error
	network     *NetworkBoundary
	clock       func() time.Time
	cache       map[string]cachedInvocation
	inflight    map[string]*inFlightInvocation
	rate        map[string]rateWindow
}

func New(lease LeaseChecker, policy PolicyEvaluator, executor ToolExecutor, artifacts ArtifactStore, recorder InvocationRecorder, revalidate func(context.Context, ToolRequest, ToolDescriptor) error, clock func() time.Time) *Broker {
	return NewWithNetworkBoundary(lease, policy, executor, artifacts, recorder, revalidate, nil, clock)
}

// NewWithNetworkBoundary constructs a broker with an injectable network
// boundary. Supplying a boundary is useful for deterministic DNS and dialer
// tests; production callers should use New.
func NewWithNetworkBoundary(lease LeaseChecker, policy PolicyEvaluator, executor ToolExecutor, artifacts ArtifactStore, recorder InvocationRecorder, revalidate func(context.Context, ToolRequest, ToolDescriptor) error, network *NetworkBoundary, clock func() time.Time) *Broker {
	if clock == nil {
		clock = time.Now
	}
	if network == nil {
		network = NewNetworkBoundary(nil, nil)
	}
	return &Broker{descriptors: make(map[string]ToolDescriptor), lease: lease, policy: policy, executor: executor, artifacts: artifacts, recorder: recorder, revalidate: revalidate, network: network, clock: clock, cache: make(map[string]cachedInvocation), inflight: make(map[string]*inFlightInvocation), rate: make(map[string]rateWindow)}
}

func (b *Broker) Register(descriptor ToolDescriptor) error {
	return b.registerBatch([]ToolDescriptor{descriptor})
}

func (b *Broker) registerBatch(descriptors []ToolDescriptor) error {
	if b == nil || len(descriptors) == 0 {
		return ErrInvalidRequest
	}
	clones := make([]ToolDescriptor, len(descriptors))
	keys := make([]string, len(descriptors))
	seen := make(map[string]struct{}, len(descriptors))
	for index, descriptor := range descriptors {
		if err := descriptor.Validate(); err != nil {
			return err
		}
		key := descriptor.ToolID + "\x00" + descriptor.Version
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("%w: %s", ErrPolicyDenied, key)
		}
		seen[key] = struct{}{}
		keys[index] = key
		clones[index] = cloneDescriptor(descriptor)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, key := range keys {
		if _, exists := b.descriptors[key]; exists {
			return fmt.Errorf("%w: %s", ErrPolicyDenied, key)
		}
	}
	for index, key := range keys {
		b.descriptors[key] = clones[index]
	}
	return nil
}

func (b *Broker) List() []ToolDescriptor {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]ToolDescriptor, 0, len(b.descriptors))
	for _, descriptor := range b.descriptors {
		result = append(result, cloneDescriptor(descriptor))
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ToolID == result[j].ToolID {
			return result[i].Version < result[j].Version
		}
		return result[i].ToolID < result[j].ToolID
	})
	return result
}

func (b *Broker) Invoke(ctx context.Context, request ToolRequest) (result ToolResult, err error) {
	if ctx == nil || !safeBrokerOpaque(request.RequestID, 512) || !safeBrokerID(request.TenantID) || !safeBrokerID(request.ProjectID) || !safeBrokerID(request.TaskID) || !safeBrokerOpaque(request.Principal.ID, 512) || !safeBrokerOpaque(request.Principal.Type, 128) || !safeBrokerOpaque(request.Principal.Role, 128) || !safeBrokerOpaque(request.ToolID, 128) || !safeBrokerOpaque(request.Version, 64) || !safeBrokerOpaque(request.PolicyVersion, 256) || !safeBrokerID(request.BudgetAccountID) || request.ExecutionLeaseID != "" && !safeBrokerOpaque(request.ExecutionLeaseID, 512) || len(request.Parameters) > maxInputBytes || !json.Valid(request.Parameters) {
		return ToolResult{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return ToolResult{}, err
	}
	digest, err := requestDigest(request.ToolID, request.Version, request.Parameters)
	if err != nil {
		return ToolResult{}, ErrInvalidRequest
	}
	cacheKey := request.TenantID + "\x00" + request.ProjectID + "\x00" + request.TaskID + "\x00" + request.Principal.ID + "\x00" + request.RequestID
	descriptor, found := b.descriptor(request.ToolID, request.Version)
	if !found {
		return ToolResult{}, ErrUnknownTool
	}
	defer func() {
		if err != nil {
			b.recordFailedAttempt(request, descriptor, err)
		}
	}()
	if !containsRole(descriptor.AllowedRoles, request.Principal.Role) {
		return ToolResult{}, ErrPolicyDenied
	}
	if isAuditorRole(request.Principal.Role) && descriptorWrites(descriptor) {
		return ToolResult{}, ErrPolicyDenied
	}
	if b.lease == nil {
		return ToolResult{}, ErrLeaseInvalid
	}
	validation, err := b.leaseValidation(request, descriptor, b.clock().UTC())
	if err != nil {
		return ToolResult{}, err
	}
	if err := b.lease.Validate(ctx, validation); err != nil {
		return ToolResult{}, fmt.Errorf("%w: %v", ErrLeaseInvalid, err)
	}
	if descriptor.RequiresApproval == ApprovalAlways && !validApproval(request.Approval, b.clock()) {
		return ToolResult{}, ErrApprovalRequired
	}
	if b.policy == nil {
		return ToolResult{}, ErrPolicyDenied
	}
	decision, err := b.policy.Evaluate(ctx, descriptor, request)
	if err != nil || !decision.Allow || decision.PolicyVersion != request.PolicyVersion {
		if err != nil {
			return ToolResult{}, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
		}
		return ToolResult{}, ErrPolicyDenied
	}
	if err := validateSchema(descriptor.InputSchemaRef, descriptor.InputSchema, request.Parameters); err != nil {
		return ToolResult{}, err
	}
	// Authorization is deliberately evaluated before serving an idempotency
	// replay. A revoked lease or policy must not turn the cache into an access
	// control bypass, even though the underlying side effect remains coalesced.
	call, cachedResult, owner, cached, conflict := b.beginInvocation(cacheKey, digest)
	if conflict {
		return ToolResult{}, ErrIdempotencyConflict
	}
	if cached {
		return cachedResult, nil
	}
	if !owner {
		select {
		case <-call.done:
			return cloneResult(call.result), call.err
		case <-ctx.Done():
			return ToolResult{}, ctx.Err()
		}
	}
	defer func() { b.finishInvocation(cacheKey, call, result, err) }()
	if !b.allowRate(descriptor, request, b.clock().UTC()) {
		return ToolResult{}, ErrRateLimited
	}
	if descriptorWrites(descriptor) {
		if err := b.revalidatePermanentEffect(ctx, request, descriptor); err != nil {
			return ToolResult{}, err
		}
	}
	if b.executor == nil {
		return ToolResult{}, ErrPolicyDenied
	}
	if descriptor.TimeoutSeconds <= 0 {
		return ToolResult{}, ErrInvalidRequest
	}
	executionCtx, cancel := context.WithTimeout(ctx, time.Duration(descriptor.TimeoutSeconds)*time.Second)
	defer cancel()
	executionCtx = context.WithValue(executionCtx, invocationRequestIDContextKey{}, request.RequestID)
	executionCtx = context.WithValue(executionCtx, executionAuthorizationContextKey{}, validation)
	var output []byte
	if descriptor.NetworkAccess != NetworkNone {
		networkExecutor, ok := b.executor.(NetworkToolExecutor)
		if !ok {
			return ToolResult{}, ErrNetworkDenied
		}
		client, networkErr := b.network.Client(executionCtx, request.Parameters, descriptor.AllowedNetworkTargets)
		if networkErr != nil {
			return ToolResult{}, networkErr
		}
		output, err = networkExecutor.ExecuteNetwork(executionCtx, descriptor, append([]byte(nil), request.Parameters...), client)
	} else {
		output, err = b.executor.Execute(executionCtx, descriptor, append([]byte(nil), request.Parameters...))
	}
	if err != nil {
		if executionCtx.Err() != nil {
			return ToolResult{}, executionCtx.Err()
		}
		return ToolResult{}, redactError(err)
	}
	redactedOutput, redacted := redact(output)
	output = redactedOutput
	if err := validateSchema(descriptor.OutputSchemaRef, descriptor.OutputSchema, output); err != nil {
		return ToolResult{}, err
	}
	oversized := len(output) > descriptor.MaxOutputBytes || len(output) > maxOutputBytes
	if descriptorWrites(descriptor) || oversized {
		if err := b.revalidatePermanentEffect(ctx, request, descriptor); err != nil {
			return ToolResult{}, err
		}
	}
	if oversized {
		if b.artifacts == nil {
			return ToolResult{}, ErrOutputTooLarge
		}
		artifact, artifactErr := b.artifacts.Put(ctx, request, output, "application/json")
		if artifactErr != nil {
			return ToolResult{}, artifactErr
		}
		output = nil
		result = ToolResult{InvocationID: stableInvocationID(request), Artifact: &artifact, OutputSHA256: artifact.SHA256, TrustLevel: "UNTRUSTED", Redacted: redacted}
		if err := b.record(executionCtx, request, descriptor, decision, result); err != nil {
			return ToolResult{}, err
		}
		b.storeCached(cacheKey, digest, result)
		return result, nil
	}
	sum := sha256.Sum256(output)
	result = ToolResult{InvocationID: stableInvocationID(request), Output: output, OutputSHA256: "sha256:" + hex.EncodeToString(sum[:]), TrustLevel: "UNTRUSTED", Redacted: redacted}
	if err := b.record(executionCtx, request, descriptor, decision, result); err != nil {
		return ToolResult{}, err
	}
	b.storeCached(cacheKey, digest, result)
	return result, nil
}

func (b *Broker) revalidatePermanentEffect(ctx context.Context, request ToolRequest, descriptor ToolDescriptor) error {
	if b.revalidate == nil {
		return ErrPolicyDenied
	}
	if descriptor.RequiresApproval == ApprovalAlways && !validApproval(request.Approval, b.clock()) {
		return ErrApprovalRequired
	}
	validation, err := b.leaseValidation(request, descriptor, b.clock().UTC())
	if err != nil {
		return err
	}
	if err := b.lease.Validate(ctx, validation); err != nil {
		return fmt.Errorf("%w: %v", ErrLeaseInvalid, err)
	}
	if err := b.revalidate(ctx, request, descriptor); err != nil {
		return fmt.Errorf("%w: %v", ErrPolicyDenied, err)
	}
	return nil
}

func (b *Broker) beginInvocation(key, digest string) (*inFlightInvocation, ToolResult, bool, bool, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if entry, ok := b.cache[key]; ok {
		if b.clock().UTC().Sub(entry.createdAt) > cacheTTL {
			delete(b.cache, key)
		} else if entry.digest != digest {
			return nil, ToolResult{}, false, false, true
		} else {
			return nil, cloneResult(entry.result), false, true, false
		}
	}
	if existing, ok := b.inflight[key]; ok {
		return existing, ToolResult{}, false, false, existing.digest != digest
	}
	call := &inFlightInvocation{digest: digest, done: make(chan struct{})}
	b.inflight[key] = call
	return call, ToolResult{}, true, false, false
}

func (b *Broker) finishInvocation(key string, call *inFlightInvocation, result ToolResult, err error) {
	b.mu.Lock()
	call.result = cloneResult(result)
	call.err = err
	delete(b.inflight, key)
	close(call.done)
	b.mu.Unlock()
}

func (b *Broker) storeCached(key, digest string, result ToolResult) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.cache) >= maxCachedCalls {
		var oldestKey string
		var oldest time.Time
		for candidate, entry := range b.cache {
			if oldestKey == "" || entry.createdAt.Before(oldest) {
				oldestKey, oldest = candidate, entry.createdAt
			}
		}
		if oldestKey != "" {
			delete(b.cache, oldestKey)
		}
	}
	b.cache[key] = cachedInvocation{digest: digest, result: cloneResult(result), createdAt: b.clock().UTC()}
}

func cloneResult(result ToolResult) ToolResult {
	result.Output = append([]byte(nil), result.Output...)
	if result.Artifact != nil {
		artifact := *result.Artifact
		result.Artifact = &artifact
	}
	return result
}

func (b *Broker) allowRate(descriptor ToolDescriptor, request ToolRequest, now time.Time) bool {
	limit, window, ok := parseRateLimit(descriptor.RateLimit)
	if !ok || limit <= 0 || window <= 0 {
		return false
	}
	key := request.TenantID + "\x00" + request.Principal.ID + "\x00" + descriptor.ToolID + "\x00" + descriptor.Version
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.rate[key]; !exists && len(b.rate) >= maxRateWindows {
		var oldestKey string
		var oldest time.Time
		for candidate, entry := range b.rate {
			if oldestKey == "" || entry.started.Before(oldest) {
				oldestKey, oldest = candidate, entry.started
			}
		}
		if oldestKey != "" {
			delete(b.rate, oldestKey)
		}
	}
	current := b.rate[key]
	if current.started.IsZero() || now.Sub(current.started) >= window {
		current = rateWindow{started: now, count: 0}
	}
	if current.count >= limit {
		b.rate[key] = current
		return false
	}
	current.count++
	b.rate[key] = current
	return true
}

func parseRateLimit(value string) (int, time.Duration, bool) {
	parts := strings.Split(strings.TrimSpace(value), "/")
	if len(parts) != 2 {
		return 0, 0, false
	}
	limit, err := strconv.Atoi(parts[0])
	if err != nil || limit < 1 || limit > 100000 {
		return 0, 0, false
	}
	var window time.Duration
	switch strings.ToLower(parts[1]) {
	case "s", "sec", "second":
		window = time.Second
	case "m", "min", "minute":
		window = time.Minute
	case "h", "hour":
		window = time.Hour
	default:
		return 0, 0, false
	}
	return limit, window, true
}

func safeBrokerID(value string) bool {
	return safeBrokerOpaque(value, 256) && !strings.ContainsAny(value, "/\\")
}

func safeBrokerOpaque(value string, limit int) bool {
	if value == "" || len(value) > limit || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func (b *Broker) descriptor(toolID, version string) (ToolDescriptor, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	descriptor, found := b.descriptors[toolID+"\x00"+version]
	return cloneDescriptor(descriptor), found
}

func (b *Broker) record(ctx context.Context, request ToolRequest, descriptor ToolDescriptor, decision PolicyDecision, result ToolResult) error {
	if b.recorder == nil {
		if descriptor.SideEffect == SideEffectIrreversible {
			return ErrInvocationRecord
		}
		return nil
	}
	inputDigest, err := canonicaljson.Digest(request.Parameters)
	if err != nil {
		return ErrInvocationRecord
	}
	occurredAt := b.clock().UTC()
	if err := b.recorder.Record(ctx, Invocation{InvocationID: result.InvocationID, RequestID: request.RequestID, TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID, PrincipalID: request.Principal.ID, ToolID: descriptor.ToolID, ToolVersion: descriptor.Version, Risk: descriptor.Risk, InputSHA256: inputDigest, Decision: "ALLOW", PolicyVersion: decision.PolicyVersion, OutputSHA256: result.OutputSHA256, TrustLevel: result.TrustLevel, Redacted: result.Redacted, Status: "SUCCEEDED", StartedAt: occurredAt, OccurredAt: occurredAt}); err != nil {
		return ErrInvocationRecord
	}
	return nil
}

func (b *Broker) recordFailedAttempt(request ToolRequest, descriptor ToolDescriptor, invocationErr error) {
	recorder, ok := b.recorder.(InvocationAttemptRecorder)
	if !ok {
		return
	}
	reason := "EXECUTION_FAILED"
	switch {
	case errors.Is(invocationErr, ErrPolicyDenied):
		reason = "POLICY_DENIED"
	case errors.Is(invocationErr, ErrLeaseInvalid):
		reason = "LEASE_INVALID"
	case errors.Is(invocationErr, ErrApprovalRequired):
		reason = "APPROVAL_REQUIRED"
	case errors.Is(invocationErr, ErrRateLimited):
		reason = "RATE_LIMITED"
	case errors.Is(invocationErr, context.Canceled):
		reason = "CANCELLED"
	case errors.Is(invocationErr, context.DeadlineExceeded):
		reason = "DEADLINE_EXCEEDED"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = recorder.RecordAttempt(ctx, InvocationAttempt{InvocationID: stableInvocationID(request), RequestID: request.RequestID, TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID, PrincipalID: request.Principal.ID, ToolID: descriptor.ToolID, ToolVersion: descriptor.Version, Status: "FAILED", ReasonCode: reason, OccurredAt: b.clock().UTC()})
}

func (d ToolDescriptor) Validate() error {
	if !safeBrokerOpaque(d.ToolID, 128) || !safeBrokerOpaque(d.Version, 64) || !safeBrokerID(d.MCPServerID) || !safeBrokerOpaque(d.InputSchemaRef, 1024) || !safeBrokerOpaque(d.OutputSchemaRef, 1024) || d.TimeoutSeconds <= 0 || d.TimeoutSeconds > 3600 || d.MaxOutputBytes <= 0 || d.MaxOutputBytes > maxOutputBytes || len(d.AllowedRoles) == 0 || len(d.AllowedRoles) > 64 || len(d.InputSchema) == 0 || len(d.InputSchema) > MaxSchemaBytes || len(d.OutputSchema) == 0 || len(d.OutputSchema) > MaxSchemaBytes || !json.Valid(d.InputSchema) || !json.Valid(d.OutputSchema) {
		return ErrInvalidRequest
	}
	if _, _, ok := parseRateLimit(d.RateLimit); !ok {
		return ErrInvalidRequest
	}
	if d.Risk != RiskLow && d.Risk != RiskMedium && d.Risk != RiskHigh && d.Risk != RiskCritical {
		return ErrInvalidRequest
	}
	if d.SideEffect != SideEffectNone && d.SideEffect != SideEffectReversible && d.SideEffect != SideEffectIrreversible {
		return ErrInvalidRequest
	}
	if d.NetworkAccess != NetworkNone && d.NetworkAccess != NetworkAllowlist {
		return ErrInvalidRequest
	}
	if d.FilesystemAccess != FilesystemNone && d.FilesystemAccess != FilesystemRead && d.FilesystemAccess != FilesystemScopedWrite {
		return ErrInvalidRequest
	}
	if d.RequiresApproval != ApprovalNever && d.RequiresApproval != ApprovalPolicy && d.RequiresApproval != ApprovalAlways {
		return ErrInvalidRequest
	}
	if d.NetworkAccess == NetworkNone && len(d.AllowedNetworkTargets) != 0 || d.NetworkAccess == NetworkAllowlist && len(d.AllowedNetworkTargets) == 0 {
		return ErrInvalidRequest
	}
	for _, target := range d.AllowedNetworkTargets {
		if err := validateNetworkTarget(target); err != nil {
			return ErrInvalidRequest
		}
	}
	if descriptorWrites(d) {
		for _, role := range d.AllowedRoles {
			if isAuditorRole(role) {
				return ErrInvalidRequest
			}
		}
	}
	seenRoles := make(map[string]struct{}, len(d.AllowedRoles))
	for _, role := range d.AllowedRoles {
		if !safeBrokerOpaque(role, 128) {
			return ErrInvalidRequest
		}
		if _, duplicate := seenRoles[role]; duplicate {
			return ErrInvalidRequest
		}
		seenRoles[role] = struct{}{}
	}
	return nil
}

func (b *Broker) leaseValidation(request ToolRequest, descriptor ToolDescriptor, now time.Time) (LeaseValidation, error) {
	expires, err := time.Parse(time.RFC3339, request.Lease.ExpiresAt)
	if err != nil || request.Lease.ID == "" || request.Lease.FencingToken < 1 || now.IsZero() || !now.Before(expires) {
		return LeaseValidation{}, ErrLeaseInvalid
	}
	parameterDigest, err := AuthorizationParameterDigest(request.Parameters)
	if err != nil {
		return LeaseValidation{}, ErrInvalidRequest
	}
	approvalID := ""
	if request.Approval != nil {
		approvalID = request.Approval.ID
	}
	resource := authorizationResourceID(descriptor.MCPServerID, descriptor.ToolID, descriptor.Version)
	return LeaseValidation{Lease: request.Lease, ExecutionLeaseID: request.ExecutionLeaseID, Principal: request.Principal, TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID, ToolID: descriptor.ToolID, ToolVersion: descriptor.Version, MCPServerID: descriptor.MCPServerID, Action: "tool.invoke", Resource: resource, ParameterSHA256: parameterDigest, PolicyVersion: request.PolicyVersion, BudgetAccountID: request.BudgetAccountID, ApprovalID: approvalID, At: now}, nil
}

func requestDigest(toolID, version string, parameters json.RawMessage) (string, error) {
	if !safeBrokerOpaque(toolID, 128) || !safeBrokerOpaque(version, 64) || len(parameters) == 0 || len(parameters) > maxInputBytes || !json.Valid(parameters) {
		return "", ErrInvalidRequest
	}
	digestInput, err := json.Marshal(struct {
		ToolID     string          `json:"toolId"`
		Version    string          `json:"version"`
		Parameters json.RawMessage `json:"parameters"`
	}{ToolID: toolID, Version: version, Parameters: parameters})
	if err != nil {
		return "", ErrInvalidRequest
	}
	return canonicaljson.Digest(digestInput)
}

func AuthorizationParameterDigest(parameters json.RawMessage) (string, error) {
	if len(parameters) == 0 || len(parameters) > maxInputBytes || !json.Valid(parameters) {
		return "", ErrInvalidRequest
	}
	return canonicaljson.Digest(parameters)
}

func cloneDescriptor(value ToolDescriptor) ToolDescriptor {
	value.AllowedRoles = append([]string(nil), value.AllowedRoles...)
	value.AllowedNetworkTargets = append([]string(nil), value.AllowedNetworkTargets...)
	value.InputSchema = append([]byte(nil), value.InputSchema...)
	value.OutputSchema = append([]byte(nil), value.OutputSchema...)
	return value
}

func containsRole(roles []string, role string) bool {
	for _, value := range roles {
		if value == role {
			return true
		}
	}
	return false
}

func isAuditorRole(role string) bool {
	switch strings.ToUpper(role) {
	case "AUDITOR", "MODULE_AUDITOR", "GLOBAL_AUDITOR":
		return true
	default:
		return false
	}
}

func descriptorWrites(descriptor ToolDescriptor) bool {
	if descriptor.SideEffect != SideEffectNone || descriptor.FilesystemAccess == FilesystemScopedWrite {
		return true
	}
	for _, segment := range strings.FieldsFunc(strings.ToLower(descriptor.ToolID), func(character rune) bool {
		return character == '.' || character == ':' || character == '/' || character == '-' || character == '_'
	}) {
		switch segment {
		case "apply", "commit", "create", "delete", "merge", "mutate", "patch", "publish", "put", "remove", "update", "write":
			return true
		}
	}
	return false
}

func validApproval(approval *Approval, now time.Time) bool {
	if approval == nil || approval.ID == "" || approval.Revoked {
		return false
	}
	if approval.ExpiresAt == "" {
		return true
	}
	expires, err := time.Parse(time.RFC3339, approval.ExpiresAt)
	return err == nil && expires.After(now)
}

func stableInvocationID(request ToolRequest) string {
	sum := sha256.Sum256([]byte(request.TenantID + "\x00" + request.ProjectID + "\x00" + request.RequestID + "\x00" + request.ToolID + "\x00" + request.Version))
	return "inv_" + hex.EncodeToString(sum[:16])
}

func validateSchema(ref string, schemaBytes, value []byte) error {
	if len(schemaBytes) == 0 {
		return nil
	}
	var document any
	if err := json.Unmarshal(schemaBytes, &document); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidRequest, ref)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource(ref, document); err != nil {
		return ErrInvalidRequest
	}
	schema, err := compiler.Compile(ref)
	if err != nil {
		return ErrInvalidRequest
	}
	var instance any
	if err := json.Unmarshal(value, &instance); err != nil || schema.Validate(instance) != nil {
		return ErrInvalidRequest
	}
	return nil
}

func redact(value []byte) ([]byte, bool) {
	text, redacted := credentials.Redact(string(value), "[REDACTED]")
	return []byte(text), redacted
}

func redactError(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{ErrInvalidRequest, ErrPolicyDenied, ErrLeaseInvalid, ErrApprovalRequired, ErrOutputTooLarge, ErrNetworkDenied, ErrInvocationRecord, ErrIdempotencyConflict, ErrRateLimited, ErrMCPConfig, ErrMCPTransport} {
		if errors.Is(err, known) {
			return known
		}
	}
	value, _ := redact([]byte(err.Error()))
	return errors.New(string(value))
}

func ValidateDestinationFromParameters(parameters []byte) error {
	parsed, err := networkURLFromParameters(parameters)
	if err != nil || forbiddenHostname(parsed.Hostname()) || ambiguousIPAddress(parsed.Hostname()) {
		return ErrNetworkDenied
	}
	if address, parseErr := netip.ParseAddr(parsed.Hostname()); parseErr == nil && forbiddenAddress(address) {
		return ErrNetworkDenied
	}
	return nil
}
