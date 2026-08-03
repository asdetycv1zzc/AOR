package toolbroker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/akimisaka/aor/internal/credentials"
	"github.com/akimisaka/aor/pkg/canonicaljson"
)

const maxOutputBytes = 1 << 20

var (
	ErrUnknownTool      = errors.New("unknown tool")
	ErrInvalidRequest   = errors.New("invalid tool request")
	ErrPolicyDenied     = errors.New("tool policy denied")
	ErrLeaseInvalid     = errors.New("tool lease invalid")
	ErrApprovalRequired = errors.New("tool approval required")
	ErrOutputTooLarge   = errors.New("tool output too large")
	ErrNetworkDenied    = errors.New("tool network destination denied")
	ErrInvocationRecord = errors.New("tool invocation could not be recorded")
)

type Broker struct {
	mu          sync.RWMutex
	descriptors map[string]ToolDescriptor
	lease       LeaseChecker
	policy      PolicyEvaluator
	executor    ToolExecutor
	artifacts   ArtifactStore
	recorder    InvocationRecorder
	revalidate  func(context.Context, ToolRequest, ToolDescriptor) error
	clock       func() time.Time
}

func New(lease LeaseChecker, policy PolicyEvaluator, executor ToolExecutor, artifacts ArtifactStore, recorder InvocationRecorder, revalidate func(context.Context, ToolRequest, ToolDescriptor) error, clock func() time.Time) *Broker {
	if clock == nil {
		clock = time.Now
	}
	return &Broker{descriptors: make(map[string]ToolDescriptor), lease: lease, policy: policy, executor: executor, artifacts: artifacts, recorder: recorder, revalidate: revalidate, clock: clock}
}

func (b *Broker) Register(descriptor ToolDescriptor) error {
	if err := descriptor.Validate(); err != nil {
		return err
	}
	key := descriptor.ToolID + "\x00" + descriptor.Version
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.descriptors[key]; exists {
		return fmt.Errorf("%w: %s", ErrPolicyDenied, key)
	}
	b.descriptors[key] = cloneDescriptor(descriptor)
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

func (b *Broker) Invoke(ctx context.Context, request ToolRequest) (ToolResult, error) {
	if request.RequestID == "" || request.TenantID == "" || request.ProjectID == "" || request.TaskID == "" || request.Principal.ID == "" || request.Principal.Type == "" || request.Principal.Role == "" || request.ToolID == "" || request.Version == "" || request.PolicyVersion == "" || request.BudgetAccountID == "" || !json.Valid(request.Parameters) {
		return ToolResult{}, ErrInvalidRequest
	}
	descriptor, found := b.descriptor(request.ToolID, request.Version)
	if !found {
		return ToolResult{}, ErrUnknownTool
	}
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
	if descriptor.SideEffect != SideEffectNone {
		if b.revalidate == nil {
			return ToolResult{}, ErrPolicyDenied
		}
		validation, err = b.leaseValidation(request, descriptor, b.clock().UTC())
		if err != nil || b.lease.Validate(ctx, validation) != nil {
			return ToolResult{}, ErrLeaseInvalid
		}
		if err := b.revalidate(ctx, request, descriptor); err != nil {
			return ToolResult{}, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
		}
	}
	if descriptor.NetworkAccess != NetworkNone {
		if err := ValidateDestinationFromParameters(request.Parameters); err != nil {
			return ToolResult{}, err
		}
	}
	if b.executor == nil {
		return ToolResult{}, ErrPolicyDenied
	}
	output, err := b.executor.Execute(ctx, descriptor, append([]byte(nil), request.Parameters...))
	if err != nil {
		return ToolResult{}, redactError(err)
	}
	redactedOutput, redacted := redact(output)
	output = redactedOutput
	if len(output) > descriptor.MaxOutputBytes || len(output) > maxOutputBytes {
		if b.artifacts == nil {
			return ToolResult{}, ErrOutputTooLarge
		}
		artifact, artifactErr := b.artifacts.Put(ctx, output, "application/octet-stream")
		if artifactErr != nil {
			return ToolResult{}, artifactErr
		}
		output = nil
		result := ToolResult{InvocationID: stableInvocationID(request), Artifact: &artifact, OutputSHA256: artifact.SHA256, TrustLevel: "UNTRUSTED", Redacted: redacted}
		if err := b.record(ctx, request, descriptor, decision, result); err != nil {
			return ToolResult{}, err
		}
		return result, nil
	}
	if err := validateSchema(descriptor.OutputSchemaRef, descriptor.OutputSchema, output); err != nil {
		return ToolResult{}, err
	}
	sum := sha256.Sum256(output)
	result := ToolResult{InvocationID: stableInvocationID(request), Output: output, OutputSHA256: "sha256:" + hex.EncodeToString(sum[:]), TrustLevel: "UNTRUSTED", Redacted: redacted}
	if err := b.record(ctx, request, descriptor, decision, result); err != nil {
		return ToolResult{}, err
	}
	return result, nil
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
	if err := b.recorder.Record(ctx, Invocation{InvocationID: result.InvocationID, RequestID: request.RequestID, TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID, PrincipalID: request.Principal.ID, ToolID: descriptor.ToolID, ToolVersion: descriptor.Version, PolicyVersion: decision.PolicyVersion, OutputSHA256: result.OutputSHA256, TrustLevel: result.TrustLevel, Redacted: result.Redacted}); err != nil {
		return ErrInvocationRecord
	}
	return nil
}

func (d ToolDescriptor) Validate() error {
	if d.ToolID == "" || d.Version == "" || d.MCPServerID == "" || d.InputSchemaRef == "" || d.OutputSchemaRef == "" || d.RateLimit == "" || d.TimeoutSeconds <= 0 || d.MaxOutputBytes <= 0 || len(d.AllowedRoles) == 0 {
		return ErrInvalidRequest
	}
	if d.Risk != RiskLow && d.Risk != RiskMedium && d.Risk != RiskHigh && d.Risk != RiskCritical {
		return ErrInvalidRequest
	}
	if d.SideEffect != SideEffectNone && d.SideEffect != SideEffectReversible && d.SideEffect != SideEffectIrreversible {
		return ErrInvalidRequest
	}
	if descriptorWrites(d) {
		for _, role := range d.AllowedRoles {
			if isAuditorRole(role) {
				return ErrInvalidRequest
			}
		}
	}
	return nil
}

func (b *Broker) leaseValidation(request ToolRequest, descriptor ToolDescriptor, now time.Time) (LeaseValidation, error) {
	expires, err := time.Parse(time.RFC3339, request.Lease.ExpiresAt)
	if err != nil || request.Lease.ID == "" || request.Lease.FencingToken < 1 || now.IsZero() || !now.Before(expires) {
		return LeaseValidation{}, ErrLeaseInvalid
	}
	parameterDigest, err := canonicaljson.Digest(request.Parameters)
	if err != nil {
		return LeaseValidation{}, ErrInvalidRequest
	}
	approvalID := ""
	if request.Approval != nil {
		approvalID = request.Approval.ID
	}
	resource := authorizationResourceID(descriptor.MCPServerID, descriptor.ToolID, descriptor.Version)
	return LeaseValidation{Lease: request.Lease, Principal: request.Principal, TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID, ToolID: descriptor.ToolID, ToolVersion: descriptor.Version, MCPServerID: descriptor.MCPServerID, Action: "tool.invoke", Resource: resource, ParameterSHA256: parameterDigest, PolicyVersion: request.PolicyVersion, BudgetAccountID: request.BudgetAccountID, ApprovalID: approvalID, At: now}, nil
}

func cloneDescriptor(value ToolDescriptor) ToolDescriptor {
	value.AllowedRoles = append([]string(nil), value.AllowedRoles...)
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
	value, _ := redact([]byte(err.Error()))
	return errors.New(string(value))
}

func ValidateDestinationFromParameters(parameters []byte) error {
	var value struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(parameters, &value); err != nil || value.URL == "" {
		return nil
	}
	parsed, err := url.Parse(value.URL)
	if err != nil || parsed.Hostname() == "" {
		return ErrNetworkDenied
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || host == "metadata.google.internal" || host == "169.254.169.254" {
		return ErrNetworkDenied
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
		return ErrNetworkDenied
	}
	return nil
}
