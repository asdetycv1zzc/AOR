package orchestrator

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
)

const CommitCapabilityVersion = 1

const maximumCommitCapabilityLifetime = 5 * time.Minute

type CommitCapability struct {
	CapabilityVersion int               `json:"capabilityVersion"`
	TenantID          string            `json:"tenantId"`
	ProjectID         string            `json:"projectId"`
	TaskID            string            `json:"taskId,omitempty"`
	PrincipalID       string            `json:"principalId"`
	PrincipalType     string            `json:"principalType"`
	Role              string            `json:"role"`
	Action            string            `json:"action"`
	ExpectedVersion   int64             `json:"expectedVersion"`
	ProjectVersion    int64             `json:"projectVersion"`
	TaskVersion       int64             `json:"taskVersion"`
	ParameterDigest   string            `json:"parameterDigest"`
	EvidenceSHA256    []string          `json:"evidenceSha256,omitempty"`
	Claims            map[string]bool   `json:"claims,omitempty"`
	ModuleSpecRef     contracts.SpecRef `json:"moduleSpecRef,omitempty"`
	GoalSpecRef       contracts.SpecRef `json:"goalSpecRef,omitempty"`
	ApprovalRecordID  string            `json:"approvalRecordId,omitempty"`
	LeaseID           string            `json:"leaseId"`
	FencingToken      int64             `json:"fencingToken"`
	PolicyVersion     string            `json:"policyVersion"`
	BudgetAccountID   string            `json:"budgetAccountId"`
	IssuedAt          time.Time         `json:"issuedAt"`
	ExpiresAt         time.Time         `json:"expiresAt"`
}

type CommitSigner interface {
	Sign([]byte) (string, error)
	Verify([]byte, string) error
}

// CommitRevalidator rehydrates the lease, policy, budget, and principal facts
// at the final persistence boundary. It must not trust fields from the request.
type CommitRevalidator interface {
	Revalidate(context.Context, CommitCapability) error
}

type SignedCommitBoundary struct {
	signer      CommitSigner
	revalidator CommitRevalidator
}

func NewSignedCommitBoundary(signer CommitSigner, revalidator CommitRevalidator) (*SignedCommitBoundary, error) {
	if signer == nil || revalidator == nil {
		return nil, ErrCommitBoundary
	}
	return &SignedCommitBoundary{signer: signer, revalidator: revalidator}, nil
}

func (b *SignedCommitBoundary) Validate(ctx context.Context, validation CommitValidation) error {
	if b == nil || b.signer == nil || b.revalidator == nil || ctx == nil {
		return ErrCommitBoundary
	}
	authorization := validation.Authorization
	capability := authorization.Capability
	if authorization.Signature == "" || validateCommitCapability(capability, validation.CommitAt) != nil || !capabilityMatchesValidation(capability, validation) {
		return ErrCommitBoundary
	}
	payload, err := json.Marshal(capability)
	if err != nil || b.signer.Verify(payload, authorization.Signature) != nil {
		return ErrCommitBoundary
	}
	if err := b.revalidator.Revalidate(ctx, cloneCommitCapability(capability)); err != nil {
		return ErrCommitBoundary
	}
	return nil
}

// SignCommitCapability is intended for the trusted evidence and policy service.
// The Orchestrator still revalidates the returned capability at commit time.
func SignCommitCapability(capability CommitCapability, signer CommitSigner) (CommitAuthorization, error) {
	if signer == nil || validateCommitCapability(capability, capability.IssuedAt) != nil {
		return CommitAuthorization{}, ErrCommitBoundary
	}
	capability = canonicalCommitCapability(capability)
	payload, err := json.Marshal(capability)
	if err != nil {
		return CommitAuthorization{}, ErrCommitBoundary
	}
	signature, err := signer.Sign(payload)
	if err != nil || signature == "" {
		return CommitAuthorization{}, ErrCommitBoundary
	}
	return CommitAuthorization{Capability: capability, Signature: signature}, nil
}

func validateCommitCapability(capability CommitCapability, at time.Time) error {
	if capability.CapabilityVersion != CommitCapabilityVersion || !safeCommitValue(capability.TenantID) || !safeCommitValue(capability.ProjectID) || !safeCommitValue(capability.PrincipalID) || !safeCommitValue(capability.PrincipalType) || !safeCommitValue(capability.Role) || !safeCommitValue(capability.Action) || !safeCommitValue(capability.LeaseID) || !safeCommitValue(capability.PolicyVersion) || !safeCommitValue(capability.BudgetAccountID) || capability.ExpectedVersion < 0 || capability.ProjectVersion < 0 || capability.TaskVersion < 0 || capability.FencingToken < 1 || !validCommitDigest(capability.ParameterDigest) || capability.IssuedAt.IsZero() || capability.ExpiresAt.IsZero() || at.IsZero() {
		return ErrCommitBoundary
	}
	if capability.ApprovalRecordID != "" && !safeCommitValue(capability.ApprovalRecordID) {
		return ErrCommitBoundary
	}
	if capability.TaskID == "" && capability.TaskVersion != 0 || capability.TaskID != "" && !safeCommitValue(capability.TaskID) {
		return ErrCommitBoundary
	}
	if capability.ModuleSpecRef != (contracts.SpecRef{}) && capability.ModuleSpecRef.Validate() != nil || capability.GoalSpecRef != (contracts.SpecRef{}) && capability.GoalSpecRef.Validate() != nil {
		return ErrCommitBoundary
	}
	if at.Before(capability.IssuedAt) || !at.Before(capability.ExpiresAt) || !capability.IssuedAt.Before(capability.ExpiresAt) || capability.ExpiresAt.Sub(capability.IssuedAt) > maximumCommitCapabilityLifetime {
		return ErrCommitBoundary
	}
	if len(capability.EvidenceSHA256) > 32 || len(capability.Claims) > 32 {
		return ErrCommitBoundary
	}
	seenEvidence := make(map[string]bool, len(capability.EvidenceSHA256))
	for _, digest := range capability.EvidenceSHA256 {
		if !validCommitDigest(digest) || seenEvidence[digest] {
			return ErrCommitBoundary
		}
		seenEvidence[digest] = true
	}
	for claim, verified := range capability.Claims {
		if !safeCommitValue(claim) || !verified {
			return ErrCommitBoundary
		}
	}
	return nil
}

func capabilityMatchesValidation(capability CommitCapability, validation CommitValidation) bool {
	expected := CommitCapability{
		CapabilityVersion: capability.CapabilityVersion,
		TenantID:          validation.TenantID,
		ProjectID:         validation.ProjectID,
		TaskID:            validation.TaskID,
		PrincipalID:       validation.PrincipalID,
		PrincipalType:     capability.PrincipalType,
		Role:              capability.Role,
		Action:            validation.Action,
		ExpectedVersion:   validation.ExpectedVersion,
		ProjectVersion:    validation.Project.Version,
		TaskVersion:       validation.Task.Version,
		ParameterDigest:   validation.ParameterDigest,
		EvidenceSHA256:    append([]string(nil), validation.EvidenceSHA256...),
		Claims:            cloneClaims(validation.Claims),
		ModuleSpecRef:     validation.ModuleSpecRef,
		GoalSpecRef:       validation.GoalSpecRef,
		ApprovalRecordID:  validation.ApprovalRecordID,
		LeaseID:           capability.LeaseID,
		FencingToken:      capability.FencingToken,
		PolicyVersion:     capability.PolicyVersion,
		BudgetAccountID:   capability.BudgetAccountID,
		IssuedAt:          capability.IssuedAt,
		ExpiresAt:         capability.ExpiresAt,
	}
	if validation.FencingToken > 0 && validation.FencingToken != capability.FencingToken {
		return false
	}
	return reflect.DeepEqual(canonicalCommitCapability(capability), canonicalCommitCapability(expected))
}

func canonicalCommitCapability(capability CommitCapability) CommitCapability {
	capability.EvidenceSHA256 = append([]string(nil), capability.EvidenceSHA256...)
	sort.Strings(capability.EvidenceSHA256)
	capability.Claims = cloneClaims(capability.Claims)
	capability.IssuedAt = capability.IssuedAt.UTC()
	capability.ExpiresAt = capability.ExpiresAt.UTC()
	return capability
}

func cloneCommitCapability(capability CommitCapability) CommitCapability {
	capability.EvidenceSHA256 = append([]string(nil), capability.EvidenceSHA256...)
	capability.Claims = cloneClaims(capability.Claims)
	return capability
}

func cloneClaims(claims map[string]bool) map[string]bool {
	if len(claims) == 0 {
		return nil
	}
	result := make(map[string]bool, len(claims))
	for key, value := range claims {
		result[key] = value
	}
	return result
}

func safeCommitValue(value string) bool {
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00")
}

func validCommitDigest(value string) bool {
	return contracts.SpecRef{Version: 1, SHA256: value}.Validate() == nil
}
