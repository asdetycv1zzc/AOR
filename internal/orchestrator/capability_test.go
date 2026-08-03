package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
)

type testCommitRevalidator struct {
	err   error
	calls int
}

func (v *testCommitRevalidator) Revalidate(_ context.Context, _ CommitCapability) error {
	v.calls++
	return v.err
}

func TestSignedCommitBoundaryBindsVerifiedFactsAtCommit(t *testing.T) {
	signer, err := authz.NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	revalidator := &testCommitRevalidator{}
	boundary, err := NewSignedCommitBoundary(signer, revalidator)
	if err != nil {
		t.Fatal(err)
	}
	validation := validCommitValidation()
	validation.Authorization = signedAuthorization(t, signer, validation)
	if err := boundary.Validate(context.Background(), validation); err != nil {
		t.Fatal(err)
	}
	if revalidator.calls != 1 {
		t.Fatalf("revalidation calls = %d", revalidator.calls)
	}

	forged := cloneCommitValidation(validation)
	forged.Claims["merge_gate_passed"] = false
	if err := boundary.Validate(context.Background(), forged); !errors.Is(err, ErrCommitBoundary) {
		t.Fatalf("forged evidence claim error = %v", err)
	}

	tampered := cloneCommitValidation(validation)
	tampered.Authorization.Capability.ParameterDigest = testCommitDigest("tampered")
	if err := boundary.Validate(context.Background(), tampered); !errors.Is(err, ErrCommitBoundary) {
		t.Fatalf("tampered capability error = %v", err)
	}
}

func TestSignedCommitBoundaryFailsClosedOnDynamicRevalidation(t *testing.T) {
	signer, err := authz.NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	revalidator := &testCommitRevalidator{err: errors.New("lease revoked")}
	boundary, err := NewSignedCommitBoundary(signer, revalidator)
	if err != nil {
		t.Fatal(err)
	}
	validation := validCommitValidation()
	validation.Authorization = signedAuthorization(t, signer, validation)
	if err := boundary.Validate(context.Background(), validation); !errors.Is(err, ErrCommitBoundary) {
		t.Fatalf("revoked lease error = %v", err)
	}
}

func validCommitValidation() CommitValidation {
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	ref := contracts.SpecRef{Version: 2, SHA256: testCommitDigest("module")}
	return CommitValidation{
		TenantID:        "tenant_1",
		ProjectID:       "project_1",
		TaskID:          "task_1",
		PrincipalID:     "agent_1",
		Action:          string(state.TaskCommandIntegrate),
		ExpectedVersion: 7,
		Project:         state.Project{TenantID: "tenant_1", ID: "project_1", State: contracts.ProjectIntegrating, Version: 11},
		Task:            state.ModuleTask{TenantID: "tenant_1", ProjectID: "project_1", ID: "task_1", State: contracts.TaskPassed, Version: 7, ModuleSpecRef: ref, FencingToken: 4},
		ParameterDigest: testCommitDigest("command"),
		EvidenceSHA256:  []string{testCommitDigest("audit")},
		Claims:          map[string]bool{"dependencies_satisfied": true, "merge_gate_passed": true},
		ModuleSpecRef:   ref,
		FencingToken:    4,
		CommitAt:        at,
	}
}

func signedAuthorization(t *testing.T, signer CommitSigner, validation CommitValidation) CommitAuthorization {
	t.Helper()
	capability := CommitCapability{
		CapabilityVersion: CommitCapabilityVersion,
		TenantID:          validation.TenantID,
		ProjectID:         validation.ProjectID,
		TaskID:            validation.TaskID,
		PrincipalID:       validation.PrincipalID,
		PrincipalType:     "AGENT_INSTANCE",
		Role:              "EXECUTOR",
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
		LeaseID:           "lease_1",
		FencingToken:      4,
		PolicyVersion:     testCommitDigest("policy"),
		BudgetAccountID:   "budget_1",
		IssuedAt:          validation.CommitAt.Add(-time.Minute),
		ExpiresAt:         validation.CommitAt.Add(time.Minute),
	}
	authorization, err := SignCommitCapability(capability, signer)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func testCommitDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
