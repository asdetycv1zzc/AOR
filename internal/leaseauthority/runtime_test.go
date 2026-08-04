package leaseauthority

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
)

func TestRuntimeAuthorityValidatesHeartbeatsAndRenewsSignedLease(t *testing.T) {
	now := time.Date(2035, 3, 4, 5, 6, 7, 0, time.UTC)
	signer, err := authz.NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := authz.NewLeaseManager(authz.LeaseManagerConfig{
		Store: authz.NewMemoryLeaseStore(), Signer: signer, Clock: func() time.Time { return now },
		DefaultTTL: 5 * time.Minute, MaxTTL: 15 * time.Minute, HeartbeatInterval: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := authn.Principal{
		ID: "agent_goal", Type: authn.PrincipalAgentInstance, Role: authn.RoleGoalProposer,
		TenantID: "tenant_1", ProjectID: "project_1",
	}
	scopes := &fixedScopeResolver{scope: Scope{
		Project: authz.ProjectScope{
			TenantID: principal.TenantID, ID: principal.ProjectID, State: "GOAL_NEGOTIATING",
			StateVersion: 4, Classification: "INTERNAL",
		},
		Budget: authz.BudgetScope{AccountID: "project_1", Available: true},
	}}
	service, err := New(Config{Manager: manager, Policy: &bindingGrantEvaluator{}, Scopes: scopes, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	principalCtx, err := authn.ContextWithPrincipal(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Issue(principalCtx, principal, GrantRequest{
		TenantID: principal.TenantID, ProjectID: principal.ProjectID,
		Action: authz.ActionModelGenerate, Resource: authz.Resource{Type: "model", ID: "provider/model"},
		ParameterDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		BudgetAccountID: "project_1", IdempotencyKey: "runtime-lease-1", TTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewRuntimeAuthority(service, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	lease := toRuntimeLease(issued)
	if err := authority.Validate(context.Background(), lease, agentruntime.LeaseOperationModel); err != nil {
		t.Fatalf("validate model lease: %v", err)
	}
	if err := authority.Validate(context.Background(), lease, agentruntime.LeaseOperationTool); !errors.Is(err, agentruntime.ErrLeaseInvalid) {
		t.Fatalf("model lease used for tool error = %v", err)
	}
	tampered := lease
	tampered.ProjectID = "project_other"
	if err := authority.Validate(context.Background(), tampered, agentruntime.LeaseOperationModel); !errors.Is(err, agentruntime.ErrLeaseInvalid) {
		t.Fatalf("tampered lease error = %v", err)
	}

	now = now.Add(10 * time.Second)
	heartbeat, err := authority.Heartbeat(context.Background(), lease)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if !heartbeat.LastHeartbeatAt.Equal(now) || heartbeat.FencingToken != lease.FencingToken || heartbeat.Nonce != lease.Nonce || heartbeat.Signature == lease.Signature {
		t.Fatalf("heartbeat lease = %#v", heartbeat)
	}

	now = now.Add(10 * time.Second)
	renewed, err := authority.Renew(context.Background(), heartbeat)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if renewed.FencingToken != heartbeat.FencingToken+1 || renewed.Nonce == heartbeat.Nonce || !renewed.ExpiresAt.After(heartbeat.ExpiresAt) {
		t.Fatalf("renewed lease = %#v", renewed)
	}
	if err := authority.Validate(context.Background(), renewed, agentruntime.LeaseOperationRenew); err != nil {
		t.Fatalf("validate renewed lease: %v", err)
	}

	now = now.Add(91 * time.Second)
	if err := authority.Validate(context.Background(), renewed, agentruntime.LeaseOperationModel); !errors.Is(err, agentruntime.ErrLeaseExpired) {
		t.Fatalf("expired lease error = %v", err)
	}
}
