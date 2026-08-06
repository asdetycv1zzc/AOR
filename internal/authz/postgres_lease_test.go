package authz

import (
	"testing"
	"time"
)

func TestPostgresLeaseCASAllowsOnlyMutableFields(t *testing.T) {
	now := time.Date(2030, 2, 3, 4, 5, 6, 0, time.UTC)
	current := CapabilityLease{
		ID: "lease_1", TenantID: "tenant_1", ProjectID: "project_1", TaskID: "task_1",
		Nonce: testParamsDigest, FencingToken: 1, State: LeaseActive,
		ExpiresAt: now.Add(time.Minute), LastHeartbeatAt: now, Signature: "signature_1",
	}
	replacement := cloneLease(current)
	replacement.ExpiresAt = now.Add(2 * time.Minute)
	replacement.LastHeartbeatAt = now.Add(time.Second)
	replacement.Nonce = testSpecDigest
	replacement.FencingToken = 2
	replacement.State = LeaseRevoked
	revokedAt := now.Add(time.Second)
	replacement.RevokedAt = &revokedAt
	replacement.Signature = "signature_2"
	if !sameLeaseBinding(current, replacement) {
		t.Fatal("mutable lease state was treated as a binding change")
	}
	replacement.ProjectID = "project_2"
	if sameLeaseBinding(current, replacement) {
		t.Fatal("project binding change was accepted")
	}
}

func TestPostgresLeaseCASRejectsActiveLeaseRevival(t *testing.T) {
	now := time.Date(2030, 2, 3, 4, 5, 6, 0, time.UTC)
	base := CapabilityLease{
		State: LeaseActive, ExpiresAt: now.Add(time.Minute), LastHeartbeatAt: now.Add(-time.Second),
		HeartbeatIntervalSeconds: 30,
	}
	replacement := cloneLease(base)
	replacement.ExpiresAt = now.Add(5 * time.Minute)
	replacement.LastHeartbeatAt = now

	tests := []struct {
		name    string
		current CapabilityLease
	}{
		{name: "absolute expiry", current: func() CapabilityLease {
			lease := cloneLease(base)
			lease.ExpiresAt = now
			return lease
		}()},
		{name: "heartbeat deadline", current: func() CapabilityLease {
			lease := cloneLease(base)
			lease.ExpiresAt = now.Add(10 * time.Minute)
			lease.LastHeartbeatAt = now.Add(-90 * time.Second)
			return lease
		}()},
		{name: "inactive state", current: func() CapabilityLease {
			lease := cloneLease(base)
			lease.State = LeaseRevoked
			return lease
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if allowsPostgresLeaseTransition(test.current, replacement, now) {
				t.Fatal("expired or inactive lease was allowed to become active")
			}
		})
	}
	if !allowsPostgresLeaseTransition(base, replacement, now) {
		t.Fatal("live active lease transition was rejected")
	}
	revocation := cloneLease(base)
	revocation.State = LeaseRevoked
	expired := cloneLease(base)
	expired.ExpiresAt = now
	if !allowsPostgresLeaseTransition(expired, revocation, now) {
		t.Fatal("non-active transition changed existing revocation semantics")
	}
}
