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
