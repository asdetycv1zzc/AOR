package servicebootstrap

import (
	"errors"
	"testing"

	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/integration"
)

func TestIntegrationLeasePolicyMismatchStillRequiresRevocation(t *testing.T) {
	issued, err := integrationLeaseIssueState(authz.CapabilityLease{
		ID:            "lease_1",
		PolicyVersion: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}, nil, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if !issued {
		t.Fatal("successfully issued lease was not marked for revocation")
	}
	if !errors.Is(err, integration.ErrNotAudited) {
		t.Fatalf("policy mismatch error = %v", err)
	}
}
