package servicebootstrap

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/toolbroker"
)

type repositoryTestLeaseChecker struct{}

func (repositoryTestLeaseChecker) Validate(context.Context, toolbroker.LeaseValidation) error {
	return nil
}

func TestRepositoryMCPToolsHaveExplicitBoundedPolicies(t *testing.T) {
	tools := repositoryMCPTools()
	policies := repositoryMCPPolicies()
	if len(tools) != 5 || len(policies) != len(tools) {
		t.Fatalf("tools=%d policies=%d", len(tools), len(policies))
	}
	seen := make(map[string]bool, len(tools))
	for _, tool := range tools {
		policy, found := policies[tool.Name]
		if !found || seen[tool.Name] || tool.InputSchema["additionalProperties"] != false || tool.OutputSchema["type"] != "object" {
			t.Fatalf("invalid repository tool registration: %#v policy=%#v", tool, policy)
		}
		seen[tool.Name] = true
		if policy.NetworkAccess != toolbroker.NetworkNone || len(policy.AllowedRoles) != 1 || policy.AllowedRoles[0] != "EXECUTOR" || policy.TimeoutSeconds <= 0 || policy.MaxOutputBytes <= 0 {
			t.Fatalf("unsafe policy for %s: %#v", tool.Name, policy)
		}
	}
	if policies[string(repository.LeaseActionSubmit)].SideEffect != toolbroker.SideEffectIrreversible || policies[string(repository.LeaseActionSubmit)].RequiresApproval != toolbroker.ApprovalPolicy {
		t.Fatalf("submission policy = %#v", policies[string(repository.LeaseActionSubmit)])
	}
}

func TestRepositoryMCPClientRegistersWithToolBrokerHost(t *testing.T) {
	signer, err := repository.NewHMACSigner([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := newRepositoryMCPClient(t.TempDir(), &sql.DB{}, repositoryTestLeaseChecker{}, signer, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	broker := toolbroker.New(repositoryTestLeaseChecker{}, nil, nil, nil, nil, nil, time.Now)
	host, err := toolbroker.NewHost(broker)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if err := host.AddServerWithPolicies(context.Background(), repositoryMCPServerID, repositoryMCPVersion, client, repositoryMCPPolicies()); err != nil {
		t.Fatal(err)
	}
	if len(host.Tools()) != 5 || len(broker.List()) != 5 {
		t.Fatalf("host tools=%d descriptors=%d", len(host.Tools()), len(broker.List()))
	}
}

func TestRepositoryArgumentsRejectUnknownFields(t *testing.T) {
	var input repositoryCreateArguments
	if err := decodeRepositoryArguments(map[string]any{"attemptSeriesId": "series", "attempt": 1, "baseCommit": "commit"}, &input); err != nil {
		t.Fatal(err)
	}
	if err := decodeRepositoryArguments(map[string]any{"attemptSeriesId": "series", "attempt": 1, "baseCommit": "commit", "repositoryPath": "/tmp/escape"}, &input); !errors.Is(err, repository.ErrInvalidRequest) {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestRepositorySigningKeyUsesDomainSeparation(t *testing.T) {
	leaseKey := []byte("01234567890123456789012345678901")
	derived := deriveRepositorySigningKey(leaseKey)
	if len(derived) != 32 || string(derived) == string(leaseKey) {
		t.Fatalf("derived key length=%d equals source=%t", len(derived), string(derived) == string(leaseKey))
	}
}

func TestRepositoryMCPClientRequiresProductionDependencies(t *testing.T) {
	if _, err := newRepositoryMCPClient(t.TempDir(), nil, nil, nil, nil); !errors.Is(err, repository.ErrInvalidRequest) {
		t.Fatalf("constructor error = %v", err)
	}
}
