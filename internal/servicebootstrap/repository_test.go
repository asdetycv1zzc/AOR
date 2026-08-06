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
		if policy.NetworkAccess != toolbroker.NetworkNone || policy.TimeoutSeconds <= 0 || policy.MaxOutputBytes <= 0 {
			t.Fatalf("unsafe policy for %s: %#v", tool.Name, policy)
		}
		allowed := map[string]bool{"EXECUTOR": true}
		if tool.Name == repositoryReadTool {
			allowed["GLOBAL_AUDITOR"] = true
			allowed["MODULE_AUDITOR"] = true
		}
		if len(policy.AllowedRoles) != len(allowed) {
			t.Fatalf("unexpected roles for %s: %#v", tool.Name, policy.AllowedRoles)
		}
		for _, role := range policy.AllowedRoles {
			if !allowed[role] {
				t.Fatalf("unexpected role %q for %s", role, tool.Name)
			}
			delete(allowed, role)
		}
		if len(allowed) != 0 {
			t.Fatalf("missing roles for %s: %#v", tool.Name, allowed)
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
	if err := decodeRepositoryArguments(map[string]any{"attemptSeriesId": "series", "attempt": 1}, &input); err != nil {
		t.Fatal(err)
	}
	if err := decodeRepositoryArguments(map[string]any{"attemptSeriesId": "series", "attempt": 1, "baseCommit": "commit"}, &input); !errors.Is(err, repository.ErrInvalidRequest) {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestRepositoryCreateToolDoesNotAcceptAgentSelectedBaseCommit(t *testing.T) {
	for _, tool := range repositoryMCPTools() {
		if tool.Name != string(repository.LeaseActionCreateWorkspace) {
			continue
		}
		properties, ok := tool.InputSchema["properties"].(map[string]any)
		if !ok {
			t.Fatalf("create properties = %#v", tool.InputSchema["properties"])
		}
		if _, found := properties["baseCommit"]; found {
			t.Fatal("create tool exposes agent-selected baseCommit")
		}
		return
	}
	t.Fatal("repository create tool is not registered")
}

func TestRepositorySigningKeyUsesDomainSeparation(t *testing.T) {
	leaseKey := []byte("01234567890123456789012345678901")
	derived := deriveRepositorySigningKey(leaseKey)
	knowledgeDerived := deriveKnowledgeUpdatedSigningKey(leaseKey)
	if len(derived) != 32 || len(knowledgeDerived) != 32 || string(derived) == string(leaseKey) || string(knowledgeDerived) == string(leaseKey) || string(derived) == string(knowledgeDerived) {
		t.Fatalf("derived key length=%d equals source=%t", len(derived), string(derived) == string(leaseKey))
	}
}

func TestRepositoryMCPClientRequiresProductionDependencies(t *testing.T) {
	if _, err := newRepositoryMCPClient(t.TempDir(), nil, nil, nil, nil); !errors.Is(err, repository.ErrInvalidRequest) {
		t.Fatalf("constructor error = %v", err)
	}
}

func TestRepositoryAttemptIsNextUncommittedAttempt(t *testing.T) {
	for completed := 0; completed < 3; completed++ {
		if !repositoryAttemptIsCurrent(completed, completed+1) {
			t.Fatalf("completed attempt %d must authorize attempt %d", completed, completed+1)
		}
		if repositoryAttemptIsCurrent(completed, completed) {
			t.Fatalf("completed attempt %d must not be writable again", completed)
		}
	}
	if repositoryAttemptIsCurrent(-1, 1) || repositoryAttemptIsCurrent(3, 4) {
		t.Fatal("out-of-range attempt state must fail closed")
	}
}
