package audit

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/pkg/contracts"
)

func TestModuleAuditContextIncludesCompleteModuleSpec(t *testing.T) {
	ref := contracts.SpecRef{Version: 1, SHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	criteria := []string{"criterion-one", "criterion-two"}
	tests := []string{"go test ./..."}
	module := contracts.ModuleSpec{ModuleSpecVersion: ref.Version, ModuleID: "module-1", Purpose: "implement the module", AcceptanceCriteria: criteria, TestRequirements: tests, SHA256: ref.SHA256}
	items, err := moduleAuditContextItems(BlindAuditInput{
		AuditRunID: "audit_1", ModuleSpecRef: ref, ModuleSpec: &module, RequiredCriteria: criteria, TestRequirements: tests,
	}, ModuleAuditReferences{GoalSpec: ref})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.Kind != agentruntime.ContextModuleReference {
			continue
		}
		var content contracts.ModuleSpec
		if err := json.Unmarshal([]byte(item.Content), &content); err != nil {
			t.Fatal(err)
		}
		if content.ModuleSpecVersion != ref.Version || content.SHA256 != ref.SHA256 || content.Purpose != module.Purpose || !slices.Equal(content.AcceptanceCriteria, criteria) || !slices.Equal(content.TestRequirements, tests) {
			t.Fatalf("module context = %#v", content)
		}
		return
	}
	t.Fatal("module context item not found")
}
