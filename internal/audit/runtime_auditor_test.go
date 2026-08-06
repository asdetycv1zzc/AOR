package audit

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/pkg/contracts"
)

func TestModuleAuditContextIncludesAcceptanceCriteria(t *testing.T) {
	ref := contracts.SpecRef{Version: 1, SHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	criteria := []string{"criterion-one", "criterion-two"}
	tests := []string{"go test ./..."}
	items, err := moduleAuditContextItems(BlindAuditInput{
		AuditRunID: "audit_1", ModuleSpecRef: ref, RequiredCriteria: criteria, TestRequirements: tests,
	}, ModuleAuditReferences{GoalSpec: ref})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.Kind != agentruntime.ContextModuleReference {
			continue
		}
		var content struct {
			ModuleSpecRef      contracts.SpecRef `json:"moduleSpecRef"`
			AcceptanceCriteria []string          `json:"acceptanceCriteria"`
			TestRequirements   []string          `json:"testRequirements"`
		}
		if err := json.Unmarshal([]byte(item.Content), &content); err != nil {
			t.Fatal(err)
		}
		if content.ModuleSpecRef != ref || !slices.Equal(content.AcceptanceCriteria, criteria) || !slices.Equal(content.TestRequirements, tests) {
			t.Fatalf("module context = %#v", content)
		}
		return
	}
	t.Fatal("module context item not found")
}
