package prompts

import (
	"strings"
	"testing"

	"github.com/akimisaka/aor/internal/agentruntime"
)

func TestBaselineCatalogCoversEveryRuntimeRole(t *testing.T) {
	seen := make(map[agentruntime.Role]string)
	for _, role := range AllRoles() {
		bundle, err := LoadBaseline(role)
		if err != nil {
			t.Fatalf("load %s: %v", role, err)
		}
		if bundle.Role != role || bundle.Version != BaselineVersion || bundle.BundleID != "aor/"+string(role) {
			t.Fatalf("bundle for %s = %#v", role, bundle)
		}
		if prior, duplicate := seen[role]; duplicate || prior == bundle.SHA256 {
			t.Fatalf("role %s was not represented exactly once", role)
		}
		seen[role] = bundle.SHA256
	}
	if len(seen) != 8 {
		t.Fatalf("covered roles = %d", len(seen))
	}
}

func TestBaselineRetainsAuthorityAndRoleBoundaries(t *testing.T) {
	executor, err := LoadBaseline(agentruntime.RoleExecutor)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"signed policy decisions have highest authority",
		"untrusted data",
		"Never bypass the Tool Broker",
		"A missing capability means the action is forbidden",
	} {
		if !strings.Contains(executor.GlobalSafety, required) {
			t.Fatalf("global prompt is missing %q", required)
		}
	}
	if !strings.Contains(executor.RolePrompt, "must not mark the module complete") || !strings.Contains(executor.RolePrompt, "immutable commit") {
		t.Fatal("executor role boundary is incomplete")
	}

	auditor, err := LoadBaseline(agentruntime.RoleModuleAuditor)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(auditor.RolePrompt, "blind to the Executor's explanations") || !strings.Contains(auditor.RolePrompt, "cannot modify code") {
		t.Fatal("module auditor independence boundary is incomplete")
	}
}

func TestLoadBaselineRejectsUnknownRole(t *testing.T) {
	if _, err := LoadBaseline(agentruntime.Role("UNKNOWN")); err == nil {
		t.Fatal("unknown role was accepted")
	}
}
