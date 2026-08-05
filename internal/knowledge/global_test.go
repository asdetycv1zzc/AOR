package knowledge

import "testing"

func TestGlobalKnowledgeNamespaceIsFixedAndSafe(t *testing.T) {
	if got := GlobalKnowledgeCategories(); len(got) != 5 || got[0] != "policies" || got[1] != "prompts" || got[2] != "protocols" || got[3] != "standards" || got[4] != "workflows" {
		t.Fatalf("global categories = %#v", got)
	}
	valid := []string{
		"global/policies/security.md",
		"global/prompts/curator.md",
		"global/protocols/aop/v1.md",
		"global/standards/go.md",
		"global/workflows/release.md",
	}
	for _, path := range valid {
		if err := ValidateGlobalPath(path); err != nil {
			t.Errorf("ValidateGlobalPath(%q) = %v", path, err)
		}
	}
	invalidPaths := []string{
		"global",
		"global/projects/project-a.md",
		"global/policies",
		"global/unknown/rules.md",
		"global/policies/../prompts/rules.md",
		"global/policies/CON.md",
		"/global/policies/rules.md",
	}
	for _, path := range invalidPaths {
		if err := ValidateGlobalPath(path); err == nil {
			t.Errorf("ValidateGlobalPath(%q) accepted an invalid path", path)
		}
	}
	if !IsGlobalPath("global/standards/go.md") || IsGlobalPath("projects/project-a/standards/go.md") {
		t.Fatal("global path classification is incorrect")
	}
}
