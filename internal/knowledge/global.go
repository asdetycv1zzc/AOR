package knowledge

import (
	"sort"
	"strings"
)

const GlobalKnowledgeRoot = "global"

var globalKnowledgeCategories = map[string]struct{}{
	"policies":  {},
	"prompts":   {},
	"protocols": {},
	"standards": {},
	"workflows": {},
}

// GlobalKnowledgeCategories returns the fixed global namespace. Callers get a
// fresh sorted slice so a request cannot mutate the policy vocabulary.
func GlobalKnowledgeCategories() []string {
	result := make([]string, 0, len(globalKnowledgeCategories))
	for category := range globalKnowledgeCategories {
		result = append(result, category)
	}
	sort.Strings(result)
	return result
}

// ValidateGlobalPath accepts only one of the five global namespaces and a
// non-empty relative document path below it. It deliberately does not permit
// callers to address the deployment root or another project's namespace.
func ValidateGlobalPath(value string) error {
	normalized, err := normalizePath(value)
	if err != nil || normalized != value {
		return invalid("global knowledge path")
	}
	parts := strings.Split(value, "/")
	if len(parts) < 3 || parts[0] != GlobalKnowledgeRoot {
		return invalid("global knowledge path")
	}
	if _, ok := globalKnowledgeCategories[parts[1]]; !ok {
		return invalid("global knowledge path")
	}
	for _, part := range parts[2:] {
		if part == "" || part == "." || part == ".." {
			return invalid("global knowledge path")
		}
	}
	return nil
}

func IsGlobalPath(value string) bool {
	return ValidateGlobalPath(value) == nil
}
