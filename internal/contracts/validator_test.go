package contracts

import (
	"path/filepath"
	"testing"
)

func TestEverySchemaCompilesAndFixturesMatchExpectation(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	findings := ValidateRepositoryContracts(root)
	for _, finding := range findings {
		t.Errorf("%s: %s", finding.Path, finding.Message)
	}
}
