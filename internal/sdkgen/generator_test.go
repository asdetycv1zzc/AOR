package sdkgen

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestGenerateProducesDeterministicClientsForEveryOperation(t *testing.T) {
	input, err := os.ReadFile("../../api/openapi/aor.v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	first, err := Generate(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Go, second.Go) || !bytes.Equal(first.TypeScript, second.TypeScript) || !bytes.Equal(first.Python, second.Python) {
		t.Fatal("SDK generation is nondeterministic")
	}
	for _, operationID := range []string{"createProject", "pauseProject", "approveGoalSpec", "decideTask", "searchKnowledge", "runDoctor"} {
		if !strings.Contains(string(first.TypeScript), operationID+"(") || !strings.Contains(string(first.Go), exported(operationID)+"(") || !strings.Contains(string(first.Python), "def "+snake(operationID)+"(") {
			t.Fatalf("operation %s missing from a generated client", operationID)
		}
	}
}

func TestGenerateRejectsReferencedPathWithoutStableOperationID(t *testing.T) {
	input := []byte("openapi: 3.2.0\npaths:\n  /v1/test:\n    $ref: '#/components/pathItems/Command'\n")
	if _, err := Generate(input); err == nil {
		t.Fatal("reference without x-operation-id was accepted")
	}
}
