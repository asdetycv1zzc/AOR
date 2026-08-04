package goalplan

import (
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestAgentResponseSchemasCompileWithoutExternalResources(t *testing.T) {
	for _, stage := range []string{"GOAL_DRAFT", "GOAL_REVISION", "GOAL_CHALLENGE", "PLAN_DRAFT", "MODULE_SPEC"} {
		t.Run(stage, func(t *testing.T) {
			response, err := responseSchemaFor(stage)
			if err != nil || response.Reference == "" || len(response.Document) == 0 {
				t.Fatalf("response schema = %#v err=%v", response, err)
			}
			var document any
			if err := json.Unmarshal(response.Document, &document); err != nil {
				t.Fatal(err)
			}
			compiler := jsonschema.NewCompiler()
			compiler.DefaultDraft(jsonschema.Draft2020)
			if err := compiler.AddResource(response.Reference, document); err != nil {
				t.Fatal(err)
			}
			if _, err := compiler.Compile(response.Reference); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAgentResponseSchemaRejectsSystemOwnedFields(t *testing.T) {
	response, err := responseSchemaFor("GOAL_DRAFT")
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(response.Document, &document); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource(response.Reference, document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(response.Reference)
	if err != nil {
		t.Fatal(err)
	}
	instance := map[string]any{
		"title": "Goal", "summary": "Summary", "problemStatement": "Problem",
		"businessOutcomes": []any{map[string]any{"id": "outcome_1", "statement": "Outcome"}},
		"scope":            map[string]any{"included": []any{"Included"}, "excluded": []any{}},
		"userPersonas":     []any{}, "functionalRequirements": []any{"Requirement"},
		"nonFunctionalRequirements": map[string]any{
			"security": []any{}, "privacy": []any{}, "performance": []any{}, "reliability": []any{}, "operability": []any{},
		},
		"constraints": []any{}, "assumptions": []any{}, "decisions": []any{}, "unresolvedItems": []any{},
		"acceptanceCriteria":  []any{map[string]any{"id": "criterion_1", "statement": "Criterion", "evidenceType": "AUTOMATED"}},
		"riskTolerance":       "LOW",
		"humanApprovalPoints": []any{}, "dataClassification": "INTERNAL", "deploymentTargets": []any{"LINUX"}, "sourceReferences": []any{},
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("valid model-owned draft rejected: %v", err)
	}
	instance["goalSpecVersion"] = 1
	instance["projectId"] = "project-spoofed"
	if err := schema.Validate(instance); err == nil {
		t.Fatal("schema accepted model-owned spoofing of control-plane fields")
	}
}
