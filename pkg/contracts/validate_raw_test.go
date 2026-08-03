package contracts

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

func TestValidateGoalJSONBindsOnlyImmutableContent(t *testing.T) {
	content := []byte(`{"goalSpecVersion":1,"projectId":"prj_1","version":1,"title":"Goal","summary":"Summary","problemStatement":"Problem","businessOutcomes":[{"id":"outcome_1","statement":"Outcome"}],"scope":{"included":[],"excluded":[]},"userPersonas":[],"functionalRequirements":[],"nonFunctionalRequirements":{"security":[],"privacy":[],"performance":[],"reliability":[],"operability":[]},"constraints":[],"assumptions":[],"decisions":[],"unresolvedItems":[],"acceptanceCriteria":[{"id":"criterion_1","statement":"Pass","evidenceType":"AUTOMATED"}],"riskTolerance":"LOW","humanApprovalPoints":[],"dataClassification":"INTERNAL","deploymentTargets":[],"sourceReferences":[],"createdAt":"2030-01-01T00:00:00Z","createdBy":{"agentInstanceId":"agt_1","role":"GOAL_PROPOSER"}}`)
	digest, err := canonicaljson.Digest(content)
	if err != nil {
		t.Fatal(err)
	}
	draft := []byte(fmt.Sprintf(`{"content":%s,"status":"DRAFT","contentSha256":"%s"}`, content, digest))
	if err := ValidateGoalJSON(draft); err != nil {
		t.Fatal(err)
	}
	approved := []byte(fmt.Sprintf(`{"content":%s,"status":"APPROVED","approvedBy":{"actorId":"usr_1","approvedAt":"2030-01-01T00:01:00Z"},"contentSha256":"%s"}`, content, digest))
	if err := ValidateGoalJSON(approved); err != nil {
		t.Fatal(err)
	}
}

func TestValidateSubmissionJSONBindsUnknownOptionalFields(t *testing.T) {
	base := []byte(`{"submissionVersion":1,"projectId":"prj_1","moduleTaskId":"task_1","attemptSeriesId":"series_1","attempt":1,"moduleSpecRef":{"version":1,"sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"baseCommit":"0000000000000000000000000000000000000001","headCommit":"0000000000000000000000000000000000000002","changedFiles":[],"deletedFiles":[],"createdFiles":[],"claimedCriteria":[],"localTestEvidenceRefs":[],"agentIdentity":{"agentInstanceId":"agt_1","role":"EXECUTOR","leaseId":"lease_1"},"createdAt":"2030-01-01T00:00:00Z","futureField":{"value":1}}`)
	digest, err := canonicaljson.Digest(base)
	if err != nil {
		t.Fatal(err)
	}
	manifest := append(base[:len(base)-1], []byte(fmt.Sprintf(`,"sha256":"%s"}`, digest))...)
	if err := ValidateSubmissionJSON(manifest); err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), manifest...)
	for i := range mutated {
		if mutated[i] == '1' && i > len(mutated)/2 {
			mutated[i] = '2'
			break
		}
	}
	if err := ValidateSubmissionJSON(mutated); err == nil {
		t.Fatal("unknown field mutation was not detected")
	}
}

func TestValidatePlanJSONBindsDAGAndDigest(t *testing.T) {
	plan := PlanSpec{
		PlanSpecVersion: 1,
		ProjectID:       "prj_1",
		GoalSpecRef:     SpecRef{Version: 2, SHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Architecture:    Architecture{Style: "modular"},
		Modules: []PlanModule{
			{ModuleID: "mod_api", Name: "API", Responsibility: "HTTP boundary", ExecutionPlatform: PlatformLinux, SandboxLevel: IsolationContainer, AcceptanceCriteria: []string{"api works"}, Risk: "HIGH"},
			{ModuleID: "mod_worker", Name: "Worker", Responsibility: "background work", ExecutionPlatform: PlatformLinux, SandboxLevel: IsolationContainer, Dependencies: []string{"mod_api"}, AcceptanceCriteria: []string{"work completes"}, Risk: "MEDIUM"},
		},
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.SHA256, err = canonicaljson.DigestObjectWithoutFields(encoded, "sha256", "signature")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = json.Marshal(plan)
	if err := ValidatePlanJSON(encoded); err != nil {
		t.Fatal(err)
	}
	plan.PlanSpecVersion = 2
	plan.SHA256 = ""
	encoded, _ = json.Marshal(plan)
	plan.SHA256, err = canonicaljson.DigestObjectWithoutFields(encoded, "sha256", "signature")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = json.Marshal(plan)
	if err := ValidatePlanJSON(encoded); err != nil {
		t.Fatal(err)
	}
	plan.Modules[1].Dependencies = []string{"mod_worker"}
	encoded, _ = json.Marshal(plan)
	if err := ValidatePlanJSON(encoded); err == nil {
		t.Fatal("cyclic plan accepted")
	}
}
