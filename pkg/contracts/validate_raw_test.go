package contracts

import (
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
