package eventing

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
)

func TestDecodeRelationalTaskRejectsUnboundIdentity(t *testing.T) {
	state := relationalTestStagedTaskState(
		"00000000-0000-4000-8000-000000000001",
		"00000000-0000-4000-8000-000000000002",
		"00000000-0000-4000-8000-000000000003",
		"00000000-0000-4000-8000-000000000004",
		"sha256:"+strings.Repeat("b", 64),
		"sha256:"+strings.Repeat("a", 64),
		"DEFINED",
		1,
	)
	var value map[string]any
	if err := json.Unmarshal(state, &value); err != nil {
		t.Fatal(err)
	}
	value["attemptSeriesId"] = "not-a-uuid"
	state, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRelationalTask(state, "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003", 1); err == nil {
		t.Fatal("untrusted attempt series identity was accepted")
	}
}

func TestTaskBlockedReasonIsStable(t *testing.T) {
	value, err := taskBlockedReason([]string{
		"00000000-0000-4000-8000-000000000003",
		"00000000-0000-4000-8000-000000000002",
	})
	if err != nil || value != "[\"00000000-0000-4000-8000-000000000002\",\"00000000-0000-4000-8000-000000000003\"]" {
		t.Fatalf("blocked reason = %v, %v", value, err)
	}
	value, err = taskBlockedReason(nil)
	if err != nil || value != nil {
		t.Fatalf("empty blocked reason = %v, %v", value, err)
	}
}

func TestRelationalSpecValidationBindsContentDigestAndPlan(t *testing.T) {
	projectID := "00000000-0000-4000-8000-000000000001"
	goalSHA := "sha256:" + strings.Repeat("1", 64)
	plan, planContent, planSHA := relationalTestPlan(t, projectID, goalSHA)
	artifact := relationalSpecArtifact{TenantID: "tenant", ProjectID: projectID, Kind: planArtifactKind, SpecID: "plan", Version: plan.PlanSpecVersion, ContentSHA256: planSHA, Content: planContent, CreatedAt: time.Unix(1, 0), CreatedBy: "agent"}
	if _, err := validatePlanArtifact(artifact, contracts.SpecRef{Version: plan.PlanSpecVersion, SHA256: planSHA}, projectID); err != nil {
		t.Fatal(err)
	}
	artifact.Content = []byte(`{"planSpecVersion":1}`)
	if _, err := validatePlanArtifact(artifact, contracts.SpecRef{Version: plan.PlanSpecVersion, SHA256: planSHA}, projectID); err == nil {
		t.Fatal("tampered PlanSpec content binding was accepted")
	}
}

func TestRelationalArtifactDecodesBinaryJSONContent(t *testing.T) {
	encoded, err := json.Marshal(struct {
		TenantID string `json:"tenantId"`
		Content  []byte `json:"content"`
	}{TenantID: "tenant", Content: []byte(`{"value":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	var artifact relationalSpecArtifact
	if err := json.Unmarshal(encoded, &artifact); err != nil {
		t.Fatal(err)
	}
	if string(artifact.Content) != `{"value":1}` {
		t.Fatalf("decoded artifact content = %s", artifact.Content)
	}
}
