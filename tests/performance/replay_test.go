package performance_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/projection"
	"github.com/akimisaka/aor/pkg/canonicaljson"
)

func TestTenThousandEventReplayCompletesWithinBaseline(t *testing.T) {
	projector := projection.New(map[string]projection.Reducer{"project": func(_ json.RawMessage, event eventing.DomainEvent) (json.RawMessage, error) {
		return append(json.RawMessage(nil), event.Payload...), nil
	}})
	started := time.Now()
	for version := int64(1); version <= 10000; version++ {
		payload := json.RawMessage(fmt.Sprintf(`{"version":%d}`, version))
		digest, err := canonicaljson.Digest(payload)
		if err != nil {
			t.Fatal(err)
		}
		_, err = projector.Apply(eventing.DomainEvent{EventID: fmt.Sprintf("evt_%d", version), TenantID: "tenant_1", ProjectID: "prj_1", AggregateType: "project", AggregateID: "prj_1", AggregateVersion: version, Type: "io.aor.project.replayed.v1", Payload: payload, PayloadSHA256: digest, OccurredAt: started})
		if err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(started); elapsed >= 10*time.Minute {
		t.Fatalf("replay took %s", elapsed)
	}
	snapshot, found := projector.Snapshot("tenant_1", "project", "prj_1")
	if !found || snapshot.Version != 10000 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}
