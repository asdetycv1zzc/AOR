package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/akimisaka/aor/pkg/contracts"
)

type fakeMerger struct {
	calls  int
	commit string
}

func (m *fakeMerger) Merge(_ context.Context, _ string, _ []string, _ string) (string, error) {
	m.calls++
	return m.commit, nil
}

func TestQueueRejectsPathAndInterfaceConflictsBeforeMerge(t *testing.T) {
	merger := &fakeMerger{commit: commit(9)}
	queue, err := NewQueue(NewMemoryStore(), merger, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest()
	request.Candidates[1].OwnedPaths = []string{"owned/api"}
	request.Candidates[1].PublicInterfaces = []string{"HTTP /v1"}
	audit, err := queue.Audit(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if audit.Passed || len(audit.Findings) != 2 || merger.calls != 0 {
		t.Fatalf("conflict audit did not fail closed: %#v calls=%d", audit, merger.calls)
	}
	if _, err := queue.Merge(context.Background(), request); !errors.Is(err, ErrConflict) {
		t.Fatalf("merge conflict error = %v", err)
	}
}

func TestQueueMergesOnceAndReturnsImmutableReplay(t *testing.T) {
	merger := &fakeMerger{commit: commit(7)}
	queue, _ := NewQueue(NewMemoryStore(), merger, nil)
	request := validRequest()
	first, err := queue.Merge(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := queue.Merge(context.Background(), request)
	if err != nil || !second.Duplicate || second.Commit != first.Commit || merger.calls != 1 {
		t.Fatalf("merge replay was not idempotent: %#v %#v calls=%d", first, second, merger.calls)
	}
	request.Candidates[0].SubmissionCommit = commit(9)
	if _, err := queue.Merge(context.Background(), request); !errors.Is(err, ErrImmutable) {
		t.Fatalf("different merge body error = %v", err)
	}
}

func TestQueueTreatsCandidateOrderAsCanonical(t *testing.T) {
	merger := &fakeMerger{commit: commit(7)}
	queue, _ := NewQueue(NewMemoryStore(), merger, nil)
	request := validRequest()
	if _, err := queue.Merge(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.Candidates[0], request.Candidates[1] = request.Candidates[1], request.Candidates[0]
	replay, err := queue.Merge(context.Background(), request)
	if err != nil || !replay.Duplicate || merger.calls != 1 {
		t.Fatalf("candidate order changed immutable replay: %#v calls=%d", replay, merger.calls)
	}
}

func validRequest() Request {
	return Request{TenantID: "tenant-1", ProjectID: "project-1", IntegrationID: "integration-1", IdempotencyKey: "merge-1", BaseCommit: commit(1), PolicyDigest: digest("policy"), Candidates: []Candidate{{TaskID: "task-1", ModuleID: "module-1", SubmissionCommit: commit(2), ModuleSpecRef: specRef(1), OwnedPaths: []string{"owned/api"}, PublicInterfaces: []string{"HTTP /v1"}, EvidenceSHA256: digest("evidence-1"), AuditPassed: true}, {TaskID: "task-2", ModuleID: "module-2", SubmissionCommit: commit(3), ModuleSpecRef: specRef(2), OwnedPaths: []string{"owned/worker"}, PublicInterfaces: []string{"HTTP /v2"}, EvidenceSHA256: digest("evidence-2"), AuditPassed: true}}}
}

func specRef(version int) contracts.SpecRef {
	return contracts.SpecRef{Version: version, SHA256: digest("module")}
}

func commit(value byte) string {
	return string(make([]byte, 0)) + repeatHex(value, 40)
}

func repeatHex(value byte, count int) string {
	character := "0"
	if value%2 == 1 {
		character = "1"
	}
	result := ""
	for index := 0; index < count; index++ {
		result += character
	}
	return result
}

func digest(value string) string {
	return "sha256:" + repeatHex(byte(len(value)), 64)
}
