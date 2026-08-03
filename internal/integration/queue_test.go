package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
)

type fakeMerger struct {
	mu      sync.Mutex
	calls   int
	commit  string
	results map[string]string
}

func (m *fakeMerger) Merge(_ context.Context, _ string, _ []string, integrationID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, found := m.results[integrationID]; found {
		return existing, nil
	}
	m.calls++
	if m.results == nil {
		m.results = make(map[string]string)
	}
	m.results[integrationID] = m.commit
	return m.commit, nil
}

func (m *fakeMerger) Lookup(_ context.Context, integrationID string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	commit, found := m.results[integrationID]
	return commit, found, nil
}

func (m *fakeMerger) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type echoGate struct{}

func (echoGate) Validate(_ context.Context, request Request) (VerifiedRequest, error) {
	return VerifiedRequest{TenantID: request.TenantID, ProjectID: request.ProjectID, IntegrationID: request.IntegrationID, BaseCommit: request.BaseCommit, Candidates: cloneCandidates(request.Candidates), PolicyDigest: request.PolicyDigest, ExpectedVersion: request.ExpectedVersion, PrincipalID: request.PrincipalID, LeaseID: request.LeaseID, FencingToken: request.FencingToken, Authorization: digest("authorization")}, nil
}

type mismatchedGate struct{ echoGate }

func (mismatchedGate) Validate(ctx context.Context, request Request) (VerifiedRequest, error) {
	verified, err := (echoGate{}).Validate(ctx, request)
	verified.ExpectedVersion++
	return verified, err
}

func TestQueueRequiresAnAuthoritativeGate(t *testing.T) {
	if _, err := NewQueue(NewMemoryStore(), &fakeMerger{commit: commit(7)}, nil); !errors.Is(err, ErrNotAudited) {
		t.Fatalf("ungated queue error = %v", err)
	}
	queue, _ := NewVerifiedQueue(NewMemoryStore(), &fakeMerger{commit: commit(7)}, mismatchedGate{}, nil)
	if _, err := queue.Merge(context.Background(), validRequest()); !errors.Is(err, ErrNotAudited) {
		t.Fatalf("mismatched authoritative facts error = %v", err)
	}
}

type flakyCompleteStore struct {
	*MemoryStore
	mu       sync.Mutex
	failures int
}

func (s *flakyCompleteStore) Complete(ctx context.Context, result MergeResult) error {
	s.mu.Lock()
	if s.failures > 0 {
		s.failures--
		s.mu.Unlock()
		return errors.New("durable result unavailable")
	}
	s.mu.Unlock()
	return s.MemoryStore.Complete(ctx, result)
}

func TestQueueRequiresTrustedGate(t *testing.T) {
	if _, err := NewQueue(NewMemoryStore(), &fakeMerger{}, nil); !errors.Is(err, ErrNotAudited) {
		t.Fatalf("ungated constructor error = %v", err)
	}
}

func TestQueueRejectsPathAndInterfaceConflictsBeforeMerge(t *testing.T) {
	merger := &fakeMerger{commit: commit(9)}
	queue, err := NewVerifiedQueue(NewMemoryStore(), merger, echoGate{}, nil)
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
	if audit.Passed || len(audit.Findings) != 2 || merger.callCount() != 0 {
		t.Fatalf("conflict audit did not fail closed: %#v calls=%d", audit, merger.callCount())
	}
	if _, err := queue.Merge(context.Background(), request); !errors.Is(err, ErrConflict) {
		t.Fatalf("merge conflict error = %v", err)
	}
}

func TestQueueMergesOnceAndReturnsImmutableReplay(t *testing.T) {
	merger := &fakeMerger{commit: commit(7)}
	queue, _ := NewVerifiedQueue(NewMemoryStore(), merger, echoGate{}, nil)
	request := validRequest()
	first, err := queue.Merge(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := queue.Merge(context.Background(), request)
	if err != nil || !second.Duplicate || second.Commit != first.Commit || merger.callCount() != 1 {
		t.Fatalf("merge replay was not idempotent: %#v %#v calls=%d", first, second, merger.callCount())
	}
	request.Candidates[0].SubmissionCommit = commit(9)
	if _, err := queue.Merge(context.Background(), request); !errors.Is(err, ErrImmutable) {
		t.Fatalf("different merge body error = %v", err)
	}
}

func TestQueueTreatsCandidateOrderAsCanonical(t *testing.T) {
	merger := &fakeMerger{commit: commit(7)}
	queue, _ := NewVerifiedQueue(NewMemoryStore(), merger, echoGate{}, nil)
	request := validRequest()
	if _, err := queue.Merge(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.Candidates[0], request.Candidates[1] = request.Candidates[1], request.Candidates[0]
	replay, err := queue.Merge(context.Background(), request)
	if err != nil || !replay.Duplicate || merger.callCount() != 1 {
		t.Fatalf("candidate order changed immutable replay: %#v calls=%d", replay, merger.callCount())
	}
}

func TestQueueConcurrentReplayHasOneMergeSideEffect(t *testing.T) {
	merger := &fakeMerger{commit: commit(7)}
	queue, _ := NewVerifiedQueue(NewMemoryStore(), merger, echoGate{}, nil)
	request := validRequest()
	const calls = 100
	errorsCh := make(chan error, calls)
	var group sync.WaitGroup
	for index := 0; index < calls; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := queue.Merge(context.Background(), request)
			errorsCh <- err
		}()
	}
	group.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if merger.callCount() != 1 {
		t.Fatalf("merge side effect count = %d", merger.callCount())
	}
}

func TestQueuesShareDurableReservationAndRecoverExecutorResult(t *testing.T) {
	store := NewMemoryStore()
	merger := &fakeMerger{commit: commit(7)}
	first, _ := NewVerifiedQueue(store, merger, echoGate{}, nil)
	second, _ := NewVerifiedQueue(store, merger, echoGate{}, nil)
	request := validRequest()
	errorsCh := make(chan error, 2)
	var group sync.WaitGroup
	for _, queue := range []*Queue{first, second} {
		group.Add(1)
		go func(queue *Queue) {
			defer group.Done()
			_, err := queue.Merge(context.Background(), request)
			errorsCh <- err
		}(queue)
	}
	group.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if merger.callCount() != 1 {
		t.Fatalf("cross-queue merge side effect count = %d", merger.callCount())
	}
}

func TestRequestDigestBindsPolicyVersionTimeAndAuthorization(t *testing.T) {
	store := NewMemoryStore()
	queue, _ := NewVerifiedQueue(store, &fakeMerger{commit: commit(7)}, echoGate{}, nil)
	request := validRequest()
	if _, err := queue.Merge(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	cases := []Request{request, request, request, request}
	cases[0].PolicyDigest = digest("different-policy")
	cases[1].ExpectedVersion++
	cases[2].CreatedAt = cases[2].CreatedAt.Add(time.Second)
	cases[3].FencingToken++
	for _, changed := range cases {
		if _, err := queue.Merge(context.Background(), changed); !errors.Is(err, ErrImmutable) {
			t.Fatalf("changed immutable request error = %v", err)
		}
	}
}

func TestQueueSharedReservationPreventsCrossInstanceMergeDuplication(t *testing.T) {
	merger := &fakeMerger{commit: commit(7)}
	store := NewMemoryStore()
	first, _ := NewVerifiedQueue(store, merger, echoGate{}, nil)
	second, _ := NewVerifiedQueue(store, merger, echoGate{}, nil)
	request := validRequest()
	const calls = 100
	errorsCh := make(chan error, calls)
	var group sync.WaitGroup
	for index := 0; index < calls; index++ {
		group.Add(1)
		queue := first
		if index%2 == 1 {
			queue = second
		}
		go func() {
			defer group.Done()
			_, err := queue.Merge(context.Background(), request)
			errorsCh <- err
		}()
	}
	group.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if merger.callCount() != 1 {
		t.Fatalf("cross-instance merge side effect count = %d", merger.callCount())
	}
}

func TestQueueRecoversMergeAfterResultPersistenceFailure(t *testing.T) {
	merger := &fakeMerger{commit: commit(7)}
	store := &flakyCompleteStore{MemoryStore: NewMemoryStore(), failures: 1}
	first, _ := NewVerifiedQueue(store, merger, echoGate{}, nil)
	request := validRequest()
	if _, err := first.Merge(context.Background(), request); err == nil {
		t.Fatal("merge result persistence failure was hidden")
	}
	second, _ := NewVerifiedQueue(store, merger, echoGate{}, nil)
	recovered, err := second.Merge(context.Background(), request)
	if err != nil || recovered.Commit != merger.commit || recovered.Pending {
		t.Fatalf("recovered merge = %#v error=%v", recovered, err)
	}
	if merger.callCount() != 1 {
		t.Fatalf("recovery repeated merge side effect: %d", merger.callCount())
	}
}

func TestQueueBindsPolicyVersionAndAuthorizationIntoImmutableRequest(t *testing.T) {
	merger := &fakeMerger{commit: commit(7)}
	queue, _ := NewVerifiedQueue(NewMemoryStore(), merger, echoGate{}, nil)
	request := validRequest()
	if _, err := queue.Merge(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.PolicyDigest = digest("x")
	if _, err := queue.Merge(context.Background(), request); !errors.Is(err, ErrImmutable) {
		t.Fatalf("changed policy replay error = %v", err)
	}
}

func validRequest() Request {
	return Request{TenantID: "tenant-1", ProjectID: "project-1", IntegrationID: "integration-1", IdempotencyKey: "merge-1", BaseCommit: commit(1), PolicyDigest: digest("policy"), ExpectedVersion: 7, CreatedAt: time.Now().UTC(), PrincipalID: "service-integration", LeaseID: "lease-integration", FencingToken: 3, Candidates: []Candidate{{TaskID: "task-1", ModuleID: "module-1", SubmissionCommit: commit(2), ModuleSpecRef: specRef(1), OwnedPaths: []string{"owned/api"}, PublicInterfaces: []string{"HTTP /v1"}, EvidenceSHA256: digest("evidence-1"), AuditPassed: true}, {TaskID: "task-2", ModuleID: "module-2", SubmissionCommit: commit(3), ModuleSpecRef: specRef(2), OwnedPaths: []string{"owned/worker"}, PublicInterfaces: []string{"HTTP /v2"}, EvidenceSHA256: digest("evidence-2"), AuditPassed: true}}}
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
