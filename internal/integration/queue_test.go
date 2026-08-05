package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
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

type revokingGate struct {
	mu     sync.Mutex
	calls  int
	failAt int
}

func (mismatchedGate) Validate(ctx context.Context, request Request) (VerifiedRequest, error) {
	verified, err := (echoGate{}).Validate(ctx, request)
	verified.ExpectedVersion++
	return verified, err
}

func (gate *revokingGate) Validate(ctx context.Context, request Request) (VerifiedRequest, error) {
	gate.mu.Lock()
	gate.calls++
	revoked := gate.failAt > 0 && gate.calls >= gate.failAt
	gate.mu.Unlock()
	if revoked {
		return VerifiedRequest{}, errors.New("authorization revoked")
	}
	return (echoGate{}).Validate(ctx, request)
}

func (gate *revokingGate) callCount() int {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return gate.calls
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

type failingConflictStore struct {
	*MemoryStore
}

func (s *failingConflictStore) RecordConflict(context.Context, MergeResult) (MergeResult, bool, error) {
	return MergeResult{}, false, errors.New("durable conflict unavailable")
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
	store := NewMemoryStore()
	merger := &fakeMerger{commit: commit(9)}
	now := time.Now().UTC()
	clock := now
	queue, err := NewVerifiedQueue(store, merger, echoGate{}, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest()
	request.CreatedAt = now
	request.Candidates[1].OwnedPaths = []string{"owned/api"}
	request.Candidates[1].PublicInterfaces = []string{"HTTP /v1"}
	first, err := queue.Merge(context.Background(), request)
	if !errors.Is(err, ErrConflict) || first.Audit.Passed || len(first.Audit.Findings) != 2 || first.Duplicate || merger.callCount() != 0 {
		t.Fatalf("conflict merge = %#v error=%v calls=%d", first, err, merger.callCount())
	}
	stored, found, storeErr := store.Get(context.Background(), request.TenantID, request.IntegrationID)
	if storeErr != nil || !found || !sameConflictResult(stored, first) {
		t.Fatalf("stored conflict = %#v found=%t error=%v", stored, found, storeErr)
	}
	if _, found, err := store.Get(context.Background(), "other-tenant", request.IntegrationID); err != nil || found {
		t.Fatalf("cross-tenant conflict lookup found=%t error=%v", found, err)
	}
	clock = clock.Add(time.Minute)
	replay, err := queue.Merge(context.Background(), request)
	if !errors.Is(err, ErrConflict) || !replay.Duplicate || !replay.Audit.CreatedAt.Equal(first.Audit.CreatedAt) {
		t.Fatalf("conflict replay = %#v error=%v", replay, err)
	}
	changed := request
	changed.Candidates = cloneCandidates(request.Candidates)
	changed.Candidates[1].OwnedPaths = []string{"owned/worker"}
	if _, err := queue.Merge(context.Background(), changed); !errors.Is(err, ErrImmutable) {
		t.Fatalf("changed conflict error = %v", err)
	}
}

func TestQueueDoesNotReturnConflictBeforePersistence(t *testing.T) {
	store := &failingConflictStore{MemoryStore: NewMemoryStore()}
	queue, _ := NewVerifiedQueue(store, &fakeMerger{commit: commit(9)}, echoGate{}, nil)
	request := validRequest()
	request.Candidates[1].PublicInterfaces = []string{"HTTP /v1"}
	if _, err := queue.Merge(context.Background(), request); err == nil || errors.Is(err, ErrConflict) {
		t.Fatalf("conflict persistence error = %v", err)
	}
}

func TestQueueRevalidatesAuthorizationImmediatelyBeforeMerge(t *testing.T) {
	store := NewMemoryStore()
	merger := &fakeMerger{commit: commit(7)}
	gate := &revokingGate{failAt: 2}
	queue, err := NewVerifiedQueue(store, merger, gate, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest()
	result, err := queue.Merge(context.Background(), request)
	if !errors.Is(err, ErrNotAudited) || !result.Pending {
		t.Fatalf("commit-time authorization error = %v result=%#v", err, result)
	}
	stored, found, storeErr := store.Get(context.Background(), request.TenantID, request.IntegrationID)
	if storeErr != nil || !found || !stored.Pending || merger.callCount() != 0 || gate.callCount() != 2 {
		t.Fatalf("revoked merge state=%#v found=%t storeErr=%v merges=%d validations=%d", stored, found, storeErr, merger.callCount(), gate.callCount())
	}
}

func TestQueueDoesNotAcceptMergeResultAfterAuthorizationRevocation(t *testing.T) {
	store := NewMemoryStore()
	merger := &fakeMerger{commit: commit(7)}
	gate := &revokingGate{failAt: 3}
	queue, err := NewVerifiedQueue(store, merger, gate, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest()
	result, err := queue.Merge(context.Background(), request)
	if !errors.Is(err, ErrNotAudited) || !result.Pending {
		t.Fatalf("post-merge authorization error = %v result=%#v", err, result)
	}
	stored, found, storeErr := store.Get(context.Background(), request.TenantID, request.IntegrationID)
	if storeErr != nil || !found || !stored.Pending || stored.Commit != "" || merger.callCount() != 1 || gate.callCount() != 3 {
		t.Fatalf("revoked merge result state=%#v found=%t storeErr=%v merges=%d validations=%d", stored, found, storeErr, merger.callCount(), gate.callCount())
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
	cases[0].PolicyDigest = digest("odd")
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
	return strings.Repeat(strconv.FormatUint(uint64(value%16), 16), 40)
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
