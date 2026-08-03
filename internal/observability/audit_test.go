package observability

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAuditLogChainsSignsAndDetectsTampering(t *testing.T) {
	log, store, signer := testAuditLog(t)
	ctx := context.Background()
	if _, err := log.Append(ctx, AuditEvent{EventID: "event:1", Type: "PROJECT_CREATED", ProjectID: "project:1", PrincipalID: "user:1"}); err != nil {
		t.Fatal(err)
	}
	security := validSecurityEvent()
	if _, err := log.Append(ctx, security); err != nil {
		t.Fatal(err)
	}
	records := store.Records()
	if err := VerifyAuditChain(ctx, records, signer); err != nil {
		t.Fatal(err)
	}
	records[0].Event.ProjectID = "project:other"
	if !errors.Is(VerifyAuditChain(ctx, records, signer), ErrAuditIntegrity) {
		t.Fatal("tampered chain verified")
	}
}

func TestSecurityAuditRequiresStructuredEvidenceContext(t *testing.T) {
	log, _, _ := testAuditLog(t)
	event := validSecurityEvent()
	event.PolicyVersion = ""
	if _, err := log.Append(context.Background(), event); !errors.Is(err, ErrAuditSecurityContext) {
		t.Fatalf("incomplete security event accepted: %v", err)
	}
}

func TestAuditLogRefusesToExtendTamperedHead(t *testing.T) {
	log, store, _ := testAuditLog(t)
	ctx := context.Background()
	if _, err := log.Append(ctx, AuditEvent{EventID: "event:1", Type: "PROJECT_CREATED", PrincipalID: "system:1"}); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.records[0].Event.ProjectID = "tampered"
	store.mu.Unlock()
	if _, err := log.Append(ctx, AuditEvent{EventID: "event:2", Type: "PROJECT_PAUSED", PrincipalID: "system:1"}); !errors.Is(err, ErrAuditIntegrity) {
		t.Fatalf("tampered head was extended: %v", err)
	}
}

func TestAuditReadsAreAuditedAndQueryable(t *testing.T) {
	log, store, signer := testAuditLog(t)
	ctx := context.Background()
	if _, err := log.Append(ctx, AuditEvent{
		EventID: "event:approval", Type: "APPROVAL_RECORDED", ProjectID: "project:1", TaskID: "task:1",
		PrincipalID: "user:1", ApprovalID: "approval:1",
	}); err != nil {
		t.Fatal(err)
	}
	records, err := log.Query(ctx, "admin:1", "INCIDENT_REVIEW", AuditFilter{ProjectID: "project:1", ApprovalID: "approval:1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[1].Event.Type != "AUDIT_LOG_READ" {
		t.Fatalf("read event was not included: %#v", records)
	}
	if err := VerifyAuditChain(ctx, store.Records(), signer); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentAuditAppendsRemainSequential(t *testing.T) {
	log, store, signer := testAuditLog(t)
	ctx := context.Background()
	var wait sync.WaitGroup
	errorsFound := make(chan error, 32)
	for index := range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := log.Append(ctx, AuditEvent{EventID: fmt.Sprintf("event:%d", index), Type: "PROJECT_UPDATED", PrincipalID: "system:1"})
			if err != nil {
				errorsFound <- err
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
	records := store.Records()
	if len(records) != 32 {
		t.Fatalf("record count = %d", len(records))
	}
	if err := VerifyAuditChain(ctx, records, signer); err != nil {
		t.Fatal(err)
	}
}

func TestFileAuditStorePersistsAppendOnlyChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := NewFileAuditStore(path, "file://audit")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewHMACAuditSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	clock := fixedTrustedClock{timestamp: TrustedTimestamp{At: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), Source: "test-ntp", Uncertainty: time.Millisecond}}
	log, err := NewAuditLog(store, signer, clock, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(context.Background(), AuditEvent{EventID: "event:file", Type: "PROJECT_CREATED", PrincipalID: "system:1"}); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileAuditStore(path, "file://audit")
	if err != nil {
		t.Fatal(err)
	}
	records, err := reopened.Query(context.Background(), AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("persisted records = %d", len(records))
	}
	if err := VerifyAuditChain(context.Background(), records, signer); err != nil {
		t.Fatal(err)
	}
}

func testAuditLog(t *testing.T) (*AuditLog, *MemoryAuditStore, *HMACAuditSigner) {
	t.Helper()
	store := &MemoryAuditStore{Destination: "worm://audit"}
	signer, err := NewHMACAuditSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	clock := fixedTrustedClock{timestamp: TrustedTimestamp{
		At: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), Source: "test-ntp", Uncertainty: time.Millisecond,
	}}
	log, err := NewAuditLog(store, signer, clock, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return log, store, signer
}

func validSecurityEvent() AuditEvent {
	return AuditEvent{
		EventID: "event:security", Type: "POLICY_BYPASS_ATTEMPT", ProjectID: "project:1", TaskID: "task:1",
		PrincipalID: "agent:1", PolicyVersion: "policy:v1",
		EvidenceSHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		TraceID:        "4bf92f3577b34da6a3ce929d0e0e4736",
	}
}

type fixedTrustedClock struct {
	timestamp TrustedTimestamp
	err       error
}

func (c fixedTrustedClock) Now(context.Context) (TrustedTimestamp, error) {
	if c.err != nil {
		return TrustedTimestamp{}, fmt.Errorf("trusted clock: %w", c.err)
	}
	return c.timestamp, nil
}
