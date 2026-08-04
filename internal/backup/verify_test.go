package backup

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

type artifactVerifier func(context.Context, ArtifactRecord) error

func (f artifactVerifier) Verify(ctx context.Context, artifact ArtifactRecord) error {
	return f(ctx, artifact)
}

func TestVerifyRejectsDanglingReferencesBeforeArtifactAccess(t *testing.T) {
	snapshot := validSnapshot()
	snapshot.Audits[0].ArtifactIDs = []string{"missing"}
	called := false
	_, err := Verify(context.Background(), snapshot, artifactVerifier(func(context.Context, ArtifactRecord) error {
		called = true
		return nil
	}))
	if !errors.Is(err, ErrDanglingReference) || called {
		t.Fatalf("dangling reference result = %v, verifier called=%v", err, called)
	}
}

func TestVerifyChecksEveryArtifactAndProducesStableDigest(t *testing.T) {
	snapshot := validSnapshot()
	seen := make([]string, 0, len(snapshot.Artifacts))
	report, err := Verify(context.Background(), snapshot, artifactVerifier(func(_ context.Context, artifact ArtifactRecord) error {
		seen = append(seen, artifact.ID)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if report.Projects != 1 || report.Goals != 1 || report.Plans != 1 || report.Tasks != 1 || report.Audits != 1 || report.Artifacts != 1 || report.Digest == "" || len(seen) != 1 {
		t.Fatalf("unexpected restore report: %#v, seen=%v", report, seen)
	}
	if _, err := Verify(context.Background(), snapshot, artifactVerifier(func(context.Context, ArtifactRecord) error { return errors.New("hash mismatch") })); !errors.Is(err, ErrArtifactIntegrity) {
		t.Fatalf("artifact failure was not surfaced: %v", err)
	}
}

func TestSnapshotDigestIsIndependentOfRestoreQueryOrder(t *testing.T) {
	first := validSnapshot()
	first.Audits[0].ArtifactIDs = []string{"artifact-2", "artifact-1"}
	first.Artifacts = append(first.Artifacts, ArtifactRecord{TenantID: "tenant-1", ProjectID: "project-1", ID: "artifact-2", URI: "s3://aor/2", SHA256: "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd", Size: 20})
	second := first
	second.Projects = append([]ProjectRecord(nil), first.Projects...)
	second.Goals = append([]GoalRecord(nil), first.Goals...)
	second.Plans = append([]PlanRecord(nil), first.Plans...)
	second.Tasks = append([]TaskRecord(nil), first.Tasks...)
	second.Audits = append([]AuditRecord(nil), first.Audits...)
	second.Artifacts = append([]ArtifactRecord(nil), first.Artifacts...)
	second.Audits[0].ArtifactIDs = []string{"artifact-1", "artifact-2"}
	second.Artifacts[0], second.Artifacts[1] = second.Artifacts[1], second.Artifacts[0]
	firstDigest, err := first.Digest()
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := second.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("query order changed snapshot digest: %s != %s", firstDigest, secondDigest)
	}
}

func TestVerifyStopsWhenContextIsCanceledDuringArtifactScan(t *testing.T) {
	snapshot := validSnapshot()
	snapshot.Artifacts = append(snapshot.Artifacts, ArtifactRecord{TenantID: "tenant-1", ProjectID: "project-1", ID: "artifact-2", URI: "s3://aor/2", SHA256: "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd", Size: 20})
	ctx, cancel := context.WithCancel(context.Background())
	called := 0
	_, err := Verify(ctx, snapshot, artifactVerifier(func(context.Context, ArtifactRecord) error {
		called++
		cancel()
		return nil
	}))
	if !errors.Is(err, context.Canceled) || called != 1 {
		t.Fatalf("canceled restore result = %v, verifier calls=%d", err, called)
	}
}

func TestPostgresSnapshotLoaderRequiresDatabase(t *testing.T) {
	if _, err := NewPostgresSnapshotLoader(nil); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("nil database result = %v", err)
	}
	if _, err := VerifyPostgres(context.Background(), (*sql.DB)(nil), "tenant-1", artifactVerifier(func(context.Context, ArtifactRecord) error { return nil })); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("nil database verification result = %v", err)
	}
}

func TestVerifyRejectsDuplicateAuditRecords(t *testing.T) {
	snapshot := validSnapshot()
	snapshot.Audits = append(snapshot.Audits, snapshot.Audits[0])
	_, err := Verify(context.Background(), snapshot, artifactVerifier(func(context.Context, ArtifactRecord) error { return nil }))
	if !errors.Is(err, ErrDanglingReference) {
		t.Fatalf("duplicate audit result = %v", err)
	}
}

func validSnapshot() Snapshot {
	return Snapshot{
		Version:   1,
		CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		Projects:  []ProjectRecord{{TenantID: "tenant-1", ID: "project-1"}},
		Goals:     []GoalRecord{{TenantID: "tenant-1", ProjectID: "project-1", ID: "goal-1", Version: 1}},
		Plans:     []PlanRecord{{TenantID: "tenant-1", ProjectID: "project-1", ID: "plan-1", GoalID: "goal-1"}},
		Tasks:     []TaskRecord{{TenantID: "tenant-1", ProjectID: "project-1", ID: "task-1", PlanID: "plan-1"}},
		Audits:    []AuditRecord{{TenantID: "tenant-1", ProjectID: "project-1", ID: "audit-1", TaskID: "task-1", ArtifactIDs: []string{"artifact-1"}}},
		Artifacts: []ArtifactRecord{{TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", ID: "artifact-1", URI: "s3://aor/1", SHA256: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Size: 10}},
	}
}
