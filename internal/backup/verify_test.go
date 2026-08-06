package backup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/artifact"
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

func TestVerifyRejectsDanglingArtifactTaskBeforeArtifactAccess(t *testing.T) {
	snapshot := validSnapshot()
	snapshot.Artifacts[0].TaskID = "missing"
	called := false
	_, err := Verify(context.Background(), snapshot, artifactVerifier(func(context.Context, ArtifactRecord) error {
		called = true
		return nil
	}))
	if !errors.Is(err, ErrDanglingReference) || called {
		t.Fatalf("dangling artifact task result = %v, verifier called=%v", err, called)
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

func TestVerifyRejectsCrossProjectActiveReferences(t *testing.T) {
	snapshot := validSnapshot()
	snapshot.Projects = append(snapshot.Projects, ProjectRecord{TenantID: "tenant-1", ID: "project-2", ActiveGoalID: "goal-1"})
	_, err := Verify(context.Background(), snapshot, artifactVerifier(func(context.Context, ArtifactRecord) error { return nil }))
	if !errors.Is(err, ErrDanglingReference) {
		t.Fatalf("cross-project active goal result = %v", err)
	}
}

func TestVerifyRejectsMissingPlanBindings(t *testing.T) {
	snapshot := validSnapshot()
	snapshot.Plans[0].GoalID = ""
	_, err := Verify(context.Background(), snapshot, artifactVerifier(func(context.Context, ArtifactRecord) error { return nil }))
	if !errors.Is(err, ErrDanglingReference) {
		t.Fatalf("missing plan goal result = %v", err)
	}
	snapshot = validSnapshot()
	snapshot.Tasks[0].PlanID = ""
	_, err = Verify(context.Background(), snapshot, artifactVerifier(func(context.Context, ArtifactRecord) error { return nil }))
	if !errors.Is(err, ErrDanglingReference) {
		t.Fatalf("missing task plan result = %v", err)
	}
}

func TestVerifyRejectsMissingFindingArtifactReference(t *testing.T) {
	snapshot := validSnapshot()
	snapshot.Audits[0].EvidenceRefs = []string{"artifact://sha256/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
	_, err := Verify(context.Background(), snapshot, artifactVerifier(func(context.Context, ArtifactRecord) error { return nil }))
	if !errors.Is(err, ErrDanglingReference) {
		t.Fatalf("missing finding artifact result = %v", err)
	}
}

func TestCatalogArtifactVerifierChecksRowAndContent(t *testing.T) {
	content := "restored artifact"
	digest := sha256.Sum256([]byte(content))
	expectedDigest := "sha256:" + hex.EncodeToString(digest[:])
	expected := ArtifactRecord{TenantID: "tenant-1", ProjectID: "project-1", ID: "artifact-1", URI: "artifact://sha256/" + hex.EncodeToString(digest[:]), SHA256: expectedDigest, Size: int64(len(content))}
	catalog := &fakeBackupArtifactCatalog{record: artifact.Record{ID: expected.ID, TenantID: expected.TenantID, ProjectID: expected.ProjectID, URI: expected.URI, SHA256: expected.SHA256, SizeBytes: expected.Size}, content: content}
	verifier, err := NewCatalogArtifactVerifier(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), expected); err != nil {
		t.Fatal(err)
	}
	catalog.record.URI = "artifact://sha256/other"
	if !errors.Is(verifier.Verify(context.Background(), expected), ErrArtifactRecordMismatch) {
		t.Fatal("catalog record mismatch was accepted")
	}
}

type fakeBackupArtifactCatalog struct {
	record  artifact.Record
	content string
}

func (catalog *fakeBackupArtifactCatalog) List(context.Context, string, string, string, int) (artifact.Page, error) {
	return artifact.Page{}, nil
}

func (catalog *fakeBackupArtifactCatalog) Get(context.Context, string, string, string) (artifact.Record, error) {
	return catalog.record, nil
}

func (catalog *fakeBackupArtifactCatalog) Open(context.Context, string, string, string) (artifact.Record, io.ReadCloser, error) {
	return catalog.record, io.NopCloser(strings.NewReader(catalog.content)), nil
}

func validSnapshot() Snapshot {
	return Snapshot{
		Version:   1,
		CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		Projects:  []ProjectRecord{{TenantID: "tenant-1", ID: "project-1", ActiveGoalID: "goal-1", ActivePlanID: "plan-1"}},
		Goals:     []GoalRecord{{TenantID: "tenant-1", ProjectID: "project-1", ID: "goal-1", Version: 1}},
		Plans:     []PlanRecord{{TenantID: "tenant-1", ProjectID: "project-1", ID: "plan-1", GoalID: "goal-1"}},
		Tasks:     []TaskRecord{{TenantID: "tenant-1", ProjectID: "project-1", ID: "task-1", PlanID: "plan-1"}},
		Audits:    []AuditRecord{{TenantID: "tenant-1", ProjectID: "project-1", ID: "audit-1", TaskID: "task-1", ArtifactIDs: []string{"artifact-1"}, EvidenceRefs: []string{"artifact://sha256/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}},
		Artifacts: []ArtifactRecord{{TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", ID: "artifact-1", URI: "artifact://sha256/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", SHA256: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Size: 10}},
	}
}
