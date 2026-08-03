package backup

import (
	"context"
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
