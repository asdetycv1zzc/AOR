package audit

import (
	"errors"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
)

func TestPostgresAuditRunStoreRequiresDatabase(t *testing.T) {
	if _, err := NewPostgresAuditRunStore(nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil database error = %v", err)
	}
}

func TestCanonicalAuditRunValidatesAndDerivesStableIdentity(t *testing.T) {
	run := validStoredAuditRun()
	canonical, err := canonicalAuditRun(run)
	if err != nil {
		t.Fatal(err)
	}
	if len(canonical.Findings) != 1 || canonical.Findings[0].StableFingerprint == "" {
		t.Fatalf("finding was not canonicalized: %#v", canonical.Findings)
	}
	replay := canonical
	replay.StartedAt = replay.StartedAt.Add(time.Minute)
	replay.CompletedAt = replay.CompletedAt.Add(time.Minute)
	if replay.ID != canonical.ID {
		t.Fatal("retry changed audit run identity")
	}
	run.SubmissionID = "submission-not-a-uuid"
	if _, err := canonicalAuditRun(run); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid submission error = %v", err)
	}
}

func validStoredAuditRun() AuditRun {
	startedAt := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	return AuditRun{
		ID:                "01936f3e-0000-7000-8000-000000000001",
		TenantID:          "11111111-1111-4111-8111-111111111111",
		ProjectID:         "22222222-2222-4222-8222-222222222222",
		SubmissionID:      "33333333-3333-4333-8333-333333333333",
		Phase:             auditPhaseLLM,
		PipelineVersion:   "1.0.0",
		Platform:          contracts.PlatformLinux,
		Isolation:         contracts.IsolationContainer,
		StartedAt:         startedAt,
		CompletedAt:       startedAt.Add(time.Second),
		Verdict:           "FAIL",
		EvidenceBundleRef: digestBytes([]byte("evidence")),
		Findings: []contracts.AuditFinding{deterministicFinding(
			contracts.FindingHigh, "SECURITY", "authorization.required", "owned/file.go",
			"handler/authorize", "missing-authorization", "authorization is enforced",
			"authorization is absent", "restore authorization without broadening access",
		)},
	}
}
