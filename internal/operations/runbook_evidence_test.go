package operations

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateRunbookEvidenceRequiresFreshSignedRecordForEveryRunbook(t *testing.T) {
	now := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	root, evidenceDir, privateKey, publicKey := newRunbookEvidenceFixture(t)
	for _, runbook := range RequiredRunbooks() {
		record := exerciseRecord(runbook, now)
		signed, err := SignRecord(record, privateKey, "ops-key-1")
		if err != nil {
			t.Fatal(err)
		}
		writeExerciseRecord(t, evidenceDir, runbook, signed)
	}
	report, err := ValidateRunbookEvidence(root, evidenceDir, now, publicKey, "ops-key-1")
	if err != nil || len(report.Records) != len(RequiredRunbooks()) || len(report.Missing) != 0 {
		t.Fatalf("fresh signed evidence report=%#v err=%v", report, err)
	}

	if err := os.Remove(filepath.Join(evidenceDir, RequiredRunbooks()[0]+".json")); err != nil {
		t.Fatal(err)
	}
	report, err = ValidateRunbookEvidence(root, evidenceDir, now, publicKey, "ops-key-1")
	if !errors.Is(err, ErrEvidenceMissing) || len(report.Missing) != 1 {
		t.Fatalf("missing evidence report=%#v err=%v", report, err)
	}
}

func TestValidateRunbookEvidenceRejectsStaleAndTamperedRecords(t *testing.T) {
	now := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	root, evidenceDir, privateKey, publicKey := newRunbookEvidenceFixture(t)
	for _, runbook := range RequiredRunbooks() {
		record := exerciseRecord(runbook, now)
		if runbook == RequiredRunbooks()[0] {
			record.StartedAt = now.Add(-DefaultRunbookMaxAge - 2*time.Hour)
			record.EndedAt = now.Add(-DefaultRunbookMaxAge - time.Hour)
		}
		signed, err := SignRecord(record, privateKey, "ops-key-1")
		if err != nil {
			t.Fatal(err)
		}
		writeExerciseRecord(t, evidenceDir, runbook, signed)
	}
	report, err := ValidateRunbookEvidence(root, evidenceDir, now, publicKey, "ops-key-1")
	if !errors.Is(err, ErrInvalidEvidence) || len(report.Findings) == 0 {
		t.Fatalf("stale evidence report=%#v err=%v", report, err)
	}

	// Restore the stale record before checking an independently tampered file.
	record := exerciseRecord(RequiredRunbooks()[0], now)
	signed, err := SignRecord(record, privateKey, "ops-key-1")
	if err != nil {
		t.Fatal(err)
	}
	writeExerciseRecord(t, evidenceDir, RequiredRunbooks()[0], signed)
	path := filepath.Join(evidenceDir, RequiredRunbooks()[1]+".json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)-2] ^= 1
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err = ValidateRunbookEvidence(root, evidenceDir, now, publicKey, "ops-key-1")
	if err == nil || len(report.Findings) == 0 {
		t.Fatalf("tampered evidence report=%#v err=%v", report, err)
	}
}

func newRunbookEvidenceFixture(t *testing.T) (string, string, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	root := t.TempDir()
	evidenceDir := filepath.Join(root, "evidence")
	if err := os.MkdirAll(filepath.Join(root, "runbooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(evidenceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, runbook := range RequiredRunbooks() {
		if err := os.WriteFile(filepath.Join(root, "runbooks", runbook), []byte("exercise procedure\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return root, evidenceDir, privateKey, publicKey
}

func exerciseRecord(runbook string, now time.Time) ExerciseRecord {
	return ExerciseRecord{
		Runbook:        runbook,
		Environment:    "isolated-test",
		StartedAt:      now.Add(-time.Hour),
		EndedAt:        now.Add(-30 * time.Minute),
		Alert:          "synthetic alert from isolated drill",
		Operator:       "operator@example.invalid",
		Result:         "PASS",
		EvidenceURIs:   []string{"artifact://sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		ArtifactSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
}

func writeExerciseRecord(t *testing.T, directory, runbook string, record ExerciseRecord) {
	t.Helper()
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, runbook+".json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
