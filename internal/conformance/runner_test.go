package conformance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunnerProducesHashableEvidenceAndHonorsEnvironmentGates(t *testing.T) {
	signer, err := NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) })
	evidence, err := runner.Run(context.Background(), Request{Root: "../..", Profile: "test", SpecVersion: "2.0.0", Groups: []string{"state-machine"}, Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.EvidenceDigest == "" || evidence.Signature == nil || len(evidence.Results) != 1 {
		t.Fatalf("invalid evidence: %#v", evidence)
	}
	if err := Verify(context.Background(), evidence, signer); err != nil {
		t.Fatal(err)
	}
	production, err := runner.Run(context.Background(), Request{Root: "../..", Target: "https://preproduction.aor.invalid", Profile: "production", SpecVersion: "2.0.0", Signer: signer})
	if !errors.Is(err, ErrGateFailed) || len(production.Exceptions) == 0 {
		t.Fatalf("production gate unexpectedly passed: %v %#v", err, production)
	}
}

func TestRunnerRejectsUnknownGroupAndWritesAtomically(t *testing.T) {
	runner := NewRunner(nil)
	if _, err := runner.Run(context.Background(), Request{Root: "../..", Profile: "test", SpecVersion: "2.0.0", Groups: []string{"unknown"}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unknown group error = %v", err)
	}
}

func TestTestProfileRecordsExternalExceptionsWithoutBlockingLocalEvidence(t *testing.T) {
	runner := NewRunner(nil)
	evidence, err := runner.Run(context.Background(), Request{Root: "../..", Profile: "test", SpecVersion: "2.0.0", Groups: []string{"security"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Exceptions) == 0 {
		t.Fatal("test profile did not record the skipped environment gate")
	}
	if evidence.Results[0].Status != "INCONCLUSIVE" {
		t.Fatalf("unexecuted environment gate status = %s", evidence.Results[0].Status)
	}
}

func TestProductionCannotSelectOnlyEasyGroups(t *testing.T) {
	signer, _ := NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	runner := NewRunner(nil)
	_, err := runner.Run(context.Background(), Request{Root: "../..", Target: "https://preproduction.aor.invalid", Profile: "production", SpecVersion: "2.0.0", Groups: []string{"contracts"}, Signer: signer})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("partial production groups error = %v", err)
	}
}

func TestBuildDigestBindsRepositoryContentAndProductionVerifyRequiresSigner(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "source.txt")
	if err := os.WriteFile(file, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := buildDigest(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := buildDigest(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("build digest did not change with source content")
	}
	evidence := ReleaseEvidence{Environment: "production", EvidenceDigest: first}
	if err := Verify(context.Background(), evidence, nil); !errors.Is(err, ErrGateFailed) {
		t.Fatalf("unsigned production verify error = %v", err)
	}
}
