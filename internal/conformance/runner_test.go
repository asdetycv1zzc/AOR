package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	production, err := runner.Run(context.Background(), Request{Root: "../..", Target: "https://preproduction.aor.invalid", Profile: "production", SpecVersion: "2.0.0", ReleaseVersion: "2.0.0-rc.1", SourceCommit: "0123456789abcdef0123456789abcdef01234567", Signer: signer})
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

func TestRequirementCoverageListsMissingAndDuplicateResults(t *testing.T) {
	root := t.TempDir()
	spec := []byte("**AOR-INV-001**: first\n**AOR-ACC-001**: second\n")
	if err := os.WriteFile(filepath.Join(root, "SPEC.md"), spec, 0o600); err != nil {
		t.Fatal(err)
	}
	result := RequirementResult{RequirementID: "AOR-INV-001", Status: "PASS", EvidenceURIs: []string{"artifact://test"}, Tool: "test", ToolVersion: "1"}
	uncovered, exceptions, err := requirementCoverage(root, []RequirementResult{result, result})
	if err != nil {
		t.Fatal(err)
	}
	if len(uncovered) != 1 || uncovered[0] != "AOR-ACC-001" {
		t.Fatalf("uncovered requirements = %#v", uncovered)
	}
	joined := strings.Join(exceptions, "\n")
	if !strings.Contains(joined, "duplicate requirement result: AOR-INV-001") {
		t.Fatalf("coverage exceptions = %#v", exceptions)
	}
}

func TestSecurityGroupFailsClosedWhenCorpusIsMissing(t *testing.T) {
	runner := NewRunner(nil)
	evidence, err := runner.Run(context.Background(), Request{Root: t.TempDir(), Profile: "test", SpecVersion: "2.0.0", Groups: []string{"security"}})
	if !errors.Is(err, ErrGateFailed) {
		t.Fatalf("missing corpus error = %v", err)
	}
	if len(evidence.Results) != 1 || evidence.Results[0].Status != "FAIL" || evidence.Results[0].RequirementID != "AOR-ACC-043" {
		t.Fatalf("missing corpus evidence = %#v", evidence.Results)
	}
}

func TestProductionCannotSelectOnlyEasyGroups(t *testing.T) {
	signer, _ := NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	runner := NewRunner(nil)
	_, err := runner.Run(context.Background(), Request{Root: "../..", Target: "https://preproduction.aor.invalid", Profile: "production", SpecVersion: "2.0.0", ReleaseVersion: "2.0.0-rc.1", SourceCommit: "0123456789abcdef0123456789abcdef01234567", Groups: []string{"contracts"}, Signer: signer})
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
	if err := os.MkdirAll(filepath.Join(root, ".cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".cache", "generated"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	withoutCache, err := buildDigest(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if first != withoutCache {
		t.Fatal("build digest included the local build cache")
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

func TestEd25519SignerRoundTrip(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEd25519Signer(privateKey, "release-1")
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(context.Background(), []byte("release evidence"))
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Verify(context.Background(), []byte("release evidence"), signature); err != nil {
		t.Fatal(err)
	}
	if err := signer.Verify(context.Background(), []byte("tampered"), signature); !errors.Is(err, ErrGateFailed) {
		t.Fatalf("tampered signature result = %v", err)
	}
}
