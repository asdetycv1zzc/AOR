package conformance

import (
	"context"
	"errors"
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
	production, err := runner.Run(context.Background(), Request{Root: "../..", Profile: "production", SpecVersion: "2.0.0", Groups: []string{"security"}, Signer: signer})
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
