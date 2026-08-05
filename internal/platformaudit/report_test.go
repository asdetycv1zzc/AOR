package platformaudit

import (
	"context"
	"errors"
	"testing"

	"github.com/akimisaka/aor/pkg/contracts"
)

func TestNativePlatformReportsCompareFunctionalResultsAndDiscloseSecurity(t *testing.T) {
	testCase := validCase()
	linux, err := Generate(context.Background(), testCase, "linux", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	windows, err := Generate(context.Background(), testCase, "windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if err := Compare(linux, windows); err != nil {
		t.Fatal(err)
	}
	if linux.FunctionalAudit.SHA256 == "" || linux.FunctionalAudit.SHA256 != windows.FunctionalAudit.SHA256 {
		t.Fatalf("functional digests differ: linux=%s windows=%s", linux.FunctionalAudit.SHA256, windows.FunctionalAudit.SHA256)
	}
	if linux.SecurityProfile.IsolationLevel != contracts.IsolationContainer || windows.SecurityProfile.IsolationLevel != contracts.IsolationNone || windows.SecurityProfile.UntrustedProductionWorkloadsAllowed {
		t.Fatalf("security difference is not explicit: linux=%#v windows=%#v", linux.SecurityProfile, windows.SecurityProfile)
	}
}

func TestCompareRejectsFunctionalDrift(t *testing.T) {
	testCase := validCase()
	linux, err := Generate(context.Background(), testCase, "linux", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	windows, err := Generate(context.Background(), testCase, "windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	windows.FunctionalAudit.Checks[0].Status = "FAIL"
	windows.FunctionalAudit.Verdict = "FAIL"
	windows.FunctionalAudit.SHA256, _ = functionalDigest(windows.FunctionalAudit)
	if err := Compare(linux, windows); !errors.Is(err, ErrNotEquivalent) {
		t.Fatalf("functional drift was accepted: %v", err)
	}
}

func TestCompareRejectsDifferentFunctionalInputs(t *testing.T) {
	testCase := validCase()
	linux, err := Generate(context.Background(), testCase, "linux", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	testCase.ForbiddenPaths = append(testCase.ForbiddenPaths, "internal/example/generated/...")
	windows, err := Generate(context.Background(), testCase, "windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if err := Compare(linux, windows); !errors.Is(err, ErrNotEquivalent) {
		t.Fatalf("different functional inputs were accepted: %v", err)
	}
}

func TestReportRejectsMissingSecurityDisclosure(t *testing.T) {
	report, err := Generate(context.Background(), validCase(), "windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	report.SecurityProfile.Limitations = nil
	if err := report.Validate(); err == nil {
		t.Fatal("missing security disclosure was accepted")
	}
}

func validCase() Case {
	module := contracts.SpecRef{Version: 1, SHA256: "sha256:5e9dc061bd5b5bc710d41d7db2789ce73290f94a717e34ca6e930317bfc8b28b"}
	testCase := Case{
		CaseVersion: 1, TenantID: "tenant-platform-ci", ModuleSpecRef: module,
		Manifest: contracts.SubmissionManifest{
			SubmissionVersion: 1, ProjectID: "project-platform-ci", ModuleTaskID: "task-platform-ci",
			AttemptSeriesID: "series-platform-ci", Attempt: 1, ModuleSpecRef: module,
			BaseCommit: "0000000000000000000000000000000000000001", HeadCommit: "0000000000000000000000000000000000000002",
			ChangedFiles: []string{"internal/example/example.go"}, ClaimedCriteria: []string{"functional-equivalence"},
			AgentIdentity: contracts.AgentIdentity{AgentInstanceID: "agent-platform-ci", Role: "EXECUTOR", LeaseID: "lease-platform-ci"},
			CreatedAt:     "2030-01-01T00:00:00Z", SHA256: "sha256:d5a7fc0a3929fca1173476b5ae431ee3d5977b9ee5327e514cf6970f584a2651",
		},
		AllowedPaths: []string{"internal/example/..."}, ForbiddenPaths: []string{"internal/example/secrets/..."},
		RequiredCriteria: []string{"functional-equivalence"}, PolicyDigest: "sha256:855b8c2d4c1da7d5c368410587f093964c33712b2f21facb4cf260c44e8955a3",
	}
	testCase.Manifest.SHA256, _ = manifestDigest(testCase.Manifest)
	return testCase
}
