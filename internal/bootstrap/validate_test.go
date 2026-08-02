package bootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverRequirementIDs(t *testing.T) {
	spec := []byte("- **AOR-INV-002**: invariant\n| AOR-ACC-001 | acceptance |\n- **AOR-INV-002**: repeated\nexample AOR-SEC-004")
	got := DiscoverRequirementIDs(spec)
	want := []string{"AOR-ACC-001", "AOR-INV-002"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestValidateRequirementCatalog(t *testing.T) {
	spec := []byte("- **AOR-INV-001**: one\n- **AOR-INV-002**: two\n")
	catalog := []byte("requirements:\n  - id: AOR-INV-001\n    status: planned\n")
	findings := ValidateRequirementCatalog(spec, catalog)
	if !hasFinding(findings, "REQUIREMENT_MISSING") {
		t.Fatalf("expected missing requirement finding, got %#v", findings)
	}
}

func TestValidateRepositoryRequiresBaselinePaths(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings := ValidateRepository(root)
	if !hasFinding(findings, "REQUIRED_PATH_MISSING") {
		t.Fatalf("expected required path finding, got %#v", findings)
	}
}

func TestScanSecretsDetectsCredentialShape(t *testing.T) {
	root := t.TempDir()
	value := "gh" + "p_" + strings.Repeat("a", 36)
	if err := os.WriteFile(filepath.Join(root, "bad.txt"), []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	findings := ScanSecrets(root)
	if !hasFinding(findings, "SECRET_PATTERN") {
		t.Fatalf("expected secret finding, got %#v", findings)
	}
}

func TestScanSecretsIgnoresGitAndBuildOutput(t *testing.T) {
	root := t.TempDir()
	value := "gh" + "p_" + strings.Repeat("a", 36)
	for _, name := range []string{".git", "bin"} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "ignored"), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if findings := ScanSecrets(root); len(findings) != 0 {
		t.Fatalf("expected ignored files, got %#v", findings)
	}
}

func TestValidateADRSections(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "adr")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "0001-test.md"), []byte("# ADR\n\n## Context\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings := ValidateADRs(root, 1)
	if !hasFinding(findings, "ADR_SECTION_MISSING") {
		t.Fatalf("expected missing ADR section finding, got %#v", findings)
	}
}

func TestValidateSourceMarkersDetectsDeferredWork(t *testing.T) {
	root := t.TempDir()
	marker := "TO" + "DO"
	if err := os.WriteFile(filepath.Join(root, "deferred.go"), []byte("package deferred\n// "+marker+": owner missing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings := ValidateSourceMarkers(root)
	if !hasFinding(findings, "DEFERRED_WORK_MARKER") {
		t.Fatalf("expected deferred work finding, got %#v", findings)
	}
}

func hasFinding(findings []Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
